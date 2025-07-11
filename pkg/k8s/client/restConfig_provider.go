// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cloudflare/cfssl/log"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

var (
	// K8sAPIServerFilePath is the file path for storing kube-apiserver service and
	// endpoints for high availability failover.
	K8sAPIServerFilePath = filepath.Join(option.Config.StateDir, "k8sapi_server_state.json")
)

type K8sServiceEndpointMapping struct {
	Service   string   `json:"service"`
	Endpoints []string `json:"endpoints"`
}

func (m K8sServiceEndpointMapping) Equal(other K8sServiceEndpointMapping) bool {
	return m.Service == other.Service && slices.Equal(m.Endpoints, other.Endpoints)
}

// restConfigManager manages the rest configuration for connecting to the API server, including the logic to fail over
// to an active kube-apiserver in order to support high availability.
//
// Below are the sequence of events to support kube-apiserver failover.
//
// Bootstrap: It parses the user provided configuration which may include multiple API server URLs. In case of multiple
// API servers, it wraps the rest configuration with an HTTP RoundTripper that enables updating the remote host while
// making API requests to the kube-apiserver. It also asynchronously monitors kube-apiserver service and endpoints related updates.
// Initially an active kube-apiserver URL is picked at random, and servers are manually rotated on connectivity failures.
//
// Runtime: After the agent's initial sync with the kube-apiserver, when the manager receives updates for the kube-apiserver
// service, it switches over to the service address as the remote host set in the rest configuration. Thereafter, manual
// rotation of API servers is not needed as Cilium datapath will load-balance API traffic to the kube-apiserver endpoints.
//
// Restore: The manager restores the persisted kube-apiserver state after restart after ensuring connectivity using
// the service address. If that fails, it'll fall back to user provided kube-apiserver URLs. Note that these could be
// different from the ones configured during initial bootstrap as those kube-apiservers may all have been rotated while
// the agent was down.
type restConfigManager struct {
	restConfig           *rest.Config
	apiServerURLs        []*url.URL
	isConnectedToService bool
	lock.RWMutex
	log *slog.Logger
	rt  *rotatingHttpRoundTripper
}

func (r *restConfigManager) getConfig() *rest.Config {
	r.RLock()
	defer r.RUnlock()
	return rest.CopyConfig(r.restConfig)
}

func (r *restConfigManager) canRotateAPIServerURL() bool {
	r.RLock()
	defer r.RUnlock()

	// API server URLs are initially manually rotated when multiple
	// servers are configured by the user. Once the connections are
	// switched over to the kube-apiserver service address, manual
	// rotation isn't needed as Cilium datapath will load balance
	// connections to active kube-apiservers.
	return len(r.apiServerURLs) > 1 && !r.isConnectedToService
}

func restConfigManagerInit(cfg Config, name string, log *slog.Logger) (*restConfigManager, error) {
	var err error
	manager := restConfigManager{
		log: log,
		rt: &rotatingHttpRoundTripper{
			log: log,
		},
	}

	manager.parseConfig(cfg)

	cmdName := "cilium"
	if len(os.Args[0]) != 0 {
		cmdName = filepath.Base(os.Args[0])
	}
	userAgent := fmt.Sprintf("%s/%s", cmdName, version.Version)

	if name != "" {
		userAgent = fmt.Sprintf("%s %s", userAgent, name)
	}

	if manager.restConfig, err = manager.createConfig(cfg, userAgent); err != nil {
		return nil, err
	}
	if manager.canRotateAPIServerURL() {
		// Pick an API server at random.
		manager.rotateAPIServerURL()

		// Restore the mappings from disk.
		manager.restoreFromDisk()
	}

	return &manager, err
}

// createConfig creates a rest.Config for connecting to k8s api-server.
//
// The precedence of the configuration selection is the following:
// 1. kubeCfgPath
// 2. apiServerURL(s) (https if specified)
// 3. rest.InClusterConfig().
func (r *restConfigManager) createConfig(cfg Config, userAgent string) (*rest.Config, error) {
	var (
		config       *rest.Config
		err          error
		apiServerURL string
	)
	if cfg.K8sAPIServer != "" {
		apiServerURL = cfg.K8sAPIServer
	} else if len(r.apiServerURLs) > 0 {
		apiServerURL = r.apiServerURLs[0].String()
	}
	kubeCfgPath := cfg.K8sKubeConfigPath
	qps := cfg.K8sClientQPS
	burst := cfg.K8sClientBurst

	switch {
	// If the apiServerURL and the kubeCfgPath are empty then we can try getting
	// the rest.Config from the InClusterConfig
	case apiServerURL == "" && kubeCfgPath == "":
		if config, err = rest.InClusterConfig(); err != nil {
			return nil, err
		}
	case kubeCfgPath != "":
		if config, err = clientcmd.BuildConfigFromFlags("", kubeCfgPath); err != nil {
			return nil, err
		}
	case strings.HasPrefix(apiServerURL, "https://"):
		if config, err = rest.InClusterConfig(); err != nil {
			return nil, err
		}
		config.Host = apiServerURL
	default:
		//exhaustruct:ignore
		config = &rest.Config{Host: apiServerURL, UserAgent: userAgent}
	}

	// The HTTP round tripper rotates API server URLs in case of connectivity failures.
	if len(r.apiServerURLs) > 1 {
		config.Wrap(r.WrapRoundTripper)
	}

	setConfig(config, userAgent, qps, burst)
	return config, nil
}

func (r *restConfigManager) parseConfig(cfg Config) {
	if cfg.K8sAPIServer != "" {
		var (
			serverURL *url.URL
			err       error
		)
		s := cfg.K8sAPIServer
		if !strings.HasPrefix(s, "http") {
			s = fmt.Sprintf("http://%s", s) // default to HTTP
		}
		serverURL, err = url.Parse(s)
		if err != nil {
			r.log.Error("Failed to parse APIServerURL, skipping",
				logfields.Error, err,
				logfields.URL, serverURL,
			)
			return
		}
		r.apiServerURLs = append(r.apiServerURLs, serverURL)
		return
	}
	for _, apiServerURL := range cfg.K8sAPIServerURLs {
		if apiServerURL == "" {
			continue
		}

		if !strings.HasPrefix(apiServerURL, "http") && !strings.HasPrefix(apiServerURL, "https") {
			apiServerURL = fmt.Sprintf("https://%s", apiServerURL)
		}

		serverURL, err := url.Parse(apiServerURL)
		if err != nil {
			r.log.Error("Failed to parse APIServerURL, skipping",
				logfields.Error, err,
				logfields.URL, apiServerURL,
			)
			continue
		}

		r.apiServerURLs = append(r.apiServerURLs, serverURL)
	}
}

func setConfig(config *rest.Config, userAgent string, qps float32, burst int) {
	if userAgent != "" {
		config.UserAgent = userAgent
	}
	if qps != 0.0 {
		config.QPS = qps
	}
	if burst != 0 {
		config.Burst = burst
	}
}

func (r *restConfigManager) rotateAPIServerURL() {
	if len(r.apiServerURLs) <= 1 {
		return
	}

	r.rt.Lock()
	defer r.rt.Unlock()
	for {
		idx := rand.IntN(len(r.apiServerURLs))
		if r.rt.apiServerURL != r.apiServerURLs[idx] {
			r.rt.apiServerURL = r.apiServerURLs[idx]
			break
		}
	}
	r.Lock()
	r.restConfig.Host = r.rt.apiServerURL.String()
	r.Unlock()
	r.log.Info("Rotated api server",
		logfields.URL, r.rt.apiServerURL,
	)
}

// rotatingHttpRoundTripper sets the remote host in the rest configuration used to make API requests to the API server.
type rotatingHttpRoundTripper struct {
	delegate     http.RoundTripper
	log          *slog.Logger
	apiServerURL *url.URL
	lock.RWMutex // Synchronizes access to apiServerURL
}

func (rt *rotatingHttpRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.RLock()
	defer rt.RUnlock()

	rt.log.Debug("Kubernetes api server host",
		logfields.URL, rt.apiServerURL,
	)
	req.URL.Host = rt.apiServerURL.Host
	return rt.delegate.RoundTrip(req)
}

func (r *restConfigManager) WrapRoundTripper(rt http.RoundTripper) http.RoundTripper {
	r.rt.delegate = rt
	return r.rt
}

func (r *restConfigManager) restoreFromDisk() {
	f, err := os.Open(K8sAPIServerFilePath)
	if err != nil {
		r.log.Error("unable "+
			"to open file, agent may not be able to fail over to an active kube-apiserver",
			logfields.Path, K8sAPIServerFilePath,
			logfields.Error, err,
		)
		return
	}
	defer f.Close()

	if finfo, err := os.Stat(K8sAPIServerFilePath); err != nil || finfo.Size() == 0 {
		return
	}

	var mapping K8sServiceEndpointMapping
	if err = json.NewDecoder(f).Decode(&mapping); err != nil {
		r.log.Error("failed to "+
			"decode file entry, agent may not be able to fail over to an active kube-apiserver",
			logfields.Error, err,
			logfields.Path, K8sAPIServerFilePath,
			logfields.Entry, mapping,
		)
		return
	}
	r.updateMappings(mapping)
}

func (r *restConfigManager) saveMapping(mapping K8sServiceEndpointMapping) {
	// Write the mappings to disk so they can be restored on restart.
	if f, err := os.OpenFile(K8sAPIServerFilePath, os.O_RDWR, 0644); err == nil {
		defer f.Close()
		if err = json.NewEncoder(f).Encode(mapping); err != nil {
			log.Error("failed to write kubernetes service entry,"+
				"agent may not be able to fail over to an active k8sapi-server",
				logfields.Error, err,
				logfields.Entry, mapping,
			)
		}
	}
}

func (r *restConfigManager) updateMappings(mapping K8sServiceEndpointMapping) {
	if err := r.checkConnToService(mapping.Service); err != nil {
		return
	}

	r.saveMapping(mapping)

	r.log.Info("Updated kubeapi server url host",
		logfields.URL, mapping.Service,
	)

	// Set in tests
	mapping.Service = strings.TrimPrefix(mapping.Service, "http://")
	r.rt.Lock()
	defer r.rt.Unlock()
	r.rt.apiServerURL.Host = mapping.Service
	r.Lock()
	defer r.Unlock()
	r.isConnectedToService = true
	r.restConfig.Host = mapping.Service
	updatedServerURLs := make([]*url.URL, 0)
	for _, endpoint := range mapping.Endpoints {
		endpoint = fmt.Sprintf("https://%s", endpoint)
		serverURL, err := url.Parse(endpoint)
		if err != nil {
			r.log.Info("Failed to parse endpoint, skipping",
				logfields.Endpoint, endpoint,
				logfields.Error, err,
			)
			continue
		}
		updatedServerURLs = append(updatedServerURLs, serverURL)
	}
	if len(updatedServerURLs) != 0 {
		r.apiServerURLs = updatedServerURLs
	}

}

// checkConnToService ensures connectivity to the API server via the passed service address.
func (r *restConfigManager) checkConnToService(host string) error {
	stop := make(chan struct{})
	timeout := time.NewTimer(connTimeout)
	defer timeout.Stop()
	var (
		config *rest.Config
		err    error
	)
	if strings.HasPrefix(host, "http") {
		// Set in tests
		//exhaustruct:ignore
		config = &rest.Config{Host: host, Timeout: connTimeout}
	} else {
		hostURL := fmt.Sprintf("https://%s", host)
		config, err = rest.InClusterConfig()
		if err != nil {
			r.log.Error("unable to read cluster config",
				logfields.Error, err,
			)
			return err
		}
		config.Host = hostURL
	}
	wait.Until(func() {
		r.log.Info("Checking connection to kubeapi service",
			logfields.Address, config.Host,
		)
		httpClient, _ := rest.HTTPClientFor(config)

		cs, _ := kubernetes.NewForConfigAndClient(config, httpClient)
		if err = isConnReady(cs); err == nil {
			close(stop)
			return
		}

		select {
		case <-timeout.C:
		default:
			return
		}

		r.log.Error("kubeapi service not ready yet",
			logfields.Address, config.Host,
			logfields.Error, err,
		)
		close(stop)
	}, connRetryInterval, stop)
	if err == nil {
		r.log.Info("Connected to kubeapi service",
			logfields.Address, config.Host,
		)
	}
	return err
}

type mappingUpdaterParams struct {
	cell.In

	JobGroup  job.Group
	Log       *slog.Logger
	Manager   *restConfigManager
	DB        *statedb.DB                           `optional:"true"`
	Frontends statedb.Table[*loadbalancer.Frontend] `optional:"true"`
}

// registerMappingsUpdater watches the default/kubernetes frontend for
// changes and updates the mapping file.
// This is currently used for supporting high availability for kubeapi-server.
func registerMappingsUpdater(p mappingUpdaterParams) {
	if p.DB == nil || p.Frontends == nil {
		// These are optional to make the [Cell] usable without
		// load-balancing control-plane.
		return
	}

	if p.Manager == nil || !p.Manager.canRotateAPIServerURL() {
		return
	}

	p.JobGroup.Add(
		job.OneShot(
			"update-k8s-api-service-mappings",
			func(ctx context.Context, health cell.Health) error {
				// Watch for changes to the default/kubernetes service frontend
				// and update the mappings if it changes.
				var previous K8sServiceEndpointMapping
				for {
					fe, _, watch, found := p.Frontends.GetWatch(
						p.DB.ReadTxn(),
						loadbalancer.FrontendByServiceName(loadbalancer.NewServiceName(
							"default", "kubernetes")))
					if found {
						mapping := frontendToMapping(fe)
						if !mapping.Equal(previous) {
							previous = mapping
							log.Info("updating kubernetes service mapping",
								logfields.Entry, mapping,
							)
							p.Manager.updateMappings(mapping)

						}
					}

					select {
					case <-ctx.Done():
						return nil
					case <-watch:
					}
				}
			}))
}

func frontendToMapping(fe *loadbalancer.Frontend) K8sServiceEndpointMapping {
	var mapping K8sServiceEndpointMapping
	mapping.Service = fe.Address.AddrString()
	for be := range fe.Backends {
		mapping.Endpoints = append(mapping.Endpoints, be.Address.AddrString())
	}
	return mapping
}
