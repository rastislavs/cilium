// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pool

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/backoff"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	"github.com/cilium/cilium/pkg/hubble/relay/defaults"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/time"
)

// defaultOptions is the reference point for default values.
var defaultOptions = options{
	peerServiceAddress: defaults.PeerTarget,
	peerClientBuilder:  peerTypes.LocalClientBuilder{},
	clientConnBuilder:  GRPCClientConnBuilder{},
	connCheckInterval:  2 * time.Minute,
	connStatusInterval: 5 * time.Second,
	retryTimeout:       defaults.RetryTimeout,
}

func defaultBackoff(logger *slog.Logger) *backoff.Exponential {
	return &backoff.Exponential{
		Logger: logger,
		Min:    time.Second,
		Max:    time.Minute,
		Factor: 2.0,
	}
}

// Option customizes the configuration of the Manager.
type Option func(o *options) error

// options stores all the configuration values for peer manager.
type options struct {
	log                *slog.Logger
	peerServiceAddress string
	peerClientBuilder  peerTypes.ClientBuilder
	clientConnBuilder  poolTypes.ClientConnBuilder
	backoff            BackoffDuration
	connCheckInterval  time.Duration
	connStatusInterval time.Duration
	retryTimeout       time.Duration
}

// WithPeerServiceAddress sets the address of the peer gRPC service.
func WithPeerServiceAddress(a string) Option {
	return func(o *options) error {
		o.peerServiceAddress = a
		return nil
	}
}

// WithPeerClientBuilder sets the ClientBuilder that is used to create new Peer
// service clients.
func WithPeerClientBuilder(b peerTypes.ClientBuilder) Option {
	return func(o *options) error {
		o.peerClientBuilder = b
		return nil
	}
}

// WithClientConnBuilder sets the GRPCClientConnBuilder that is used to create
// new gRPC connections to peers.
func WithClientConnBuilder(b poolTypes.ClientConnBuilder) Option {
	return func(o *options) error {
		o.clientConnBuilder = b
		return nil
	}
}

// WithBackoff sets the backoff between after a failed connection attempt.
func WithBackoff(b BackoffDuration) Option {
	return func(o *options) error {
		o.backoff = b
		return nil
	}
}

// WithConnCheckInterval sets the time interval between peer connections health
// checks.
func WithConnCheckInterval(i time.Duration) Option {
	return func(o *options) error {
		o.connCheckInterval = i
		return nil
	}
}

// WithConnStatusInterval sets the time interval between peer connection status
// is reported through Prometheus gauge metrics.
func WithConnStatusInterval(i time.Duration) Option {
	return func(o *options) error {
		o.connStatusInterval = i
		return nil
	}
}

// WithRetryTimeout sets the duration to wait before attempting to re-connect
// to the peer gRPC service.
func WithRetryTimeout(t time.Duration) Option {
	return func(o *options) error {
		o.retryTimeout = t
		return nil
	}
}

// WithLogger sets the logger to use for logging.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) error {
		o.log = l
		return nil
	}
}
