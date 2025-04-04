// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controlplane

import (
	"bytes"
	_ "embed"
	"regexp"
)

var (
	//go:embed k8s_versions.txt
	k8sVersionsData []byte
)

func K8sVersions() (k8sVersions []string) {
	for w := range bytes.SplitSeq(k8sVersionsData, []byte{'\n'}) {
		if len(w) != 0 {
			version := regexp.MustCompile(`\d\.\d{2}`).Find(w)
			k8sVersions = append(k8sVersions, string(version))
		}
	}
	return k8sVersions
}
