package main

// httpclient.go — shared HTTP client helpers.

import (
	"crypto/tls"
	"net/http"
	"time"
)

// insecureHTTPClient returns an HTTP client that skips TLS certificate
// verification.  This is intentionally insecure — in a real observability
// agent you would load the cluster CA bundle from
// /var/run/secrets/kubernetes.io/serviceaccount/ca.crt.
//
// VULN[BASIC]: skipping TLS verification allows MITM attacks against
// the Kubernetes API server connection.
func insecureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}
