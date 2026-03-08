// Ooopservability — Intentionally Vulnerable Observability Agent
//
// Educational tool for Kubernetes security tutorials.
// Demonstrates the risks of over-permissive RBAC, specifically:
//   nodes/proxy GET → full kubelet API access
//
// DO NOT deploy in production. This service contains deliberate
// unauthenticated RCE, path traversal, and fileless execution vectors.

package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof" // VULN[BASIC]: pprof left exposed — leaks goroutines, heap, config
	"os"
	"text/template"
)

//go:embed static/index.html
var staticFiles embed.FS

var dashboardTmpl *template.Template

func main() {
	var err error
	dashboardTmpl, err = template.ParseFS(staticFiles, "static/index.html")
	if err != nil {
		log.Fatalf("failed to parse dashboard template: %v", err)
	}

	mux := http.NewServeMux()
	registerRoutes(mux)

	// VULN[BASIC]: pprof handlers registered on default mux, exposed below
	mux.Handle("/debug/", http.DefaultServeMux)

	port := envOr("PORT", "8080")
	log.Printf("[ooopservability] agent starting  node=%s  namespace=%s  port=%s",
		envOr("NODE_NAME", "unknown"),
		envOr("POD_NAMESPACE", "ooopservability"),
		port,
	)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", handleDashboard)
	mux.HandleFunc("/healthz", handleHealthz)

	// "Observability" API
	mux.HandleFunc("/api/v1/metrics", handleMetrics)
	mux.HandleFunc("/api/v1/nodes", handleNodes)
	mux.HandleFunc("/api/v1/logs/search", handleLogSearch)    // VULN[BASIC]:   command injection
	mux.HandleFunc("/api/v1/diagnostics/run", handleExec)     // VULN[BASIC]:   unauthenticated RCE
	mux.HandleFunc("/api/v1/diagnostics/upload", handleUpload) // VULN[ADVANCED]: fileless execution
	mux.HandleFunc("/api/v1/plugins/update", handlePluginUpdate)    // VULN[ADVANCED]: RCE + fileless exec
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := map[string]string{
		"NodeName":  envOr("NODE_NAME", "unknown"),
		"Namespace": envOr("POD_NAMESPACE", "ooopservability"),
		"Version":   "v0.1.0",
	}
	w.Header().Set("Content-Type", "text/html")
	if err := dashboardTmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{"status":"ok"}`)
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
