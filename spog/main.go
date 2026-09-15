// Single Pain of Glass — the "real" observability platform.
//
// Purely cosmetic: it exists to look like a legit, boring, over-promised
// dashboard next to the deliberately vulnerable Oopservability agent. It
// does not scrape, store, or query anything — every number on the page is
// made up, which is arguably still more honest than most dashboards.

package main

import (
	"embed"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"
)

//go:embed static/index.html
var staticFiles embed.FS

var dashboardTmpl *template.Template

var startedAt = time.Now()

func main() {
	var err error
	dashboardTmpl, err = template.ParseFS(staticFiles, "static/index.html")
	if err != nil {
		log.Fatalf("failed to parse dashboard template: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleDashboard)
	mux.HandleFunc("/healthz", handleHealthz)

	port := envOr("PORT", "8080")
	log.Printf("[single-pain-of-glass] serving unified insights nobody asked for on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := map[string]string{
		"Uptime": time.Since(startedAt).Round(time.Second).String(),
	}
	w.Header().Set("Content-Type", "text/html")
	if err := dashboardTmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","panes":1,"pain":"unbounded"}`))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
