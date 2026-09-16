# anvilkit-job-access-sidecar

Per-job access proxy for credential isolation, scoped model and artifact access, and protected control and result submission. It is the trusted access sidecar of DD-03 §5 in the AnvilKit architecture (`docs/architecture/execution.md` of `anvilkit-services`): the only process of a Job Pod that holds the Job's network identity and reaches Control. The launcher runs it as a Kubernetes native sidecar (an init container with `restartPolicy: Always`): it starts before the trusted harness and the kubelet stops it once the harness exited, so a finished launch never stays alive behind it.

## Boundary

- Runs as UID 10002 with no capability and the supplementary groups `[0, 10001]`. It creates its socket directory (`10002:0`, `0711`), `trusted.sock` (`10002:0`, `0660`) and `candidate.sock` (`10002:10001`, `0660`); the directory is a read-only mount in the other containers. Every step verifies the owner, group and mode it produced.
- Every accepted connection is bound to the peer's kernel-reported credentials (`SO_PEERCRED`): only UID 0 on the trusted socket, only UID 10001 on the candidate socket; anything else is closed at accept. Ancillary data (a delegated descriptor) closes the connection unserved. Each connection serves one request and closes.
- The execution scope is never claimed and never cached: it is what the trusted launcher registered with Control (`ExecutionService.GetInstance` by backend, launch key and the Pod UID the kubelet injected), read again from Control before every protected request — the scope, staging and serving inputs, transfers, results and relays. Historical physical ownership is not current permission: the answer authorizes only while the registration names the launch envelope's attempt, profile, launch key and epochs, the instance is the current one, the attempt is `LAUNCH_PREPARED` or `RUNNING` under the operation's current execution epoch, the operation is not fenced (no cancel or hold intent, not terminal, not reconciling) and the attempt and operation deadlines have not passed. A registered but non-current instance (a duplicate Pod) never gains authority; a closed attempt, a fenced operation, a moved epoch or a passed deadline ends it (`403 STALE_EXECUTION`, `NO_AUTHORITY`, `DEADLINE_EXCEEDED`); an unregistered Pod, an unreachable Control or a Control that reports no operation state authorizes nothing (`503`). Like Control's own acceptance, a pending cancel alone still lets the trusted observer's result of the running instance reach Control.

## Routes

| Socket | Route | Behaviour |
|---|---|---|
| candidate | `GET /v1/inputs/{name}` | Bytes of a permitted input the trusted harness staged, served only inside an execution authority Control confirms now; anything else `404` |
| candidate | `POST /v1/model/relay` | The controlled model relay; without a configured upstream (P11) `503 DEPENDENCY_UNAVAILABLE`; never a direct provider or network fallback |
| candidate | everything else | `403 ROUTE_FORBIDDEN` |
| trusted | `GET /v1/scope` | The scope Control confirms now; `503 SCOPE_UNAVAILABLE` until registered, `503 DEPENDENCY_UNAVAILABLE` while Control cannot be asked, `403 NO_AUTHORITY` for a non-current instance, `403 STALE_EXECUTION` once the attempt or operation ended the scope, `403 DEADLINE_EXCEEDED` past the deadline |
| trusted | `PUT /v1/inputs/{name}` | Stages a permitted input under a confirmed scope, verified against the digest the launch envelope declares |
| trusted | `POST /v1/transfers` | `BeginTransfer` under the scope, the one PUT the capability authorizes, `FinalizeTransfer` naming the object version and the current instance; the capability never leaves the process |
| trusted | `POST /v1/results` | `AcceptResult` under the current instance and execution epoch; a repeat of the same bytes reenters the same stage, another result is refused by Control |
| trusted | `POST /v1/model/relay`, `/v1/knowledge/…`, `/v1/mcp/…` | Trusted expert relays; `503 DEPENDENCY_UNAVAILABLE` until their units wire an upstream |

## Configuration

One reviewed, secret-free `config.yaml` (baked into the image) plus the allowlisted environment: `ANVILKIT_SIDECAR_CONTROL_ADDRESS`, `ANVILKIT_SIDECAR_IDENTITY_MODE` (`development` is the plaintext identity of the development foundation and qualifies nothing; `mtls` names the workload certificate files of the production path; the default `disabled` makes the process exit before a socket exists), `ANVILKIT_SIDECAR_BACKEND`, `ANVILKIT_SIDECAR_LAUNCH_KEY`, `ANVILKIT_SIDECAR_POD_UID` (downward API `metadata.uid`) and `ANVILKIT_SIDECAR_LAUNCH_ENVELOPE`. The launch facts are refused inside the file.

## Verification

`go build ./... && go vet ./... && go test ./...` (the process tests spawn the sidecar as UID 10002 and a candidate as UID 10001 and need a root caller; they skip otherwise; they cover a closed attempt, a cancel fence, a fenced or terminal operation, epochs that differ from the envelope, an unregistered Pod, an unreachable Control and a Control without operation state). The module requires the contracts module as an explicit versioned dependency: `ExecutionService.GetInstance` with its `operation` view is on the contracts repository's pushed `main` (`a397fee`), pinned here as the Go pseudo-version `v0.1.2-0.20260916181159-a397fee37c16` until a `go/v0.1.2` tag exists, so `GOWORK=off go build ./... && go vet ./... && go test ./...` and `docker build .` work from this repository alone; inside the `anvilkit-services` workspace it builds against the contracts checkout.
