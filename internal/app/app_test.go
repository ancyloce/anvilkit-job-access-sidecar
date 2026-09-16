package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/control/v1"
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/app"
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/config"
)

const (
	sidecarUID   = 10002
	candidateUID = 10001
)

// TestMain doubles as the helper processes: "serve" runs the sidecar (as
// UID 10002, spawned by the root test), "candidate" runs the candidate-side
// probes (as UID 10001).
func TestMain(m *testing.M) {
	switch os.Getenv("SIDECAR_HELPER") {
	case "serve":
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(2)
		}
		log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		ctx, stop := context.WithCancel(context.Background())
		go func() {
			// The parent closes stdin to stop the sidecar.
			_, _ = io.Copy(io.Discard, os.Stdin)
			stop()
		}()
		if err := app.Run(ctx, cfg, log); err != nil {
			fmt.Fprintln(os.Stderr, "run:", err)
			os.Exit(1)
		}
		os.Exit(0)
	case "candidate":
		candidateProbes(os.Getenv("SIDECAR_DIR"), os.Getenv("SIDECAR_INPUT"))
		os.Exit(0)
	case "candidate-input":
		// One permitted-input read as UID 10001: prints "<status> <code>".
		fmt.Print(candidateInput(os.Getenv("SIDECAR_DIR"), os.Getenv("SIDECAR_INPUT")))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// fakeControl is the in-process Control the sidecar talks to: it answers
// the instance registration the scenario configures (the instance, its
// attempt and the operation as of the read) and records every begin,
// finalize and acceptance.
type fakeControl struct {
	controlv1.UnimplementedExecutionServiceServer
	controlv1.UnimplementedArtifactServiceServer
	mu          sync.Mutex
	registered  bool
	current     bool
	deadline    time.Time
	attempt     controlv1.AttemptState
	lifecycle   controlv1.Lifecycle
	control     controlv1.ControlState
	opEpoch     string // the operation's current execution epoch
	atEpoch     string // the attempt's execution epoch
	launchEpoch string // the instance's launch epoch
	noOperation bool   // a Control that reports no operation state
	lookups     atomic.Int32
	transfers   map[string]*controlv1.Transfer // by handle
	finalized   map[string]bool
	stages      map[string]string // attempt -> stage id
	stageDigest map[string]string
	uploadURL   string
	accepts     int
}

func (f *fakeControl) GetInstance(ctx context.Context, req *controlv1.GetInstanceRequest) (*controlv1.GetInstanceResponse, error) {
	f.lookups.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.registered || req.GetPodUid() != "pod-1" || req.GetLaunchKey() != "cg-test" || req.GetBackend() != "test-backend" {
		return nil, status.Error(codes.NotFound, "NOT_FOUND")
	}
	resp := &controlv1.GetInstanceResponse{
		Instance: &controlv1.PhysicalInstance{InstanceId: "inst_1", AttemptId: "att_1", LaunchKey: "cg-test", Backend: "test-backend", PodUid: "pod-1", Current: f.current, LaunchEpoch: f.launchEpoch},
		Attempt:  &controlv1.Attempt{AttemptId: "att_1", OperationId: "op_1", ProfileId: "harness-wiring-dev-v1", ExecutionEpoch: f.atEpoch, State: f.attempt, Deadline: timestamppb.New(f.deadline)},
		TenantId: "tenant_a", RecoveryEpoch: "1",
	}
	if !f.noOperation {
		resp.Operation = &controlv1.OperationView{OperationId: "op_1", TenantId: "tenant_a", Lifecycle: f.lifecycle, Control: f.control, ExecutionEpoch: f.opEpoch, Deadline: timestamppb.New(f.deadline.Add(time.Hour))}
	}
	return resp, nil
}

// set changes Control's answer under the lock.
func (f *fakeControl) set(change func(f *fakeControl)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}

func (f *fakeControl) BeginTransfer(ctx context.Context, req *controlv1.BeginTransferRequest) (*controlv1.BeginTransferResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.transfers {
		if t.ExpectedDigest == req.GetExpectedDigest() && t.Class == req.GetClass() {
			return &controlv1.BeginTransferResponse{Transfer: t, Existing: true, Upload: &controlv1.TransferCapability{Url: f.uploadURL, Method: "PUT", Headers: map[string]string{"Content-Type": req.GetMediaType()}}}, nil
		}
	}
	handle := fmt.Sprintf("hdl_%d", len(f.transfers)+1)
	t := &controlv1.Transfer{TransferId: "xfer_" + handle, Handle: handle, Class: req.GetClass(), ExpectedDigest: req.GetExpectedDigest(), ExpectedSize: req.GetExpectedSize(), State: controlv1.TransferState_TRANSFER_STATE_BEGUN, TenantId: req.GetScope().GetTenantId()}
	f.transfers[handle] = t
	return &controlv1.BeginTransferResponse{Transfer: t, Upload: &controlv1.TransferCapability{Url: f.uploadURL, Method: "PUT", Headers: map[string]string{"Content-Type": req.GetMediaType()}}}, nil
}

func (f *fakeControl) FinalizeTransfer(ctx context.Context, req *controlv1.FinalizeTransferRequest) (*controlv1.FinalizeTransferResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.transfers[req.GetHandle()]
	if !ok {
		return nil, status.Error(codes.NotFound, "NOT_FOUND")
	}
	if req.GetInstanceId() != "inst_1" {
		return nil, status.Error(codes.FailedPrecondition, "STALE_EXECUTION: not the current instance")
	}
	version := req.GetObjectVersion()
	t.State, t.ObjectVersion = controlv1.TransferState_TRANSFER_STATE_FINALIZED, &version
	f.finalized[req.GetHandle()] = true
	return &controlv1.FinalizeTransferResponse{Transfer: t}, nil
}

func (f *fakeControl) AcceptResult(ctx context.Context, req *controlv1.AcceptResultRequest) (*controlv1.AcceptResultResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accepts++
	if req.GetInstanceId() != "inst_1" {
		return nil, status.Error(codes.FailedPrecondition, "STALE_EXECUTION: not the current instance")
	}
	if id, ok := f.stages[req.GetAttemptId()]; ok {
		if f.stageDigest[req.GetAttemptId()] != req.GetResultDigest() {
			return nil, status.Error(codes.Aborted, "IDEMPOTENCY_CONFLICT: another result")
		}
		return &controlv1.AcceptResultResponse{Stage: &controlv1.AcceptedStage{StageId: id, ResultDigest: req.GetResultDigest()}, Existing: true}, nil
	}
	f.stages[req.GetAttemptId()] = "stg_1"
	f.stageDigest[req.GetAttemptId()] = req.GetResultDigest()
	f.attempt = controlv1.AttemptState_ATTEMPT_STATE_RESULT_ACCEPTED // as Control moves the attempt
	return &controlv1.AcceptResultResponse{Stage: &controlv1.AcceptedStage{StageId: "stg_1", ResultDigest: req.GetResultDigest()}}, nil
}

// logBuffer collects the sidecar's stderr from exec's copying goroutine
// while the test reads it.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type harness struct {
	t       *testing.T
	dir     string // sockets dir
	control *fakeControl
	sidecar *exec.Cmd
	stdin   io.WriteCloser
	helper  string
	stderr  logBuffer
	// controlAddr and serve restart the fake Control on the same address
	// after it was stopped (the unavailable-Control scenario).
	controlAddr string
	serve       func() *grpc.Server
	srv         *grpc.Server
}

const envelopeJSON = `{"schemaVersion":1,"launchId":"lch_1","launchKey":"cg-test","operationId":"op_1","attemptId":"att_1","profileId":"harness-wiring-dev-v1","profileRevision":"1","jobKind":"codegen","executionEpoch":"1","launchEpoch":"1","deadline":"2030-01-01T00:00:00Z","inputs":[{"name":"fixed-input","digest":"sha256:abeb263b000189efdd8206ff39eeb4f2f7f3217f1c480491868b46da4a21c6a8"}]}`

const fixedInput = "anvilkit-codegen-fixed-v1 input\n"

// start runs a fake Control, a fake object store and the sidecar as UID
// 10002 with supplementary groups 0 and 10001 in a world-traversable
// directory (go test's build directory is not).
func start(t *testing.T, registered, current bool, deadline time.Time) *harness {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the sidecar tests spawn processes under other UIDs and need root")
	}
	root, err := os.MkdirTemp("/tmp", "sidecar-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(root) })
	require.NoError(t, os.Chmod(root, 0o755))
	self, err := os.Executable()
	require.NoError(t, err)
	raw, err := os.ReadFile(self)
	require.NoError(t, err)
	helper := filepath.Join(root, "helper")
	require.NoError(t, os.WriteFile(helper, raw, 0o755))
	// The volume the sidecar owns its directory in: an emptyDir is 0777.
	volume := filepath.Join(root, "run")
	require.NoError(t, os.Mkdir(volume, 0o777))
	require.NoError(t, os.Chmod(volume, 0o777))

	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			w.WriteHeader(405)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("x-amz-version-id", "v-"+fmt.Sprint(time.Now().UnixNano()))
		w.WriteHeader(200)
	}))
	t.Cleanup(store.Close)
	fc := &fakeControl{registered: registered, current: current, deadline: deadline, attempt: controlv1.AttemptState_ATTEMPT_STATE_RUNNING, lifecycle: controlv1.Lifecycle_LIFECYCLE_RUNNING, control: controlv1.ControlState_CONTROL_STATE_NONE, opEpoch: "1", atEpoch: "1", launchEpoch: "1",
		transfers: map[string]*controlv1.Transfer{}, finalized: map[string]bool{}, stages: map[string]string{}, stageDigest: map[string]string{}, uploadURL: store.URL + "/object"}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	h := &harness{t: t, dir: filepath.Join(volume, "sockets"), control: fc, helper: helper, controlAddr: lis.Addr().String()}
	h.serve = func() *grpc.Server {
		srv := grpc.NewServer()
		controlv1.RegisterExecutionServiceServer(srv, fc)
		controlv1.RegisterArtifactServiceServer(srv, fc)
		go srv.Serve(lis)
		h.srv = srv
		return srv
	}
	srv := h.serve()
	t.Cleanup(func() { h.srv.Stop() })

	cfgPath := filepath.Join(root, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("control:\n  timeout: 5s\nidentity:\n  mode: development\n"), 0o644))
	cmd := exec.Command(helper)
	cmd.Env = []string{"SIDECAR_HELPER=serve", "ANVILKIT_SIDECAR_CONFIG=" + cfgPath, "ANVILKIT_SIDECAR_CONTROL_ADDRESS=" + h.controlAddr,
		"ANVILKIT_SIDECAR_SOCKETS_DIR=" + h.dir, "ANVILKIT_SIDECAR_BACKEND=test-backend", "ANVILKIT_SIDECAR_LAUNCH_KEY=cg-test", "ANVILKIT_SIDECAR_POD_UID=pod-1", "ANVILKIT_SIDECAR_LAUNCH_ENVELOPE=" + envelopeJSON}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: sidecarUID, Gid: sidecarUID, Groups: []uint32{0, candidateUID}}}
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	cmd.Stderr = &h.stderr
	require.NoError(t, cmd.Start())
	h.sidecar, h.stdin = cmd, stdin
	t.Cleanup(func() {
		stdin.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
		}
		if t.Failed() {
			t.Logf("sidecar log:\n%s", h.stderr.String())
		}
	})
	_ = srv
	require.Eventually(t, func() bool {
		st, err := os.Lstat(filepath.Join(h.dir, "candidate.sock"))
		return err == nil && st.Mode()&os.ModeSocket != 0
	}, 10*time.Second, 50*time.Millisecond, "sidecar did not open its sockets: %s", h.stderr.String())
	return h
}

type answer struct {
	Status int
	Code   string
	Body   map[string]any
	Raw    []byte
}

// trusted sends one request over a fresh connection to trusted.sock.
func (h *harness) trusted(method, path string, headers map[string]string, body []byte) answer {
	return call(h.t, filepath.Join(h.dir, "trusted.sock"), method, path, headers, body)
}

func call(t *testing.T, socket, method, path string, headers map[string]string, body []byte) answer {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: true}
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, err := http.NewRequest(method, "http://sidecar"+path, bytes.NewReader(body))
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	a := answer{Status: resp.StatusCode, Raw: raw}
	_ = json.Unmarshal(raw, &a.Body)
	a.Code, _ = a.Body["code"].(string)
	return a
}

func ownership(t *testing.T, path string) (uid, gid uint32, mode os.FileMode) {
	t.Helper()
	st, err := os.Lstat(path)
	require.NoError(t, err)
	sys := st.Sys().(*syscall.Stat_t)
	return sys.Uid, sys.Gid, st.Mode().Perm()
}

// The socket layout carries the DD-03 ownership and modes.
func TestSocketLayout(t *testing.T) {
	h := start(t, true, true, time.Now().Add(time.Hour))
	uid, gid, mode := ownership(t, h.dir)
	require.Equal(t, [3]any{uint32(sidecarUID), uint32(0), os.FileMode(0o711)}, [3]any{uid, gid, mode}, "directory owner:0 0711")
	uid, gid, mode = ownership(t, filepath.Join(h.dir, "trusted.sock"))
	require.Equal(t, [3]any{uint32(sidecarUID), uint32(0), os.FileMode(0o660)}, [3]any{uid, gid, mode}, "trusted.sock owner:0 0660")
	uid, gid, mode = ownership(t, filepath.Join(h.dir, "candidate.sock"))
	require.Equal(t, [3]any{uint32(sidecarUID), uint32(candidateUID), os.FileMode(0o660)}, [3]any{uid, gid, mode}, "candidate.sock owner:candidate 0660")
}

// Trusted routes answer the scope only once the launcher registered the
// instance; the trusted flow then completes begin, upload, finalize and
// acceptance, and a repeated submission reenters the same stage.
func TestTrustedFlow(t *testing.T) {
	h := start(t, false, true, time.Now().Add(time.Hour))
	a := h.trusted("GET", "/v1/scope", nil, nil)
	require.Equal(t, 503, a.Status)
	require.Equal(t, "SCOPE_UNAVAILABLE", a.Code)
	a = h.trusted("POST", "/v1/transfers", map[string]string{"X-Anvilkit-Class": "result"}, []byte("x"))
	require.Equal(t, 503, a.Status, "no scope, no transfer")
	h.control.mu.Lock()
	h.control.registered = true
	h.control.mu.Unlock()
	require.Eventually(t, func() bool { return h.trusted("GET", "/v1/scope", nil, nil).Status == 200 }, 10*time.Second, 100*time.Millisecond)
	a = h.trusted("GET", "/v1/scope", nil, nil)
	scope := a.Body["scope"].(map[string]any)
	require.Equal(t, "inst_1", scope["instanceId"])
	require.Equal(t, true, scope["current"])
	require.Equal(t, []any{"fixed-input"}, a.Body["inputs"])

	// Inputs are bound to the envelope's digests.
	a = h.trusted("PUT", "/v1/inputs/fixed-input", nil, []byte("other bytes"))
	require.Equal(t, 400, a.Status)
	require.Equal(t, "INPUT_REJECTED", a.Code)
	a = h.trusted("PUT", "/v1/inputs/undeclared", nil, []byte(fixedInput))
	require.Equal(t, 400, a.Status)
	a = h.trusted("PUT", "/v1/inputs/fixed-input", nil, []byte(fixedInput))
	require.Equal(t, 200, a.Status, string(a.Raw))

	result := []byte("anvilkit-codegen-fixed-v1\ninput fixed-input sha256:abeb263b000189efdd8206ff39eeb4f2f7f3217f1c480491868b46da4a21c6a8\n")
	a = h.trusted("POST", "/v1/transfers", map[string]string{"X-Anvilkit-Class": "result", "Content-Type": "text/plain"}, result)
	require.Equal(t, 200, a.Status, string(a.Raw))
	require.Equal(t, "finalized", a.Body["state"])
	handle := a.Body["handle"].(string)
	resultDigest := a.Body["digest"]
	require.NotEmpty(t, a.Body["objectVersion"])
	require.True(t, h.control.finalized[handle])
	require.NotContains(t, string(a.Raw), "127.0.0.1", "no capability URL leaves the sidecar")
	again := h.trusted("POST", "/v1/transfers", map[string]string{"X-Anvilkit-Class": "result", "Content-Type": "text/plain"}, result)
	require.Equal(t, 200, again.Status)
	require.Equal(t, handle, again.Body["handle"], "the same bytes reenter the same transfer")
	require.Equal(t, true, again.Body["existing"])

	// Expert relays are trusted-only and, without an upstream, unavailable.
	a = h.trusted("POST", "/v1/knowledge/search", nil, []byte("{}"))
	require.Equal(t, 503, a.Status)
	require.Equal(t, "DEPENDENCY_UNAVAILABLE", a.Code)
	a = h.trusted("POST", "/v1/model/relay", nil, []byte("{}"))
	require.Equal(t, 503, a.Status)

	manifest := fmt.Sprintf(`{"schemaVersion":1,"launchId":"lch_1","attemptId":"att_1","jobKind":"codegen","profileId":"harness-wiring-dev-v1","verdict":"certified","outputs":[{"class":"result","digest":"%s","sizeBytes":"%d","handle":"%s"}],"completedAt":"2026-09-16T12:00:00Z"}`, resultDigest, len(result), handle)
	submit := []byte(`{"verdict":"certified","observerIdentity":"test-observer","manifest":` + manifest + `}`)
	a = h.trusted("POST", "/v1/results", map[string]string{"Content-Type": "application/json"}, submit)
	require.Equal(t, 200, a.Status, string(a.Raw))
	require.Equal(t, "stg_1", a.Body["stageId"])
	require.Equal(t, false, a.Body["existing"])
	a = h.trusted("POST", "/v1/results", map[string]string{"Content-Type": "application/json"}, submit)
	require.Equal(t, 200, a.Status, "the attempt is result_accepted now; the same result reenters: %s", a.Raw)
	require.Equal(t, "stg_1", a.Body["stageId"])
	require.Equal(t, true, a.Body["existing"], "a duplicate submission reenters the stage")
	a = h.trusted("POST", "/v1/transfers", map[string]string{"X-Anvilkit-Class": "result", "Content-Type": "text/plain"}, []byte("late"))
	require.Equal(t, 403, a.Status)
	require.Equal(t, "STALE_EXECUTION", a.Code, "an accepted attempt admits no new transfer")
	require.Equal(t, 403, h.trusted("GET", "/v1/scope", nil, nil).Status, "and grants no new scope")
	other := []byte(`{"verdict":"certified","observerIdentity":"test-observer","manifest":{"schemaVersion":1,"launchId":"lch_1","attemptId":"att_1","jobKind":"codegen","profileId":"harness-wiring-dev-v1","verdict":"certified","outputs":[],"completedAt":"2026-09-16T12:00:01Z"}}`)
	a = h.trusted("POST", "/v1/results", map[string]string{"Content-Type": "application/json"}, other)
	require.Equal(t, 409, a.Status)
	require.Equal(t, "IDEMPOTENCY_CONFLICT", a.Code, "a second result never creates a second acceptance")
	require.Equal(t, 3, h.control.accepts)
	a = h.trusted("POST", "/v1/knowledge/search", nil, []byte("{}"))
	require.Equal(t, 403, a.Status)
	require.Equal(t, "STALE_EXECUTION", a.Code, "an accepted attempt authorizes no relay either")
}

// A registered but non-current instance (a duplicate Pod) has no authority.
func TestStaleInstanceHasNoAuthority(t *testing.T) {
	h := start(t, true, false, time.Now().Add(time.Hour))
	require.Eventually(t, func() bool { return h.trusted("GET", "/v1/scope", nil, nil).Status == 403 }, 10*time.Second, 100*time.Millisecond)
	a := h.trusted("GET", "/v1/scope", nil, nil)
	require.Equal(t, "NO_AUTHORITY", a.Code)
	a = h.trusted("POST", "/v1/transfers", map[string]string{"X-Anvilkit-Class": "result"}, []byte("x"))
	require.Equal(t, 403, a.Status)
	a = h.trusted("POST", "/v1/results", map[string]string{"Content-Type": "application/json"}, []byte(`{"verdict":"certified","observerIdentity":"o","manifest":{}}`))
	require.Equal(t, 403, a.Status)
	require.Equal(t, 0, h.control.accepts, "nothing reached Control")
}

// A passed attempt deadline refuses the scope and every trusted action; a
// scope that turns non-current between requests is refused on the next
// one: every protected request is decided on Control's answer now.
func TestExpiredScopeIsRefused(t *testing.T) {
	h := start(t, true, true, time.Now().Add(-time.Minute))
	a := h.trusted("GET", "/v1/scope", nil, nil)
	require.Equal(t, 403, a.Status)
	require.Equal(t, "DEADLINE_EXCEEDED", a.Code, "an expired attempt grants no scope")
	a = h.trusted("POST", "/v1/transfers", map[string]string{"X-Anvilkit-Class": "result"}, []byte("x"))
	require.Equal(t, 403, a.Status)
	require.Equal(t, "DEADLINE_EXCEEDED", a.Code)
	h.control.set(func(f *fakeControl) { f.deadline = time.Now().Add(time.Hour) })
	require.Equal(t, 200, h.trusted("GET", "/v1/scope", nil, nil).Status)
	h.control.set(func(f *fakeControl) { f.current = false })
	a = h.trusted("POST", "/v1/transfers", map[string]string{"X-Anvilkit-Class": "result"}, []byte("x"))
	require.Equal(t, 403, a.Status)
	require.Equal(t, "NO_AUTHORITY", a.Code, "ownership is rechecked before every action")
	require.Equal(t, 403, h.trusted("GET", "/v1/scope", nil, nil).Status, "and the scope is not served from the earlier answer")
	require.Empty(t, h.control.transfers)
}

// stagedFlow brings the sidecar to a confirmed scope with the permitted
// input staged and a candidate read served: the state every lifecycle
// scenario below starts from.
func stagedFlow(t *testing.T, h *harness) {
	t.Helper()
	require.Eventually(t, func() bool { return h.trusted("GET", "/v1/scope", nil, nil).Status == 200 }, 10*time.Second, 100*time.Millisecond)
	a := h.trusted("PUT", "/v1/inputs/fixed-input", nil, []byte(fixedInput))
	require.Equal(t, 200, a.Status, string(a.Raw))
	require.Equal(t, fmt.Sprintf("200 %d", len(fixedInput)), h.candidateRead("fixed-input"), "a valid input read is served")
}

// refusedEverywhere asserts that no protected request is served: the
// scope, the staged input on the candidate socket, staging, a transfer and
// (unless Control may still record the result) a result submission.
func refusedEverywhere(t *testing.T, h *harness, status int, code string, resultToo bool) {
	t.Helper()
	a := h.trusted("GET", "/v1/scope", nil, nil)
	require.Equal(t, [2]any{status, code}, [2]any{a.Status, a.Code}, "scope: %s", a.Raw)
	require.Equal(t, fmt.Sprintf("%d %s", status, code), h.candidateRead("fixed-input"), "the staged content is not served on stale authority")
	a = h.trusted("PUT", "/v1/inputs/fixed-input", nil, []byte(fixedInput))
	require.Equal(t, [2]any{status, code}, [2]any{a.Status, a.Code}, "staging: %s", a.Raw)
	a = h.trusted("POST", "/v1/transfers", map[string]string{"X-Anvilkit-Class": "result", "Content-Type": "text/plain"}, []byte("x"))
	require.Equal(t, [2]any{status, code}, [2]any{a.Status, a.Code}, "transfer: %s", a.Raw)
	require.Empty(t, h.control.transfers, "no transfer reached Control")
	if resultToo {
		a = h.trusted("POST", "/v1/results", map[string]string{"Content-Type": "application/json"}, []byte(`{"verdict":"certified","observerIdentity":"o","manifest":{}}`))
		require.Equal(t, [2]any{status, code}, [2]any{a.Status, a.Code}, "results: %s", a.Raw)
		require.Equal(t, 0, h.control.accepts, "nothing reached Control")
	}
}

// A closed attempt ends the scope: an instance row that still records
// historical current ownership authorizes nothing once the attempt is
// closed (the launcher's cancellation or completion), including the
// candidate's reads of content staged earlier and the result submission.
func TestClosedAttemptEndsTheScope(t *testing.T) {
	h := start(t, true, true, time.Now().Add(time.Hour))
	stagedFlow(t, h)
	h.control.set(func(f *fakeControl) {
		f.attempt = controlv1.AttemptState_ATTEMPT_STATE_CLOSED
		f.lifecycle = controlv1.Lifecycle_LIFECYCLE_CANCELED
		f.control = controlv1.ControlState_CONTROL_STATE_CANCEL_APPLIED
	})
	refusedEverywhere(t, h, 403, "STALE_EXECUTION", true)
	// An attempt whose result was accepted authorizes nothing new either;
	// only the result route still reaches Control, which answers the
	// existing stage for the same result and conflicts on another.
	h.control.set(func(f *fakeControl) {
		f.attempt = controlv1.AttemptState_ATTEMPT_STATE_RESULT_ACCEPTED
		f.lifecycle = controlv1.Lifecycle_LIFECYCLE_RUNNING
		f.control = controlv1.ControlState_CONTROL_STATE_NONE
	})
	refusedEverywhere(t, h, 403, "STALE_EXECUTION", false)
	a := h.trusted("POST", "/v1/results", map[string]string{"Content-Type": "application/json"}, []byte(`{"verdict":"certified","observerIdentity":"o","manifest":{"schemaVersion":1}}`))
	require.Equal(t, 200, a.Status, "Control decides the repeat: %s", a.Raw)
	require.Equal(t, 1, h.control.accepts)
}

// A pending cancel fences new authorization (no scope, no inputs, no
// transfer) while, as in Control's own acceptance, the trusted observer's
// result of the still running instance may be recorded.
func TestCancelFenceRefusesNewAuthorization(t *testing.T) {
	h := start(t, true, true, time.Now().Add(time.Hour))
	stagedFlow(t, h)
	h.control.set(func(f *fakeControl) { f.control = controlv1.ControlState_CONTROL_STATE_CANCEL_PENDING })
	refusedEverywhere(t, h, 403, "STALE_EXECUTION", false)
	a := h.trusted("POST", "/v1/results", map[string]string{"Content-Type": "application/json"}, []byte(`{"verdict":"invalid","failureCode":"CANCELED","observerIdentity":"o","manifest":{"schemaVersion":1}}`))
	require.Equal(t, 200, a.Status, "Control decides the result of a running instance under a cancel fence: %s", a.Raw)
	require.Equal(t, 1, h.control.accepts)
}

// A recovery fence (the operation reconciling under a moved execution
// epoch) or a terminal operation ends the scope for every request, the
// result included; the instance row is still the historical current one.
func TestFencedOperationEndsTheScope(t *testing.T) {
	h := start(t, true, true, time.Now().Add(time.Hour))
	stagedFlow(t, h)
	h.control.set(func(f *fakeControl) {
		f.lifecycle = controlv1.Lifecycle_LIFECYCLE_RECONCILING
		f.opEpoch = "2"
	})
	refusedEverywhere(t, h, 403, "STALE_EXECUTION", true)
	h.control.set(func(f *fakeControl) {
		f.lifecycle = controlv1.Lifecycle_LIFECYCLE_FAILED
		f.opEpoch = "1"
	})
	refusedEverywhere(t, h, 403, "STALE_EXECUTION", true)
}

// A registration whose epochs are not the launch envelope's (another
// launch of the same attempt, or a Pod of a later epoch answered for this
// one) carries no authority for this sidecar.
func TestEnvelopeEpochsMustMatchTheRegistration(t *testing.T) {
	h := start(t, true, true, time.Now().Add(time.Hour))
	stagedFlow(t, h)
	h.control.set(func(f *fakeControl) { f.atEpoch = "2"; f.opEpoch = "2" })
	refusedEverywhere(t, h, 403, "NO_AUTHORITY", true)
	h.control.set(func(f *fakeControl) { f.atEpoch = "1"; f.opEpoch = "1"; f.launchEpoch = "2" })
	refusedEverywhere(t, h, 403, "NO_AUTHORITY", true)
}

// An unregistered Pod (the registration disappeared, or was never there)
// and a Control that cannot be asked serve nothing from what was answered
// or staged before; once Control answers again the scope is back.
func TestUnavailableControlServesNothing(t *testing.T) {
	h := start(t, true, true, time.Now().Add(time.Hour))
	stagedFlow(t, h)
	h.control.set(func(f *fakeControl) { f.registered = false })
	refusedEverywhere(t, h, 503, "SCOPE_UNAVAILABLE", true)
	h.control.set(func(f *fakeControl) { f.registered = true })
	require.Equal(t, 200, h.trusted("GET", "/v1/scope", nil, nil).Status)

	h.srv.Stop()
	refusedEverywhere(t, h, 503, "DEPENDENCY_UNAVAILABLE", true)
	lis, err := net.Listen("tcp", h.controlAddr)
	require.NoError(t, err, "the fake Control comes back on the same address")
	srv := grpc.NewServer()
	controlv1.RegisterExecutionServiceServer(srv, h.control)
	controlv1.RegisterArtifactServiceServer(srv, h.control)
	go srv.Serve(lis)
	h.srv = srv
	require.Eventually(t, func() bool { return h.trusted("GET", "/v1/scope", nil, nil).Status == 200 }, 15*time.Second, 200*time.Millisecond, "authority is confirmed again from Control, not from a cache")
	require.Equal(t, fmt.Sprintf("200 %d", len(fixedInput)), h.candidateRead("fixed-input"))
}

// A Control that answers the registration without the operation's state
// cannot confirm the fence or the current execution epoch: nothing is
// authorized on that answer.
func TestControlWithoutOperationStateAuthorizesNothing(t *testing.T) {
	h := start(t, true, true, time.Now().Add(time.Hour))
	h.control.set(func(f *fakeControl) { f.noOperation = true })
	a := h.trusted("GET", "/v1/scope", nil, nil)
	require.Equal(t, 503, a.Status)
	require.Equal(t, "DEPENDENCY_UNAVAILABLE", a.Code, string(a.Raw))
	require.Equal(t, "503 DEPENDENCY_UNAVAILABLE", h.candidateRead("fixed-input"))
}

// One trusted connection serves one request: a second request on the same
// connection is not answered.
func TestOneRequestPerTrustedConnection(t *testing.T) {
	h := start(t, true, true, time.Now().Add(time.Hour))
	conn, err := net.Dial("unix", filepath.Join(h.dir, "trusted.sock"))
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("GET /v1/scope HTTP/1.1\r\nHost: sidecar\r\n\r\nGET /v1/scope HTTP/1.1\r\nHost: sidecar\r\n\r\n"))
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	raw, _ := io.ReadAll(conn)
	require.Equal(t, 1, strings.Count(string(raw), "HTTP/1.1 "), "exactly one response, then the connection closes: %q", raw)
	require.Contains(t, string(raw), "Connection: close")
}

// The root test process can open candidate.sock (it holds DAC override):
// the peer credential check still refuses it, and a descriptor delegated
// over trusted.sock closes the connection unserved.
func TestPeerCredentialsAndDelegation(t *testing.T) {
	h := start(t, true, true, time.Now().Add(time.Hour))
	conn, err := net.Dial("unix", filepath.Join(h.dir, "candidate.sock"))
	require.NoError(t, err)
	_, _ = conn.Write([]byte("GET /v1/inputs/fixed-input HTTP/1.1\r\nHost: sidecar\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, _ := io.ReadAll(conn)
	conn.Close()
	require.Empty(t, raw, "uid 0 on the candidate socket is closed at accept")

	uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(h.dir, "trusted.sock"), Net: "unix"})
	require.NoError(t, err)
	f, _ := os.Open(os.DevNull)
	_, _, err = uc.WriteMsgUnix([]byte("GET /v1/scope HTTP/1.1\r\nHost: sidecar\r\n\r\n"), unix.UnixRights(int(f.Fd())), nil)
	f.Close()
	require.NoError(t, err)
	_ = uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, _ = io.ReadAll(uc)
	uc.Close()
	require.Empty(t, raw, "a delegated descriptor closes the connection without a response")
	a := h.trusted("GET", "/v1/scope", nil, nil)
	require.Equal(t, 200, a.Status, "the sidecar keeps serving afterwards")
}

// The candidate identity (UID 10001) reaches only its own socket and only
// the permitted routes there; the report is what the helper observed.
func TestCandidateBoundary(t *testing.T) {
	h := start(t, true, true, time.Now().Add(time.Hour))
	require.Eventually(t, func() bool { return h.trusted("GET", "/v1/scope", nil, nil).Status == 200 }, 10*time.Second, 100*time.Millisecond)
	a := h.trusted("PUT", "/v1/inputs/fixed-input", nil, []byte(fixedInput))
	require.Equal(t, 200, a.Status)
	cmd := exec.Command(h.helper)
	cmd.Env = []string{"SIDECAR_HELPER=candidate", "SIDECAR_DIR=" + h.dir, "SIDECAR_INPUT=fixed-input"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: candidateUID, Gid: candidateUID, Groups: []uint32{}}}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	var rep map[string]string
	require.NoError(t, json.Unmarshal(out, &rep), string(out))
	require.Equal(t, "EACCES", rep["connect:trusted.sock"], "the candidate cannot open the trusted socket")
	require.Equal(t, "200 ", rep["candidate:inputs-permitted"])
	require.Equal(t, "404 NOT_FOUND", rep["candidate:inputs-other"])
	require.Equal(t, "403 ROUTE_FORBIDDEN", rep["candidate:scope"])
	require.Equal(t, "403 ROUTE_FORBIDDEN", rep["candidate:results"])
	require.Equal(t, "403 ROUTE_FORBIDDEN", rep["candidate:transfers"])
	require.Equal(t, "403 ROUTE_FORBIDDEN", rep["candidate:knowledge"])
	require.Equal(t, "503 DEPENDENCY_UNAVAILABLE", rep["candidate:model-relay"])
	require.Equal(t, "CLOSED", rep["candidate:fd-delegation"])
	require.Equal(t, fixedInput, rep["candidate:input-bytes"])
	require.Equal(t, 0, h.control.accepts, "no candidate request reached Control")
}

// candidateRead performs one permitted-input read as UID 10001 and
// returns "<status> <code>".
func (h *harness) candidateRead(input string) string {
	h.t.Helper()
	cmd := exec.Command(h.helper)
	cmd.Env = []string{"SIDECAR_HELPER=candidate-input", "SIDECAR_DIR=" + h.dir, "SIDECAR_INPUT=" + input}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: candidateUID, Gid: candidateUID, Groups: []uint32{}}}
	out, err := cmd.CombinedOutput()
	require.NoError(h.t, err, string(out))
	return strings.TrimSpace(string(out))
}

func candidateInput(dir, input string) string {
	socket := filepath.Join(dir, "candidate.sock")
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: true}
	c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := c.Get("http://sidecar/v1/inputs/" + input)
	if err != nil {
		return "ERR " + err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var f struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(raw, &f)
	if resp.StatusCode == 200 {
		return fmt.Sprintf("200 %d", len(raw))
	}
	return fmt.Sprintf("%d %s", resp.StatusCode, f.Code)
}

// candidateProbes is the UID 10001 helper.
func candidateProbes(dir, input string) {
	rep := map[string]string{}
	errString := func(err error) string {
		for {
			switch e := err.(type) {
			case *net.OpError:
				err = e.Err
				continue
			case *os.SyscallError:
				err = e.Err
				continue
			case syscall.Errno:
				return strings.ToUpper(unix.ErrnoName(e))
			}
			return err.Error()
		}
	}
	if c, err := net.DialTimeout("unix", filepath.Join(dir, "trusted.sock"), 2*time.Second); err == nil {
		c.Close()
		rep["connect:trusted.sock"] = "CONNECTED"
	} else {
		rep["connect:trusted.sock"] = errString(err)
	}
	socket := filepath.Join(dir, "candidate.sock")
	ask := func(key, method, path, body string) []byte {
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}, DisableKeepAlives: true}
		c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		req, _ := http.NewRequest(method, "http://sidecar"+path, strings.NewReader(body))
		resp, err := c.Do(req)
		if err != nil {
			rep[key] = errString(err)
			return nil
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var f struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(raw, &f)
		rep[key] = fmt.Sprintf("%d %s", resp.StatusCode, f.Code)
		return raw
	}
	rep["candidate:input-bytes"] = string(ask("candidate:inputs-permitted", "GET", "/v1/inputs/"+input, ""))
	ask("candidate:inputs-other", "GET", "/v1/inputs/not-permitted", "")
	ask("candidate:scope", "GET", "/v1/scope", "")
	ask("candidate:results", "POST", "/v1/results", `{"verdict":"certified","observerIdentity":"c","manifest":{}}`)
	ask("candidate:transfers", "POST", "/v1/transfers", "x")
	ask("candidate:knowledge", "POST", "/v1/knowledge/search", "{}")
	ask("candidate:model-relay", "POST", "/v1/model/relay", "{}")
	uc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		rep["candidate:fd-delegation"] = errString(err)
	} else {
		f, _ := os.Open(os.DevNull)
		_, _, _ = uc.WriteMsgUnix([]byte("GET /v1/inputs/"+input+" HTTP/1.1\r\nHost: sidecar\r\n\r\n"), unix.UnixRights(int(f.Fd())), nil)
		f.Close()
		_ = uc.SetReadDeadline(time.Now().Add(3 * time.Second))
		raw, _ := io.ReadAll(uc)
		uc.Close()
		if len(raw) == 0 {
			rep["candidate:fd-delegation"] = "CLOSED"
		} else {
			rep["candidate:fd-delegation"] = "SERVED"
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(rep)
}
