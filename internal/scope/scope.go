// Package scope is the sidecar's trusted side: the Control client that
// resolves the execution scope of the physical instance this sidecar runs
// in and performs the scoped artifact flow for the trusted harness. The
// scope is never claimed and never cached: it is what the trusted
// launcher registered with Control (GetInstance by backend, launch key
// and the Pod UID the kubelet injected), read again before every
// protected request. Historical physical ownership (the instance row's
// current flag) is not current execution permission: authority holds
// only while the registration names the launch envelope's attempt,
// profile and epochs, the instance is the current one, the attempt is
// still executing under the operation's current execution epoch, the
// operation is not fenced (no cancel or hold intent, not terminal, not
// reconciling) and the deadlines have not passed — the facts Control's
// own transactions check before they accept anything. When Control cannot
// be asked, nothing is authorized.
package scope

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/control/v1"
)

// ActorID is the actor every command of the sidecar carries.
const ActorID = "anvilkit-job-access-sidecar"

var (
	// ErrUnregistered: the launcher has not registered this Pod yet.
	ErrUnregistered = errors.New("instance not registered")
	// ErrNoAuthority: the instance is registered but not the current one
	// (a duplicate or superseded Pod), or the registration does not name
	// the launch this sidecar was started for; it never gains authority.
	ErrNoAuthority = errors.New("instance is not the current physical owner")
	// ErrDeadline: the attempt (or operation) deadline passed.
	ErrDeadline = errors.New("attempt deadline passed")
	// ErrStale: the registration is the current instance's, but the
	// attempt is no longer executing or the operation is fenced, terminal,
	// reconciling or past the attempt's execution epoch: the scope ended.
	ErrStale = errors.New("execution scope ended")
	// ErrRefused wraps a Control precondition failure with its public code.
	ErrRefused = errors.New("refused")
	// ErrUnavailable: a dependency is not configured or cannot answer.
	ErrUnavailable = errors.New("dependency unavailable")
)

// Identity is the launch identity the sidecar presents (all injected, none
// chosen by the sidecar).
type Identity struct {
	Backend   string
	LaunchKey string
	PodUID    string
}

// Scope is the resolved execution scope as the trusted harness sees it.
type Scope struct {
	TenantID       string    `json:"tenantId"`
	OperationID    string    `json:"operationId"`
	AttemptID      string    `json:"attemptId"`
	InstanceID     string    `json:"instanceId"`
	Current        bool      `json:"current"`
	ProfileID      string    `json:"profileId"`
	ExecutionEpoch string    `json:"executionEpoch"`
	RecoveryEpoch  string    `json:"recoveryEpoch"`
	LaunchKey      string    `json:"launchKey"`
	Deadline       time.Time `json:"deadline"`
}

// Registration is Control's answer about this Pod as of one read: the
// scope plus the facts an authority decision needs.
type Registration struct {
	Scope     Scope
	Instance  *controlv1.PhysicalInstance
	Attempt   *controlv1.Attempt
	Operation *controlv1.OperationView
}

// Binding is what the launch envelope fixed for this Pod; a registration
// that names anything else carries no authority here.
type Binding struct {
	OperationID, AttemptID, ProfileID, LaunchKey, ExecutionEpoch, LaunchEpoch string
}

// Purpose of an authority decision.
type Purpose int

const (
	// ForNewAuthorization: serving the scope, staging or serving inputs,
	// beginning transfers, relaying. Any control intent on the operation
	// (a pending cancel included) refuses it.
	ForNewAuthorization Purpose = iota
	// ForResult: submitting the trusted observer's result. Like Control's
	// acceptance, a cancel fence alone still lets the verdict of the
	// running instance be recorded, and an attempt whose result was
	// accepted still takes the same result again (Control answers the
	// existing stage; another result conflicts there); a terminal or
	// reconciling operation, a moved epoch, a closed attempt or a passed
	// deadline refuses it.
	ForResult
)

// Confirm decides whether the registration carries execution authority
// now, for the purpose. The instance row's current flag is necessary and
// never sufficient: the attempt and operation state decide.
func (r *Registration) Confirm(b Binding, now time.Time, purpose Purpose) error {
	inst, at, op := r.Instance, r.Attempt, r.Operation
	if inst == nil || at == nil {
		return fmt.Errorf("%w: Control answered no instance or attempt", ErrUnavailable)
	}
	if op == nil {
		// A Control that does not report the operation cannot confirm the
		// fence state or the current execution epoch: nothing is authorized.
		return fmt.Errorf("%w: Control answered no operation state; current authority cannot be confirmed", ErrUnavailable)
	}
	if at.GetAttemptId() != b.AttemptID || at.GetOperationId() != b.OperationID || at.GetProfileId() != b.ProfileID || inst.GetLaunchKey() != b.LaunchKey {
		return fmt.Errorf("%w: registration names attempt %s of %s (%s, launch %s), the envelope %s of %s (%s, launch %s)", ErrNoAuthority,
			at.GetAttemptId(), at.GetOperationId(), at.GetProfileId(), inst.GetLaunchKey(), b.AttemptID, b.OperationID, b.ProfileID, b.LaunchKey)
	}
	if inst.GetAttemptId() != at.GetAttemptId() || op.GetOperationId() != at.GetOperationId() {
		return fmt.Errorf("%w: Control answered an instance, attempt and operation that do not belong together", ErrUnavailable)
	}
	if at.GetExecutionEpoch() != b.ExecutionEpoch || inst.GetLaunchEpoch() != b.LaunchEpoch {
		return fmt.Errorf("%w: registration runs under execution epoch %s and launch epoch %s, the envelope under %s and %s", ErrNoAuthority,
			at.GetExecutionEpoch(), inst.GetLaunchEpoch(), b.ExecutionEpoch, b.LaunchEpoch)
	}
	if !inst.GetCurrent() {
		return ErrNoAuthority
	}
	st := at.GetState()
	executing := st == controlv1.AttemptState_ATTEMPT_STATE_LAUNCH_PREPARED || st == controlv1.AttemptState_ATTEMPT_STATE_RUNNING
	if !executing && !(purpose == ForResult && st == controlv1.AttemptState_ATTEMPT_STATE_RESULT_ACCEPTED) {
		return fmt.Errorf("%w: attempt %s is %s", ErrStale, at.GetAttemptId(), strings.ToLower(strings.TrimPrefix(st.String(), "ATTEMPT_STATE_")))
	}
	if op.GetExecutionEpoch() != at.GetExecutionEpoch() {
		return fmt.Errorf("%w: operation %s is at execution epoch %s, the attempt at %s", ErrStale, op.GetOperationId(), op.GetExecutionEpoch(), at.GetExecutionEpoch())
	}
	terminal := op.GetLifecycle() == controlv1.Lifecycle_LIFECYCLE_SUCCEEDED || op.GetLifecycle() == controlv1.Lifecycle_LIFECYCLE_FAILED || op.GetLifecycle() == controlv1.Lifecycle_LIFECYCLE_CANCELED
	reconciling := op.GetLifecycle() == controlv1.Lifecycle_LIFECYCLE_RECONCILING
	controlled := op.GetControl() != controlv1.ControlState_CONTROL_STATE_NONE && op.GetControl() != controlv1.ControlState_CONTROL_STATE_UNSPECIFIED
	fenced := controlled || terminal || reconciling
	if fenced && (purpose == ForNewAuthorization || !controlled) {
		return fmt.Errorf("%w: operation %s is fenced (%s/%s)", ErrStale, op.GetOperationId(),
			strings.ToLower(strings.TrimPrefix(op.GetLifecycle().String(), "LIFECYCLE_")), strings.ToLower(strings.TrimPrefix(op.GetControl().String(), "CONTROL_STATE_")))
	}
	if !now.Before(at.GetDeadline().AsTime()) {
		return ErrDeadline
	}
	if op.GetDeadline() != nil && !now.Before(op.GetDeadline().AsTime()) {
		return fmt.Errorf("%w: operation deadline", ErrDeadline)
	}
	return nil
}

// Dial options.
type Options struct {
	Address string
	Timeout time.Duration
	// TLS is nil for the development identity (plaintext, DEVELOPMENT_ONLY)
	// and the workload certificate material otherwise.
	TLS *TLSFiles
	// Upload is the client for the one PUT a transfer capability authorizes.
	Upload *http.Client
}

type TLSFiles struct{ CertFile, KeyFile, CAFile, ServerName string }

// Client talks to Control's ExecutionService and ArtifactService.
type Client struct {
	conn     *grpc.ClientConn
	exec     controlv1.ExecutionServiceClient
	artifact controlv1.ArtifactServiceClient
	timeout  time.Duration
	upload   *http.Client
	identity Identity
}

func Dial(id Identity, o Options) (*Client, error) {
	creds := insecure.NewCredentials()
	if o.TLS != nil {
		cert, err := tls.LoadX509KeyPair(o.TLS.CertFile, o.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("identity: client certificate: %w", err)
		}
		ca, err := os.ReadFile(o.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("identity: ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, errors.New("identity: ca file holds no certificate")
		}
		creds = credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: o.TLS.ServerName, MinVersion: tls.VersionTLS13})
	}
	conn, err := grpc.NewClient(o.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	up := o.Upload
	if up == nil {
		up = &http.Client{Timeout: 5 * time.Minute}
	}
	return &Client{conn: conn, exec: controlv1.NewExecutionServiceClient(conn), artifact: controlv1.NewArtifactServiceClient(conn), timeout: o.Timeout, upload: up, identity: id}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.timeout)
}

// refusal maps a Control status to the sidecar's errors: NotFound on the
// instance read means unregistered; precondition/aborted/invalid answers
// are refusals carrying Control's public code; anything else is
// unavailable (retryable by the caller under its own bound).
func refusal(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	switch st.Code() {
	case codes.FailedPrecondition, codes.Aborted, codes.InvalidArgument, codes.NotFound, codes.PermissionDenied, codes.ResourceExhausted, codes.DataLoss:
		code, _, _ := strings.Cut(st.Message(), ":")
		return fmt.Errorf("%w: %s", ErrRefused, strings.TrimSpace(code))
	default:
		return fmt.Errorf("%w: %s", ErrUnavailable, st.Code())
	}
}

// Code extracts the public code of a refusal ("" otherwise).
func Code(err error) string {
	if !errors.Is(err, ErrRefused) {
		return ""
	}
	_, code, _ := strings.Cut(err.Error(), "refused: ")
	return code
}

// Lookup reads the registration of this Pod once: ErrUnregistered while
// the launcher has not registered it, ErrUnavailable when Control cannot
// answer (nothing is authorized then).
func (c *Client) Lookup(ctx context.Context) (*Registration, error) {
	ctx, cancel := c.call(ctx)
	defer cancel()
	resp, err := c.exec.GetInstance(ctx, &controlv1.GetInstanceRequest{Backend: c.identity.Backend, LaunchKey: c.identity.LaunchKey, PodUid: c.identity.PodUID})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return nil, ErrUnregistered
		}
		return nil, refusal(err)
	}
	inst, at := resp.GetInstance(), resp.GetAttempt()
	if inst.GetPodUid() != c.identity.PodUID || inst.GetLaunchKey() != c.identity.LaunchKey || inst.GetBackend() != c.identity.Backend {
		return nil, fmt.Errorf("%w: Control answered another registration", ErrUnavailable)
	}
	return &Registration{
		Scope: Scope{
			TenantID: resp.GetTenantId(), OperationID: at.GetOperationId(), AttemptID: at.GetAttemptId(), InstanceID: inst.GetInstanceId(),
			Current: inst.GetCurrent(), ProfileID: at.GetProfileId(), ExecutionEpoch: at.GetExecutionEpoch(), RecoveryEpoch: resp.GetRecoveryEpoch(),
			LaunchKey: inst.GetLaunchKey(), Deadline: at.GetDeadline().AsTime(),
		},
		Instance: inst, Attempt: at, Operation: resp.GetOperation(),
	}, nil
}

// Confirm reads the registration now and decides its authority for the
// purpose. Read the clock after the lookup, immediately before deciding;
// a request that crossed either deadline grants no authority. The returned
// scope is usable only when the error is nil.
func (c *Client) Confirm(ctx context.Context, b Binding, now func() time.Time, purpose Purpose) (*Scope, error) {
	r, err := c.Lookup(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.Confirm(b, now(), purpose); err != nil {
		return nil, err
	}
	return &r.Scope, nil
}

func command(tenant, id string, input any) *controlv1.CommandIdentity {
	raw, _ := json.Marshal(input)
	return &controlv1.CommandIdentity{TenantId: tenant, CommandId: id, ActorId: ActorID, RequestDigest: DigestOf(raw)}
}

func DigestOf(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }

var classes = map[string]controlv1.ArtifactClass{
	"prompt": controlv1.ArtifactClass_ARTIFACT_CLASS_PROMPT, "brief": controlv1.ArtifactClass_ARTIFACT_CLASS_BRIEF, "source": controlv1.ArtifactClass_ARTIFACT_CLASS_SOURCE,
	"stage": controlv1.ArtifactClass_ARTIFACT_CLASS_STAGE, "result": controlv1.ArtifactClass_ARTIFACT_CLASS_RESULT, "evidence": controlv1.ArtifactClass_ARTIFACT_CLASS_EVIDENCE,
	"answer": controlv1.ArtifactClass_ARTIFACT_CLASS_ANSWER, "argument": controlv1.ArtifactClass_ARTIFACT_CLASS_ARGUMENT,
	"npm": controlv1.ArtifactClass_ARTIFACT_CLASS_NPM, "browser": controlv1.ArtifactClass_ARTIFACT_CLASS_BROWSER, "css": controlv1.ArtifactClass_ARTIFACT_CLASS_CSS,
}

// Transfer is the outcome of one scoped upload.
type Transfer struct {
	Handle        string `json:"handle"`
	TransferID    string `json:"transferId"`
	Class         string `json:"class"`
	Digest        string `json:"digest"`
	SizeBytes     string `json:"sizeBytes"`
	ObjectVersion string `json:"objectVersion"`
	State         string `json:"state"`
	Existing      bool   `json:"existing"`
}

type transferBinding struct {
	Attempt, Class, Digest, MediaType string
	Size                              int64
}

// Upload runs the trusted artifact flow for bytes the trusted harness
// produced: BeginTransfer under the scope (the command identity binds
// attempt, class, digest, size and media type, so a repeat reenters the
// same transfer), the one PUT the capability authorizes, then
// FinalizeTransfer naming the object version the store assigned and the
// current instance. The capability URL and headers stay in this process;
// nothing of them is logged or answered.
func (c *Client) Upload(ctx context.Context, s *Scope, class, mediaType string, body []byte) (*Transfer, error) {
	cls, ok := classes[class]
	if !ok {
		return nil, fmt.Errorf("%w: INVALID_ARGUMENT unknown artifact class %q", ErrRefused, class)
	}
	digest := DigestOf(body)
	b := transferBinding{Attempt: s.AttemptID, Class: class, Digest: digest, MediaType: mediaType, Size: int64(len(body))}
	cmdID := s.AttemptID + ":xfer:" + class + ":" + strings.TrimPrefix(digest, "sha256:")[:32]
	bctx, cancel := c.call(ctx)
	begun, err := c.artifact.BeginTransfer(bctx, &controlv1.BeginTransferRequest{
		Command: command(s.TenantID, cmdID, b), Scope: &controlv1.Scope{TenantId: s.TenantID, ActorId: ActorID},
		Class: cls, ExpectedDigest: digest, ExpectedSize: strconv.FormatInt(int64(len(body)), 10), MediaType: mediaType,
		OperationId: &s.OperationID, AttemptId: &s.AttemptID, Deadline: timestamppb.New(s.Deadline),
	})
	cancel()
	if err != nil {
		return nil, refusal(err)
	}
	t := begun.GetTransfer()
	out := &Transfer{Handle: t.GetHandle(), TransferID: t.GetTransferId(), Class: class, Digest: digest, SizeBytes: strconv.Itoa(len(body)), Existing: begun.GetExisting()}
	if t.GetState() == controlv1.TransferState_TRANSFER_STATE_FINALIZED {
		out.ObjectVersion, out.State = t.GetObjectVersion(), "finalized"
		return out, nil
	}
	up := begun.GetUpload()
	if up == nil || up.GetUrl() == "" {
		return nil, fmt.Errorf("%w: STALE_EXECUTION transfer %s is %s and no upload capability was issued", ErrRefused, t.GetTransferId(), strings.ToLower(strings.TrimPrefix(t.GetState().String(), "TRANSFER_STATE_")))
	}
	version, err := c.put(ctx, up, body)
	if err != nil {
		return nil, err
	}
	fctx, cancel := c.call(ctx)
	defer cancel()
	fin, err := c.artifact.FinalizeTransfer(fctx, &controlv1.FinalizeTransferRequest{
		Command: command(s.TenantID, s.AttemptID+":fin:"+t.GetHandle(), map[string]string{"handle": t.GetHandle(), "objectVersion": version}),
		Handle:  t.GetHandle(), ObjectVersion: version, InstanceId: s.InstanceID,
	})
	if err != nil {
		return nil, refusal(err)
	}
	ft := fin.GetTransfer()
	out.ObjectVersion = ft.GetObjectVersion()
	out.State = strings.ToLower(strings.TrimPrefix(ft.GetState().String(), "TRANSFER_STATE_"))
	if ft.GetState() != controlv1.TransferState_TRANSFER_STATE_FINALIZED {
		return out, fmt.Errorf("%w: %s transfer %s rejected", ErrRefused, ft.GetReasonCode(), ft.GetTransferId())
	}
	return out, nil
}

// put performs exactly the request the capability authorizes.
func (c *Client) put(ctx context.Context, cap *controlv1.TransferCapability, body []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, cap.GetMethod(), cap.GetUrl(), bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("%w: upload request: %v", ErrUnavailable, err)
	}
	for k, v := range cap.GetHeaders() {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		req.Header.Set(k, v)
	}
	req.ContentLength = int64(len(body))
	resp, err := c.upload.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: upload: transport error", ErrUnavailable)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("%w: upload answered %d", ErrUnavailable, resp.StatusCode)
	}
	version := resp.Header.Get("x-amz-version-id")
	if version == "" {
		return "", fmt.Errorf("%w: the store assigned no object version (versioning is required)", ErrUnavailable)
	}
	return version, nil
}

var verdicts = map[string]controlv1.Verdict{
	"certified": controlv1.Verdict_VERDICT_CERTIFIED, "repairable": controlv1.Verdict_VERDICT_REPAIRABLE, "invalid": controlv1.Verdict_VERDICT_INVALID,
	"infrastructure_failed": controlv1.Verdict_VERDICT_INFRASTRUCTURE_FAILED, "canceled": controlv1.Verdict_VERDICT_CANCELED,
}

// Stage is an accepted result.
type Stage struct {
	StageID      string `json:"stageId"`
	ResultDigest string `json:"resultDigest"`
	Existing     bool   `json:"existing"`
}

// AcceptedStage is the accepted result of this attempt as Control records
// it (P12 joint stage recovery): the stage identity, the verdict, the
// digest of the accepted result manifest, the epochs it was accepted under
// and every artifact it binds with its exact object version.
type AcceptedStage struct {
	StageID          string             `json:"stageId"`
	AttemptID        string             `json:"attemptId"`
	InstanceID       string             `json:"instanceId"`
	Verdict          string             `json:"verdict"`
	FailureCode      string             `json:"failureCode,omitempty"`
	ResultDigest     string             `json:"resultDigest"`
	ObserverIdentity string             `json:"observerIdentity"`
	ProfileID        string             `json:"profileId"`
	ExecutionEpoch   string             `json:"executionEpoch"`
	RecoveryEpoch    string             `json:"recoveryEpoch"`
	Artifacts        []AcceptedArtifact `json:"artifacts"`
}

type AcceptedArtifact struct {
	Handle        string `json:"handle"`
	Class         string `json:"class"`
	Digest        string `json:"digest"`
	SizeBytes     string `json:"sizeBytes"`
	TransferID    string `json:"transferId"`
	ObjectVersion string `json:"objectVersion"`
}

// AcceptedStage reads the accepted stage of the scope's attempt; nil when
// no result is accepted yet. It never submits, resends or reopens anything.
func (c *Client) AcceptedStage(ctx context.Context, s *Scope) (*AcceptedStage, error) {
	ctx, cancel := c.call(ctx)
	defer cancel()
	resp, err := c.exec.GetAcceptedStage(ctx, &controlv1.GetAcceptedStageRequest{AttemptId: s.AttemptID, TenantId: s.TenantID})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil
		}
		return nil, refusal(err)
	}
	return fromAcceptedStage(resp.GetStage()), nil
}

// Submit submits the trusted observer's result manifest for acceptance
// under the current instance and execution epoch: one result per attempt,
// a repeat of the same bytes reenters the original stage, Control refuses
// everything else.
func (c *Client) Submit(ctx context.Context, s *Scope, verdict, failureCode, observer string, manifest []byte) (*Stage, error) {
	v, ok := verdicts[verdict]
	if !ok {
		return nil, fmt.Errorf("%w: INVALID_ARGUMENT unknown verdict %q", ErrRefused, verdict)
	}
	digest := DigestOf(manifest)
	req := &controlv1.AcceptResultRequest{
		Command:   command(s.TenantID, s.AttemptID+":accept", map[string]string{"attempt": s.AttemptID, "instance": s.InstanceID, "digest": digest, "verdict": verdict}),
		AttemptId: s.AttemptID, InstanceId: s.InstanceID, ProfileId: s.ProfileID, Verdict: v, ResultDigest: digest, ResultManifest: manifest,
		ObserverIdentity: observer, ExecutionEpoch: s.ExecutionEpoch,
	}
	if failureCode != "" {
		req.FailureCode = &failureCode
	}
	ctx, cancel := c.call(ctx)
	defer cancel()
	resp, err := c.exec.AcceptResult(ctx, req)
	if err != nil {
		return nil, refusal(err)
	}
	return &Stage{StageID: resp.GetStage().GetStageId(), ResultDigest: resp.GetStage().GetResultDigest(), Existing: resp.GetExisting()}, nil
}

// PriorStage reads the accepted stage of another attempt of the scope's
// operation (P13-04 cross-attempt recovery): Control checks the
// relationship (the stage belongs to an attempt of this operation and
// tenant); nil when that attempt has no accepted stage. Nothing is
// resent or reopened.
func (c *Client) PriorStage(ctx context.Context, s *Scope, attemptID string) (*AcceptedStage, error) {
	ctx, cancel := c.call(ctx)
	defer cancel()
	resp, err := c.exec.GetAcceptedStage(ctx, &controlv1.GetAcceptedStageRequest{AttemptId: attemptID, TenantId: s.TenantID, OperationId: s.OperationID})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil
		}
		return nil, refusal(err)
	}
	return fromAcceptedStage(resp.GetStage()), nil
}

func fromAcceptedStage(st *controlv1.AcceptedStage) *AcceptedStage {
	if st == nil {
		return nil
	}
	out := &AcceptedStage{
		StageID: st.GetStageId(), AttemptID: st.GetAttemptId(), InstanceID: st.GetInstanceId(),
		Verdict: strings.ToLower(strings.TrimPrefix(st.GetVerdict().String(), "VERDICT_")), FailureCode: st.GetFailureCode(),
		ResultDigest: st.GetResultDigest(), ObserverIdentity: st.GetObserverIdentity(), ProfileID: st.GetProfileId(),
		ExecutionEpoch: st.GetExecutionEpoch(), RecoveryEpoch: st.GetRecoveryEpoch(), Artifacts: []AcceptedArtifact{},
	}
	for _, a := range st.GetArtifacts() {
		out.Artifacts = append(out.Artifacts, AcceptedArtifact{Handle: a.GetHandle(), Class: a.GetClass(), Digest: a.GetDigest(), SizeBytes: a.GetSizeBytes(), TransferID: a.GetTransferId(), ObjectVersion: a.GetObjectVersion()})
	}
	return out
}

// Loaded is an artifact read through Control under the scope.
type Loaded struct {
	Handle    string
	Class     string
	Digest    string
	SizeBytes int64
	Bytes     []byte
}

// Load reads the artifact a launch input names by handle (P13-04):
// Control issues the scoped download capability only under an authorized
// relationship between this instance's operation and the artifact (its
// brief, an accepted stage of one of its attempts) while the instance is
// the current one of an executing attempt; the bytes are fetched through
// the capability and verified against the digest and size Control
// answered before anything is staged. maxBytes bounds the read. The
// capability never leaves this process.
func (c *Client) Load(ctx context.Context, s *Scope, handle string, maxBytes int64) (*Loaded, error) {
	rctx, cancel := c.call(ctx)
	resp, err := c.artifact.ReadArtifact(rctx, &controlv1.ReadArtifactRequest{Handle: handle, OperationId: s.OperationID, InstanceId: s.InstanceID})
	cancel()
	if err != nil {
		return nil, refusal(err)
	}
	t := resp.GetTransfer()
	size, err := strconv.ParseInt(t.GetExpectedSize(), 10, 64)
	if err != nil || size < 0 {
		return nil, fmt.Errorf("%w: transfer %s declares size %q", ErrUnavailable, t.GetTransferId(), t.GetExpectedSize())
	}
	if maxBytes > 0 && size > maxBytes {
		return nil, fmt.Errorf("%w: INVALID_ARGUMENT artifact %s holds %d bytes, the input bound is %d", ErrRefused, handle, size, maxBytes)
	}
	cap := resp.GetDownload()
	if cap == nil || cap.GetUrl() == "" {
		return nil, fmt.Errorf("%w: no download capability was issued", ErrUnavailable)
	}
	req, err := http.NewRequestWithContext(ctx, cap.GetMethod(), cap.GetUrl(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: download request: %v", ErrUnavailable, err)
	}
	for k, v := range cap.GetHeaders() {
		req.Header.Set(k, v)
	}
	res, err := c.upload.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: download: transport error", ErrUnavailable)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: download answered %d", ErrUnavailable, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, size+1))
	if err != nil {
		return nil, fmt.Errorf("%w: download: transport error", ErrUnavailable)
	}
	if int64(len(body)) != size || DigestOf(body) != t.GetExpectedDigest() {
		return nil, fmt.Errorf("%w: STALE_EXECUTION artifact %s: the downloaded bytes (%d, %s) are not the recorded object (%s, %s)", ErrRefused, handle, len(body), DigestOf(body), t.GetExpectedSize(), t.GetExpectedDigest())
	}
	return &Loaded{Handle: t.GetHandle(), Class: strings.ToLower(strings.TrimPrefix(t.GetClass().String(), "ARTIFACT_CLASS_")), Digest: t.GetExpectedDigest(), SizeBytes: size, Bytes: body}, nil
}
