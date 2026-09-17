// Package server serves the two route sets of the access sidecar over the
// sockets of DD-03 §5. Candidate routes (candidate.sock, peer UID
// candidate) provide permitted inputs and the controlled model relay only;
// trusted routes (trusted.sock, peer UID trusted) resolve the execution
// scope, stage permitted inputs, run the scoped artifact transfer and
// submit results, and reach the Knowledge/MCP expert relays. Every
// protected request is intersected with the execution authority Control
// confirms at that moment: no registration, an unreachable Control, a
// non-current instance, a closed attempt, a fenced operation or a passed
// deadline serves nothing, neither content nor a scope, from any earlier
// answer. Each connection serves one request (keep-alives are disabled)
// and closes.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/envelope"
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/scope"
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/sockets"
)

// Envelope is the typed launch envelope the launcher supplied.
type Envelope = envelope.Envelope

// Inputs holds the permitted inputs the trusted harness staged, each
// verified against the digest the envelope declares for its name.
type Inputs struct {
	mu       sync.RWMutex
	declared map[string]string
	bytes    map[string][]byte
}

func NewInputs(env Envelope) *Inputs {
	in := &Inputs{declared: map[string]string{}, bytes: map[string][]byte{}}
	for _, i := range env.Inputs {
		in.declared[i.Name] = i.Digest
	}
	return in
}

// Names lists the permitted input names.
func (in *Inputs) Names() []string {
	in.mu.RLock()
	defer in.mu.RUnlock()
	out := make([]string, 0, len(in.declared))
	for n := range in.declared {
		out = append(out, n)
	}
	return out
}

// Stage records bytes for a permitted name after verifying their digest.
func (in *Inputs) Stage(name string, b []byte) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	want, ok := in.declared[name]
	if !ok {
		return fmt.Errorf("input %q is not declared by the launch envelope", name)
	}
	if got := scope.DigestOf(b); got != want {
		return fmt.Errorf("input %q bytes hash to %s, the envelope declares %s", name, got, want)
	}
	in.bytes[name] = b
	return nil
}

// Get returns staged bytes of a permitted name.
func (in *Inputs) Get(name string) ([]byte, bool) {
	in.mu.RLock()
	defer in.mu.RUnlock()
	b, ok := in.bytes[name]
	return b, ok
}

// Limits are the reviewed request bounds.
type Limits struct {
	MaxInputBytes    int64
	MaxTransferBytes int64
	MaxManifestBytes int64
	RequestTimeout   time.Duration
}

// ScopeSource is what the routes consult: Control's confirmation of the
// execution authority now, for the purpose, and the trusted actions.
type ScopeSource interface {
	// Confirm reads the registration from Control and decides: the scope
	// when authority holds; scope.ErrUnregistered while the launcher has
	// not registered the Pod, scope.ErrUnavailable when Control cannot be
	// asked, scope.ErrNoAuthority for a non-current or foreign instance,
	// scope.ErrStale for an ended attempt or a fenced operation,
	// scope.ErrDeadline for a passed deadline. The clock must be read after
	// the Control lookup, immediately before the authorization decision.
	Confirm(ctx context.Context, now func() time.Time, purpose scope.Purpose) (*scope.Scope, error)
	Upload(ctx context.Context, s *scope.Scope, class, mediaType string, body []byte) (*scope.Transfer, error)
	Submit(ctx context.Context, s *scope.Scope, verdict, failureCode, observer string, manifest []byte) (*scope.Stage, error)
}

type Server struct {
	TrustedUID   uint32
	CandidateUID uint32
	Envelope     Envelope
	Inputs       *Inputs
	Scope        ScopeSource
	Limits       Limits
	Log          *slog.Logger
	Now          func() time.Time
}

type peerKey struct{}

// ConnContext binds the accepted connection's peer credentials to every
// request served on it.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if pc, ok := c.(*sockets.Conn); ok {
		return context.WithValue(ctx, peerKey{}, pc.Peer)
	}
	return ctx
}

func peer(r *http.Request) (sockets.Peer, bool) {
	p, ok := r.Context().Value(peerKey{}).(sockets.Peer)
	return p, ok
}

// HTTPServer builds the server for one socket: one request per connection.
func (s *Server) HTTPServer(h http.Handler) *http.Server {
	srv := &http.Server{
		Handler: h, ConnContext: ConnContext, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: s.Limits.RequestTimeout, WriteTimeout: s.Limits.RequestTimeout + 10*time.Second, MaxHeaderBytes: 16 << 10,
	}
	srv.SetKeepAlivesEnabled(false)
	return srv
}

type failure struct {
	Code   string `json:"code"`
	Reason string `json:"reason,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code, reason string) {
	writeJSON(w, status, failure{Code: code, Reason: reason})
}

// guard refuses a request whose connection is not from the expected UID.
func (s *Server) guard(uid uint32, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := peer(r)
		if !ok || p.UID != uid {
			s.Log.Warn("connection from an unexpected peer refused", "expectedUid", uid, "peerUid", p.UID, "peerPid", p.PID, "route", r.Method+" "+r.URL.Path)
			fail(w, http.StatusForbidden, "PEER_UID_MISMATCH", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

var inputName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// Candidate is the candidate route set.
func (s *Server) Candidate() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/inputs/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !inputName.MatchString(name) {
			fail(w, http.StatusNotFound, "NOT_FOUND", "")
			return
		}
		// Inputs are permitted only inside an execution authority Control
		// confirms now; staged bytes are never served on an earlier answer.
		if _, err := s.Scope.Confirm(r.Context(), s.Now, scope.ForNewAuthorization); !s.answerScopeError(w, err) {
			return
		}
		b, ok := s.Inputs.Get(name)
		if !ok {
			fail(w, http.StatusNotFound, "NOT_FOUND", "")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Connection", "close")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("POST /v1/model/relay", func(w http.ResponseWriter, r *http.Request) {
		// The controlled model relay is the candidate's only outbound
		// route. Its upstream (Model Proxy, P11) is not configured in this
		// unit: the route exists and answers that the dependency is
		// unavailable; there is no direct provider or network fallback.
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		fail(w, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "model relay upstream not configured (P11)")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fail(w, http.StatusForbidden, "ROUTE_FORBIDDEN", "")
	})
	return s.guard(s.CandidateUID, mux)
}

// Trusted is the trusted route set.
func (s *Server) Trusted() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/scope", func(w http.ResponseWriter, r *http.Request) {
		sc, err := s.Scope.Confirm(r.Context(), s.Now, scope.ForNewAuthorization)
		if !s.answerScopeError(w, err) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"scope": sc, "launchId": s.Envelope.LaunchID, "inputs": s.Inputs.Names()})
	})
	mux.HandleFunc("PUT /v1/inputs/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.Limits.MaxInputBytes))
		if err != nil {
			fail(w, http.StatusRequestEntityTooLarge, "INPUT_TOO_LARGE", "")
			return
		}
		if _, err := s.Scope.Confirm(r.Context(), s.Now, scope.ForNewAuthorization); !s.answerScopeError(w, err) {
			return
		}
		if err := s.Inputs.Stage(name, body); err != nil {
			fail(w, http.StatusBadRequest, "INPUT_REJECTED", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"name": name, "sizeBytes": len(body)})
	})
	mux.HandleFunc("POST /v1/transfers", func(w http.ResponseWriter, r *http.Request) {
		class := r.Header.Get("X-Anvilkit-Class")
		mediaType := r.Header.Get("Content-Type")
		if mediaType == "" {
			mediaType = "application/octet-stream"
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.Limits.MaxTransferBytes))
		if err != nil {
			fail(w, http.StatusRequestEntityTooLarge, "TRANSFER_TOO_LARGE", "")
			return
		}
		sc, err := s.Scope.Confirm(r.Context(), s.Now, scope.ForNewAuthorization)
		if !s.answerScopeError(w, err) {
			return
		}
		t, err := s.Scope.Upload(r.Context(), sc, class, mediaType, body)
		if err != nil {
			s.answerActionError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, t)
	})
	mux.HandleFunc("POST /v1/results", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Verdict          string          `json:"verdict"`
			FailureCode      string          `json:"failureCode"`
			ObserverIdentity string          `json:"observerIdentity"`
			Manifest         json.RawMessage `json:"manifest"`
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.Limits.MaxManifestBytes+4096))
		if err != nil {
			fail(w, http.StatusRequestEntityTooLarge, "RESULT_TOO_LARGE", "")
			return
		}
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil || len(in.Manifest) == 0 || in.ObserverIdentity == "" {
			fail(w, http.StatusBadRequest, "INVALID_ARGUMENT", "verdict, observerIdentity and manifest are required")
			return
		}
		if int64(len(in.Manifest)) > s.Limits.MaxManifestBytes {
			fail(w, http.StatusRequestEntityTooLarge, "RESULT_TOO_LARGE", "")
			return
		}
		sc, err := s.Scope.Confirm(r.Context(), s.Now, scope.ForResult)
		if !s.answerScopeError(w, err) {
			return
		}
		st, err := s.Scope.Submit(r.Context(), sc, in.Verdict, in.FailureCode, in.ObserverIdentity, []byte(in.Manifest))
		if err != nil {
			s.answerActionError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, st)
	})
	unavailable := func(dep string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
			if _, err := s.Scope.Confirm(r.Context(), s.Now, scope.ForNewAuthorization); !s.answerScopeError(w, err) {
				return
			}
			fail(w, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", dep+" upstream not configured")
		}
	}
	// Trusted expert relays: reserved for the trusted harness (P12/P16/P19
	// wire their upstreams); they never exist on the candidate socket.
	mux.HandleFunc("POST /v1/model/relay", unavailable("model relay (P11)"))
	mux.HandleFunc("POST /v1/knowledge/", unavailable("knowledge (P16)"))
	mux.HandleFunc("POST /v1/mcp/", unavailable("mcp (P19)"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fail(w, http.StatusForbidden, "ROUTE_FORBIDDEN", "")
	})
	return s.guard(s.TrustedUID, mux)
}

// answerScopeError writes the answer for a scope that is not usable and
// reports whether the caller may proceed.
func (s *Server) answerScopeError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, scope.ErrUnregistered):
		w.Header().Set("Retry-After", "2")
		fail(w, http.StatusServiceUnavailable, "SCOPE_UNAVAILABLE", "the launcher has not registered this instance")
	case errors.Is(err, scope.ErrNoAuthority):
		fail(w, http.StatusForbidden, "NO_AUTHORITY", "this instance is not the current physical owner of the attempt")
	case errors.Is(err, scope.ErrDeadline):
		fail(w, http.StatusForbidden, "DEADLINE_EXCEEDED", "the attempt deadline passed")
	case errors.Is(err, scope.ErrStale):
		fail(w, http.StatusForbidden, "STALE_EXECUTION", "the execution scope ended: the attempt is no longer executing or the operation is fenced")
	case errors.Is(err, scope.ErrRefused):
		fail(w, http.StatusForbidden, scope.Code(err), "")
	default:
		w.Header().Set("Retry-After", "2")
		fail(w, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "control unavailable")
	}
	return false
}

func (s *Server) answerActionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scope.ErrRefused):
		code := scope.Code(err)
		status := http.StatusConflict
		if code == "INVALID_ARGUMENT" {
			status = http.StatusBadRequest
		}
		fail(w, status, code, "")
	default:
		fail(w, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", "")
	}
}
