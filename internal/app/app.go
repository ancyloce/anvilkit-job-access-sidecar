// Package app wires the access sidecar: the identity check, the sockets,
// the two route sets and the live resolution of the execution scope from
// Control before every protected request.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/config"
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/envelope"
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/scope"
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/server"
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/sockets"
)

// resolver is what the routes consult: Control read now, the launch
// envelope's binding, and the decision. Nothing is cached between
// requests; the first confirmed authority is announced in the log once.
type resolver struct {
	client    *scope.Client
	binding   scope.Binding
	log       *slog.Logger
	mu        sync.Mutex
	announced bool
}

func (r *resolver) Confirm(ctx context.Context, now func() time.Time, purpose scope.Purpose) (*scope.Scope, error) {
	s, err := r.client.Confirm(ctx, r.binding, now, purpose)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	first := !r.announced
	r.announced = true
	r.mu.Unlock()
	if first {
		r.log.Info("scope confirmed", "attemptId", s.AttemptID, "instanceId", s.InstanceID, "deadline", s.Deadline.UTC().Format(time.RFC3339))
	}
	return s, nil
}

func (r *resolver) Upload(ctx context.Context, s *scope.Scope, class, mediaType string, body []byte) (*scope.Transfer, error) {
	return r.client.Upload(ctx, s, class, mediaType, body)
}

func (r *resolver) Submit(ctx context.Context, s *scope.Scope, verdict, failureCode, observer string, manifest []byte) (*scope.Stage, error) {
	return r.client.Submit(ctx, s, verdict, failureCode, observer, manifest)
}

func (r *resolver) AcceptedStage(ctx context.Context, s *scope.Scope) (*scope.AcceptedStage, error) {
	return r.client.AcceptedStage(ctx, s)
}

// Run serves until ctx ends. It refuses to run under any UID but the
// configured owner and with a disabled identity.
func Run(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	if cfg.Disabled() {
		return errors.New("profile disabled: identity.mode is disabled (no trusted identity input for this environment); nothing is served")
	}
	if uid := uint32(os.Getuid()); uid != cfg.Sockets.OwnerUID || uint32(os.Geteuid()) != cfg.Sockets.OwnerUID {
		return fmt.Errorf("the sidecar runs as uid %d, expected %d", uid, cfg.Sockets.OwnerUID)
	}
	env, err := envelope.Parse([]byte(cfg.Launch.Envelope))
	if err != nil {
		return err
	}
	var tlsFiles *scope.TLSFiles
	if cfg.Identity.Mode == config.IdentityMTLS {
		m := cfg.Identity.MTLS
		tlsFiles = &scope.TLSFiles{CertFile: m.CertFile, KeyFile: m.KeyFile, CAFile: m.CAFile, ServerName: m.ServerName}
	} else {
		log.Warn("DEVELOPMENT_ONLY identity: plaintext Control transport; qualifies no production identity")
	}
	client, err := scope.Dial(scope.Identity{Backend: cfg.Launch.Backend, LaunchKey: cfg.Launch.LaunchKey, PodUID: cfg.Launch.PodUID},
		scope.Options{Address: cfg.Control.Address, Timeout: cfg.Control.Timeout, TLS: tlsFiles, Upload: &http.Client{Timeout: cfg.Limits.UploadTimeout}})
	if err != nil {
		return fmt.Errorf("control client: %w", err)
	}
	defer client.Close()
	res := &resolver{client: client, log: log, binding: scope.Binding{
		OperationID: env.OperationID, AttemptID: env.AttemptID, ProfileID: env.ProfileID, LaunchKey: cfg.Launch.LaunchKey,
		ExecutionEpoch: env.ExecutionEpoch, LaunchEpoch: env.LaunchEpoch,
	}}
	if env.LaunchKey != cfg.Launch.LaunchKey {
		return fmt.Errorf("launch envelope names launch key %s, the launch environment %s", env.LaunchKey, cfg.Launch.LaunchKey)
	}

	layout, err := sockets.Create(cfg.Sockets.Dir, cfg.Sockets.TrustedUID, cfg.Sockets.CandidateUID, func(p sockets.Peer) {
		log.Warn("connection refused at accept: unexpected peer", "peerUid", p.UID, "peerPid", p.PID)
	})
	if err != nil {
		return err
	}
	var relay server.ModelRelay
	if cfg.ModelProxy.URL != "" {
		o := scope.RelayOptions{URL: cfg.ModelProxy.URL, Timeout: cfg.ModelProxy.Timeout}
		if tlsFiles != nil {
			o.TLS = tlsFiles
		} else {
			o.Token = cfg.ModelProxy.Token
		}
		r, err := scope.NewRelay(o)
		if err != nil {
			return fmt.Errorf("model relay: %w", err)
		}
		relay = r
	} else {
		log.Warn("model proxy url not configured; the model relay answers DEPENDENCY_UNAVAILABLE")
	}
	srv := &server.Server{
		TrustedUID: cfg.Sockets.TrustedUID, CandidateUID: cfg.Sockets.CandidateUID, Envelope: env, Inputs: server.NewInputs(env), Scope: res, Relay: relay,
		Limits: server.Limits{MaxInputBytes: cfg.Limits.MaxInputBytes, MaxTransferBytes: cfg.Limits.MaxTransferBytes, MaxManifestBytes: cfg.Limits.MaxManifestBytes, RequestTimeout: cfg.Limits.RequestTimeout},
		Log:    log, Now: time.Now,
	}
	trusted, candidate := srv.HTTPServer(srv.Trusted()), srv.HTTPServer(srv.Candidate())
	errs := make(chan error, 2)
	go func() { errs <- trusted.Serve(layout.Trusted) }()
	go func() { errs <- candidate.Serve(layout.Candidate) }()
	log.Info("access sidecar serving", "dir", layout.Dir, "launchKey", cfg.Launch.LaunchKey, "backend", cfg.Launch.Backend, "identity", cfg.Identity.Mode, "modelRelay", relay != nil)

	select {
	case <-ctx.Done():
	case err := <-errs:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	_ = trusted.Shutdown(shutdown)
	_ = candidate.Shutdown(shutdown)
	return nil
}
