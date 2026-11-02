package server_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/envelope"
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/scope"
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/server"
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/sockets"
)

// confirmOnly is a ScopeSource that answers Confirm with err and counts the
// calls; the trusted actions are not reached by the input routes.
type confirmOnly struct {
	server.ScopeSource
	err   error
	calls int
}

func (c *confirmOnly) Confirm(context.Context, func() time.Time, scope.Purpose) (*scope.Scope, error) {
	c.calls++
	if c.err != nil {
		return nil, c.err
	}
	return &scope.Scope{}, nil
}

// TestInputReadOnBothRouteSets pins GET /v1/inputs/{name} on each socket's
// route set: served only to that socket's peer UID, and only after Control
// confirms the authority on every request.
func TestInputReadOnBothRouteSets(t *testing.T) {
	const trustedUID, candidateUID = 10002, 10001
	staged := []byte("fixed input bytes")
	env := envelope.Envelope{Inputs: []envelope.Input{{Name: "fixed-input", Digest: scope.DigestOf(staged)}}}
	inputs := server.NewInputs(env)
	require.NoError(t, inputs.Stage("fixed-input", staged))
	src := &confirmOnly{}
	srv := &server.Server{TrustedUID: trustedUID, CandidateUID: candidateUID, Envelope: env, Inputs: inputs, Scope: src,
		Log: slog.New(slog.DiscardHandler), Now: time.Now}

	get := func(h http.Handler, uid uint32, path string) *httptest.ResponseRecorder {
		ctx := server.ConnContext(context.Background(), &sockets.Conn{Peer: sockets.Peer{UID: uid}})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil).WithContext(ctx))
		return rec
	}

	for _, rs := range []struct {
		name       string
		handler    http.Handler
		uid, other uint32
	}{
		{"trusted", srv.Trusted(), trustedUID, candidateUID},
		{"candidate", srv.Candidate(), candidateUID, trustedUID},
	} {
		t.Run(rs.name, func(t *testing.T) {
			src.err, src.calls = nil, 0

			rec := get(rs.handler, rs.uid, "/v1/inputs/fixed-input")
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Equal(t, staged, rec.Body.Bytes())
			require.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
			rec = get(rs.handler, rs.uid, "/v1/inputs/fixed-input")
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, 2, src.calls, "every request asks Control again")

			rec = get(rs.handler, rs.other, "/v1/inputs/fixed-input")
			require.Equal(t, http.StatusForbidden, rec.Code)
			require.Contains(t, rec.Body.String(), "PEER_UID_MISMATCH")
			require.Equal(t, 2, src.calls, "the peer check precedes Control")

			src.err = scope.ErrStale
			rec = get(rs.handler, rs.uid, "/v1/inputs/fixed-input")
			require.Equal(t, http.StatusForbidden, rec.Code)
			require.Contains(t, rec.Body.String(), "STALE_EXECUTION")
			require.NotContains(t, rec.Body.String(), string(staged))
			src.err = nil

			require.Equal(t, http.StatusNotFound, get(rs.handler, rs.uid, "/v1/inputs/not-staged").Code)
			require.Equal(t, http.StatusNotFound, get(rs.handler, rs.uid, "/v1/inputs/Bad_Name").Code)
		})
	}
}
