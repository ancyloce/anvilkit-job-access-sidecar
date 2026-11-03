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
	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/peer"
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

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestInputReadOnBothRouteSets pins GET /v1/inputs/{name} on each socket's
// route set: served only to that socket's peer UID with that socket's
// peer token and a fresh nonce (DEC-045 B2), with the sidecar's proof on
// every answer past the guard, and only after Control confirms the
// authority on every request.
func TestInputReadOnBothRouteSets(t *testing.T) {
	const trustedUID, candidateUID = 10002, 10001
	staged := []byte("fixed input bytes")
	env := envelope.Envelope{Inputs: []envelope.Input{{Name: "fixed-input", Digest: scope.DigestOf(staged)}}}
	inputs := server.NewInputs(env)
	require.NoError(t, inputs.Stage("fixed-input", staged))
	src := &confirmOnly{}
	secret, err := peer.ParseSecret(testSecret)
	require.NoError(t, err)
	trustedToken, candidateToken := peer.Token(secret, peer.RoleTrusted), peer.Token(secret, peer.RoleCandidate)
	srv := &server.Server{TrustedUID: trustedUID, CandidateUID: candidateUID, TrustedToken: trustedToken, CandidateToken: candidateToken,
		Envelope: env, Inputs: inputs, Scope: src, Log: slog.New(slog.DiscardHandler), Now: time.Now}

	// get sends one request as uid with the headers given; nonce "" sends
	// none. It returns the recorder and whether the proof matches the nonce.
	get := func(h http.Handler, uid uint32, path, token, nonce string) (*httptest.ResponseRecorder, bool) {
		ctx := server.ConnContext(context.Background(), &sockets.Conn{Peer: sockets.Peer{UID: uid}})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil).WithContext(ctx)
		if token != "" {
			req.Header.Set(peer.HeaderToken, token)
		}
		if nonce != "" {
			req.Header.Set(peer.HeaderNonce, nonce)
		}
		h.ServeHTTP(rec, req)
		want, _ := peer.Proof(token, nonce)
		got := rec.Header().Get(peer.HeaderProof)
		return rec, got != "" && want != "" && peer.Equal(got, want)
	}
	nonce := func() string {
		n, err := peer.NewNonce()
		require.NoError(t, err)
		return n
	}

	for _, rs := range []struct {
		name         string
		handler      http.Handler
		uid, other   uint32
		token, wrong string
	}{
		{"trusted", srv.Trusted(), trustedUID, candidateUID, trustedToken, candidateToken},
		{"candidate", srv.Candidate(), candidateUID, trustedUID, candidateToken, trustedToken},
	} {
		t.Run(rs.name, func(t *testing.T) {
			src.err, src.calls = nil, 0

			rec, proved := get(rs.handler, rs.uid, "/v1/inputs/fixed-input", rs.token, nonce())
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.Equal(t, staged, rec.Body.Bytes())
			require.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
			require.True(t, proved, "a served answer carries the proof of its nonce")
			rec, _ = get(rs.handler, rs.uid, "/v1/inputs/fixed-input", rs.token, nonce())
			require.Equal(t, http.StatusOK, rec.Code)
			require.Equal(t, 2, src.calls, "every request asks Control again")

			rec, proved = get(rs.handler, rs.other, "/v1/inputs/fixed-input", rs.token, nonce())
			require.Equal(t, http.StatusForbidden, rec.Code)
			require.Contains(t, rec.Body.String(), "PEER_UID_MISMATCH")
			require.False(t, proved)
			require.Empty(t, rec.Header().Get(peer.HeaderProof), "a guard refusal carries no proof")
			require.Equal(t, 2, src.calls, "the peer check precedes Control")

			rec, _ = get(rs.handler, rs.uid, "/v1/inputs/fixed-input", rs.token, "")
			require.Equal(t, http.StatusBadRequest, rec.Code)
			require.Contains(t, rec.Body.String(), "PEER_NONCE_INVALID")
			require.Empty(t, rec.Header().Get(peer.HeaderProof))
			rec, _ = get(rs.handler, rs.uid, "/v1/inputs/fixed-input", rs.token, "not-a-nonce")
			require.Equal(t, http.StatusBadRequest, rec.Code)
			rec, _ = get(rs.handler, rs.uid, "/v1/inputs/fixed-input", rs.wrong, nonce())
			require.Equal(t, http.StatusForbidden, rec.Code, "the other socket's token is refused")
			require.Contains(t, rec.Body.String(), "PEER_TOKEN_MISMATCH")
			require.Empty(t, rec.Header().Get(peer.HeaderProof))
			rec, _ = get(rs.handler, rs.uid, "/v1/inputs/fixed-input", "", nonce())
			require.Equal(t, http.StatusForbidden, rec.Code, "no token is refused")
			require.Equal(t, 2, src.calls, "the token check precedes Control")

			src.err = scope.ErrStale
			rec, proved = get(rs.handler, rs.uid, "/v1/inputs/fixed-input", rs.token, nonce())
			require.Equal(t, http.StatusForbidden, rec.Code)
			require.Contains(t, rec.Body.String(), "STALE_EXECUTION")
			require.NotContains(t, rec.Body.String(), string(staged))
			require.True(t, proved, "a refusal past the guard carries the proof too")
			src.err = nil

			rec, proved = get(rs.handler, rs.uid, "/v1/inputs/not-staged", rs.token, nonce())
			require.Equal(t, http.StatusNotFound, rec.Code)
			require.True(t, proved)
			rec, _ = get(rs.handler, rs.uid, "/v1/inputs/Bad_Name", rs.token, nonce())
			require.Equal(t, http.StatusNotFound, rec.Code)
		})
	}
}
