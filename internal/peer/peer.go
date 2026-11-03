// Package peer is the second peer binding of the access sidecar's sockets
// (DEC-045 B2, DD-03 §5): beside the kernel-reported peer UID, every
// request carries a token derived from the launch secret the launcher
// issued to the sidecar and the trusted container, and every answer
// carries a proof derived from that token and the request's nonce, so a
// client without SO_PEERCRED (a Node process) can still tell it reached
// the sidecar. The derivations are exact byte layouts the supervisor, the
// validator and the team re-implement:
//
//	token(role) = hex(HMAC-SHA256(key = secret, msg = "anvilkit/peer-token/v1/" + role))
//	proof       = hex(HMAC-SHA256(key = hexdecode(token), msg = "anvilkit/sidecar-proof/v1/" + nonce))
//
// The secret is 32 bytes as 64 lowercase hex characters; a nonce is 16
// bytes as 32 lowercase hex characters, fresh per request.
package peer

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// HeaderToken carries token(role) on every request.
	HeaderToken = "Anvilkit-Peer-Token"
	// HeaderNonce carries the request's fresh nonce.
	HeaderNonce = "Anvilkit-Peer-Nonce"
	// HeaderProof carries the sidecar's proof on every answer of a request
	// that passed the peer checks.
	HeaderProof = "Anvilkit-Sidecar-Proof"

	RoleTrusted   = "trusted"
	RoleCandidate = "candidate"

	tokenPrefix = "anvilkit/peer-token/v1/"
	proofPrefix = "anvilkit/sidecar-proof/v1/"

	secretHexLen = 64
	nonceHexLen  = 32
)

// ErrSecret marks a launch secret that is not 64 lowercase hex characters.
var ErrSecret = errors.New("the launch secret must be exactly 64 lowercase hex characters")

// ParseSecret checks and decodes the launch secret.
func ParseSecret(s string) ([]byte, error) {
	if !lowerHex(s, secretHexLen) {
		return nil, ErrSecret
	}
	return hex.DecodeString(s)
}

// Token derives the peer token of a role from the decoded secret.
func Token(secret []byte, role string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(tokenPrefix + role))
	return hex.EncodeToString(m.Sum(nil))
}

// Proof derives the sidecar's proof for a token and a nonce.
func Proof(token, nonce string) (string, error) {
	key, err := hex.DecodeString(token)
	if err != nil || len(key) != sha256.Size {
		return "", fmt.Errorf("peer token is not %d hex characters", 2*sha256.Size)
	}
	if !ValidNonce(nonce) {
		return "", errors.New("nonce is not 32 lowercase hex characters")
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(proofPrefix + nonce))
	return hex.EncodeToString(m.Sum(nil)), nil
}

// ValidNonce reports whether s is a well-formed nonce.
func ValidNonce(s string) bool { return lowerHex(s, nonceHexLen) }

// NewNonce draws a fresh nonce.
func NewNonce() (string, error) {
	var b [nonceHexLen / 2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Equal compares two hex strings in constant time.
func Equal(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
