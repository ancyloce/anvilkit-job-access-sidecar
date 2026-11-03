package peer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func hmacHex(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// The derivations are the exact byte layouts the clients re-implement.
func TestDerivations(t *testing.T) {
	secretHex := strings.Repeat("0123456789abcdef", 4)
	secret, err := ParseSecret(secretHex)
	require.NoError(t, err)
	require.Len(t, secret, 32)
	_, err = ParseSecret(strings.ToUpper(secretHex))
	require.ErrorIs(t, err, ErrSecret, "uppercase is refused")
	_, err = ParseSecret(secretHex[:63])
	require.ErrorIs(t, err, ErrSecret)

	trusted, candidate := Token(secret, RoleTrusted), Token(secret, RoleCandidate)
	require.Len(t, trusted, 64)
	require.NotEqual(t, trusted, candidate)
	// The layouts every client re-implements.
	require.Equal(t, hmacHex(secret, "anvilkit/peer-token/v1/trusted"), trusted)
	require.Equal(t, hmacHex(secret, "anvilkit/peer-token/v1/candidate"), candidate)

	nonce := strings.Repeat("ab", 16)
	require.True(t, ValidNonce(nonce))
	require.False(t, ValidNonce(strings.Repeat("AB", 16)))
	require.False(t, ValidNonce(nonce[:30]))
	proof, err := Proof(trusted, nonce)
	require.NoError(t, err)
	key, _ := hex.DecodeString(trusted)
	require.Equal(t, hmacHex(key, "anvilkit/sidecar-proof/v1/"+nonce), proof)
	other, err := Proof(candidate, nonce)
	require.NoError(t, err)
	require.NotEqual(t, proof, other, "the proof is bound to the socket's token")
	_, err = Proof("zz", nonce)
	require.Error(t, err)
	_, err = Proof(trusted, "short")
	require.Error(t, err)

	fresh, err := NewNonce()
	require.NoError(t, err)
	require.True(t, ValidNonce(fresh))
	again, _ := NewNonce()
	require.NotEqual(t, fresh, again)
	require.True(t, Equal(proof, proof))
	require.False(t, Equal(proof, other))
	require.False(t, Equal(proof, proof[:63]))
}
