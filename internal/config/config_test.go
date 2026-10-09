package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const testEnvelope = `{"schemaVersion":1,"launchId":"lch_1","launchKey":"cg-test","operationId":"op_1","attemptId":"att_1","profileId":"harness-wiring-dev-v1","profileRevision":"1","jobKind":"codegen","executionEpoch":"1","launchEpoch":"1","deadline":"2030-01-01T00:00:00Z","inputs":[]}`

// The Model Proxy connection has its own identity mode: a bearer proxy
// beside an mTLS Control is DEVELOPMENT_ONLY and needs the file's guard; a
// proxy mTLS without the workload identity has no material.
func TestModelProxyIdentityPerConnection(t *testing.T) {
	load := func(file string) (Config, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "sidecar.yaml")
		require.NoError(t, os.WriteFile(path, []byte(file), 0o600))
		return LoadFrom(path, []string{
			"ANVILKIT_SIDECAR_CONTROL_ADDRESS=127.0.0.1:9101", "ANVILKIT_SIDECAR_BACKEND=kind-anvilkit-dev", "ANVILKIT_SIDECAR_LAUNCH_KEY=cg-test",
			"ANVILKIT_SIDECAR_POD_UID=pod-1", "ANVILKIT_SIDECAR_LAUNCH_ENVELOPE=" + testEnvelope, "ANVILKIT_SIDECAR_SOCKETS_DIR=/run/anvilkit/sockets",
			"ANVILKIT_SIDECAR_MODEL_PROXY_URL=http://127.0.0.1:9103", "ANVILKIT_SIDECAR_MODEL_PROXY_TOKEN=dev-token-0123456789",
		})
	}
	mtls := "identity:\n  mode: mtls\n  mtls:\n    cert_file: /c\n    key_file: /k\n    ca_file: /a\n    server_name: anvilkit-agent-control\n"
	c, err := load(mtls)
	require.NoError(t, err)
	require.Equal(t, IdentityMTLS, c.ModelProxy.IdentityMode, "an unset connection mode follows identity.mode")
	_, err = load(mtls + "model_proxy:\n  identity_mode: development\n")
	require.ErrorContains(t, err, "requires development.enabled")
	c, err = load("development:\n  enabled: true\n" + mtls + "model_proxy:\n  identity_mode: development\n")
	require.NoError(t, err)
	require.Equal(t, IdentityDevelopment, c.ModelProxy.IdentityMode)
	_, err = load("development:\n  enabled: true\nidentity:\n  mode: development\nmodel_proxy:\n  identity_mode: mtls\n")
	require.ErrorContains(t, err, "needs the workload identity")
}
