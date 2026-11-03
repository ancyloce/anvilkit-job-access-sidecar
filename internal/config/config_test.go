package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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
			"ANVILKIT_SIDECAR_POD_UID=pod-1", "ANVILKIT_SIDECAR_LAUNCH_ENVELOPE=" + testEnvelope, "ANVILKIT_SIDECAR_LAUNCH_SECRET=" + testSecret,
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

// DEC-045: the socket names are abstract file keys, the launch secret an
// environment-only 64-hex value required whenever the sidecar serves.
func TestSocketNamesAndLaunchSecret(t *testing.T) {
	load := func(file string, env ...string) (Config, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "sidecar.yaml")
		require.NoError(t, os.WriteFile(path, []byte(file), 0o600))
		return LoadFrom(path, append([]string{
			"ANVILKIT_SIDECAR_CONTROL_ADDRESS=127.0.0.1:9101", "ANVILKIT_SIDECAR_BACKEND=kind-anvilkit-dev", "ANVILKIT_SIDECAR_LAUNCH_KEY=cg-test",
			"ANVILKIT_SIDECAR_POD_UID=pod-1", "ANVILKIT_SIDECAR_LAUNCH_ENVELOPE=" + testEnvelope,
		}, env...))
	}
	mtls := "identity:\n  mode: mtls\n  mtls:\n    cert_file: /c\n    key_file: /k\n    ca_file: /a\n    server_name: anvilkit-agent-control\n"
	c, err := load(mtls, "ANVILKIT_SIDECAR_LAUNCH_SECRET="+testSecret)
	require.NoError(t, err)
	require.Equal(t, "@anvilkit/trusted", c.Sockets.TrustedName)
	require.Equal(t, "@anvilkit/candidate", c.Sockets.CandidateName)
	require.Equal(t, testSecret, c.Launch.Secret)
	c, err = load(mtls+"sockets:\n  trusted_name: \"@t/1\"\n  candidate_name: \"@c/1\"\n", "ANVILKIT_SIDECAR_LAUNCH_SECRET="+testSecret)
	require.NoError(t, err)
	require.Equal(t, "@t/1", c.Sockets.TrustedName)
	_, err = load(mtls)
	require.ErrorContains(t, err, "ANVILKIT_SIDECAR_LAUNCH_SECRET", "serving needs the secret")
	_, err = load(mtls, "ANVILKIT_SIDECAR_LAUNCH_SECRET=0123")
	require.ErrorContains(t, err, "64 lowercase hex")
	_, err = load(mtls, "ANVILKIT_SIDECAR_LAUNCH_SECRET="+strings.ToUpper(testSecret))
	require.ErrorContains(t, err, "64 lowercase hex")
	_, err = load(mtls + "launch:\n  secret: " + testSecret + "\n")
	require.ErrorContains(t, err, "launch.secret", "the secret is refused inside the file")
	_, err = load(mtls+"sockets:\n  trusted_name: /run/anvilkit/sockets/trusted.sock\n", "ANVILKIT_SIDECAR_LAUNCH_SECRET="+testSecret)
	require.ErrorContains(t, err, "abstract socket name")
	_, err = load(mtls+"sockets:\n  trusted_name: \"@same\"\n  candidate_name: \"@same\"\n", "ANVILKIT_SIDECAR_LAUNCH_SECRET="+testSecret)
	require.ErrorContains(t, err, "must differ")
	_, err = load(mtls+"sockets:\n  dir: /run/anvilkit/sockets\n", "ANVILKIT_SIDECAR_LAUNCH_SECRET="+testSecret)
	require.Error(t, err, "sockets.dir is gone")
	_, err = load(mtls, "ANVILKIT_SIDECAR_LAUNCH_SECRET="+testSecret, "ANVILKIT_SIDECAR_SOCKETS_DIR=/tmp")
	require.ErrorContains(t, err, "not allowed overrides", "the directory override is gone")
	c, err = load("identity:\n  mode: disabled\n")
	require.NoError(t, err, "a disabled profile serves nothing and needs no secret")
	require.True(t, c.Disabled())
}
