// Package config builds the sidecar's immutable configuration snapshot with
// koanf (A09, DD-09 §4): defaults < the reviewed config.yaml baked into the
// image < the allowlisted ANVILKIT_SIDECAR_* environment overrides, which are
// the deployment placements the Job template supplies (the Control address,
// the identity mode of the environment) and the launch identity Kubernetes
// injects (the Pod UID through the downward API, the launch key, the launch
// backend and the typed launch envelope). Unknown keys, missing values and
// contradictory settings stop the process before a socket exists. The
// launch fields are refused inside the file: they are per-Job facts, never
// image content.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	"github.com/ancyloce/anvilkit-job-access-sidecar/internal/envelope"
)

const (
	envPrefix         = "ANVILKIT_SIDECAR_"
	EnvConfigFile     = "ANVILKIT_SIDECAR_CONFIG"
	DefaultConfigFile = "config.yaml"

	IdentityDisabled    = "disabled"
	IdentityDevelopment = "development"
	IdentityMTLS        = "mtls"
)

// Sockets is the DD-03 §5 socket layout: the sidecar owns the directory and
// both sockets; the trusted socket is reachable by the trusted UID (group 0),
// the candidate socket by the candidate UID (group candidate).
type Sockets struct {
	Dir          string `koanf:"dir"`
	TrustedUID   uint32 `koanf:"trusted_uid"`
	CandidateUID uint32 `koanf:"candidate_uid"`
	// OwnerUID is the UID this process must run as (10002); sockets are
	// created under it and any other effective UID refuses to start.
	OwnerUID uint32 `koanf:"owner_uid"`
}

type Control struct {
	Address string        `koanf:"address"`
	Timeout time.Duration `koanf:"timeout"`
}

// MTLS names the workload identity material (mounted into this container
// only, never into the candidate's). Required when identity.mode is mtls.
type MTLS struct {
	CertFile   string `koanf:"cert_file"`
	KeyFile    string `koanf:"key_file"`
	CAFile     string `koanf:"ca_file"`
	ServerName string `koanf:"server_name"`
}

// Identity selects how the sidecar authenticates to Control. disabled keeps
// the profile disabled (the process refuses to serve); development is the
// plaintext loopback/gateway identity of the development foundation and
// qualifies nothing; mtls is the production path (ENV-03 input).
type Identity struct {
	Mode string `koanf:"mode"`
	MTLS MTLS   `koanf:"mtls"`
}

// Launch is the per-Job identity, environment-only.
type Launch struct {
	Backend   string `koanf:"backend"`
	LaunchKey string `koanf:"launch_key"`
	PodUID    string `koanf:"pod_uid"`
	Envelope  string `koanf:"envelope"`
}

type Limits struct {
	MaxInputBytes    int64         `koanf:"max_input_bytes"`
	MaxTransferBytes int64         `koanf:"max_transfer_bytes"`
	MaxManifestBytes int64         `koanf:"max_manifest_bytes"`
	RequestTimeout   time.Duration `koanf:"request_timeout"`
	UploadTimeout    time.Duration `koanf:"upload_timeout"`
}

type Config struct {
	Sockets         Sockets       `koanf:"sockets"`
	Control         Control       `koanf:"control"`
	Identity        Identity      `koanf:"identity"`
	Launch          Launch        `koanf:"launch"`
	Limits          Limits        `koanf:"limits"`
	ShutdownTimeout time.Duration `koanf:"shutdown_timeout"`
}

var defaults = map[string]any{
	"sockets.dir":               "/run/anvilkit/sockets",
	"sockets.trusted_uid":       0,
	"sockets.candidate_uid":     10001,
	"sockets.owner_uid":         10002,
	"control.timeout":           "15s",
	"identity.mode":             IdentityDisabled,
	"limits.max_input_bytes":    1 << 20,
	"limits.max_transfer_bytes": 64 << 20,
	"limits.max_manifest_bytes": 16384,
	"limits.request_timeout":    "60s",
	"limits.upload_timeout":     "5m",
	"shutdown_timeout":          "20s",
}

// envOverrides is the complete set of accepted environment variables.
var envOverrides = map[string]string{
	"ANVILKIT_SIDECAR_CONTROL_ADDRESS": "control.address",
	"ANVILKIT_SIDECAR_IDENTITY_MODE":   "identity.mode",
	"ANVILKIT_SIDECAR_SOCKETS_DIR":     "sockets.dir",
	"ANVILKIT_SIDECAR_BACKEND":         "launch.backend",
	"ANVILKIT_SIDECAR_LAUNCH_KEY":      "launch.launch_key",
	"ANVILKIT_SIDECAR_POD_UID":         "launch.pod_uid",
	"ANVILKIT_SIDECAR_LAUNCH_ENVELOPE": "launch.envelope",
}

var launchKeyPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

func Load() (Config, error) {
	path := os.Getenv(EnvConfigFile)
	if path == "" {
		path = DefaultConfigFile
	}
	return LoadFrom(path, os.Environ())
}

// LoadFrom is Load with explicit inputs (tests).
func LoadFrom(path string, environ []string) (Config, error) {
	k := koanf.New(".")
	if err := k.Load(confmap.Provider(defaults, "."), nil); err != nil {
		return Config{}, err
	}
	if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
		return Config{}, fmt.Errorf("config file %s: %w", path, err)
	}
	for _, key := range []string{"launch.backend", "launch.launch_key", "launch.pod_uid", "launch.envelope"} {
		if k.Exists(key) {
			return Config{}, fmt.Errorf("config file %s: %s is a per-Job launch fact and is supplied only through the environment", path, key)
		}
	}
	if err := applyEnv(k, environ); err != nil {
		return Config{}, err
	}
	var c Config
	if err := k.UnmarshalWithConf("", &c, koanf.UnmarshalConf{DecoderConfig: &mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
		ErrorUnused:      true,
		WeaklyTypedInput: true,
		Result:           &c,
	}}); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	return c, c.validate()
}

func applyEnv(k *koanf.Koanf, environ []string) error {
	var unknown []string
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, envPrefix) || name == EnvConfigFile {
			continue
		}
		key, ok := envOverrides[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		if err := k.Set(key, value); err != nil {
			return err
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("config: environment variables are not allowed overrides: %s", strings.Join(unknown, ", "))
	}
	return nil
}

// Disabled reports whether the identity inputs keep the profile disabled:
// the process then exits instead of serving any route.
func (c Config) Disabled() bool { return c.Identity.Mode == IdentityDisabled }

func (c Config) validate() error {
	var errs []error
	s := c.Sockets
	if s.Dir == "" {
		errs = append(errs, errors.New("sockets.dir is required"))
	}
	if s.TrustedUID == s.CandidateUID || s.OwnerUID == s.TrustedUID || s.OwnerUID == s.CandidateUID {
		errs = append(errs, fmt.Errorf("sockets: trusted (%d), candidate (%d) and owner (%d) UIDs must differ", s.TrustedUID, s.CandidateUID, s.OwnerUID))
	}
	if s.CandidateUID == 0 || s.OwnerUID == 0 {
		errs = append(errs, errors.New("sockets: the candidate and owner UIDs must not be root"))
	}
	switch c.Identity.Mode {
	case IdentityDisabled:
	case IdentityDevelopment:
		if c.Control.Address == "" {
			errs = append(errs, errors.New("control.address is required unless identity.mode is disabled"))
		}
	case IdentityMTLS:
		if c.Control.Address == "" {
			errs = append(errs, errors.New("control.address is required unless identity.mode is disabled"))
		}
		m := c.Identity.MTLS
		if m.CertFile == "" || m.KeyFile == "" || m.CAFile == "" {
			errs = append(errs, errors.New("identity.mtls.cert_file, key_file and ca_file are required for identity.mode mtls"))
		}
	default:
		errs = append(errs, fmt.Errorf("identity.mode %q is not one of disabled, development, mtls", c.Identity.Mode))
	}
	if c.Control.Timeout < time.Second || c.Control.Timeout > 5*time.Minute {
		errs = append(errs, fmt.Errorf("control.timeout %s outside [1s, 5m]", c.Control.Timeout))
	}
	if !c.Disabled() {
		l := c.Launch
		if l.Backend == "" || len(l.Backend) > 64 {
			errs = append(errs, errors.New("ANVILKIT_SIDECAR_BACKEND (launch.backend) is required, at most 64 characters"))
		}
		if !launchKeyPattern.MatchString(l.LaunchKey) {
			errs = append(errs, errors.New("ANVILKIT_SIDECAR_LAUNCH_KEY (launch.launch_key) must be a DNS label"))
		}
		if l.PodUID == "" || len(l.PodUID) > 128 {
			errs = append(errs, errors.New("ANVILKIT_SIDECAR_POD_UID (launch.pod_uid, the downward API metadata.uid) is required"))
		}
		if l.Envelope == "" {
			errs = append(errs, errors.New("ANVILKIT_SIDECAR_LAUNCH_ENVELOPE (launch.envelope) is required"))
		} else if _, err := envelope.Parse([]byte(l.Envelope)); err != nil {
			errs = append(errs, fmt.Errorf("launch.envelope: %v", err))
		}
	}
	lim := c.Limits
	if lim.MaxInputBytes < 1 || lim.MaxInputBytes > 256<<20 {
		errs = append(errs, fmt.Errorf("limits.max_input_bytes %d outside [1, 256Mi]", lim.MaxInputBytes))
	}
	if lim.MaxTransferBytes < 1 || lim.MaxTransferBytes > 1<<30 {
		errs = append(errs, fmt.Errorf("limits.max_transfer_bytes %d outside [1, 1Gi]", lim.MaxTransferBytes))
	}
	if lim.MaxManifestBytes < 256 || lim.MaxManifestBytes > 16384 {
		errs = append(errs, fmt.Errorf("limits.max_manifest_bytes %d outside [256, 16384] (the contract bound)", lim.MaxManifestBytes))
	}
	within := func(name string, v, lo, hi time.Duration) {
		if v < lo || v > hi {
			errs = append(errs, fmt.Errorf("%s %s outside [%s, %s]", name, v, lo, hi))
		}
	}
	within("limits.request_timeout", lim.RequestTimeout, time.Second, 10*time.Minute)
	within("limits.upload_timeout", lim.UploadTimeout, time.Second, time.Hour)
	within("shutdown_timeout", c.ShutdownTimeout, time.Second, 5*time.Minute)
	return errors.Join(errs...)
}
