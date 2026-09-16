// Package envelope reads the typed launch envelope of the jobs contract
// (contracts/jobs job.schema.json#/$defs/launchEnvelope) with a strict,
// structural check. The sidecar deliberately does not link the contracts'
// jobschema package: that package embeds profiles.json, which records this
// sidecar's own image digest, and an image whose bytes depend on its own
// digest can never be pinned. Control validates every manifest and profile
// against the schema itself.
package envelope

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

var (
	idPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	sequencePattern  = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)
	launchKeyPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	inputNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	jobKinds         = map[string]bool{"codegen": true, "validator": true, "preview": true, "parser": true, "migration": true}
)

// Input is one typed input: a name bound to a digest and, optionally, an
// opaque handle.
type Input struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Handle string `json:"handle,omitempty"`
}

// Envelope is the launch envelope.
type Envelope struct {
	SchemaVersion   int     `json:"schemaVersion"`
	LaunchID        string  `json:"launchId"`
	LaunchKey       string  `json:"launchKey"`
	OperationID     string  `json:"operationId"`
	AttemptID       string  `json:"attemptId"`
	ProfileID       string  `json:"profileId"`
	ProfileRevision string  `json:"profileRevision"`
	JobKind         string  `json:"jobKind"`
	ExecutionEpoch  string  `json:"executionEpoch"`
	LaunchEpoch     string  `json:"launchEpoch"`
	Deadline        string  `json:"deadline"`
	Inputs          []Input `json:"inputs"`
}

// Parse decodes and checks an envelope; unknown fields are refused.
func Parse(raw []byte) (Envelope, error) {
	var e Envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Envelope{}, fmt.Errorf("launch envelope: %v", err)
	}
	if dec.More() {
		return Envelope{}, fmt.Errorf("launch envelope: trailing data")
	}
	if e.SchemaVersion != 1 {
		return Envelope{}, fmt.Errorf("launch envelope: schemaVersion %d is not 1", e.SchemaVersion)
	}
	for name, v := range map[string]string{"launchId": e.LaunchID, "operationId": e.OperationID, "attemptId": e.AttemptID, "profileId": e.ProfileID} {
		if len(v) == 0 || len(v) > 128 || !idPattern.MatchString(v) {
			return Envelope{}, fmt.Errorf("launch envelope: %s %q is not an id", name, v)
		}
	}
	if !launchKeyPattern.MatchString(e.LaunchKey) {
		return Envelope{}, fmt.Errorf("launch envelope: launchKey %q is not a DNS label", e.LaunchKey)
	}
	for name, v := range map[string]string{"profileRevision": e.ProfileRevision, "executionEpoch": e.ExecutionEpoch, "launchEpoch": e.LaunchEpoch} {
		if !sequencePattern.MatchString(v) {
			return Envelope{}, fmt.Errorf("launch envelope: %s %q is not a sequence", name, v)
		}
	}
	if !jobKinds[e.JobKind] {
		return Envelope{}, fmt.Errorf("launch envelope: jobKind %q unknown", e.JobKind)
	}
	if _, err := e.DeadlineTime(); err != nil {
		return Envelope{}, err
	}
	if len(e.Inputs) > 64 {
		return Envelope{}, fmt.Errorf("launch envelope: more than 64 inputs")
	}
	seen := map[string]bool{}
	for _, in := range e.Inputs {
		if !inputNamePattern.MatchString(in.Name) || !digestPattern.MatchString(in.Digest) || len(in.Handle) > 256 || seen[in.Name] {
			return Envelope{}, fmt.Errorf("launch envelope: input %q is not a typed input", in.Name)
		}
		seen[in.Name] = true
	}
	return e, nil
}

// DeadlineTime parses the RFC 3339 UTC deadline.
func (e Envelope) DeadlineTime() (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, e.Deadline)
	if err != nil || t.Location() != time.UTC {
		return time.Time{}, fmt.Errorf("launch envelope: deadline %q is not an RFC 3339 UTC timestamp", e.Deadline)
	}
	return t, nil
}
