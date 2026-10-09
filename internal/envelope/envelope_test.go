package envelope

import (
	"strings"
	"testing"
)

const base = `{"schemaVersion":1,"launchId":"lch_1","launchKey":"val-1","operationId":"op_1","attemptId":"att_1","profileId":"validator-source-dev-v1","profileRevision":"1","jobKind":"validator","executionEpoch":"1","launchEpoch":"1","deadline":"2026-10-08T12:00:00Z",%s"inputs":[{"name":"source","digest":"sha256:5555555555555555555555555555555555555555555555555555555555555555","handle":"h"}]}`

func envelopeWith(component string) []byte {
	return []byte(strings.Replace(base, "%s", component, 1))
}

// P0.8: the allocated identity rides in the envelope; the sidecar accepts a
// well-formed one, refuses a malformed one and still refuses unknown fields.
func TestComponentIdentity(t *testing.T) {
	e, err := Parse(envelopeWith(`"component":{"componentId":"cmp_hero_fixed","puckType":"Hero","packageName":"@anvilkit/hero-fixed","sourceRevision":"7"},`))
	if err != nil {
		t.Fatal(err)
	}
	if e.Component == nil || e.Component.PuckType != "Hero" || e.Component.SourceRevision != "7" {
		t.Fatalf("component not carried: %+v", e.Component)
	}
	if _, err := Parse(envelopeWith("")); err != nil {
		t.Fatalf("an envelope without a component: %v", err)
	}
	// A preview or release launch names the revision alone.
	if e, err := Parse(envelopeWith(`"component":{"sourceRevision":"4"},`)); err != nil || e.Component.SourceRevision != "4" || e.Component.PuckType != "" {
		t.Fatalf("a revision-only component: %+v %v", e.Component, err)
	}
	for name, c := range map[string]string{
		"lower-case puckType":    `"component":{"componentId":"cmp_x","puckType":"hero","packageName":"p","sourceRevision":"1"},`,
		"empty package":          `"component":{"componentId":"cmp_x","puckType":"Hero","packageName":"","sourceRevision":"1"},`,
		"non-canonical revision": `"component":{"componentId":"cmp_x","puckType":"Hero","packageName":"p","sourceRevision":"01"},`,
		"unknown component key":  `"component":{"componentId":"cmp_x","puckType":"Hero","packageName":"p","sourceRevision":"1","owner":"x"},`,
		"unknown envelope key":   `"owner":"x",`,
		"no revision":            `"component":{"componentId":"cmp_x","puckType":"Hero","packageName":"p"},`,
		"partial identity":       `"component":{"puckType":"Hero","sourceRevision":"1"},`,
	} {
		if _, err := Parse(envelopeWith(c)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
