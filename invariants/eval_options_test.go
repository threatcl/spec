package invariants

import (
	"strings"
	"testing"

	"github.com/threatcl/spec"
)

func evalRawOpts(tb testing.TB, src string, models []*Model, opts ...EvaluateOption) (*Report, error) {
	tb.Helper()
	invs := mustParseRaw(tb, src)
	return Evaluate(invs, models, opts...)
}

const danglingExemptionSrc = `
invariant "impossible" {
  target    = "threatmodel"
  condition = false

  exemption {
    model         = threatmodel["Another Model"]
    justification = "Not in this run"
  }
}
`

func TestEvaluateLenientExemptionsDanglingReference(t *testing.T) {
	// The same file that is a hard error by default (see
	// TestEvaluateExemptionDanglingReference) resolves to an inactive
	// exemption when the caller is only evaluating a subset of the fleet.
	report, err := evalRawOpts(t, danglingExemptionSrc, testModels(), WithLenientExemptions())
	if err != nil {
		t.Fatalf("unexpected error with lenient exemptions: %s", err)
	}

	if len(report.Exemptions) != 0 {
		t.Errorf("expected no active exemptions, got %d", len(report.Exemptions))
	}
	if len(report.InactiveExemptions) != 1 {
		t.Fatalf("expected 1 inactive exemption, got %d", len(report.InactiveExemptions))
	}

	inactive := report.InactiveExemptions[0]
	if inactive.Invariant == nil || inactive.Invariant.Name != "impossible" {
		t.Errorf("expected the inactive exemption to carry its invariant, got %+v", inactive.Invariant)
	}
	if exp := `threatmodel["Another Model"]`; inactive.Reference != exp {
		t.Errorf("expected reference %q, got %q", exp, inactive.Reference)
	}
	if inactive.Justification != "Not in this run" {
		t.Errorf("unexpected justification: %q", inactive.Justification)
	}
	if strings.TrimSpace(inactive.Reason) == "" {
		t.Errorf("expected a non-empty reason for an unresolvable reference")
	}

	// The invariant still applies to the models that *are* present.
	if len(report.Violations) != 1 {
		t.Fatalf("expected the present model to still be evaluated, got %d violations", len(report.Violations))
	}
	if report.Violations[0].Model.TM.Name != "Test Model" {
		t.Errorf("unexpected violating model: %q", report.Violations[0].Model.TM.Name)
	}
}

func TestEvaluateExemptionTryNullRecordedInBothModes(t *testing.T) {
	// try(..., null) is inactive by design in either mode — but it's recorded
	// now, so a caller can tell "waived nothing" from "was never written".
	src := `
invariant "impossible" {
  target    = "threatmodel"
  condition = false

  exemption {
    model         = try(threatmodel["Another Model"], null)
    justification = "Only applies in the fleet that has this model"
  }
}
`

	cases := []struct {
		name string
		opts []EvaluateOption
	}{
		{"strict", nil},
		{"lenient", []EvaluateOption{WithLenientExemptions()}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := evalRawOpts(t, src, testModels(), tc.opts...)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if len(report.Exemptions) != 0 {
				t.Errorf("expected no active exemptions, got %d", len(report.Exemptions))
			}
			if len(report.InactiveExemptions) != 1 {
				t.Fatalf("expected 1 inactive exemption, got %d", len(report.InactiveExemptions))
			}
			if exp := "resolved to null"; report.InactiveExemptions[0].Reason != exp {
				t.Errorf("expected reason %q, got %q", exp, report.InactiveExemptions[0].Reason)
			}
			if exp := `try(threatmodel["Another Model"], null)`; report.InactiveExemptions[0].Reference != exp {
				t.Errorf("expected reference %q, got %q", exp, report.InactiveExemptions[0].Reference)
			}
			if len(report.Violations) != 1 {
				t.Errorf("expected 1 violation when the exemption is inactive, got %d", len(report.Violations))
			}
		})
	}
}

func TestEvaluateActiveExemptionNotRecordedInactive(t *testing.T) {
	src := `
invariant "impossible" {
  target    = "threatmodel"
  condition = false

  exemption {
    model         = threatmodel["Test Model"]
    justification = "Known exception; tracked in SEC-1"
  }
}
`

	for _, opts := range [][]EvaluateOption{nil, {WithLenientExemptions()}} {
		report, err := evalRawOpts(t, src, testModels(), opts...)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if len(report.Exemptions) != 1 {
			t.Errorf("expected 1 active exemption, got %d", len(report.Exemptions))
		}
		if len(report.InactiveExemptions) != 0 {
			t.Errorf("expected an active exemption not to be recorded inactive, got %d", len(report.InactiveExemptions))
		}
	}
}

func TestEvaluateLenientExemptionsKeepsHardErrors(t *testing.T) {
	// Lenient is about which models are in scope, not about accepting a
	// malformed invariants file or an unaddressable set of models.
	cases := []struct {
		name   string
		src    string
		models []*Model
		exp    string
	}{
		{
			"non_model_reference",
			`invariant "impossible" {
  target    = "threatmodel"
  condition = false

  exemption {
    model         = threatmodel["Test Model"].author
    justification = "A field, not a model"
  }
}`,
			testModels(),
			"must reference a threat model",
		},
		{
			"registry_error",
			`invariant "anything" {
  target    = "threatmodel"
  condition = true
}`,
			[]*Model{
				{TM: &spec.Threatmodel{Name: "My App", Author: "@x"}, File: "a.hcl"},
				{TM: &spec.Threatmodel{Name: "my app", Author: "@x"}, File: "b.hcl"},
			},
			"collides",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := evalRawOpts(t, tc.src, tc.models, WithLenientExemptions())
			if err == nil {
				t.Fatalf("expected an error containing %q even with lenient exemptions, got none", tc.exp)
			}
			if !strings.Contains(err.Error(), tc.exp) {
				t.Errorf("expected error to contain %q, got: %s", tc.exp, err)
			}
		})
	}
}

func TestExemptionReferenceSourceText(t *testing.T) {
	invs := mustParseRaw(t, `
invariant "x" {
  target    = "threatmodel"
  condition = false

  exemption {
    model         = threatmodel["Legacy Public API"]
    justification = "index syntax"
  }

  exemption {
    model         = threatmodel.buildings.tower
    justification = "dotted address"
  }

  exemption {
    model         = try(threatmodel["Other Fleet"], null)
    justification = "wrapped"
  }
}
`)

	if len(invs) != 1 {
		t.Fatalf("expected 1 invariant, got %d", len(invs))
	}
	exp := []string{
		`threatmodel["Legacy Public API"]`,
		`threatmodel.buildings.tower`,
		`try(threatmodel["Other Fleet"], null)`,
	}
	if len(invs[0].Exemptions) != len(exp) {
		t.Fatalf("expected %d exemptions, got %d", len(exp), len(invs[0].Exemptions))
	}
	for i, want := range exp {
		if got := invs[0].Exemptions[i].Reference; got != want {
			t.Errorf("exemption %d: expected reference %q, got %q", i+1, want, got)
		}
	}
}
