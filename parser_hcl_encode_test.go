package spec

import (
	"strings"
	"testing"
)

// reparse renders the parser's wrapped state to HCL, parses it back into a
// fresh parser, and returns the new parser.
func reparse(t *testing.T, p *ThreatmodelParser) *ThreatmodelParser {
	t.Helper()
	out := p.HclString()
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p2 := NewThreatmodelParser(cfg)
	if err := p2.ParseHCLRaw([]byte(out)); err != nil {
		t.Fatalf("round-trip parse failed:\n--- HCL ---\n%s\n--- ERR ---\n%s", out, err)
	}
	return p2
}

func TestRoundTripControlBlock(t *testing.T) {
	src := `spec_version = "` + Version + `"

threatmodel "Repro" {
  author = "tester"
  threat "SQLi" {
    description = "Local SQL injection"
    impacts = ["Confidentiality"]
    control "Parameterized Queries" {
      description = "Use prepared statements"
      implemented = true
      risk_reduction = 90
    }
  }
}
`
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	if err := p.ParseHCLRaw([]byte(src)); err != nil {
		t.Fatalf("initial parse failed: %s", err)
	}

	out := p.HclString()
	if !strings.Contains(out, `control "Parameterized Queries"`) {
		t.Errorf("expected proper block syntax, got:\n%s", out)
	}
	if strings.Contains(out, "control = [") {
		t.Errorf("output still uses list-of-objects encoding:\n%s", out)
	}

	p2 := reparse(t, p)
	tm := p2.GetWrapped().Threatmodels[0]
	if len(tm.Threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(tm.Threats))
	}
	th := tm.Threats[0]
	if len(th.Controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(th.Controls))
	}
	c := th.Controls[0]
	if c.Name != "Parameterized Queries" {
		t.Errorf("control name = %q, want %q", c.Name, "Parameterized Queries")
	}
	if !c.Implemented {
		t.Errorf("control.Implemented = false, want true")
	}
	if c.RiskReduction != 90 {
		t.Errorf("control.RiskReduction = %d, want 90", c.RiskReduction)
	}
	if c.Description != "Use prepared statements" {
		t.Errorf("control.Description = %q", c.Description)
	}
}

func TestRoundTripNoNoise(t *testing.T) {
	src := `spec_version = "` + Version + `"
threatmodel "minimal" {
  author = "x"
}
`
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	if err := p.ParseHCLRaw([]byte(src)); err != nil {
		t.Fatalf("parse failed: %s", err)
	}

	out := p.HclString()
	for _, banned := range []string{
		"imports",
		"created_at",
		"updated_at",
		"= null",
		"stride",
		"information_asset_refs",
		"control_imports",
		"expanded_control",
	} {
		if strings.Contains(out, banned) {
			t.Errorf("output contains unwanted token %q:\n%s", banned, out)
		}
	}
	if !strings.Contains(out, `threatmodel "minimal"`) {
		t.Errorf("missing threatmodel block:\n%s", out)
	}
	if !strings.Contains(out, `author = "x"`) {
		t.Errorf("missing author attribute:\n%s", out)
	}
}

func TestRoundTripAllBlockTypes(t *testing.T) {
	src := `spec_version = "` + Version + `"

backend "primary" {
  organization = "acme"
  threatmodel = "tm-main"
  project = "core"
}

component "control" "shared_auth" {
  description = "Shared auth control"
  implemented = true
  risk_reduction = 50
}

variable "env" {
  value = "prod"
}

threatmodel "full" {
  author = "@me"
  description = "everything"

  attributes {
    new_initiative = true
    internet_facing = false
    initiative_size = "small"
  }

  additional_attribute "segment" {
    value = "dmz"
  }

  information_asset "creds" {
    description = "stored credentials"
    information_classification = "Restricted"
  }

  usecase {
    description = "users do things"
  }

  exclusion {
    description = "out of scope: kernel bugs"
  }

  third_party_dependency "IdP" {
    description = "external idp"
    uptime_dependency = "degraded"
  }

  threat "t1" {
    description = "t1 description"
    impacts = ["Confidentiality"]

    proposed_control {
      description = "do thing"
      implemented = true
    }

    control "c1" {
      description = "c1 desc"
      implemented = true
      risk_reduction = 80
      attribute "owner" {
        value = "team-a"
      }
    }
  }

  data_flow_diagram_v2 "dfd1" {
    process "p1" {}
    external_element "user" {}
    data_store "db" {
      information_asset = "creds"
    }
    flow "https" {
      from = "user"
      to = "p1"
    }
    trust_zone "secure" {
      process "p2" {}
    }
  }
}

threatmodel "legacy_dfd_owner" {
  author = "@me"

  data_flow_diagram {
    process "lp" {}
    external_element "lext" {}
    flow "tcp" {
      from = "lext"
      to = "lp"
    }
  }
}
`
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	if err := p.ParseHCLRaw([]byte(src)); err != nil {
		t.Fatalf("initial parse failed: %s", err)
	}

	p2 := reparse(t, p)
	w := p2.GetWrapped()

	if len(w.Backends) != 1 || w.Backends[0].BackendOrg != "acme" {
		t.Errorf("backend lost: %+v", w.Backends)
	}
	if len(w.Components) != 1 || w.Components[0].ComponentName != "shared_auth" {
		t.Errorf("component lost: %+v", w.Components)
	}
	if len(w.Variables) != 1 || w.Variables[0].VariableValue != "prod" {
		t.Errorf("variable lost: %+v", w.Variables)
	}
	if len(w.Threatmodels) != 2 {
		t.Fatalf("expected 2 threatmodels, got %d", len(w.Threatmodels))
	}

	tm := w.Threatmodels[0]
	if tm.Attributes == nil || !strings.EqualFold(tm.Attributes.InitiativeSize, "small") {
		t.Errorf("attributes block lost: %+v", tm.Attributes)
	}
	if len(tm.AdditionalAttributes) != 1 || tm.AdditionalAttributes[0].Value != "dmz" {
		t.Errorf("additional_attribute lost: %+v", tm.AdditionalAttributes)
	}
	if len(tm.InformationAssets) != 1 || tm.InformationAssets[0].Name != "creds" {
		t.Errorf("information_asset lost: %+v", tm.InformationAssets)
	}
	if len(tm.UseCases) != 1 {
		t.Errorf("usecase lost: %+v", tm.UseCases)
	}
	if len(tm.Exclusions) != 1 {
		t.Errorf("exclusion lost: %+v", tm.Exclusions)
	}
	if len(tm.ThirdPartyDependencies) != 1 || tm.ThirdPartyDependencies[0].Name != "IdP" {
		t.Errorf("third_party_dependency lost: %+v", tm.ThirdPartyDependencies)
	}
	if len(tm.Threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(tm.Threats))
	}
	threat := tm.Threats[0]
	if len(threat.ProposedControls) != 1 || !threat.ProposedControls[0].Implemented {
		t.Errorf("proposed_control lost: %+v", threat.ProposedControls)
	}
	if len(threat.Controls) != 1 || threat.Controls[0].Name != "c1" {
		t.Fatalf("control lost: %+v", threat.Controls)
	}
	if len(threat.Controls[0].Attributes) != 1 || threat.Controls[0].Attributes[0].Name != "owner" {
		t.Errorf("control attribute lost: %+v", threat.Controls[0].Attributes)
	}
	if len(tm.DataFlowDiagrams) != 1 {
		t.Fatalf("data_flow_diagram_v2 lost: %+v", tm.DataFlowDiagrams)
	}
	dfd := tm.DataFlowDiagrams[0]
	if len(dfd.Processes) != 1 || len(dfd.ExternalElements) != 1 ||
		len(dfd.DataStores) != 1 || len(dfd.Flows) != 1 || len(dfd.TrustZones) != 1 {
		t.Errorf("dfd children lost: %+v", dfd)
	}
	if len(dfd.TrustZones[0].Processes) != 1 {
		t.Errorf("trust_zone nested process lost: %+v", dfd.TrustZones[0])
	}

	tm2 := w.Threatmodels[1]
	// The legacy data_flow_diagram block gets shifted into DataFlowDiagrams
	// at parse time (see shiftLegacyDfd), so check the shifted form rather
	// than LegacyDfd which is cleared after the shift.
	if len(tm2.DataFlowDiagrams) != 1 {
		t.Fatalf("legacy dfd not shifted: %+v", tm2)
	}
	ldfd := tm2.DataFlowDiagrams[0]
	if len(ldfd.Processes) != 1 || len(ldfd.ExternalElements) != 1 || len(ldfd.Flows) != 1 {
		t.Errorf("legacy dfd children lost: %+v", ldfd)
	}
}

func TestRoundTripStableEncoding(t *testing.T) {
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	if err := p.ParseHCLRaw([]byte(tmTestValid)); err != nil {
		t.Fatalf("initial parse failed: %s", err)
	}

	first := p.HclString()
	p2 := reparse(t, p)
	second := p2.HclString()
	if first != second {
		t.Errorf("encoding is not stable across round-trips\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestRoundTripExistingFixture(t *testing.T) {
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	if err := p.ParseFile("./testdata/tm1.hcl", false); err != nil {
		t.Fatalf("initial parse failed: %s", err)
	}

	first := p.HclString()
	cfg2 := &ThreatmodelSpecConfig{}
	cfg2.setDefaults()
	p2 := NewThreatmodelParser(cfg2)
	if err := p2.ParseHCLRaw([]byte(first)); err != nil {
		t.Fatalf("round-trip parse failed:\n%s\n--- err ---\n%s", first, err)
	}
	second := p2.HclString()
	if first != second {
		t.Errorf("tm1.hcl encoding is not stable across round-trips")
	}
}
