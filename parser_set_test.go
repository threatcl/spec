package spec

import (
	"strings"
	"testing"
)

func parseSkipExtendsTest(tb testing.TB, in string) (*ThreatmodelParser, error) {
	tb.Helper()

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)
	tmParser.SetSkipExtendsResolution(true)
	err := tmParser.ParseHCLRaw([]byte(in))
	return tmParser, err
}

func parseSetTest(tb testing.TB, inputs []NamedInput) (*ThreatmodelParser, error) {
	tb.Helper()

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)
	err := tmParser.ParseHCLRawSet(inputs)
	return tmParser, err
}

func setExtendsParent() string {
	return `threatmodel "App" {
  id     = "app"
  author = "@xntrik"

  threat "Break-in" {
    description = "Someone forces a door"
  }
}
`
}

func setExtendsChild() string {
	return `threatmodel "Frontend" {
  id      = "app.frontend"
  extends = "app"
  author  = "@xntrik"

  threat "XSS" {
    description = "Someone injects script"
  }
}
`
}

func TestSkipExtendsResolutionUnresolvedTarget(t *testing.T) {
	tmParser, err := parseSkipExtendsTest(t, setExtendsChild())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	tms := tmParser.GetWrapped().Threatmodels
	if len(tms) != 1 {
		t.Fatalf("expected one threat model, got %d", len(tms))
	}

	tm := &tms[0]
	if tm.Extends != "app" {
		t.Errorf("expected Extends to stay populated as 'app', got %q", tm.Extends)
	}
	if len(tm.Threats) != 1 || tm.Threats[0].Name != "XSS" {
		t.Errorf("expected only the file's own threat, got %+v", tm.Threats)
	}
}

func TestSkipExtendsResolutionNoInheritance(t *testing.T) {
	// Even with the extends target present in the parsed content, skip mode
	// must not materialize inherited entities.
	tmParser, err := parseSkipExtendsTest(t, extendsFixture())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	var child *Threatmodel
	for i := range tmParser.GetWrapped().Threatmodels {
		if tmParser.GetWrapped().Threatmodels[i].Id == "buildings.tower" {
			child = &tmParser.GetWrapped().Threatmodels[i]
		}
	}
	if child == nil {
		t.Fatal("child threat model not found")
	}

	if child.Extends != "buildings" {
		t.Errorf("expected Extends to stay populated as 'buildings', got %q", child.Extends)
	}
	if len(child.Threats) != 1 || child.Threats[0].Name != "Crown theft" {
		t.Errorf("expected only the child's own threat, got %+v", child.Threats)
	}
	if len(child.InformationAssets) != 0 {
		t.Errorf("expected no inherited information assets, got %+v", child.InformationAssets)
	}
	if child.Attributes != nil {
		t.Errorf("expected no inherited attributes block, got %+v", child.Attributes)
	}
}

func TestSkipExtendsResolutionStillValidates(t *testing.T) {
	cases := []struct {
		name string
		in   string
		exp  string
	}{
		{
			"duplicate_id",
			`threatmodel "A" {
  id     = "tower"
  author = "@xntrik"
}
threatmodel "B" {
  id     = "tower"
  author = "@xntrik"
}`,
			"duplicate id 'tower'",
		},
		{
			"invalid_id",
			`threatmodel "A" {
  id     = "Tower"
  author = "@xntrik"
}`,
			"invalid id 'Tower'",
		},
		{
			"reserved_segment",
			`threatmodel "A" {
  id     = "app"
  author = "@xntrik"
}
threatmodel "B" {
  id     = "app.threats"
  author = "@xntrik"
}`,
			"uses reserved segment 'threats'",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSkipExtendsTest(t, tc.in)
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tc.exp)
			}
			if !strings.Contains(err.Error(), tc.exp) {
				t.Errorf("expected error to contain %q, got: %s", tc.exp, err)
			}
		})
	}
}

func TestParseHCLRawSetExtends(t *testing.T) {
	parent := NamedInput{Name: "parent.hcl", Content: []byte(setExtendsParent())}
	child := NamedInput{Name: "child.hcl", Content: []byte(setExtendsChild())}

	cases := []struct {
		name   string
		inputs []NamedInput
	}{
		{"parent_first", []NamedInput{parent, child}},
		{"child_first", []NamedInput{child, parent}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmParser, err := parseSetTest(t, tc.inputs)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			var childTm *Threatmodel
			for i := range tmParser.GetWrapped().Threatmodels {
				if tmParser.GetWrapped().Threatmodels[i].Id == "app.frontend" {
					childTm = &tmParser.GetWrapped().Threatmodels[i]
				}
			}
			if childTm == nil {
				t.Fatal("child threat model not found")
			}

			if len(childTm.Threats) != 2 {
				t.Fatalf("expected the child's own threat plus the inherited one, got %d", len(childTm.Threats))
			}
			foundInherited := false
			for _, th := range childTm.Threats {
				if th.Name == "Break-in" {
					foundInherited = true
				}
			}
			if !foundInherited {
				t.Errorf("expected inherited threat 'Break-in' on the child")
			}
		})
	}
}

func TestParseHCLRawSetErrors(t *testing.T) {
	cases := []struct {
		name   string
		inputs []NamedInput
		exp    string
	}{
		{
			"unknown_extends_target",
			[]NamedInput{
				{Name: "child.hcl", Content: []byte(setExtendsChild())},
				{Name: "other.hcl", Content: []byte(`threatmodel "Other" {
  id     = "other"
  author = "@xntrik"
}`)},
			},
			"extends references unknown threat model id 'app'",
		},
		{
			"cross_input_cycle",
			[]NamedInput{
				{Name: "a.hcl", Content: []byte(`threatmodel "A" {
  id      = "a"
  extends = "b"
  author  = "@xntrik"
}`)},
				{Name: "b.hcl", Content: []byte(`threatmodel "B" {
  id      = "b"
  extends = "a"
  author  = "@xntrik"
}`)},
			},
			"extends cycle",
		},
		{
			"duplicate_names_across_inputs",
			[]NamedInput{
				{Name: "one.hcl", Content: []byte(`threatmodel "App" {
  author = "@xntrik"
}`)},
				{Name: "two.hcl", Content: []byte(`threatmodel "App" {
  author = "@xntrik"
}`)},
			},
			"TM 'App': duplicate found",
		},
		{
			"duplicate_ids_across_inputs",
			[]NamedInput{
				{Name: "one.hcl", Content: []byte(`threatmodel "App" {
  id     = "app"
  author = "@xntrik"
}`)},
				{Name: "two.hcl", Content: []byte(`threatmodel "Also App" {
  id     = "app"
  author = "@xntrik"
}`)},
			},
			"duplicate id 'app'",
		},
		{
			"reserved_segment_across_inputs",
			[]NamedInput{
				{Name: "parent.hcl", Content: []byte(`threatmodel "App" {
  id     = "app"
  author = "@xntrik"
}`)},
				{Name: "child.hcl", Content: []byte(`threatmodel "Threats" {
  id     = "app.threats"
  author = "@xntrik"
}`)},
			},
			"uses reserved segment 'threats'",
		},
		{
			"two_backends_in_one_input",
			[]NamedInput{
				{Name: "two-backends.hcl", Content: []byte(`backend "one" {
  organization = "org_one"
}
backend "two" {
  organization = "org_two"
}
threatmodel "App" {
  author = "@xntrik"
}`)},
			},
			"input 'two-backends.hcl': only one backend block is allowed per input, found 2",
		},
		{
			"decode_error_names_input",
			[]NamedInput{
				{Name: "good.hcl", Content: []byte(setExtendsParent())},
				{Name: "bad.hcl", Content: []byte(`threatmodel "Bad" {
  author  = "@xntrik"
  no_such = "attribute"
}`)},
			},
			"bad.hcl",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSetTest(t, tc.inputs)
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tc.exp)
			}
			if !strings.Contains(err.Error(), tc.exp) {
				t.Errorf("expected error to contain %q, got: %s", tc.exp, err)
			}
		})
	}
}

func TestParseHCLRawSetBackends(t *testing.T) {
	tmParser, err := parseSetTest(t, []NamedInput{
		{Name: "one.hcl", Content: []byte(`backend "threatcl-cloud" {
  organization = "org_one"
}
threatmodel "App" {
  id     = "app"
  author = "@xntrik"
}`)},
		{Name: "two.hcl", Content: []byte(`backend "threatcl-cloud" {
  organization = "org_two"
}
threatmodel "Frontend" {
  id     = "app.frontend"
  author = "@xntrik"
}`)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	backends := tmParser.GetWrapped().Backends
	if len(backends) != 2 {
		t.Fatalf("expected both inputs' backends on the wrapped set, got %d", len(backends))
	}
	if backends[0].BackendOrg != "org_one" || backends[1].BackendOrg != "org_two" {
		t.Errorf("expected backends in input order, got %+v and %+v", backends[0], backends[1])
	}
}

func TestParseHCLRawSetPerInputVars(t *testing.T) {
	// Each input is treated as its own top-level file: variables declared in
	// one input resolve there and don't leak into (or depend on) another.
	tmParser, err := parseSetTest(t, []NamedInput{
		{Name: "one.hcl", Content: []byte(`variable "descr" {
  value = "from input one"
}
threatmodel "One" {
  author      = "@xntrik"
  description = var.descr
}`)},
		{Name: "two.hcl", Content: []byte(`variable "descr" {
  value = "from input two"
}
threatmodel "Two" {
  author      = "@xntrik"
  description = var.descr
}`)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	tms := tmParser.GetWrapped().Threatmodels
	if len(tms) != 2 {
		t.Fatalf("expected two threat models, got %d", len(tms))
	}
	if tms[0].Description != "from input one" {
		t.Errorf("expected input one's variable value, got %q", tms[0].Description)
	}
	if tms[1].Description != "from input two" {
		t.Errorf("expected input two's variable value, got %q", tms[1].Description)
	}
}

func TestParseHCLRawSetSingleInputMatchesRaw(t *testing.T) {
	rawParser, err := parseExtendsTest(t, extendsFixture())
	if err != nil {
		t.Fatalf("unexpected error from ParseHCLRaw: %s", err)
	}

	setParser, err := parseSetTest(t, []NamedInput{
		{Name: "fixture.hcl", Content: []byte(extendsFixture())},
	})
	if err != nil {
		t.Fatalf("unexpected error from ParseHCLRawSet: %s", err)
	}

	rawTms := rawParser.GetWrapped().Threatmodels
	setTms := setParser.GetWrapped().Threatmodels
	if len(setTms) != len(rawTms) {
		t.Fatalf("expected %d threat models, got %d", len(rawTms), len(setTms))
	}
	for i := range rawTms {
		if len(setTms[i].Threats) != len(rawTms[i].Threats) {
			t.Errorf("TM %q: expected %d threats, got %d",
				rawTms[i].Name, len(rawTms[i].Threats), len(setTms[i].Threats))
		}
	}
}
