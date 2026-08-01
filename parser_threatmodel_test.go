package spec

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseHCLFileWithIncluding(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app.hcl", false)

	// t.Logf("out1: '%s', out2: '%s'", out1, out2)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundIncludeduc := false
	foundSelfuc := false

	foundOverwrittenIa := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		t.Logf("tm: '%s'", tm.Name)
		if tm.Name == "Tower of London" {
			for _, uc := range tm.UseCases {
				if strings.Contains(uc.Description, "fetch the crown") {
					foundIncludeduc = true
				}

				if strings.Contains(uc.Description, "another uc perhaps") {
					foundSelfuc = true
				}
			}

			for _, ia := range tm.InformationAssets {
				if strings.Contains(ia.Description, "I should be overriden") {
					foundOverwrittenIa = true
				}

			}
		}
	}

	if !foundSelfuc {
		t.Errorf("We didn't find our own use case")
	}

	if !foundIncludeduc {
		t.Errorf("We didn't find our included use case")
	}

	if foundOverwrittenIa {
		t.Errorf("We found an IA that should have been overwritten")
	}

}

func TestParseHCLFileWithIncludingRemote(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	defaultCfg.AllowRemoteImports = true
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app-remote.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundOverwrittenIa := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		if tm.Name == "Tower of London" {
			for _, ia := range tm.InformationAssets {
				if strings.Contains(ia.Name, "crown jewels") {
					foundOverwrittenIa = true
				}
			}
		}
	}

	if !foundOverwrittenIa {
		t.Errorf("We didn't find an IA that should have been overwritten")
	}

}

func TestParseHCLFileWithIncludingRemoteGit(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	defaultCfg.AllowRemoteImports = true
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app-remote2.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundOverwrittenIa := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		if tm.Name == "Tower of London" {
			for _, ia := range tm.InformationAssets {
				if strings.Contains(ia.Name, "crown jewels") {
					foundOverwrittenIa = true
				}
			}
		}
	}

	if !foundOverwrittenIa {
		t.Errorf("We didn't find an IA that should have been overwritten")
	}

}

func TestRemoteImportDisabledByDefault(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	// AllowRemoteImports defaults to false; a remote `including` must be
	// rejected before any network fetch happens.
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app-remote.hcl", false)
	if err == nil {
		t.Fatalf("expected remote import to be rejected when allow_remote_imports is false")
	}

	if !strings.Contains(err.Error(), "allow_remote_imports") {
		t.Errorf("expected error to mention allow_remote_imports, got: %s", err)
	}
}

func TestIsRemoteSource(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		{"shared/tower.hcl", false},
		{"tower.hcl", false},
		{"file:///etc/passwd", false},
		{"https://example.com/tower.hcl", true},
		{"http://169.254.169.254/latest/meta-data/", true},
		{"git::https://github.com/threatcl/spec.git", true},
		{"github.com/threatcl/spec", true},
	}

	for _, tc := range cases {
		got, err := isRemoteSource(tc.src, "/tmp")
		if err != nil {
			t.Errorf("isRemoteSource(%q) unexpected error: %s", tc.src, err)
			continue
		}
		if got != tc.want {
			t.Errorf("isRemoteSource(%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

func TestEnsureLocalSourceContained(t *testing.T) {
	base := "/home/user/models"

	allowed := []string{
		"tower.hcl",
		"shared/tower.hcl",
		"./shared/tower.hcl",
	}
	for _, src := range allowed {
		if err := ensureLocalSourceContained(base, src); err != nil {
			t.Errorf("ensureLocalSourceContained(%q) = %v, want nil", src, err)
		}
	}

	blocked := []string{
		"../../../etc/passwd",
		"file:///etc/passwd",
		"/etc/passwd",
		"shared/../../secrets.hcl",
	}
	for _, src := range blocked {
		if err := ensureLocalSourceContained(base, src); err == nil {
			t.Errorf("ensureLocalSourceContained(%q) = nil, want error", src)
		}
	}
}

func TestEnsureWithin(t *testing.T) {
	base := "/tmp/hcltm123/nest"

	if err := ensureWithin(base, base+"/tower.hcl"); err != nil {
		t.Errorf("ensureWithin in-tree = %v, want nil", err)
	}
	if err := ensureWithin(base, base+"/sub/dir/tower.hcl"); err != nil {
		t.Errorf("ensureWithin nested in-tree = %v, want nil", err)
	}

	// The "repo|../../etc/passwd" traversal form must be rejected.
	if err := ensureWithin(base, base+"/../../../../etc/passwd"); err == nil {
		t.Errorf("ensureWithin traversal = nil, want error")
	}
}

func TestParseHCLFileWithIncludingTooMany(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app2.hcl", false)

	if err == nil {
		t.Errorf("We should have gotten an error")
	}

	if !strings.Contains(err.Error(), "incorrect number of threat models. Expected 1 but got 2") {
		t.Errorf("We should have an error about too many models")
	}
}

func TestTmaddcovIncludeMergesAndDedups(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/tmaddcov-parent.hcl", false)

	if err != nil {
		t.Fatalf("Error parsing legit TM file: %s", err)
	}

	var tm *Threatmodel
	for i, candidate := range tmParser.GetWrapped().Threatmodels {
		if candidate.Name == "Coverage Castle" {
			tm = &tmParser.GetWrapped().Threatmodels[i]
		}
	}

	if tm == nil {
		t.Fatalf("We didn't find the parent threat model")
	}

	// Use cases: the parent's "shared use case" should suppress the
	// included duplicate, while "included-only use case" is merged in
	if len(tm.UseCases) != 2 {
		t.Errorf("Expected 2 use cases but got %d", len(tm.UseCases))
	}

	foundIncludedOnlyUc := false
	for _, uc := range tm.UseCases {
		if uc.Description == "included-only use case" {
			foundIncludedOnlyUc = true
		}
	}

	if !foundIncludedOnlyUc {
		t.Errorf("We didn't find the included-only use case")
	}

	// Exclusions: same dedup-by-description behaviour
	if len(tm.Exclusions) != 2 {
		t.Errorf("Expected 2 exclusions but got %d", len(tm.Exclusions))
	}

	foundIncludedOnlyExcl := false
	for _, excl := range tm.Exclusions {
		if excl.Description == "included-only exclusion" {
			foundIncludedOnlyExcl = true
		}
	}

	if !foundIncludedOnlyExcl {
		t.Errorf("We didn't find the included-only exclusion")
	}

	// Third party dependencies: dedup by name, keeping the parent's copy
	if len(tm.ThirdPartyDependencies) != 2 {
		t.Errorf("Expected 2 third party dependencies but got %d", len(tm.ThirdPartyDependencies))
	}

	for _, tpd := range tm.ThirdPartyDependencies {
		if tpd.Name == "shared tpd" && !strings.Contains(tpd.Description, "parent copy") {
			t.Errorf("The parent's 'shared tpd' should not have been overwritten")
		}
	}

	// DFDs: dedup by name, keeping the parent's copy
	if len(tm.DataFlowDiagrams) != 2 {
		t.Errorf("Expected 2 data flow diagrams but got %d", len(tm.DataFlowDiagrams))
	}

	foundIncludedDfd := false
	for _, dfd := range tm.DataFlowDiagrams {
		if dfd.Name == "included dfd" {
			foundIncludedDfd = true
		}

		if dfd.Name == "shared dfd" {
			if len(dfd.Processes) != 1 || dfd.Processes[0].Name != "parent proc" {
				t.Errorf("The parent's 'shared dfd' should not have been overwritten")
			}
		}
	}

	if !foundIncludedDfd {
		t.Errorf("We didn't find the included-only dfd")
	}

	// Mermaid diagrams: dedup by name, keeping the parent's copy
	if len(tm.MermaidDiagrams) != 2 {
		t.Errorf("Expected 2 mermaid diagrams but got %d", len(tm.MermaidDiagrams))
	}

	foundIncludedMermaid := false
	for _, mermaid := range tm.MermaidDiagrams {
		if mermaid.Name == "included mermaid" {
			foundIncludedMermaid = true
		}

		if mermaid.Name == "shared mermaid" && mermaid.Content != "graph TD; P-->Q;" {
			t.Errorf("The parent's 'shared mermaid' should not have been overwritten")
		}
	}

	if !foundIncludedMermaid {
		t.Errorf("We didn't find the included-only mermaid diagram")
	}
}

func TestTmaddcovIncludeEmptyIncluding(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()

	tm := &Threatmodel{
		Name:   "no include here",
		Author: "@coverage",
	}

	err := tm.Include(defaultCfg, "./testdata/tm1.hcl")

	if err == nil {
		t.Fatalf("We should have gotten an error")
	}

	if !strings.Contains(err.Error(), "empty including") {
		t.Errorf("We should have an error about an empty including, got: %s", err)
	}
}

func TestTmaddcovIncludeMissingFile(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/tmaddcov-missing-include.hcl", false)

	if err == nil {
		t.Fatalf("We should have gotten an error")
	}

	if strings.Contains(err.Error(), "empty including") {
		t.Errorf("We should have a fetch error, not an empty including error, got: %s", err)
	}
}

func TestTmaddcovIncludeInvalidChild(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/tmaddcov-badinclude.hcl", false)

	if err == nil {
		t.Fatalf("We should have gotten an error")
	}

	if !strings.Contains(err.Error(), "author") {
		t.Errorf("We should have an error about the child's missing author, got: %s", err)
	}
}

// Threat names are unique per threatmodel and control names unique per
// threat: they're the identity key `extends`/`including` merge on, and
// threatcl cloud rejects a duplicate of either.
func TestValidateTmDuplicateThreatAndControlNames(t *testing.T) {
	cases := []struct {
		name string
		in   string
		exp  string
	}{
		{
			"duplicate_threat_name",
			`threatmodel "test" {
				author = "@x"
				threat "same" {
					description = "first"
				}
				threat "same" {
					description = "second"
				}
			}`,
			"TM 'test': duplicate threat 'same'",
		},
		{
			"duplicate_control_name",
			`threatmodel "test" {
				author = "@x"
				threat "thr" {
					description = "a threat"
					control "ctl" {
						description = "first"
					}
					control "ctl" {
						description = "second"
					}
				}
			}`,
			"TM 'test' / Threat 'thr': duplicate control 'ctl'",
		},
		{
			"duplicate_control_name_via_expanded_control",
			`threatmodel "test" {
				author = "@x"
				threat "thr" {
					description = "a threat"
					control "ctl" {
						description = "declared"
					}
					expanded_control "ctl" {
						description = "merged in for backwards compatibility"
					}
				}
			}`,
			"TM 'test' / Threat 'thr': duplicate control 'ctl'",
		},
		{
			// Controls are scoped to their threat, so the same control name
			// under two different threats is fine.
			"same_control_name_across_threats",
			`threatmodel "test" {
				author = "@x"
				threat "one" {
					description = "first"
					control "ctl" {
						description = "on the first threat"
					}
				}
				threat "two" {
					description = "second"
					control "ctl" {
						description = "on the second threat"
					}
				}
			}`,
			"",
		},
		{
			"unique_names",
			`threatmodel "test" {
				author = "@x"
				threat "one" {
					description = "first"
					control "ctl_a" {
						description = "a"
					}
					control "ctl_b" {
						description = "b"
					}
				}
				threat "two" {
					description = "second"
				}
			}`,
			"",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			defaultCfg := &ThreatmodelSpecConfig{}
			defaultCfg.setDefaults()
			tmParser := NewThreatmodelParser(defaultCfg)

			err := tmParser.ParseHCLRaw([]byte(tc.in))

			if tc.exp == "" {
				if err != nil {
					t.Errorf("%s: unexpected error: %s", tc.name, err)
				}
				return
			}

			if err == nil {
				t.Fatalf("%s: expected an error containing '%s', got none", tc.name, tc.exp)
			}

			if !strings.Contains(err.Error(), tc.exp) {
				t.Errorf("%s: expected an error containing '%s', got: %s", tc.name, tc.exp, err)
			}
		})
	}
}

// A control_imports entry resolving to the same name as a declared control is
// the local shape of the collision threatcl cloud reports as duplicate_entity
// when library enrichment expands a ref.
func TestValidateTmDuplicateControlNameFromImport(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/tm-dupe-control-import.hcl", false)

	if err == nil {
		t.Fatalf("expected an error for the imported control colliding with a declared one")
	}

	exp := "TM 'test_dupe_control_import' / Threat 'collides_with_import': duplicate control 'authentication_control'"
	if !strings.Contains(err.Error(), exp) {
		t.Errorf("expected an error containing '%s', got: %s", exp, err)
	}
}

func TestTmaddcovFetchRemoteTmTempDirFailure(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()

	// Point TMPDIR at a directory that doesn't exist so that
	// fetchRemoteTm's os.MkdirTemp call fails
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))

	_, err := fetchRemoteTm(defaultCfg, "tmaddcov-included.hcl", "./testdata/tmaddcov-parent.hcl")

	if err == nil {
		t.Errorf("We should have gotten an error creating the temp dir")
	}
}
