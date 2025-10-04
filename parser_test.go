package spec

import (
	"os"
	"strings"
	"testing"

	"github.com/zenizh/go-capturer"
)

const (
	tmTestValid = `spec_version = "0.1.14"
		threatmodel "test" {
			author = "@xntrik"
		}
	`
	tmTestValidJson = `{"spec_version": "0.1.14",
    "threatmodel": {
		  "test": {
			  "author": "@xntrik"
			}
		}
	}`
)

func TestNewTMParser(t *testing.T) {

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()

	tmParser := NewThreatmodelParser(defaultCfg)

	tmParser.validateSpec("blep")

	out := capturer.CaptureStdout(func() {
		tmParser.validateSpec("blop")
	})

	if !strings.Contains(out, "No provided version.") {
		t.Error("Missing stdout from a blank spec version")
		t.Log(out)
	}

	tmw := &ThreatmodelWrapped{
		SpecVersion: "NOPE",
	}

	tmParser.wrapped = tmw

	out = capturer.CaptureStdout(func() {
		tmParser.validateSpec("blop")
	})

	// @TODO: When we tidy up spec versioning, redo these tests
	// if !strings.Contains(out, "Provided version ('NOPE') doesn't match") {
	// 	t.Error("Missing stdout from a blank spec version")
	// 	t.Log(out)
	// }

	if tmParser.GetWrapped() == nil {
		t.Error("GetWrapped shouldn't return nil")
		t.Logf("%+v\n", tmParser.GetWrapped())
	}

}

func TestParserHclString(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()

	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	hclOut := tmParser.HclString()
	// t.Errorf("hclString:\n%s\n", tmParser.HclString())

	if !strings.Contains(hclOut, "threatmodel \"Tower of London\"") {
		t.Errorf("Did not find Tower of London HCL")
	}

	if !strings.Contains(hclOut, "A historic castle") {
		t.Errorf("Did not find 'A historic castle'")
	}
}

func TestParseInvalidFileExt(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/tm1.csv", false)

	if err == nil {
		t.Errorf("Error parsing illegitimate TM extension: %s", err)
	}
}

func TestParseHCLFile(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm1.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	err = tmParser.ParseFile("./testdata/tm1.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	err = tmParser.ParseHCLFile("./testdata/tm-invalid.hcl", false)

	if err == nil {
		t.Errorf("Error parsing broken TM file: %s", err)
	}
}

func TestParseJsonFile(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseJSONFile("./testdata/tm1.json", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	err = tmParser.ParseFile("./testdata/tm1.json", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	err = tmParser.ParseJSONFile("./testdata/tm-invalid.json", false)

	if err == nil {
		t.Errorf("Error parsing broken TM file: %s", err)
	}
}

func TestParseHCLFileWithVar(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm-withvar.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundVarVal := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		for _, threat := range tm.Threats {
			t.Logf("%s - %s", threat.Description, threat.Control)
			if strings.Contains(threat.Description, "test_var_val") {
				foundVarVal = true
			}
		}
	}

	if !foundVarVal {
		t.Errorf("We didn't find the variable")
	}
}

func TestParseHCLFileWithImport(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm-withimport.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundImport := false
	foundImportSubfolder := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		for _, threat := range tm.Threats {
			t.Logf("%s - %s", threat.Description, threat.Control)
			if strings.Contains(threat.Description, "ANd it should have spaces") {
				if threat.Control == "Valid controls only" {
					foundImport = true
				}
			}

			if threat.Description == "words" {
				if threat.Control == "Still valid controls only" {
					foundImportSubfolder = true
				}
			}
		}
	}

	if !foundImport {
		t.Errorf("We didn't find the imported control")
	}

	if !foundImportSubfolder {
		t.Errorf("We didn't find the imported control from the subfolder")
	}
}

func TestParseHCLFileWithExpandedControlImports(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm-with-expanded-controls.hcl", false)

	if err != nil {
		t.Errorf("Error parsing TM file with expanded control imports: %s", err)
	}

	foundLegacyControl := false
	foundExpandedAuthControl := false
	foundExpandedEncryptionControl := false
	foundExpandedAccessControl := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		if tm.Name == "test_expanded_controls" {
			for _, threat := range tm.Threats {
				// Check legacy control
				if threat.Control == "Valid controls only" {
					foundLegacyControl = true
				}

				// Check expanded controls
				for _, control := range threat.Controls {
					if control.Name == "auth_control" && control.Description == "Multi-factor authentication required" && control.Implemented == true {
						foundExpandedAuthControl = true
					}
					if control.Name == "encryption_control" && control.Description == "Data encrypted at rest and in transit" && control.Implemented == false {
						foundExpandedEncryptionControl = true
					}
					if control.Name == "access_control" && control.Description == "Role-based access control implemented" && control.Implemented == true {
						foundExpandedAccessControl = true
					}
				}
			}
		}
	}

	if !foundLegacyControl {
		t.Errorf("We didn't find the legacy imported control")
	}

	if !foundExpandedAuthControl {
		t.Errorf("We didn't find the expanded authentication control")
	}

	if !foundExpandedEncryptionControl {
		t.Errorf("We didn't find the expanded encryption control")
	}

	if !foundExpandedAccessControl {
		t.Errorf("We didn't find the expanded access control")
	}
}

func TestParseHCLFileWithControlImports(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm-with-control-import.hcl", false)

	if err != nil {
		t.Errorf("Error parsing TM file with control import: %s", err)
	}

	foundSingleImport := false
	foundMultipleImports := false
	foundMixedApproach := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		if tm.Name == "test_control_import" {
			for _, threat := range tm.Threats {
				if threat.Description == "Test control import" {
					// Should have 1 control from control_import
					if len(threat.Controls) == 1 {
						control := threat.Controls[0]
						if control.Name == "authentication_control" &&
							control.Description == "Multi-factor authentication required" &&
							control.Implemented == true {
							foundSingleImport = true
						}
					}
				}

				if threat.Description == "Test multiple control imports" {
					// Should have 2 controls from control_import array
					if len(threat.Controls) == 2 {
						authFound := false
						encFound := false
						for _, control := range threat.Controls {
							if control.Name == "authentication_control" {
								authFound = true
							}
							if control.Name == "encryption_control" {
								encFound = true
							}
						}
						if authFound && encFound {
							foundMultipleImports = true
						}
					}
				}

				if threat.Description == "Test mixed approach" {
					// Should have 2 controls: 1 from control_import + 1 from expanded_control block
					if len(threat.Controls) == 2 {
						importFound := false
						customFound := false
						for _, control := range threat.Controls {
							if control.Name == "access_control" {
								importFound = true
							}
							if control.Name == "custom_control" {
								customFound = true
							}
						}
						if importFound && customFound {
							foundMixedApproach = true
						}
					}
				}
			}
		}
	}

	if !foundSingleImport {
		t.Errorf("We didn't find the single control import")
	}

	if !foundMultipleImports {
		t.Errorf("We didn't find the multiple control imports")
	}

	if !foundMixedApproach {
		t.Errorf("We didn't find the mixed approach")
	}
}

func TestParseHCLFileWithMissingImport(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm-withimport-missingfile.hcl", false)

	if err != nil && !strings.Contains(err.Error(), "othercontrols.hcl: no such file or directory") {
		t.Errorf("Different error parsing legit TM file: %s", err)
	}

}

func TestParseHCLFileWithBadRefImport(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm-withimport-badref.hcl", false)

	if err != nil && !strings.Contains(err.Error(), "This object does not have an attribute named \"aer_control_name\"") {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

}

func TestAddTMAndWrite(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	tm := Threatmodel{
		Name:   "test",
		Author: "x",
	}

	out := capturer.CaptureStdout(func() {
		_ = tmParser.AddTMAndWrite(tm, os.Stdout, false)
	})

	if !strings.Contains(out, "threatmodel \"test\"") {
		t.Error("The tm wasn't added correctly")
	}

	out = capturer.CaptureStdout(func() {
		_ = tmParser.AddTMAndWrite(tm, os.Stdout, true)
	})

	if !strings.Contains(out, "Name: (string) (len=4) \"test\"") {
		t.Error("The tm wasn't added correctly")
	}

}

func TestParseHCLRaw(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		exp         string
		errorthrown bool
	}{
		{
			"valid_hcltm",
			tmTestValid,
			"",
			false,
		},
		{
			"invalid_block",
			"spec_version \"0.1.14\"",
			"Invalid block definition",
			true,
		},
		{
			"invalid_number_literal",
			"spec_version = 0.1.14\"",
			"Invalid number literal",
			true,
		},
		{
			"invalid_spec_version",
			"spec_veon = \"0.1.14\"",
			"Unsupported argument; An argument named \"spec_veon\"",
			true,
		},
		{
			"invalid_dupe_tm",
			tmTestValid + `
	threatmodel "test" {
		author = "j"
	}
			`,
			"TM 'test': duplicate found",
			true,
		},
		{
			"invalid_dupe_infoasset",
			`threatmodel "test" {
		author = "j"
		information_asset "asset" {information_classification = "Public"}
		information_asset "asset" {information_classification = "Public"}
	}
			`,
			"TM 'test': duplicate information_asset 'asset'",
			true,
		},
		{
			"invalid_tminfoassetref",
			`threatmodel "test" {
		author = "j"
		threat {
			description = "threat"
			information_asset_refs = ["nope"]
		}
	}
			`,
			"trying to refer to non-existent information_asset 'nope'",
			true,
		},
		{
			"invalid_tminfoassetref2",
			`threatmodel "test" {
		author = "j"
		information_asset "asset" {information_classification = "Public"}
		threat {
			description = "threat"
			information_asset_refs = ["nope"]
		}
	}
			`,
			"trying to refer to non-existent information_asset 'nope'",
			true,
		},
		{
			"tminfoassetref",
			`threatmodel "test" {
		author = "j"
		information_asset "asset" {information_classification = "Public"}
		threat {
			description = "threat"
			information_asset_refs = ["asset"]
		}
	}
			`,
			"",
			false,
		},
		{
			"tmimportfailurestdin",
			`threatmodel "test" {
		imports = ["errorhere.hcl"]
		author = "j"
		threat {
			description = "threat"
			information_asset_refs = ["asset"]
		}
	}
			`,
			"errorhere.hcl: no such file or directory",
			true,
		},
		{
			"tmvar_working",
			`variable "test_var" {
			 value = "test_var_val"
			}
			threatmodel "test" {
			author = "j"
			threat {
			  description = var.test_var
			}
			}`,
			"",
			false,
		},
		{
			"tmvar_arg_block_req_err",
			`variable 1 {
			 value = "test_var_val"
			}
			threatmodel "test" {
			author = "j"
			threat {
			  description = var.test_var
			}
			}`,
			"Argument or block definition required",
			true,
		},
		{
			"tmvar_wrong_arg_err",
			`variable "1" {
			 value = "test_var_val"
			 nope = 2
			}
			threatmodel "test" {
			author = "j"
			threat {
			  description = "var.test_var"
			}
			}`,
			"An argument named \"nope\" is not expected here",
			true,
		},
		// {
		// 	"tmvar_wrong_arg_err2",
		// 	`variable "test_var" {
		// 	 value = 1
		// 	}
		// 	threatmodel "test" {
		// 	author = "j"
		// 	threat {
		// 	  description = var.test_var
		// 	}
		// 	}`,
		// 	"An argument named \"nope\" is not expected here",
		// 	true,
		// },
		{
			"var_in_tm_err",
			`threatmodel "test" {
			variable "test_var" {
			 value = "test_var_val"
			}
			author = "j"
			threat {
			  description = var.test_var
			}
			}`,
			"Blocks of type \"variable\" are not expected here",
			true,
		},
		{
			"dfd_missing_ia_from_datastore",
			`threatmodel "dfdtest" {
			  author = "j"
		    information_asset "valid_asset" {information_classification = "Public"}
				data_flow_diagram {
					data_store "1" {
					  information_asset = "nope"
					}
				}
			}`,
			"TM 'dfdtest' DFD Data Store '1' trying to refer to non-existent information_asset 'nope'",
			true,
		},
		{
			"dfd_dupe_process",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  process "1" {}
					process "1" {}
				}
			}`,
			"duplicate process found in dfd '1'",
			true,
		},
		{
			"dfd_dupe_flow",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  process "1" {}
					process "2" {}
					flow "http" {
					  from = "1"
						to = "2"
					}
					flow "http" {
					  from = "1"
						to = "2"
					}
				}
			}`,
			"duplicate flow found in dfd '1:2'",
			true,
		},
		{
			"dfd_invalid_flow_from",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  process "1" {}
					process "2" {}
					flow "http" {
					  from = "1"
						to = "2"
					}
					flow "http" {
					  from = "x"
						to = "2"
					}
				}
			}`,
			"invalid from connection for flow 'x:2'",
			true,
		},
		{
			"dfd_invalid_flow_to",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  process "1" {}
					process "2" {}
					flow "http" {
					  from = "1"
						to = "2"
					}
					flow "http" {
					  from = "2"
						to = "x"
					}
				}
			}`,
			"invalid to connection for flow '2:x'",
			true,
		},
		{
			"dfd_invalid_self_flow",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  process "1" {}
					process "2" {}
					flow "http" {
					  from = "1"
						to = "1"
					}
				}
			}`,
			"flow can't connect to itself '1:1'",
			true,
		},
		{
			"dfd_dupe_external",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  process "1" {}
					external_element "1" {}
				}
			}`,
			"duplicate external_element found in dfd '1'",
			true,
		},
		{
			"dfd_dupe_data",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
					external_element "a" {}
					data_store "a" {}
				}
			}`,
			"duplicate data_store found in dfd 'a'",
			true,
		},
		{
			"dfd_dupe_zone",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {}
					trust_zone "tza" {}
					external_element "a" {}
					data_store "b" {}
				}
			}`,
			"duplicate trust_zone block found 'tza'",
			true,
		},
		{
			"dfd_dupe_proc_in_zone",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  process "a" {}
					}
					trust_zone "tzb" {}
					process "a" {}
					data_store "b" {}
				}
			}`,
			"duplicate process found in dfd 'a'",
			true,
		},
		{
			"dfd_dupe_element_in_zone",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  external_element "a" {}
					}
					trust_zone "tzb" {}
					process "a" {}
					data_store "b" {}
				}
			}`,
			"duplicate external_element found in dfd 'a'",
			true,
		},
		{
			"dfd_dupe_data_in_zone",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  data_store "a" {}
					}
					trust_zone "tzb" {}
					process "a" {}
					data_store "b" {}
				}
			}`,
			"duplicate data_store found in dfd 'a'",
			true,
		},
		{
			"dfd_data_in_zone_invalid_ialink",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  data_store "a" {information_asset = "not_found"}
					}
					trust_zone "tzb" {}
					data_store "b" {}
				}
			}`,
			"trying to refer to non-existent information_asset 'not_found'",
			true,
		},
		{
			"dfd_mismatch_zone_process",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  process "a" {
						  trust_zone = "nottza"
						}
					}
					trust_zone "tzb" {}
					process "c" {}
					data_store "b" {}
				}
			}`,
			"process trust_zone mis-match found in 'a'",
			true,
		},
		{
			"dfd_mismatch_zone_element",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  external_element "a" {
						  trust_zone = "nottza"
						}
					}
					trust_zone "tzb" {}
					process "c" {}
					data_store "b" {}
				}
			}`,
			"external_element trust_zone mis-match found in 'a'",
			true,
		},
		{
			"dfd_mismatch_zone_data",
			`threatmodel "dfdtest" {
			  author = "j"
				data_flow_diagram {
				  trust_zone "tza" {
					  data_store "a" {
						  trust_zone = "nottza"
						}
					}
					trust_zone "tzb" {}
					process "c" {}
					data_store "b" {}
				}
			}`,
			"data_store trust_zone mis-match found in 'a'",
			true,
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

			t.Logf("============ %v+\n", err)

			if err != nil {
				t.Logf("Err: '%s'. Expected: '%s'.", err.Error(), tc.exp)
				if !strings.Contains(err.Error(), tc.exp) {
					t.Errorf("%s: Error parsing hcl tm: %s", tc.name, err)
				}
			} else {
				t.Logf("Expected: '%s'.", tc.exp)
				if tc.errorthrown {
					t.Errorf("%s: An error was thrown when it shouldn't have", tc.name)
				}
			}
		})
	}
}

func TestParseJsonRaw(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		exp         string
		errorthrown bool
	}{
		{
			"valid_hcltm",
			tmTestValidJson,
			"",
			false,
		},
		{
			"invalid_block",
			"{spec_version: \"0.1.14\"}",
			"Invalid JSON keyword",
			true,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			defaultCfg := &ThreatmodelSpecConfig{}
			defaultCfg.setDefaults()
			tmParser := NewThreatmodelParser(defaultCfg)

			err := tmParser.ParseJSONRaw([]byte(tc.in))

			if err != nil {
				if !strings.Contains(err.Error(), tc.exp) {
					t.Errorf("%s: Error parsing hcl tm: %s", tc.name, err)
				}
			} else {
				if tc.errorthrown {
					t.Errorf("%s: An error was thrown when it shouldn't have", tc.name)
				}
			}
		})
	}
}
