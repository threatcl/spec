spec_version = "0.1.17"

threatmodel "test_control_import" {
  imports = ["expanded-controls.hcl"]
  author = "@xntrik"

  threat "test_control_import" {
    description = "Test control import"
    impacts = ["Confidentiality"]

    # New clean syntax - provide import path as string
    control_imports = ["import.control.authentication_control"]
  }

  threat "test_multiple_imports" {
    description = "Test multiple control imports"
    impacts = ["Integrity"]

    # Can also import multiple controls
    control_imports = [
      "import.control.authentication_control",
      "import.control.encryption_control"
    ]
  }

  threat "test_mixed_approach" {
    description = "Test mixed approach"
    impacts = ["Availability"]

    # Can mix control_imports with explicit control blocks
    control_imports = ["import.expanded_control.access_control"]

    control "custom_control" {
      description = "Custom control with overrides"
      implemented = true
      risk_reduction = 50
    }
  }
}
