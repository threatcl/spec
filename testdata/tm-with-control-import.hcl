spec_version = "0.1.15"

threatmodel "test_control_import" {
  imports = ["expanded-controls.hcl"]
  author = "@xntrik"

  threat {
    description = "Test control import"
    impacts = ["Confidentiality"]
    
    # New clean syntax - provide import path as string
    control_imports = ["import.expanded_control.authentication_control"]
  }

  threat {
    description = "Test multiple control imports"
    impacts = ["Integrity"]
    
    # Can also import multiple controls
    control_imports = [
      "import.expanded_control.authentication_control",
      "import.expanded_control.encryption_control"
    ]
  }

  threat {
    description = "Test mixed approach"
    impacts = ["Availability"]
    
    # Can mix control_imports with explicit expanded_control blocks
    control_imports = ["import.expanded_control.access_control"]
    
    expanded_control "custom_control" {
      description = "Custom control with overrides"
      implemented = true
      risk_reduction = 50
    }
  }
}
