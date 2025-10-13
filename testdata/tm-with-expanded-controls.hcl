spec_version = "0.1.15"

threatmodel "test_expanded_controls" {
  imports = ["expanded-controls.hcl", "controls.hcl"]
  author = "@xntrik"

  threat {
    description = "Unauthorized access to user data"
    impacts = ["Confidentiality"]
    
    # Legacy control reference (backward compatible)
    control = import.control.control_name.description
    
    # New expanded_control reference from components
    expanded_control "auth_control" {
      description = import.expanded_control.authentication_control.description
      implemented = import.expanded_control.authentication_control.implemented
      implementation_notes = import.expanded_control.authentication_control.implementation_notes
      risk_reduction = import.expanded_control.authentication_control.risk_reduction
    }
  }
  
  threat {
    description = "Data breach"
    impacts = ["Confidentiality", "Integrity"]
    
    expanded_control "encryption_control" {
      description = import.expanded_control.encryption_control.description
      implemented = import.expanded_control.encryption_control.implemented
      risk_reduction = import.expanded_control.encryption_control.risk_reduction
    }
  }
  
  threat {
    description = "Privilege escalation"
    impacts = ["Confidentiality", "Integrity"]
    
    expanded_control "access_control" {
      description = import.expanded_control.access_control.description
      implemented = import.expanded_control.access_control.implemented
      implementation_notes = import.expanded_control.access_control.implementation_notes
      risk_reduction = import.expanded_control.access_control.risk_reduction
    }
  }
}
