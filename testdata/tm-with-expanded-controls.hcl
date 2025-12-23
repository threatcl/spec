spec_version = "0.1.17"

threatmodel "test_expanded_controls" {
  imports = ["expanded-controls.hcl", "controls.hcl"]
  author = "@xntrik"

  threat "unauthorized_access" {
    description = "Unauthorized access to user data"
    impacts = ["Confidentiality"]

    # Legacy control reference (backward compatible)
    control = import.control.control_name.description

    # New control reference from components
    control "auth_control" {
      description = import.control.authentication_control.description
      implemented = import.control.authentication_control.implemented
      implementation_notes = import.control.authentication_control.implementation_notes
      risk_reduction = import.control.authentication_control.risk_reduction
    }
  }

  threat "data_breach" {
    description = "Data breach"
    impacts = ["Confidentiality", "Integrity"]

    control "encryption_control" {
      description = import.control.encryption_control.description
      implemented = import.control.encryption_control.implemented
      risk_reduction = import.control.encryption_control.risk_reduction
    }
  }

  threat "privilege_escalation" {
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
