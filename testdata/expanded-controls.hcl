spec_version = "0.1.13"

component "control" "legacy_control" {
  description = "Valid controls only"
}

component "expanded_control" "authentication_control" {
  description = "Multi-factor authentication required"
  implemented = true
  implementation_notes = "Using TOTP for all admin accounts"
  risk_reduction = 80
  
  attribute "category" {
    value = "Authentication"
  }
  
  attribute "framework" {
    value = "NIST"
  }
}

component "expanded_control" "encryption_control" {
  description = "Data encrypted at rest and in transit"
  implemented = false
  risk_reduction = 90
}

component "expanded_control" "access_control" {
  description = "Role-based access control implemented"
  implemented = true
  implementation_notes = "Using RBAC with least privilege principle"
  risk_reduction = 75
  
  attribute "standard" {
    value = "ISO 27001"
  }
}
