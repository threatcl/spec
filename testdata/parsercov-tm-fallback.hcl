spec_version = "0.8.0"

threatmodel "parsercov_fallback" {
  imports = ["parsercov-controls-only.hcl"]
  author  = "@xntrik"

  threat "fallback" {
    description     = "Threat using expanded_control fallback to control namespace"
    control_imports = ["import.expanded_control.parsercov_fallback_control"]
  }
}
