spec_version = "0.7.0"

threatmodel "parsercov_bare_expanded" {
  imports = ["parsercov-controls.hcl"]
  author  = "@xntrik"

  threat "bare" {
    description     = "Threat using a bare expanded control"
    control_imports = ["import.expanded_control.bare_expanded"]
  }

  threat "misc" {
    description     = "Threat using a component of another type"
    control_imports = ["import.control.misc_component"]
  }
}
