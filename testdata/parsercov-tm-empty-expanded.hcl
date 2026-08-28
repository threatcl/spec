spec_version = "0.8.1"

threatmodel "parsercov_empty_expanded" {
  imports = ["parsercov-noctl.hcl"]
  author  = "@xntrik"

  threat "ghost" {
    description     = "References an expanded control from an empty library"
    control_imports = ["import.expanded_control.ghost_control"]
  }
}
