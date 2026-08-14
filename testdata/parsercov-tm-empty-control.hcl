spec_version = "0.8.0"

threatmodel "parsercov_empty_control" {
  imports = ["parsercov-noctl.hcl"]
  author  = "@xntrik"

  threat "ghost" {
    description     = "References a control from an empty library"
    control_imports = ["import.control.ghost_control"]
  }
}
