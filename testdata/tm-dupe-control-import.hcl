spec_version = "0.8.1"

threatmodel "test_dupe_control_import" {
  imports = ["expanded-controls.hcl"]
  author = "@xntrik"

  threat "collides_with_import" {
    description = "An imported control colliding with a declared one"
    impacts = ["Confidentiality"]

    control_imports = ["import.control.authentication_control"]

    control "authentication_control" {
      description = "Declared control with the same name as the imported one"
    }
  }
}
