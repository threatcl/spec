spec_version = "0.8.0"

threatmodel "constraintcov expanded" {
  description = "Threat model with a deprecated expanded_control block"
  author = "@xntrik"

  threat "expanded_control_threat" {
    description = "A threat with a deprecated expanded_control block"
    impacts = ["Confidentiality"]

    expanded_control "access_control" {
      description = "An expanded control that should trip the deprecation warning"
      implemented = true
    }
  }
}
