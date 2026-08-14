spec_version = "0.8.0"

threatmodel "constraintcov clean" {
  description = "Threat model that trips no deprecation constraints"
  author = "@xntrik"

  threat "plain_threat" {
    description = "A threat with no deprecated blocks or attributes"
    impacts = ["Confidentiality"]
  }
}
