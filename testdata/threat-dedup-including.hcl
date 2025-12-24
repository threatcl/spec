spec_version = "0.2.3"

threatmodel "test_dedup" {
  author = "@test"

  including = "threat-dedup-base.hcl"

  threat "threat_one" {
    description = "This is a DIFFERENT description for threat one"
    impacts = ["Availability"]
  }

  threat "threat_three" {
    description = "This is the third threat"
    impacts = ["Confidentiality"]
  }
}
