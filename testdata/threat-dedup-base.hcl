spec_version = "0.2.4"

threatmodel "test_dedup" {
  author = "@test"

  threat "threat_one" {
    description = "This is the first threat"
    impacts = ["Confidentiality"]
  }

  threat "threat_two" {
    description = "This is the second threat"
    impacts = ["Integrity"]
  }
}
