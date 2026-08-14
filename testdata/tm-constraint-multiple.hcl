 spec_version = "0.8.0"

 threatmodel "multi tm1" {
   description = "A threat model that trips multiple constraints"
   author = "@xntrik"

   threat "threat_with_control_string" {
     description = "A threat with a legacy control string and a proposed_control block"
     impacts = ["Confidentiality"]
     control = "A legacy control string"

     proposed_control {
       implemented = false
       description = "blep"
     }
  }

  data_flow_diagram {
    process "Client" {}
  }
}

 threatmodel "multi tm2" {
   description = "A second threat model that also trips a constraint"
   author = "@xntrik"

   threat "another_threat_with_control_string" {
     description = "A threat with a legacy control string"
     impacts = ["Availability"]
     control = "Another legacy control string"
  }
}
