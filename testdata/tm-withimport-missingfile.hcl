 spec_version = "0.8.1"

 threatmodel "test" {
   imports = ["nope/othercontrols.hcl"]
   author = "@xntrik"

   threat "test_threat" {
     description = "words"

     control = import.control.another_control_name.description
    }
 }
