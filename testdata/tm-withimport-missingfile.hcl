 spec_version = "0.1.17"

 threatmodel "test" {
   imports = ["nope/othercontrols.hcl"]
   author = "@xntrik"

   threat "test_threat" {
     description = "words"

     control = import.control.another_control_name.description
    }
 }
