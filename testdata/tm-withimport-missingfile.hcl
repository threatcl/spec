 spec_version = "0.1.14"

 threatmodel "test" {
   imports = ["nope/othercontrols.hcl"]
   author = "@xntrik"

   threat {
     description = "words"

     control = import.control.another_control_name.description
    }
 }
