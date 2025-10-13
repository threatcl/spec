 spec_version = "0.1.15"

 threatmodel "test" {
   imports = ["subfolder/othercontrols.hcl"]
   author = "@xntrik"

   threat {
     description = "words"

     control = import.control.aer_control_name.description
    }
 }
