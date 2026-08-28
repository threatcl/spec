 spec_version = "0.8.1"

 threatmodel "test" {
   imports = ["subfolder/othercontrols.hcl"]
   author = "@xntrik"

   threat "test_threat" {
     description = "words"

     control = import.control.aer_control_name.description
    }
 }
