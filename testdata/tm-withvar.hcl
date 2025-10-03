 spec_version = "0.1.13"

 variable "test_var" {
   value = "test_var_val"
 }

 threatmodel "test" {
   author = "@xntrik"

   threat {
     description = var.test_var

     control = "control words"
    }
 }

