 spec_version = "0.1.17"

 variable "test_var" {
   value = "test_var_val"
 }

 threatmodel "test" {
   author = "@xntrik"

   threat "test_threat" {
     description = var.test_var

     control = "control words"
    }
 }

