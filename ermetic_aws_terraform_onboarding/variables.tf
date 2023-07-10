variable "access_key" {
     description = "Access key to AWS console"
}
variable "secret_key" {
     description = "Secret key to AWS console"
}
variable "region" {
     description = "Region of AWS VPC"
}
variable "name" {
  default = "ErmeticRole"
  type        = string
  description = "The name of Ermetic's IAM Role."
}
variable "principal_arns" {
  default = ["081802104111"]
  type        = list(string)
  description = "Ermetic's source AWS account"
}
variable "policy_arns" {
  default = ["arn:aws:iam::aws:policy/SecurityAudit"]
  type        = list(string)
  description = "Managed policy required for onboarding"
}
variable "external_id" {
  default = ["xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"]
  type        = list(string)
  description = "The External ID of your Ermetic tenant"
}

