
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
  default = ["25b1295f-19eb-4614-ae75-e6b3833c9cd0"]
  type        = list(string)
  description = "The External ID of your Ermetic tenant"
}

