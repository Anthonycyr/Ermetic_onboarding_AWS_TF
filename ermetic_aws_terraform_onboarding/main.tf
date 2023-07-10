provider "aws" {
  region     = var.region
  access_key = var.access_key
  secret_key = var.secret_key
}
data "aws_caller_identity" "current" {}
locals {
  account_id = data.aws_caller_identity.current.account_id
  bucket_name = "ermetic_trail-bucket${locals.account_id}"
}
data "aws_iam_policy_document" "cross_account_assume_role_policy" {
  statement {
    effect = "Allow"


    principals {
      type        = "AWS"
      identifiers = var.principal_arns
    }

    actions = ["sts:AssumeRole"]

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = var.external_id
    }
  }
}

resource "aws_iam_role" "cross_account_assume_role" {
  name               = var.name
  assume_role_policy = data.aws_iam_policy_document.cross_account_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "cross_account_assume_role" {
  count = length(var.policy_arns)

  role       = aws_iam_role.cross_account_assume_role.name
  policy_arn = element(var.policy_arns, count.index)
}

resource "aws_iam_role_policy" "ErmeticPolicyRO" {
  name       = "ErmeticPolicyRO"
  role       = var.name
  depends_on = [aws_iam_role_policy_attachment.cross_account_assume_role]
  policy     = <<EOF
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
            "acm:Describe*",
            "acm:List*",
            "autoscaling:Describe*",
            "batch:Describe*",
            "batch:List*",
            "cloudformation:Describe*",
            "cloudformation:List*",
            "cloudfront:Get*",
            "cloudfront:ListDistributions*",
            "cloudtrail:Describe*",
            "cloudtrail:Get*",
            "cloudtrail:List*",
            "cloudtrail:LookupEvents",
            "cloudwatch:Describe*",
            "cloudwatch:GetMetric*",
            "cloudwatch:ListMetrics",
            "cognito-idp:ListResourcesForWebACL",
            "cognito-sync:GetCognitoEvents",
            "config:Describe*",
            "dynamodb:Describe*",
            "dynamodb:List*",
            "ec2:Describe*",
            "ecr:Describe*",
            "ecr:GetRegistryScanningConfiguration",
            "ecr:GetRepositoryPolicy",
            "ecr:List*",
            "ecr:StartImageScan",
            "ecr-public:Describe*",
            "ecr-public:GetRepositoryPolicy",
            "ecr-public:List*",
            "ecs:Describe*",
            "ecs:List*",
            "eks:Describe*",
            "eks:List*",
            "elasticache:Describe*",
            "elasticache:List*",
            "elasticbeanstalk:Describe*",
            "elasticbeanstalk:List*",
            "elasticloadbalancing:Describe*",
            "elasticmapreduce:Describe*",
            "elasticmapreduce:List*",
            "es:Describe*",
            "es:List*",
            "events:ListRules",
            "iam:Generate*",
            "iam:Get*",
            "iam:List*",
            "identitystore:Describe*",
            "inspector2:List*",
            "iot:GetTopicRule",
            "kms:Describe*",
            "kms:GetKey*",
            "kms:List*",
            "kinesis:Describe*",
            "kinesis:List*",
            "lambda:Get*Policy",
            "lambda:GetAccountSettings",
            "lambda:List*",
            "logs:Describe*",
            "organizations:Describe*",
            "organizations:List*",
            "rds:Describe*",
            "rds:List*",
            "redshift:Describe*",
            "redshift:List*",
            "route53:Get*",
            "route53:List*",
            "route53domains:Get*",
            "route53domains:List*",
            "route53resolver:Get*",
            "route53resolver:List*",
            "s3:Describe*",
            "s3:GetAccessPoint*",
            "s3:GetAccountPublicAccessBlock",
            "s3:GetBucket*",
            "s3:GetEncryptionConfiguration",
            "s3:GetJobTagging",
            "s3:GetLifecycleConfiguration",
            "s3:ListAccessPoints",
            "s3:ListAllMyBuckets",
            "s3:ListBucketVersions",
            "s3:ListJobs",
            "secretsmanager:Describe*",
            "secretsmanager:GetResourcePolicy",
            "secretsmanager:List*",
            "sns:Get*",
            "sns:List*",
            "sqs:Get*",
            "sqs:List*",
            "ssm:Describe*",
            "ssm:List*",
            "sso:Describe*",
            "sso:Get*",
            "sso:List*",
            "sso-directory:List*",
            "sso-directory:Search*",
            "sts:DecodeAuthorizationMessage",
            "tag:Get*",
            "wafv2:Get*",
            "wafv2:List*"
         ],
         "Resource": "*"
       },
       {
         "Effect": "Allow",
         "Action": [
           "s3:GetObject",
           "s3:ListBucket"
         ],
         "Resource": "arn:aws:s3:::elasticbeanstalk-*"
       },
       {
         "Effect": "Allow",
         "Action": "apigateway:Get*",
         "NotResource": "arn:aws:apigateway:*::/apikeys*"
       }
     ]
   }
EOF
}

resource "aws_cloudtrail" "ermetic_trail" {
  name                          = "ermetic_trail"
  s3_bucket_name                = aws_s3_bucket.ermetic_trail_bucket.id
  include_global_service_events = true
  enable_logging = true
  is_multi_region_trail = true
  enable_log_file_validation = true
}

resource "aws_s3_bucket" "ermetic_trail_bucket" {
  bucket        = local.bucket_name
  force_destroy = true
}
resource "aws_s3_bucket_policy" "allow_access_from_another_account" {
  bucket = aws_s3_bucket.ermetic_trail_bucket.id
  policy = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AWSCloudTrailAclCheck",
        "Effect": "Allow",
        "Principal": {
          "Service": "cloudtrail.amazonaws.com"
        },
        "Action": "s3:GetBucketAcl",
        "Resource": "arn:aws:s3:::${aws_s3_bucket.ermetic_trail_bucket.id}"
      },
      {
        "Sid": "AWSCloudTrailWrite",
        "Effect": "Allow",
        "Principal": {
          "Service": "cloudtrail.amazonaws.com"
        },
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::${aws_s3_bucket.ermetic_trail_bucket.id}/AWSLogs/${locals.account_id}/*",
        "Condition": {
          "StringEquals": {
            "s3:x-amz-acl": "bucket-owner-full-control"
          }
        }
      }
    ]
  }
  EOF
}
