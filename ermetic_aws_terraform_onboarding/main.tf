provider "aws" {
  region     = var.region
}
data "aws_caller_identity" "current" {}
locals {
  account_id = data.aws_caller_identity.current.account_id
  bucket_name = "ermetic-trail-bucket-${local.account_id}"
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
  policy     = file("${path.module}/role_policy.json")
}
resource "aws_iam_role_policy" "ErmeticPolicyforBucketRead" {
  name       = "ErmeticPolicyforBucketRead"
  role       = var.name
  depends_on = [aws_iam_role_policy_attachment.cross_account_assume_role]
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::${aws_s3_bucket.ermetic_trail_bucket.id}",
        "arn:aws:s3:::${aws_s3_bucket.ermetic_trail_bucket.id}/*"
      ]
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
      "Resource": "arn:aws:s3:::${aws_s3_bucket.ermetic_trail_bucket.id}/AWSLogs/${local.account_id}/*",
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

data "aws_iam_role" "ermetic_role" {
  name = var.name
}
output "role" {
  description = "Arn of the Ermetic role"
  value       = data.aws_iam_role.ermetic_role.arn
}
