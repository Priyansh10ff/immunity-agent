---
title: Secure AWS Terraform Configurations
impact: HIGH
impactDescription: Cloud misconfigurations expose data, enable privilege escalation, and create unauthorized access vectors
tags: security, terraform, aws, infrastructure, iac, s3, iam, ec2
attribution: Curated and enhanced for Prismor
---

## Secure AWS Terraform Configurations

Security best practices for AWS Terraform configurations to prevent common misconfigurations.

### S3 — Encryption at Rest

**Incorrect:** No `kms_key_id` on S3 objects means data is stored unencrypted.

**Correct:**
```hcl
resource "aws_s3_bucket_object" "pass" {
  bucket     = aws_s3_bucket.bucket.bucket
  key        = "my-object"
  content    = "data"
  kms_key_id = aws_kms_key.example.arn
}
```

### IAM — Least Privilege Policies

**Incorrect:**
```hcl
resource "aws_iam_policy" "fail" {
  policy = <<POLICY
{"Version":"2012-10-17","Statement":[{"Action":"*","Effect":"Allow","Resource":"*"}]}
POLICY
}
```

**Correct:**
```hcl
resource "aws_iam_policy" "pass" {
  policy = <<POLICY
{"Version":"2012-10-17","Statement":[{"Action":["s3:GetObject*"],"Effect":"Allow","Resource":"arn:aws:s3:::bucket/*"}]}
POLICY
}
```

### Network — No World-Open Ports

**Incorrect:**
```hcl
resource "aws_security_group_rule" "fail" {
  type        = "ingress"; protocol = "tcp"; from_port = 22; to_port = 22
  cidr_blocks = ["0.0.0.0/0"]
}
```

**Correct:**
```hcl
resource "aws_security_group_rule" "pass" {
  type        = "ingress"; protocol = "tcp"; from_port = 22; to_port = 22
  cidr_blocks = ["10.0.0.0/8"]
}
```

### Storage — Encryption Required

**Incorrect (EBS):**
```hcl
resource "aws_ebs_volume" "fail" { availability_zone = "us-west-2a"; encrypted = false }
```

**Correct (EBS):**
```hcl
resource "aws_ebs_volume" "pass" { availability_zone = "us-west-2a"; encrypted = true }
```

**Correct (SQS/SNS):**
```hcl
resource "aws_sqs_queue" "pass" { name = "queue"; sqs_managed_sse_enabled = true }
resource "aws_sns_topic" "pass" { kms_master_key_id = "alias/aws/sns" }
```

### KMS — Key Rotation

**Incorrect:**
```hcl
resource "aws_kms_key" "fail" { enable_key_rotation = false }
```

**Correct:**
```hcl
resource "aws_kms_key" "pass" { enable_key_rotation = true }
```

### Credentials — Never Hardcode

**Incorrect:**
```hcl
provider "aws" {
  region = "us-west-2"; access_key = "AKIAEXAMPLE"; secret_key = "secret"
}
```

**Correct:**
```hcl
provider "aws" {
  region = "us-west-2"; shared_credentials_file = "~/.aws/creds"; profile = "myprofile"
}
```

## Key Prevention Rules

1. **Encrypt at rest** — all storage (S3, EBS, RDS, DynamoDB, SQS, SNS) must use KMS encryption
2. **Least privilege IAM** — no `Action: "*"` or `Resource: "*"` in production policies
3. **No public network access** — restrict security group CIDRs to known networks
4. **Enable KMS key rotation** — `enable_key_rotation = true` on all keys
5. **Enable CloudTrail with KMS** — audit logs must be encrypted
6. **Never hardcode credentials** — use IAM roles, instance profiles, or shared credentials files

**References:**
- [AWS Security Best Practices](https://aws.amazon.com/security/security-learning/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [Prismor](https://github.com/PrismorSec/prismor)
