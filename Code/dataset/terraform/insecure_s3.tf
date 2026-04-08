# =============================================================================
# DATASET FILE: terraform/insecure_s3.tf
# Smells: [TF-S3-01] Public ACL, [TF-S3-02] No encryption, [TF-S3-03] No versioning
# Checkov IDs: CKV_AWS_19, CKV_AWS_20, CKV_AWS_52
# CWE: CWE-312 (Cleartext Storage), CWE-732 (Incorrect Permission)
# =============================================================================

provider "aws" {
  region = "us-east-1"
}

# SMELL [TF-S3-01] Bucket is publicly readable — CKV_AWS_20 / CWE-732
# SMELL [TF-S3-02] No server-side encryption — CKV_AWS_19 / CWE-312
# SMELL [TF-S3-03] Versioning disabled — CKV_AWS_52
resource "aws_s3_bucket" "data_bucket" {
  bucket = "my-company-data-bucket"
  acl    = "public-read"          # SMELL: public-read exposes all objects
}

# No aws_s3_bucket_server_side_encryption_configuration block → encryption missing
# No aws_s3_bucket_versioning block → versioning missing

# SMELL [TF-S3-04] Logging disabled — CKV_AWS_18
resource "aws_s3_bucket_public_access_block" "data_bucket_pab" {
  bucket = aws_s3_bucket.data_bucket.id

  block_public_acls       = false   # SMELL: should be true
  block_public_policy     = false   # SMELL: should be true
  ignore_public_acls      = false   # SMELL: should be true
  restrict_public_buckets = false   # SMELL: should be true
}
