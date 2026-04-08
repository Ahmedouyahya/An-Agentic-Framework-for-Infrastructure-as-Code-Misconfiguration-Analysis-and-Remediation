# =============================================================================
# DATASET FILE: terraform/insecure_iam.tf
# PURPOSE: Explicit IAM permission and access control smells
# Smells:
#   [IAM-01] Wildcard IAM policy (Action: *)       — CWE-732 / CKV_AWS_40
#   [IAM-02] Wildcard resource (Resource: *)       — CWE-732 / CKV_AWS_107
#   [IAM-03] IAM user with inline policy           — CWE-732 / CKV_AWS_40
#   [IAM-04] IAM access key not rotated            — CWE-324 / CKV_AWS_273
#   [IAM-05] No MFA on root account (comment)      — CWE-308 / documentation
# DETECTION: Checkov + heuristic
# DIFFICULTY: HIGH (semantic understanding needed for wildcard detection)
# =============================================================================

provider "aws" {
  region = "us-east-1"
}

# SMELL [IAM-01] + [IAM-02]: Wildcard actions AND resources — effectively root access
# CKV_AWS_40 flags Action: * on any policy
resource "aws_iam_policy" "admin_all" {
  name        = "AdminAllPolicy"
  description = "Grants unrestricted access to all AWS resources"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"           # SMELL [IAM-01]: wildcard actions — CWE-732
        Resource = "*"           # SMELL [IAM-02]: wildcard resource — CWE-732
      }
    ]
  })
}

# SMELL [IAM-03]: IAM user with direct inline policy — should use groups/roles
resource "aws_iam_user" "developer" {
  name = "developer-user"
}

resource "aws_iam_user_policy" "developer_inline" {
  name = "developer-inline-policy"
  user = aws_iam_user.developer.name

  # SMELL: inline policies on users (should attach via role or group)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*", "ec2:*"]   # SMELL: overly broad actions
        Resource = "*"
      }
    ]
  })
}

# SMELL [IAM-04]: Access key created and not managed for rotation
resource "aws_iam_access_key" "developer_key" {
  user = aws_iam_user.developer.name
  # No rotation configured — key may be long-lived
  # CWE-324: Use of a Key Past its Expiration Date
}

# SMELL: IAM role with trust policy for ANY AWS account (wildcard principal)
resource "aws_iam_role" "cross_account" {
  name = "cross-account-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }   # SMELL: any AWS account can assume this role
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cross_account_admin" {
  role       = aws_iam_role.cross_account.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # SMELL: admin policy
}
