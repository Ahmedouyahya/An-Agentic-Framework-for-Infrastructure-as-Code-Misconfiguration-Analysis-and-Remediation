# =============================================================================
# DATASET FILE: terraform/insecure_ec2.tf
# Smells: [TF-EC2-01] Hardcoded credentials, [TF-EC2-02] Open security group,
#         [TF-EC2-03] No IMDSv2, [TF-EC2-04] Unencrypted EBS
# Checkov IDs: CKV_AWS_8, CKV_AWS_79, CKV2_AWS_41, CKV_AWS_3
# CWE: CWE-798, CWE-732, CWE-312
# =============================================================================

provider "aws" {
  region     = "eu-west-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"          # SMELL [TF-EC2-01]: hardcoded credential CWE-798
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfi"  # SMELL [TF-EC2-01]: hardcoded secret CWE-259
}

# SMELL [TF-EC2-02]: Security group allows ALL traffic from anywhere — CKV_AWS_25 / CWE-732
resource "aws_security_group" "open_sg" {
  name        = "open-security-group"
  description = "Wide-open security group for testing"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # SMELL: allows all IPs on all ports
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami                    = "ami-0c02fb55956c7d316"
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.open_sg.id]

  # SMELL [TF-EC2-03]: IMDSv2 not enforced — CKV_AWS_79
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"   # SMELL: should be "required"
    http_put_response_hop_limit = 2            # SMELL: should be 1
  }

  # SMELL [TF-EC2-04]: Root EBS volume not encrypted — CKV_AWS_8
  root_block_device {
    volume_type = "gp2"
    volume_size = 20
    encrypted   = false   # SMELL: should be true
  }

  tags = {
    Name = "insecure-web-server"
  }
}
