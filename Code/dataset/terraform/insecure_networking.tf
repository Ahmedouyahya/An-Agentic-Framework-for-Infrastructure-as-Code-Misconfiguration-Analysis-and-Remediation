# =============================================================================
# DATASET FILE: terraform/insecure_networking.tf
# PURPOSE: Network-level security smells — VPC, SG, ELB, logging
# Smells:
#   [NET-01] Security group allows ALL inbound TCP (0.0.0.0/0)  — CWE-732 / CKV_AWS_25
#   [NET-02] Security group allows ALL outbound                  — CWE-732 / CKV_AWS_277
#   [NET-03] VPC Flow Logs disabled                              — CWE-778 / CKV2_AWS_11
#   [NET-04] HTTP load balancer (no HTTPS redirect)              — CWE-319 / CKV_AWS_2
#   [NET-05] ELB access logging disabled                         — CWE-778 / CKV_AWS_92
# DETECTION: All have direct Checkov IDs
# DIFFICULTY: LOW (clear structural patterns — good for baseline testing)
# =============================================================================

provider "aws" {
  region = "eu-central-1"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  # SMELL [NET-03]: No Flow Log resource attached to this VPC — CKV2_AWS_11 / CWE-778
  # (absence of aws_flow_log resource pointing to this VPC)
  tags = { Name = "main-vpc" }
}

# SMELL [NET-01] + [NET-02]: Security group with no restrictions
resource "aws_security_group" "web_sg" {
  name        = "web-security-group"
  description = "Web server security group"
  vpc_id      = aws_vpc.main.id

  # SMELL [NET-01]: ALL TCP from anywhere — direct attack surface
  ingress {
    description = "All TCP"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # SMELL: should restrict to port 443 only
  }

  # SMELL: SSH open to internet — should use bastion/VPN
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # SMELL: CWE-732 — should restrict to admin IPs
  }

  # SMELL [NET-02]: Unrestricted outbound to internet
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]   # SMELL: should restrict egress
  }

  tags = { Name = "web-sg" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "eu-central-1a"
  map_public_ip_on_launch = true   # SMELL: auto-assigning public IPs is risky
}

# SMELL [NET-04]: HTTP-only load balancer, no HTTPS listener
resource "aws_lb" "web" {
  name               = "web-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.web_sg.id]
  subnets            = [aws_subnet.public.id]

  # SMELL [NET-05]: Access logging disabled — CKV_AWS_92 / CWE-778
  # access_logs block is absent — should enable with S3 bucket target
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web.arn
  port              = "80"
  protocol          = "HTTP"   # SMELL [NET-04]: should use HTTPS — CKV_AWS_2 / CWE-319

  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.web.arn
    # SMELL: should redirect HTTP to HTTPS instead of forwarding
  }
}

resource "aws_lb_target_group" "web" {
  name     = "web-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
}
