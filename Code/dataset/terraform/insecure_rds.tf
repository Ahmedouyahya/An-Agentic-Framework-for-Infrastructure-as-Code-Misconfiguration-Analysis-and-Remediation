# =============================================================================
# DATASET FILE: terraform/insecure_rds.tf
# Smells: [TF-RDS-01] Publicly accessible, [TF-RDS-02] No encryption,
#         [TF-RDS-03] No backup, [TF-RDS-04] Hardcoded password
# Checkov IDs: CKV_AWS_17, CKV_AWS_16, CKV_AWS_133
# CWE: CWE-259, CWE-312, CWE-732
# =============================================================================

resource "aws_db_instance" "prod_db" {
  identifier        = "prod-database"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "appdb"
  username = "admin"
  password = "SuperSecret123!"   # SMELL [TF-RDS-04]: hardcoded DB password — CWE-259

  # SMELL [TF-RDS-01]: Database exposed to the internet — CKV_AWS_17 / CWE-732
  publicly_accessible = true

  # SMELL [TF-RDS-02]: Storage not encrypted — CKV_AWS_16 / CWE-312
  storage_encrypted = false

  # SMELL [TF-RDS-03]: Automated backups disabled — CKV_AWS_133
  backup_retention_period = 0

  # SMELL [TF-RDS-05]: Minor version upgrades disabled — CKV_AWS_129
  auto_minor_version_upgrade = false

  # SMELL [TF-RDS-06]: Deletion protection off — CKV_AWS_293
  deletion_protection = false

  skip_final_snapshot = true
}
