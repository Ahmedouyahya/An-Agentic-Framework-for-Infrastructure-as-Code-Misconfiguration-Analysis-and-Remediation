"""
Central configuration for the IaC security dataset scraper.
All tunables live here — change once, applies everywhere.
"""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent
OUTPUT_DIR = BASE_DIR / "output"
RAW_DIR = OUTPUT_DIR / "raw"
MERGED_DIR = OUTPUT_DIR / "merged"

# ---------------------------------------------------------------------------
# GitHub API
# ---------------------------------------------------------------------------
GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
GITHUB_API_BASE = "https://api.github.com"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"

# Concurrency limits
MAX_CONCURRENT_REQUESTS = 12  # parallel API calls in flight (burst)
SEARCH_DELAY_SECONDS = 2.1    # delay between search pages (30 req/min = 1 per 2s)
REST_REQUESTS_PER_SECOND = 1.1  # global throttle — 5000/hr limit, targeting 3960/hr (79%)

# How many commits to fetch per search query page
COMMITS_PER_PAGE = 30         # GitHub max
MAX_SEARCH_PAGES = 10         # 300 commits max per query (adjust up for big runs)

# Maximum file size to download (bytes) — skip huge generated files
MAX_FILE_BYTES = 200_000

# ---------------------------------------------------------------------------
# IaC file extensions / filenames
# ---------------------------------------------------------------------------
TERRAFORM_EXTENSIONS = {".tf", ".tfvars"}
ANSIBLE_EXTENSIONS = {".yml", ".yaml"}
KUBERNETES_EXTENSIONS = {".yml", ".yaml"}
DOCKER_FILENAMES = {"Dockerfile", "dockerfile"}
DOCKER_EXTENSIONS = {".dockerfile"}
CLOUDFORMATION_EXTENSIONS = {".yml", ".yaml", ".json", ".template"}

ALL_IAC_EXTENSIONS = TERRAFORM_EXTENSIONS | ANSIBLE_EXTENSIONS | DOCKER_EXTENSIONS

# ---------------------------------------------------------------------------
# GitHub commit search queries
# Syntax: https://docs.github.com/en/search-github/searching-on-github/searching-commits
# ---------------------------------------------------------------------------
COMMIT_SEARCH_QUERIES = [
    # Terraform fixes — credential/secret management
    "fix hardcoded credentials terraform",
    "remove hardcoded password terraform",
    "remove hardcoded secret terraform",
    "fix hardcoded api key terraform",
    # Terraform fixes — network
    "fix security group 0.0.0.0 terraform",
    "restrict cidr terraform",
    "remove public access terraform",
    # Terraform fixes — encryption / storage
    "fix s3 bucket encryption terraform",
    "enable encryption terraform",
    "fix s3 bucket public terraform",
    "fix s3 bucket acl terraform",
    # Terraform fixes — IAM
    "fix iam overly permissive terraform",
    "fix iam wildcard terraform",
    "least privilege iam terraform",
    # Terraform fixes — database
    "fix rds encryption terraform",
    "fix rds public terraform",
    "fix database security terraform",
    # Terraform fixes — logging
    "enable logging terraform",
    "fix cloudtrail terraform",
    "fix logging disabled terraform",
    # Terraform general
    "fix security vulnerability terraform",
    "security fix infrastructure terraform",
    "checkov fix terraform",
    "tfsec fix terraform",
    # Kubernetes fixes
    "fix privileged container kubernetes",
    "add security context kubernetes",
    "add securityContext kubernetes",
    "fix rbac overly permissive kubernetes",
    "remove root user kubernetes",
    "fix security kubernetes manifest",
    "add readOnlyRootFilesystem kubernetes",
    "allowPrivilegeEscalation false kubernetes",
    "add resource limits kubernetes",
    "fix network policy kubernetes",
    # Dockerfile fixes
    "fix Dockerfile security",
    "run non-root Dockerfile",
    "fix hardcoded secret Dockerfile",
    "pin base image Dockerfile",
    "remove root user Dockerfile",
    "fix USER root Dockerfile",
    "add HEALTHCHECK Dockerfile",
    # Ansible fixes
    "fix ansible security",
    "remove hardcoded password ansible",
    "no_log ansible security",
    # CloudFormation
    "fix cloudformation security",
    "fix cloudformation encryption",
    # General IaC
    "fix iac security vulnerability",
    "fix infrastructure security",
    "CWE-798 fix",
    "CWE-732 fix",
    "CWE-250 fix kubernetes",
    "CWE-312 fix encryption",
    "security remediation infrastructure",
    "fix checkov failed",
    "fix tfsec",
    "fix kics",
]

# ---------------------------------------------------------------------------
# GitHub code search queries (find insecure files to label)
# ---------------------------------------------------------------------------
CODE_SEARCH_QUERIES = [
    # Terraform insecure patterns
    'acl = "public-read" extension:tf',
    'cidr_blocks = ["0.0.0.0/0"] extension:tf',
    'encrypted = false extension:tf',
    'password = extension:tf NOT var NOT variable',
    # Kubernetes insecure patterns
    'privileged: true extension:yaml path:kubernetes',
    'runAsUser: 0 extension:yaml',
    'allowPrivilegeEscalation: true extension:yaml',
    # Dockerfile insecure patterns
    'USER root filename:Dockerfile',
    'FROM ubuntu:latest filename:Dockerfile',
    'ADD http filename:Dockerfile',
]

# ---------------------------------------------------------------------------
# Known IaC security repositories (curated)
# Format: (owner, repo, description, has_fix_commits)
# ---------------------------------------------------------------------------
KNOWN_REPOS = [
    # Intentionally vulnerable — good for insecure examples
    ("bridgecrewio", "terragoat",              "Vulnerable Terraform by Bridgecrew",        False),
    ("bridgecrewio", "cfngoat",                "Vulnerable CloudFormation by Bridgecrew",   False),
    ("madhuakula",   "kubernetes-goat",        "Vulnerable Kubernetes by madhuakula",       False),
    ("OWASP",        "wrongsecrets",           "OWASP WrongSecrets — secrets in IaC",       False),
    ("bridgecrewio", "BrokenAzure",            "Vulnerable Azure Terraform by Bridgecrew",  False),
    ("bridgecrewio", "BrokenGCP",              "Vulnerable GCP Terraform by Bridgecrew",    False),
    ("kabirbaidhya",  "infra-as-code-lab",     "IaC lab with vulnerable examples",          False),
    ("anaisotlans",  "vulnerable-terraform",   "Deliberately vulnerable Terraform",         False),
    ("ScaleSec",     "scalesec-vuln-tf",       "Vulnerable Terraform for training",         False),
    ("badsecrets",   "badsecrets",             "Kubernetes/Docker bad secrets examples",     False),
    # Checkov — PASSED/FAILED test resource pairs
    ("bridgecrewio", "checkov",                "Checkov scanner — PASSED/FAILED pairs",     True),
    # KICS — Checkmarx IaC scanner with positive/negative query examples
    ("Checkmarx",    "kics",                   "KICS scanner — vulnerable/fixed pairs",     True),
    # tfsec — has example Terraform resources (PASSED/FAILED)
    ("aquasecurity", "tfsec",                  "tfsec — Terraform security scanner",        True),
    # Trivy / Defsec — has IaC test cases
    ("aquasecurity", "defsec",                 "Defsec — IaC security rules + examples",    True),
]

# Checkov test resource directories (relative to repo root)
CHECKOV_RESOURCE_DIRS = {
    "terraform":    "tests/resources/example_*",
    "kubernetes":   "tests/resources/example_*",
    "dockerfile":   "tests/resources/example_*",
    "ansible":      "tests/resources/example_*",
}

# ---------------------------------------------------------------------------
# Smell taxonomy mapping (smell type → CWE + severity + category)
# Mirrors dataset/taxonomy/smells_taxonomy.json for classifier use
# ---------------------------------------------------------------------------
SMELL_TAXONOMY = {
    "hardcoded_password": {
        "cwe": "CWE-259", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_SECRET_*"],
    },
    "hardcoded_credential": {
        "cwe": "CWE-798", "severity": "CRITICAL", "category": "Security",
        "checkov_ids": ["CKV_AWS_41", "CKV_SECRET_*"],
    },
    "overly_permissive_cidr": {
        "cwe": "CWE-732", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_AWS_25", "CKV_AWS_277"],
    },
    "overly_permissive_acl": {
        "cwe": "CWE-732", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_AWS_20"],
    },
    "privileged_container": {
        "cwe": "CWE-250", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_K8S_16", "CKV_DOCKER_5"],
    },
    "root_user": {
        "cwe": "CWE-250", "severity": "MEDIUM", "category": "Security",
        "checkov_ids": ["CKV_K8S_6", "CKV_DOCKER_8"],
    },
    "missing_encryption": {
        "cwe": "CWE-312", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_AWS_19", "CKV_AWS_7"],
    },
    "public_access_block_disabled": {
        "cwe": "CWE-732", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_AWS_53", "CKV_AWS_54"],
    },
    "versioning_disabled": {
        "cwe": "CWE-693", "severity": "LOW", "category": "Configuration Data",
        "checkov_ids": ["CKV_AWS_52"],
    },
    "logging_disabled": {
        "cwe": "CWE-778", "severity": "MEDIUM", "category": "Configuration Data",
        "checkov_ids": ["CKV_AWS_18", "CKV_AWS_86"],
    },
    "unencrypted_database": {
        "cwe": "CWE-312", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_AWS_16", "CKV_AWS_17"],
    },
    "insecure_tls": {
        "cwe": "CWE-326", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_AWS_84", "CKV_AWS_68"],
    },
    "missing_resource_limits": {
        "cwe": "CWE-400", "severity": "MEDIUM", "category": "Configuration Data",
        "checkov_ids": ["CKV_K8S_11", "CKV_K8S_13"],
    },
    "allow_privilege_escalation": {
        "cwe": "CWE-250", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_K8S_20"],
    },
    "unpinned_base_image": {
        "cwe": "CWE-1357", "severity": "MEDIUM", "category": "Dependency",
        "checkov_ids": ["CKV_DOCKER_6"],
    },
    "secrets_in_env": {
        "cwe": "CWE-798", "severity": "CRITICAL", "category": "Security",
        "checkov_ids": ["CKV_K8S_35", "CKV_DOCKER_3"],
    },
    "overly_permissive_iam": {
        "cwe": "CWE-732", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_AWS_40", "CKV_AWS_274"],
    },
    "missing_network_policy": {
        "cwe": "CWE-923", "severity": "MEDIUM", "category": "Security",
        "checkov_ids": ["CKV_K8S_7"],
    },
}

# ---------------------------------------------------------------------------
# Dataset split ratios
# ---------------------------------------------------------------------------
SPLIT_RATIOS = {"train": 0.80, "val": 0.10, "test": 0.10}
