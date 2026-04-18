"""
Central configuration for the IaC security dataset scraper.
All tunables live here — change once, applies everywhere.
"""

import os
from datetime import date
from itertools import product
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

# ---------------------------------------------------------------------------
# GitLab API
# ---------------------------------------------------------------------------
GITLAB_TOKEN: str = os.getenv("GITLAB_TOKEN", "")
GITLAB_API_BASE = "https://gitlab.com/api/v4"

# Concurrency limits
MAX_CONCURRENT_REQUESTS = 20  # parallel API calls in flight (burst)
SEARCH_DELAY_SECONDS = 2.1    # delay between search pages (30 req/min = 1 per 2s)
REST_REQUESTS_PER_SECOND = 1.3  # global throttle — 5000/hr limit, targeting 4680/hr (94%)

# How many commits to fetch per search query page
COMMITS_PER_PAGE = 30         # GitHub max
MAX_SEARCH_PAGES = 10         # 300 commits max per query/window

# Maximum file size to download (bytes) — skip huge generated files
MAX_FILE_BYTES = 200_000

# ---------------------------------------------------------------------------
# Date-window partitioning for commit search.
# GitHub search caps at 1000 results per query. By splitting each query
# into many date windows we multiply the unique-commit yield by 10-50x.
# ---------------------------------------------------------------------------
DATE_WINDOW_START = date(2015, 1, 1)
DATE_WINDOW_END   = date.today()
DATE_WINDOW_DAYS  = 14

# ---------------------------------------------------------------------------
# Watchdog — exit non-zero if no new records for this many seconds,
# so a supervisor script (run_forever.sh / systemd) can restart.
# ---------------------------------------------------------------------------
WATCHDOG_STALL_SECONDS = 900  # 15 minutes

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
# Query-set generation
#
# Instead of hardcoding ~50 queries, we generate ~250 by multiplying across
# (fix_verb × issue × tool). With 14-day date-window partitioning that gives
# ~250 × 280 windows ≈ 70,000 unique search scopes, which is far more than
# any single week-long run will exhaust. The scraper picks them in order,
# so newest fixes are found first.
# ---------------------------------------------------------------------------

_FIX_VERBS = ["fix", "patch", "resolve", "remediate", "harden", "secure", "correct"]

_IAC_TOOLS = [
    "terraform", "kubernetes", "helm", "dockerfile",
    "ansible", "pulumi", "cloudformation", "bicep",
]

_SECURITY_ISSUES = [
    # Secret & credential
    "hardcoded credentials", "hardcoded password", "hardcoded secret",
    "hardcoded api key", "hardcoded token", "exposed secret", "leaked credential",
    # Network
    "open security group", "0.0.0.0/0", "public ingress", "unrestricted cidr",
    "public endpoint", "public access", "public bucket",
    # Encryption
    "missing encryption", "disable encryption", "enable encryption",
    "unencrypted storage", "tls version", "insecure tls",
    # IAM / RBAC
    "overly permissive iam", "iam wildcard", "least privilege",
    "overly permissive rbac", "wildcard action",
    # Container / K8s
    "privileged container", "run as root", "runAsNonRoot", "security context",
    "privilege escalation", "root user", "read only root filesystem",
    "resource limits", "network policy",
    # Storage / database
    "s3 public", "s3 acl", "rds encryption", "rds public", "database encryption",
    # Logging / monitoring
    "logging disabled", "cloudtrail", "enable logging", "audit logging",
    # Dockerfile-specific
    "USER root", "base image latest", "pin base image", "HEALTHCHECK",
    # General
    "security vulnerability", "security issue", "misconfiguration",
]

_CWE_IDS = [
    "CWE-22", "CWE-78", "CWE-200", "CWE-250", "CWE-259", "CWE-276",
    "CWE-284", "CWE-295", "CWE-306", "CWE-311", "CWE-312", "CWE-319",
    "CWE-326", "CWE-327", "CWE-400", "CWE-521", "CWE-522", "CWE-611",
    "CWE-693", "CWE-732", "CWE-770", "CWE-778", "CWE-798", "CWE-862",
    "CWE-863", "CWE-915", "CWE-923", "CWE-1357",
]

_SCANNERS = [
    "checkov", "tfsec", "kics", "terrascan", "snyk", "prowler",
    "trivy", "kube-linter", "kube-bench", "datree", "opa",
]


def _gen_commit_queries() -> list[str]:
    queries: list[str] = []

    # Core: verb × issue × tool (most productive shape)
    for verb, issue, tool in product(_FIX_VERBS, _SECURITY_ISSUES, _IAC_TOOLS):
        queries.append(f"{verb} {issue} {tool}")

    # CWE-based
    for cwe, tool in product(_CWE_IDS, _IAC_TOOLS):
        queries.append(f"{cwe} fix {tool}")

    # Scanner-findings-based
    for scanner in _SCANNERS:
        queries.append(f"fix {scanner}")
        queries.append(f"{scanner} failed fix")
        queries.append(f"{scanner} finding fix")

    # Rule-ID-prefix queries (very targeted)
    for prefix in ["CKV_AWS_", "CKV_K8S_", "CKV_DOCKER_", "AVD-AWS-",
                   "AVD-KSV-", "AVD-DS-", "KICS-"]:
        queries.append(f"{prefix} fix")

    # Deduplicate while preserving order
    seen: set = set()
    out: list[str] = []
    for q in queries:
        if q not in seen:
            seen.add(q)
            out.append(q)
    return out


def _gen_code_queries() -> list[str]:
    # Format: (pattern, github_search_qualifier)
    patterns: list[str] = []

    tf_patterns = [
        'acl = "public-read" extension:tf',
        'acl = "public-read-write" extension:tf',
        'cidr_blocks = ["0.0.0.0/0"] extension:tf',
        'ipv6_cidr_blocks = ["::/0"] extension:tf',
        'encrypted = false extension:tf',
        'storage_encrypted = false extension:tf',
        'publicly_accessible = true extension:tf',
        'skip_final_snapshot = true extension:tf',
        'block_public_acls = false extension:tf',
        'block_public_policy = false extension:tf',
        'password = extension:tf NOT var NOT variable',
        'access_key = extension:tf NOT var',
        'secret_key = extension:tf NOT var',
        'kms_key_id = "" extension:tf',
        'versioning { enabled = false } extension:tf',
        'min_tls_version = "TLS_1_0" extension:tf',
    ]
    patterns.extend(tf_patterns)

    k8s_patterns = [
        'privileged: true extension:yaml path:kubernetes',
        'privileged: true extension:yaml path:k8s',
        'privileged: true extension:yaml path:manifests',
        'runAsUser: 0 extension:yaml',
        'runAsNonRoot: false extension:yaml',
        'allowPrivilegeEscalation: true extension:yaml',
        'readOnlyRootFilesystem: false extension:yaml',
        'hostNetwork: true extension:yaml',
        'hostPID: true extension:yaml',
        'hostIPC: true extension:yaml',
        'automountServiceAccountToken: true extension:yaml',
        'capabilities:\n    add:\n      - ALL extension:yaml',
    ]
    patterns.extend(k8s_patterns)

    docker_patterns = [
        'USER root filename:Dockerfile',
        'FROM ubuntu:latest filename:Dockerfile',
        'FROM debian:latest filename:Dockerfile',
        'FROM alpine:latest filename:Dockerfile',
        'FROM node:latest filename:Dockerfile',
        'FROM python:latest filename:Dockerfile',
        'ADD http filename:Dockerfile',
        'ADD https filename:Dockerfile',
        'sudo apt filename:Dockerfile',
        'curl http filename:Dockerfile',
        'wget http filename:Dockerfile',
    ]
    patterns.extend(docker_patterns)

    ansible_patterns = [
        'no_log: false extension:yml path:roles',
        'become: true extension:yml path:playbooks',
        'validate_certs: no extension:yml',
        'state: present password= extension:yml',
    ]
    patterns.extend(ansible_patterns)

    cfn_patterns = [
        '"PubliclyAccessible": true extension:json',
        '"Encrypted": false extension:json',
        '"CidrIp": "0.0.0.0/0" extension:yaml',
        'PubliclyAccessible: true extension:yaml',
    ]
    patterns.extend(cfn_patterns)

    seen: set = set()
    out: list[str] = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


COMMIT_SEARCH_QUERIES = _gen_commit_queries()
CODE_SEARCH_QUERIES   = _gen_code_queries()

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
    "cors_wildcard": {
        "cwe": "CWE-942", "severity": "MEDIUM", "category": "Security",
        "checkov_ids": ["CKV_AWS_65"],
    },
    "weak_hash": {
        "cwe": "CWE-327", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_AWS_145"],
    },
    "plaintext_protocol": {
        "cwe": "CWE-319", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_AWS_103"],
    },
    "deletion_protection_disabled": {
        "cwe": "CWE-693", "severity": "MEDIUM", "category": "Configuration Data",
        "checkov_ids": ["CKV_AWS_28"],
    },
    "backup_disabled": {
        "cwe": "CWE-693", "severity": "MEDIUM", "category": "Configuration Data",
        "checkov_ids": ["CKV_AWS_118"],
    },
    "no_mfa": {
        "cwe": "CWE-308", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_AWS_171"],
    },
    "image_pull_policy_not_always": {
        "cwe": "CWE-1357", "severity": "LOW", "category": "Dependency",
        "checkov_ids": ["CKV_K8S_15"],
    },
    "readiness_probe_missing": {
        "cwe": "CWE-754", "severity": "LOW", "category": "Configuration Data",
        "checkov_ids": ["CKV_K8S_9"],
    },
    "liveness_probe_missing": {
        "cwe": "CWE-754", "severity": "LOW", "category": "Configuration Data",
        "checkov_ids": ["CKV_K8S_8"],
    },
    "read_only_fs_disabled": {
        "cwe": "CWE-732", "severity": "MEDIUM", "category": "Security",
        "checkov_ids": ["CKV_K8S_22"],
    },
    "service_account_token_auto_mount": {
        "cwe": "CWE-250", "severity": "MEDIUM", "category": "Security",
        "checkov_ids": ["CKV_K8S_38"],
    },
    "uri_credentials": {
        "cwe": "CWE-798", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_SECRET_*"],
    },
    "latest_image_tag": {
        "cwe": "CWE-1357", "severity": "MEDIUM", "category": "Dependency",
        "checkov_ids": ["CKV_DOCKER_7"],
    },
    "missing_healthcheck": {
        "cwe": "CWE-754", "severity": "LOW", "category": "Configuration Data",
        "checkov_ids": ["CKV_DOCKER_2"],
    },
    "apt_no_install_recommends": {
        "cwe": "CWE-1357", "severity": "LOW", "category": "Dependency",
        "checkov_ids": ["CKV_DOCKER_9"],
    },
    "host_namespace_shared": {
        "cwe": "CWE-250", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_K8S_1", "CKV_K8S_2", "CKV_K8S_3"],
    },
    "capabilities_added": {
        "cwe": "CWE-250", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_K8S_37"],
    },
    "imds_v1": {
        "cwe": "CWE-862", "severity": "HIGH", "category": "Security",
        "checkov_ids": ["CKV_AWS_79"],
    },
    "ssh_port_open_world": {
        "cwe": "CWE-732", "severity": "CRITICAL", "category": "Security",
        "checkov_ids": ["CKV_AWS_24"],
    },
    "rdp_port_open_world": {
        "cwe": "CWE-732", "severity": "CRITICAL", "category": "Security",
        "checkov_ids": ["CKV_AWS_25"],
    },
    "validate_certs_disabled": {
        "cwe": "CWE-295", "severity": "HIGH", "category": "Security",
        "checkov_ids": [],
    },
    "become_root": {
        "cwe": "CWE-250", "severity": "MEDIUM", "category": "Security",
        "checkov_ids": [],
    },
    "no_log_disabled": {
        "cwe": "CWE-532", "severity": "MEDIUM", "category": "Security",
        "checkov_ids": [],
    },
}

# ---------------------------------------------------------------------------
# Dataset split ratios
# ---------------------------------------------------------------------------
SPLIT_RATIOS = {"train": 0.80, "val": 0.10, "test": 0.10}
