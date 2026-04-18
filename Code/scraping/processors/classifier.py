"""
IaC tool type detector and security smell classifier.

Given a file path + content (or a unified diff), returns:
  - iac_tool: terraform | ansible | kubernetes | docker | cloudformation | unknown
  - smells:   list[SmellAnnotation]

The classifier uses regex pattern matching against the smell taxonomy in config.py.
It is intentionally conservative: false negatives are better than false positives
because downstream Checkov validation will catch real issues.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

from scraping.config import SMELL_TAXONOMY
from scraping.schemas import SmellAnnotation

# ---------------------------------------------------------------------------
# IaC tool detection
# ---------------------------------------------------------------------------

# Patterns that strongly indicate Kubernetes (checked before Ansible since both use YAML)
_K8S_MARKERS = re.compile(
    r"(^apiVersion:\s*(apps|batch|rbac\.authorization|networking|policy)/|"
    r"^kind:\s*(Deployment|Pod|Service|Ingress|ConfigMap|Secret|DaemonSet|"
    r"StatefulSet|ReplicaSet|Job|CronJob|ClusterRole|Role|RoleBinding|"
    r"NetworkPolicy|PersistentVolumeClaim)\b)",
    re.MULTILINE,
)

_CLOUDFORMATION_MARKERS = re.compile(
    r"(^AWSTemplateFormatVersion:|^Resources:\s*$|Type:\s*AWS::)",
    re.MULTILINE,
)

_ANSIBLE_MARKERS = re.compile(
    r"(^-\s+name:|^\s+hosts:|^\s+tasks:|^\s+become:|ansible\.builtin\.)",
    re.MULTILINE,
)

_TERRAFORM_MARKERS = re.compile(
    r'(^resource\s+"[a-z][a-z0-9_]+"|\bprovider\s+"[a-z][a-z0-9_-]*"|\bterraform\s*\{|'
    r'\bdata\s+"[a-z][a-z0-9_]+"\s+"[a-z][a-z0-9_]+")',
    re.MULTILINE,
)

_DOCKER_FIRST_LINE = re.compile(r"^\s*(FROM|ARG)\s+\S", re.IGNORECASE)


def detect_iac_tool(file_path: str, content: str = "") -> str:
    """
    Return the IaC tool type for a given file path and content.
    Falls back to 'unknown' if not recognizable.
    """
    p = Path(file_path)
    name = p.name.lower()
    suffix = p.suffix.lower()

    # Dockerfile by name
    if "dockerfile" in name or suffix == ".dockerfile":
        return "docker"

    # Terraform by extension
    if suffix in (".tf", ".tfvars"):
        return "terraform"

    if content:
        # CloudFormation (check before Ansible — both use YAML)
        if _CLOUDFORMATION_MARKERS.search(content):
            return "cloudformation"
        # Kubernetes (check before Ansible — both use YAML)
        if _K8S_MARKERS.search(content):
            return "kubernetes"
        # Ansible
        if _ANSIBLE_MARKERS.search(content):
            return "ansible"
        # Terraform (can be .txt or renamed)
        if _TERRAFORM_MARKERS.search(content):
            return "terraform"
        # Dockerfile by first line
        if _DOCKER_FIRST_LINE.match(content.lstrip()):
            return "docker"

    # YAML files: try extension heuristic if content empty
    if suffix in (".yml", ".yaml"):
        # Without content we can't be sure, but lean toward kubernetes for paths
        # containing k8s/kubernetes, ansible for playbooks, etc.
        parts = {p.lower() for p in Path(file_path).parts}
        if parts & {"kubernetes", "k8s", "manifests", "charts", "helm"}:
            return "kubernetes"
        if parts & {"ansible", "playbooks", "roles", "tasks"}:
            return "ansible"
        return "unknown"

    return "unknown"


def is_iac_file(file_path: str, content: str = "") -> bool:
    """Return True if the file is a recognizable IaC file."""
    return detect_iac_tool(file_path, content) != "unknown"


# ---------------------------------------------------------------------------
# Smell patterns — keyed by smell type (matches SMELL_TAXONOMY keys)
# Each entry: list of (regex, optional line-number extraction group)
# Patterns match on REMOVED lines from a diff, or on full file content.
# ---------------------------------------------------------------------------

_RAW_PATTERNS: List[Tuple[str, List[str]]] = [
    ("hardcoded_password", [
        r'password\s*[=:]\s*["\'][^"\'$\{\}\s]{3,}["\']',
        r'passwd\s*[=:]\s*["\'][^"\'$\{\}\s]{3,}["\']',
        r'db_password\s*=\s*["\'][^"\'$]{3,}["\']',
        r'MYSQL_ROOT_PASSWORD\s*[:=]\s*["\'][^"\'$]{3,}["\']',
    ]),
    ("hardcoded_credential", [
        r'access_key\s*=\s*["\'][A-Z0-9]{16,}["\']',
        r'secret_key\s*=\s*["\'][^"\'$\{\}\s]{16,}["\']',
        r'aws_access_key_id\s*=\s*["\'][A-Z0-9]{20}["\']',
        r'aws_secret_access_key\s*=\s*["\'][^"\'$]{30,}["\']',
        r'api_key\s*=\s*["\'][^"\'$\{\}\s]{16,}["\']',
        r'token\s*=\s*["\'][^"\'$\{\}\s]{16,}["\']',
        r'private_key\s*=\s*["\'][^"\'$\{\}\s]{10,}["\']',
    ]),
    ("overly_permissive_cidr", [
        r'0\.0\.0\.0/0',
        r'::/0',
        r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]',
        r'ipv6_cidr_blocks\s*=\s*\["::/0"\]',
    ]),
    ("overly_permissive_acl", [
        r'acl\s*=\s*["\']public-read["\']',
        r'acl\s*=\s*["\']public-read-write["\']',
        r'acl\s*=\s*["\']authenticated-read["\']',
    ]),
    ("privileged_container", [
        r'privileged\s*:\s*true',
        r'"Privileged"\s*:\s*true',
        r'privileged\s*=\s*true',
    ]),
    ("root_user", [
        r'^\s*USER\s+root\s*$',
        r'runAsUser\s*:\s*0\b',
        r'runAsNonRoot\s*:\s*false',
    ]),
    ("allow_privilege_escalation", [
        r'allowPrivilegeEscalation\s*:\s*true',
    ]),
    ("missing_encryption", [
        r'encrypted\s*=\s*false',
        r'enable_encryption\s*=\s*false',
        r'storage_encrypted\s*=\s*false',
        r'kms_key_id\s*=\s*["\']["\']',   # empty kms key
    ]),
    ("public_access_block_disabled", [
        r'block_public_acls\s*=\s*false',
        r'block_public_policy\s*=\s*false',
        r'ignore_public_acls\s*=\s*false',
        r'restrict_public_buckets\s*=\s*false',
    ]),
    ("versioning_disabled", [
        r'versioning\s*\{[^}]*enabled\s*=\s*false',
    ]),
    ("logging_disabled", [
        r'logging\s*=\s*false',
        r'enable_logging\s*=\s*false',
        r'access_log\s*\{\s*\}',
    ]),
    ("insecure_tls", [
        r'ssl_policy\s*=\s*["\']ELBSecurityPolicy-2015-05["\']',
        r'minimum_protocol_version\s*=\s*["\']TLSv1["\']',
        r'tls_version\s*=\s*["\']TLS1_0["\']',
        r'min_tls_version\s*=\s*["\']TLS_1_0["\']',
    ]),
    ("missing_resource_limits", [
        r'resources\s*:\s*\{\}',
        r'resources\s*:\s*$',  # empty resources block in YAML
    ]),
    ("unpinned_base_image", [
        r'FROM\s+\S+:latest\b',
        r'FROM\s+(?!scratch)\S+\s*$',    # FROM with no tag at all
    ]),
    ("secrets_in_env", [
        r'env\s*:\s*\n\s+-\s+name:\s+\w*(PASSWORD|SECRET|KEY|TOKEN)\w*\s*\n\s+value:\s*\S+',
        r'ENV\s+\w*(PASSWORD|SECRET|KEY|TOKEN)\w*\s*=\s*[^\$\{\}\n]+',
        r'SECRET\s*=\s*["\'][^"\'$\{\}]{6,}["\']',
    ]),
    ("overly_permissive_iam", [
        r'"Action"\s*:\s*"\*"',
        r'"Action"\s*:\s*\[\s*"\*"\s*\]',
        r'"Resource"\s*:\s*"\*"',
        r'"Resource"\s*:\s*\[\s*"\*"\s*\]',
        r'actions\s*=\s*\[\s*"\*"\s*\]',
        r'resources\s*=\s*\[\s*"\*"\s*\]',
        r'effect\s*=\s*["\']Allow["\'].*actions.*\*',
        r'apiGroups\s*:\s*\[\s*["\']?\*["\']?\s*\]',
        r'verbs\s*:\s*\[\s*["\']?\*["\']?\s*\]',
    ]),
    # --- new smells ----------------------------------------------------------
    ("cors_wildcard", [
        r'allowed_origins\s*=\s*\[\s*["\']\*["\']\s*\]',
        r'"AllowedOrigins"\s*:\s*\[\s*"\*"\s*\]',
        r'allowedOrigins\s*:\s*\[\s*["\']?\*["\']?\s*\]',
        r'Access-Control-Allow-Origin[:=]\s*["\']?\*',
    ]),
    ("weak_hash", [
        r'\b(md5|sha1)\s*\(',
        r'["\'](md5|sha1)["\']',
        r'digest\s*[:=]\s*["\']?(md5|sha1)\b',
        r'signature_algorithm\s*=\s*["\']?(md5|sha1)\w*["\']?',
    ]),
    ("plaintext_protocol", [
        r'https?://[^/\s"\']*:[^/\s"\']+@',  # URI creds (also matched by uri_credentials)
        r'protocol\s*=\s*["\']HTTP["\']',
        r'"Protocol"\s*:\s*"HTTP"',
        r'use_https\s*=\s*false',
        r'enforce_ssl\s*=\s*false',
        r'force_ssl\s*=\s*false',
        r'insecure\s*[:=]\s*true',
    ]),
    ("deletion_protection_disabled", [
        r'deletion_protection\s*=\s*false',
        r'enable_deletion_protection\s*=\s*false',
        r'"DeletionProtection"\s*:\s*false',
    ]),
    ("backup_disabled", [
        r'backup_retention_period\s*=\s*0\b',
        r'backup_retention_days\s*=\s*0\b',
        r'"BackupRetentionPeriod"\s*:\s*0\b',
        r'point_in_time_recovery\s*\{[^}]*enabled\s*=\s*false',
        r'skip_final_snapshot\s*=\s*true',
    ]),
    ("no_mfa", [
        r'mfa_delete\s*=\s*false',
        r'"MFADelete"\s*:\s*"Disabled"',
        r'require_mfa\s*=\s*false',
    ]),
    ("image_pull_policy_not_always", [
        r'imagePullPolicy\s*:\s*(IfNotPresent|Never)\b',
    ]),
    # readiness/liveness "absence" checks are unreliable and catastrophic with
    # regex on large files. Deliberately delegated to Checkov (CKV_K8S_8/9).
    ("read_only_fs_disabled", [
        r'readOnlyRootFilesystem\s*:\s*false',
    ]),
    ("service_account_token_auto_mount", [
        r'automountServiceAccountToken\s*:\s*true',
    ]),
    ("uri_credentials", [
        r'(postgres|postgresql|mysql|mongodb|redis|amqp|jdbc:[a-z]+)://[^/\s"\']+:[^/\s"\']+@',
        r'smtp://[^/\s"\']+:[^/\s"\']+@',
        r'ftp://[^/\s"\']+:[^/\s"\']+@',
    ]),
    ("latest_image_tag", [
        r'image\s*:\s*\S+:latest\b',
        r'FROM\s+\S+:latest\b',
    ]),
    # "missing HEALTHCHECK" is delegated to Checkov (CKV_DOCKER_2); whole-file
    # negative regex is too fragile to keep here.
    ("apt_no_install_recommends", [
        r'apt-get\s+install\s+(?!.*--no-install-recommends)',
    ]),
    ("host_namespace_shared", [
        r'hostNetwork\s*:\s*true',
        r'hostPID\s*:\s*true',
        r'hostIPC\s*:\s*true',
    ]),
    ("capabilities_added", [
        # Line-based patterns, no catastrophic backtracking
        r'^\s+-\s+(ALL|SYS_ADMIN|NET_ADMIN|NET_RAW|SYS_PTRACE|SYS_MODULE)\s*$',
        r'"Capabilities"\s*:.*?"(ALL|SYS_ADMIN|NET_ADMIN|NET_RAW)"',
    ]),
    ("imds_v1", [
        r'http_tokens\s*=\s*["\']optional["\']',
        r'"HttpTokens"\s*:\s*"optional"',
    ]),
    ("ssh_port_open_world", [
        r'from_port\s*=\s*22\b[^}]*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"',
        r'"FromPort"\s*:\s*22\b[\s\S]{0,400}"CidrIp"\s*:\s*"0\.0\.0\.0/0"',
    ]),
    ("rdp_port_open_world", [
        r'from_port\s*=\s*3389\b[^}]*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"',
        r'"FromPort"\s*:\s*3389\b[\s\S]{0,400}"CidrIp"\s*:\s*"0\.0\.0\.0/0"',
    ]),
    ("validate_certs_disabled", [
        r'validate_certs\s*:\s*(no|false)',
        r'verify\s*=\s*False\b',
        r'ssl_verify\s*=\s*false',
        r'insecure_skip_verify\s*=\s*true',
    ]),
    ("become_root", [
        r'become\s*:\s*(yes|true)\b[\s\S]{0,200}become_user\s*:\s*root',
    ]),
    ("no_log_disabled", [
        r'no_log\s*:\s*(no|false)\b',
    ]),
    # Expanded insecure_tls coverage
    ("insecure_tls", [
        r'ssl_policy\s*=\s*["\']ELBSecurityPolicy-(2015|2016)',
        r'minimum_protocol_version\s*=\s*["\']TLSv1(\.1)?["\']',
        r'tls_version\s*=\s*["\']TLS1_[01]["\']',
        r'min_tls_version\s*=\s*["\']TLS_1_[01]["\']',
        r'minimumTlsVersion\s*[:=]\s*["\']?(1\.0|1\.1|TLS1_[01])',
        r'sslProtocols?\s*[:=].*(SSLv[23]|TLSv1\.0|TLSv1\.1)',
    ]),
    # Expanded missing_encryption
    ("missing_encryption", [
        r'encrypted\s*=\s*false',
        r'enable_encryption\s*=\s*false',
        r'storage_encrypted\s*=\s*false',
        r'kms_key_id\s*=\s*["\']["\']',
        r'"Encrypted"\s*:\s*false',
        r'server_side_encryption_configuration\s*\{[^}]*rule[^}]*sse_algorithm\s*=\s*["\']AES256["\']\s*\}',  # missing kms
        r'at_rest_encryption_enabled\s*=\s*false',
        r'transit_encryption_enabled\s*=\s*false',
    ]),
    # Expanded hardcoded_credential
    ("hardcoded_credential", [
        r'access_key\s*=\s*["\'][A-Z0-9]{16,}["\']',
        r'secret_key\s*=\s*["\'][^"\'$\{\}\s]{16,}["\']',
        r'aws_access_key_id\s*=\s*["\']AKIA[A-Z0-9]{16}["\']',
        r'aws_secret_access_key\s*=\s*["\'][^"\'$]{30,}["\']',
        r'api_key\s*=\s*["\'][^"\'$\{\}\s]{16,}["\']',
        r'token\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']',
        r'bearer\s+[A-Za-z0-9_\-\.]{20,}',
        r'ghp_[A-Za-z0-9]{30,}',
        r'xox[baprs]-[A-Za-z0-9\-]{10,}',
        r'-----BEGIN\s+(RSA|OPENSSH|EC|PGP|DSA|PRIVATE)\s+PRIVATE\s+KEY-----',
    ]),
    # Expanded logging_disabled
    ("logging_disabled", [
        r'logging\s*=\s*false',
        r'enable_logging\s*=\s*false',
        r'"LoggingEnabled"\s*:\s*false',
        r'enable_cloudwatch_logs_exports\s*=\s*\[\s*\]',
        r'access_logs\s*\{[^}]*enabled\s*=\s*false',
        r'audit_logs\s*\{[^}]*enabled\s*=\s*false',
        r'flow_log_config\s*\{[^}]*enabled\s*=\s*false',
    ]),
    # Keep only the cheap/reliable empty-block patterns; "no limits: key"
    # style absence-checks are delegated to Checkov (CKV_K8S_11/13).
    ("missing_resource_limits", [
        r'resources\s*:\s*\{\s*\}',
        r'^\s*resources\s*:\s*$',
    ]),
]

# Compiled pattern list
_COMPILED_PATTERNS: List[Tuple[str, List[re.Pattern]]] = [
    (smell_type, [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns])
    for smell_type, patterns in _RAW_PATTERNS
]


def classify_smells(content: str, use_removed_lines_only: bool = False) -> List[SmellAnnotation]:
    """
    Classify security smells in IaC content.

    Args:
        content: Full file content OR a unified diff.
        use_removed_lines_only: If True (diff mode), only scan lines starting with '-'.

    Returns:
        List of SmellAnnotation objects (deduplicated by smell type).
    """
    if use_removed_lines_only:
        # Extract only removed lines from diff (the "before" state)
        lines = [
            line[1:]  # strip leading '-'
            for line in content.splitlines()
            if line.startswith("-") and not line.startswith("---")
        ]
        scan_text = "\n".join(lines)
    else:
        scan_text = content

    found: List[SmellAnnotation] = []
    seen_types: set = set()

    for smell_type, compiled in _COMPILED_PATTERNS:
        if smell_type in seen_types:
            continue
        tax = SMELL_TAXONOMY.get(smell_type, {})
        for pattern in compiled:
            match = pattern.search(scan_text)
            if match:
                found.append(SmellAnnotation(
                    type=smell_type,
                    cwe=tax.get("cwe"),
                    checkov_id=(tax.get("checkov_ids") or [None])[0],
                    severity=tax.get("severity"),
                    category=tax.get("category"),
                    description=f"Pattern match: {match.group(0)[:80]}",
                ))
                seen_types.add(smell_type)
                break  # one annotation per smell type

    return found


def classify_diff_smells(diff: str) -> Tuple[List[SmellAnnotation], List[SmellAnnotation]]:
    """
    Given a unified diff, return smells present before the fix (removed lines)
    and smells still present after (added lines).

    Returns: (before_smells, after_smells)
    """
    before_smells = classify_smells(diff, use_removed_lines_only=True)

    # Added lines
    added_lines = [
        line[1:]
        for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    after_smells = classify_smells("\n".join(added_lines), use_removed_lines_only=False)
    return before_smells, after_smells
