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
        r'"Action"\s*:\s*["\*"]',
        r'"Resource"\s*:\s*["\*"]',
        r'actions\s*=\s*\["[*]"\]',
        r'resources\s*=\s*\["[*]"\]',
        r'effect\s*=\s*["\']Allow["\'].*actions.*\*',
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
