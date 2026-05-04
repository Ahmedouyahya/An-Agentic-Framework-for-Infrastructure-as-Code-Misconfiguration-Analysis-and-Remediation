#!/usr/bin/env python3
"""
Command-line entry point for the IaC security agent.

Useful for demos:
  python3 scripts/run_agent.py analyze dataset/terraform/insecure_s3.tf
  python3 scripts/run_agent.py analyze dataset/docker/Dockerfile.node_api_insecure --json
  python3 scripts/run_agent.py full dataset/terraform/insecure_s3.tf --model deepseek-v4-flash
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

from analyzer.contextual import ContextualAnalyzer


class LimitedAnalyzer:
    """Wrap an analyzer and keep only the first N findings for focused demos."""

    def __init__(self, analyzer: ContextualAnalyzer, max_smells: int | None):
        self.analyzer = analyzer
        self.max_smells = max_smells

    def analyze(self, script_path: Path) -> dict:
        result = self.analyzer.analyze(script_path)
        if self.max_smells is not None:
            result["smells"] = result["smells"][: self.max_smells]
        return result


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def _print_analysis(result: dict, path: Path) -> None:
    print(f"File: {_relative(path)}")
    print(f"Tool: {result['tool']}")
    print(
        "Metrics: "
        f"{result['metrics']['line_count']} lines, "
        f"{result['metrics']['token_count']} tokens, "
        f"{result['metrics']['comment_lines']} comment lines"
    )
    print(f"Findings: {len(result['smells'])}")

    if not result["smells"]:
        print("No security smells detected.")
        return

    for idx, smell in enumerate(result["smells"], 1):
        checker = smell.get("checker_id") or "UNKNOWN"
        cwe = smell.get("cwe") or "CWE pending"
        line = smell.get("line") or "?"
        kind = smell.get("type") or "unknown"
        desc = smell.get("description") or "No description"
        print(f"{idx:02d}. line {line} [{checker}] {kind} ({cwe})")
        print(f"    {desc}")


def analyze(args: argparse.Namespace) -> int:
    path = Path(args.file).resolve()
    if not path.exists():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 2

    result = ContextualAnalyzer().analyze(path)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_analysis(result, path)
    return 0


def full(args: argparse.Namespace) -> int:
    path = Path(args.file).resolve()
    if not path.exists():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 2

    try:
        from agent.orchestrator import CentralAgent
        from formatter.patch_formatter import PatchFormatter
        from generator.fix_generator import FixGenerator
        from knowledge.knowledge_base import KnowledgeBase
        from knowledge.retriever import KnowledgeRetriever
        from validator.tool_integrator import ExternalToolValidator
    except ImportError as exc:
        print(f"ERROR: missing dependency: {exc}", file=sys.stderr)
        print("Install dependencies with: pip install -r requirements.txt", file=sys.stderr)
        return 2

    kb = KnowledgeBase(persist_dir=str(ROOT / "chroma_db"))
    kb.build()

    agent = CentralAgent(
        analyzer=LimitedAnalyzer(ContextualAnalyzer(), args.max_smells),
        retriever=KnowledgeRetriever(kb),
        generator=FixGenerator(args.model, self_consistency=not args.no_self_consistency),
        validator=ExternalToolValidator(),
        formatter=PatchFormatter(),
    )
    result = agent.run(path)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result["success"] else 1

    print(f"File: {_relative(path)}")
    print(f"Success: {result['success']}")
    print(f"Detected smells: {len(result['smells'])}")
    print()
    print(result["explanation"])
    if result.get("patch"):
        print("\n--- Patch ---")
        print(result["patch"])
    return 0 if result["success"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze IaC files and optionally run the full validated remediation agent."
    )
    parser.add_argument("--verbose", action="store_true", help="Enable info logging.")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_cmd = sub.add_parser("analyze", help="Detect IaC tool and security smells.")
    analyze_cmd.add_argument("file", help="Path to Terraform, Ansible, Kubernetes, or Dockerfile input.")
    analyze_cmd.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    analyze_cmd.set_defaults(func=analyze)

    full_cmd = sub.add_parser("full", help="Run analyze -> retrieve -> generate -> validate -> format.")
    full_cmd.add_argument("file", help="Path to Terraform, Ansible, Kubernetes, or Dockerfile input.")
    full_cmd.add_argument("--model", default=None, help="LLM model name. Defaults to backend env vars.")
    full_cmd.add_argument("--no-self-consistency", action="store_true", help="Generate one patch instead of N samples.")
    full_cmd.add_argument("--max-smells", type=int, default=None, help="Only send the first N detected findings to the generator.")
    full_cmd.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    full_cmd.set_defaults(func=full)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s | %(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
