"""
Central Agent (Orchestrator)
----------------------------
Heart of the agentic framework. Receives an IaC script, drives the full
analysis → retrieval → generation → validation → formatting loop, and
retries up to MAX_RETRIES times if a generated patch fails validation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

MAX_RETRIES = 3


@dataclass
class AgentState:
    """Carries workflow state across pipeline stages."""
    script_path: Path
    iac_tool: str = ""                    # e.g. "terraform", "ansible", "kubernetes"
    detected_smells: list[dict] = field(default_factory=list)
    rag_context: str = ""
    proposed_patches: list[str] = field(default_factory=list)
    validated_patch: Optional[str] = None
    explanation: str = ""
    retry_count: int = 0


class CentralAgent:
    """
    Orchestrates the six pipeline modules in sequence:
      Contextual Analyzer → Knowledge Retriever → Fix Generator
      → External Validator → (retry if invalid) → Patch Formatter
    """

    def __init__(self, analyzer, retriever, generator, validator, formatter):
        self.analyzer = analyzer
        self.retriever = retriever
        self.generator = generator
        self.validator = validator
        self.formatter = formatter

    def run(self, script_path: str | Path) -> dict:
        """
        Entry point. Returns a dict with keys:
          - 'patch'       : unified diff string (or None if all retries failed)
          - 'explanation' : natural language explanation with CWE references
          - 'smells'      : list of detected smell dicts
          - 'success'     : bool
        """
        state = AgentState(script_path=Path(script_path))
        logger.info("Starting analysis of %s", state.script_path)

        # Stage 1 – Contextual analysis
        analysis = self.analyzer.analyze(state.script_path)
        state.iac_tool = analysis["tool"]
        state.detected_smells = analysis["smells"]
        logger.info("Detected %d smell(s) in %s script", len(state.detected_smells), state.iac_tool)

        if not state.detected_smells:
            return {"patch": None, "explanation": "No security smells detected.", "smells": [], "success": True}

        # Stage 2 – RAG retrieval
        state.rag_context = self.retriever.retrieve(state.detected_smells, state.iac_tool)

        # Stage 3-5 – Generate → Validate → (Retry loop)
        for attempt in range(1, MAX_RETRIES + 1):
            state.retry_count = attempt
            logger.info("Patch attempt %d/%d", attempt, MAX_RETRIES)

            patches = self.generator.generate(
                script_path=state.script_path,
                smells=state.detected_smells,
                rag_context=state.rag_context,
            )

            for patch in patches:
                result = self.validator.validate(
                    original_path=state.script_path,
                    patch=patch,
                    smells=state.detected_smells,
                )
                if result["valid"]:
                    state.validated_patch = patch
                    break

            if state.validated_patch:
                break

            # Adjust RAG query on retry
            logger.warning("Patch invalid on attempt %d, refining RAG query...", attempt)
            state.rag_context = self.retriever.retrieve(
                state.detected_smells, state.iac_tool, retry=attempt
            )

        # Stage 6 – Format output
        if state.validated_patch:
            formatted = self.formatter.format(
                original_path=state.script_path,
                patch=state.validated_patch,
                smells=state.detected_smells,
            )
            return {
                "patch": formatted["diff"],
                "explanation": formatted["explanation"],
                "smells": state.detected_smells,
                "success": True,
            }

        logger.error("All %d attempts failed to produce a valid patch.", MAX_RETRIES)
        return {
            "patch": None,
            "explanation": f"Could not generate a validated patch after {MAX_RETRIES} attempts.",
            "smells": state.detected_smells,
            "success": False,
        }
