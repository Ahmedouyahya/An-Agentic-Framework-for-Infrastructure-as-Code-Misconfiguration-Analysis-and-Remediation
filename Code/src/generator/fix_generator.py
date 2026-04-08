"""
Fix Generator (LLM-based)
--------------------------
Calls an LLM (OpenAI-compatible API) with a structured prompt that includes:
  - The original IaC script
  - The detected smells
  - The RAG context from the Knowledge Retriever

Supported backends (detected from environment variables, in priority order):
  ANTHROPIC_API_KEY   → Anthropic Claude
  OPENROUTER_API_KEY  → OpenRouter (free models: Llama, Mistral, MiniMax, Gemma…)
  MINIMAX_API_KEY     → MiniMax API directly
  OPENAI_API_KEY      → OpenAI

Returns one or more candidate patch strings (unified diff format).
Confidence filtering is applied (SecLLM-inspired).
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security expert specializing in Infrastructure as Code (IaC).
Your task is to fix security vulnerabilities in IaC scripts.
Rules:
- Output ONLY valid unified diff format (--- original / +++ fixed).
- Make the minimal change necessary to fix the reported smell.
- Do not introduce new features or refactor unrelated code.
- After the diff, output a confidence score: CONFIDENCE: 0.0-1.0
"""

FIX_PROMPT_TEMPLATE = """
## IaC Tool
{iac_tool}

## Detected Security Smells
{smells}

## Relevant Security Knowledge
{rag_context}

## Original Script
```
{script_content}
```

Generate a unified diff patch that fixes ALL listed smells. Output the diff only.
"""

CONFIDENCE_THRESHOLD = 0.6

# Default model for each backend when no explicit model is configured
_BACKEND_DEFAULTS = {
    "anthropic":  "claude-sonnet-4-6",
    "openrouter": "meta-llama/llama-3.1-8b-instruct:free",
    "minimax":    "MiniMax-Text-01",
    "openai":     "gpt-4o-mini",
}

# OpenRouter base URL (OpenAI-compatible)
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# MiniMax base URL (OpenAI-compatible)
MINIMAX_BASE_URL = "https://api.minimax.chat/v1"


class FixGenerator:
    """
    Wraps an LLM client to generate IaC security patches.

    Backend is selected automatically from environment variables:
      ANTHROPIC_API_KEY   → Anthropic
      OPENROUTER_API_KEY  → OpenRouter (many free models including MiniMax, Llama, Mistral)
      MINIMAX_API_KEY     → MiniMax directly
      OPENAI_API_KEY      → OpenAI fallback

    The `model` parameter specifies the model name for the active backend.
    Pass None to use the backend's default (e.g. the free Llama-3.1-8B on OpenRouter).

    Examples:
      FixGenerator()                                   # auto-detect, use default model
      FixGenerator("minimax/minimax-01")               # OpenRouter, MiniMax model
      FixGenerator("mistralai/mistral-7b-instruct:free")  # OpenRouter, free Mistral
      FixGenerator("MiniMax-Text-01")                  # MiniMax direct API
      FixGenerator("gpt-4o-mini")                      # OpenAI
    """

    def __init__(self, model: str | None = None):
        self.model = model  # None = use backend default
        self._backend = self._detect_backend()
        effective = self._effective_model()
        logger.info("FixGenerator backend=%s model=%s", self._backend, effective)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, script_path: Path, smells: list[dict], rag_context: str) -> list[str]:
        """
        Returns a list of candidate patches (strings, unified diff format),
        filtered by confidence threshold.
        """
        script_content = script_path.read_text(errors="replace")
        iac_tool = self._guess_tool(script_path)

        smells_text = "\n".join(
            f"- Line {s.get('line', '?')}: {s.get('description', s.get('type', ''))} [{s.get('cwe', '')}]"
            for s in smells
        )

        user_prompt = FIX_PROMPT_TEMPLATE.format(
            iac_tool=iac_tool,
            smells=smells_text,
            rag_context=rag_context,
            script_content=script_content,
        )

        raw_response = self._call_llm(user_prompt)
        return self._parse_response(raw_response)

    # ------------------------------------------------------------------
    # Backend detection
    # ------------------------------------------------------------------

    def _detect_backend(self) -> str:
        if os.getenv("ANTHROPIC_API_KEY"):
            return "anthropic"
        if os.getenv("OPENROUTER_API_KEY"):
            return "openrouter"
        if os.getenv("MINIMAX_API_KEY"):
            return "minimax"
        return "openai"

    def _effective_model(self) -> str:
        """Return the model to actually use, falling back to backend default."""
        if self.model:
            return self.model
        return _BACKEND_DEFAULTS[self._backend]

    # ------------------------------------------------------------------
    # LLM dispatch
    # ------------------------------------------------------------------

    def _call_llm(self, user_prompt: str) -> str:
        if self._backend == "anthropic":
            return self._call_anthropic(user_prompt)
        if self._backend == "openrouter":
            return self._call_openai_compatible(
                user_prompt,
                base_url=OPENROUTER_BASE_URL,
                api_key=os.environ["OPENROUTER_API_KEY"],
                extra_headers={
                    "HTTP-Referer": "https://github.com/pfe-iac-security",
                    "X-Title": "IaC Security Framework",
                },
            )
        if self._backend == "minimax":
            return self._call_openai_compatible(
                user_prompt,
                base_url=MINIMAX_BASE_URL,
                api_key=os.environ["MINIMAX_API_KEY"],
            )
        return self._call_openai(user_prompt)

    def _call_openai(self, user_prompt: str) -> str:
        from openai import OpenAI
        client = OpenAI()
        response = client.chat.completions.create(
            model=self._effective_model(),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content or ""

    def _call_openai_compatible(
        self,
        user_prompt: str,
        base_url: str,
        api_key: str,
        extra_headers: dict | None = None,
    ) -> str:
        from openai import OpenAI
        client = OpenAI(base_url=base_url, api_key=api_key)
        kwargs: dict = dict(
            model=self._effective_model(),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=0.2,
        )
        if extra_headers:
            kwargs["extra_headers"] = extra_headers
        response = client.chat.completions.create(**kwargs)
        return response.choices[0].message.content or ""

    def _call_anthropic(self, user_prompt: str) -> str:
        import anthropic
        client = anthropic.Anthropic()
        response = client.messages.create(
            model=self._effective_model(),
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, raw: str) -> list[str]:
        """Extract diff block and apply confidence filter."""
        conf_match = re.search(r"CONFIDENCE:\s*([\d.]+)", raw)
        confidence = float(conf_match.group(1)) if conf_match else 1.0

        if confidence < CONFIDENCE_THRESHOLD:
            logger.warning(
                "Patch confidence %.2f below threshold %.2f, skipping.",
                confidence, CONFIDENCE_THRESHOLD,
            )
            return []

        diff_match = re.search(r"(---\s+.+?(?=\Z|\n\n\n))", raw, re.DOTALL)
        if diff_match:
            return [diff_match.group(1).strip()]
        if raw.strip():
            return [raw.strip()]
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _guess_tool(self, path: Path) -> str:
        if path.suffix == ".tf":
            return "terraform"
        if "ansible" in str(path) or path.suffix in (".yml", ".yaml"):
            return "ansible/kubernetes"
        if "docker" in path.name.lower():
            return "docker"
        return "unknown"
