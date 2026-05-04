"""
Fix Generator (LLM-based)
--------------------------
Calls an LLM with a structured prompt that includes:
  - The original IaC script
  - The detected smells
  - The RAG context from the Knowledge Retriever

Supported backends (detected from environment variables, in priority order):
  ANTHROPIC_API_KEY   → Anthropic Claude
  DEEPSEEK_API_KEY    → DeepSeek (OpenAI-compatible)
  OPENROUTER_API_KEY  → OpenRouter (free models: Llama, Mistral, Gemma…)
  OLLAMA_MODEL        → Local Ollama (e.g. gemma3:4b, qwen2.5-coder:7b)
  OPENAI_API_KEY      → OpenAI

Self-consistency (N=5 samples at T=0.7) replaces log-prob confidence.
Returns one or more candidate patch strings (unified diff format).
"""

from __future__ import annotations

import logging
import os
import re
from collections import Counter
from pathlib import Path

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security expert specializing in Infrastructure as Code (IaC).
Your task is to fix security vulnerabilities in IaC scripts.
Rules:
- Output ONLY valid unified diff format (--- original / +++ fixed).
- Make the minimal change necessary to fix the reported smell.
- Do not introduce new features or refactor unrelated code.
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

CONFIDENCE_THRESHOLD = 0.4

# Default model for each backend when no explicit model is configured
_BACKEND_DEFAULTS = {
    "anthropic":  "claude-sonnet-4-5-20241022",
    "deepseek":   "deepseek-v4-flash",
    "openrouter": "meta-llama/llama-3.1-8b-instruct:free",
    "ollama":     "gemma3:4b",
    "openai":     "gpt-4o-mini",
}

# DeepSeek OpenAI-compatible base URL
DEEPSEEK_BASE_URL = "https://api.deepseek.com"

# OpenRouter base URL (OpenAI-compatible)
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Ollama default base URL (OpenAI-compatible)
OLLAMA_BASE_URL = "http://localhost:11434/v1"

# Self-consistency parameters
SELF_CONSISTENCY_N = 5
SELF_CONSISTENCY_TEMP = 0.7


class FixGenerator:
    """
    Wraps an LLM client to generate IaC security patches.

    Backend is selected automatically from environment variables:
      ANTHROPIC_API_KEY   → Anthropic
      DEEPSEEK_API_KEY    → DeepSeek
      OPENROUTER_API_KEY  → OpenRouter (many free models)
      OLLAMA_MODEL        → Local Ollama instance
      OPENAI_API_KEY      → OpenAI fallback

    The `model` parameter specifies the model name for the active backend.
    Pass None to use the backend's default.

    Examples:
      FixGenerator()                                      # auto-detect, use default model
      FixGenerator("deepseek-v4-flash")                   # DeepSeek fast model
      FixGenerator("gemma3:4b")                           # Ollama local with Gemma 3 4B
      FixGenerator("mistralai/mistral-7b-instruct:free")  # OpenRouter, free Mistral
      FixGenerator("gpt-4o-mini")                         # OpenAI
    """

    def __init__(self, model: str | None = None, self_consistency: bool = True):
        self.model = model
        self._backend = self._detect_backend()
        self._self_consistency = self_consistency
        effective = self._effective_model()
        logger.info("FixGenerator backend=%s model=%s self_consistency=%s",
                     self._backend, effective, self._self_consistency)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, script_path: Path, smells: list[dict], rag_context: str) -> list[str]:
        """
        Returns a list of candidate patches (strings, unified diff format),
        filtered by self-consistency confidence threshold.
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

        if self._self_consistency:
            return self._generate_with_consistency(user_prompt)
        else:
            raw_response = self._call_llm(user_prompt, temperature=0.2)
            patches = self._parse_response(raw_response)
            return patches

    def generate_with_confidence(
        self, script_path: Path, smells: list[dict], rag_context: str
    ) -> list[tuple[str, float]]:
        """
        Like generate(), but returns (patch, confidence) tuples.
        Confidence is the self-consistency score: fraction of N samples
        that produce an equivalent patch after normalisation.
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

        return self._self_consistency_with_scores(user_prompt)

    # ------------------------------------------------------------------
    # Self-consistency logic
    # ------------------------------------------------------------------

    def _generate_with_consistency(self, user_prompt: str) -> list[str]:
        """
        Draw N samples at T=0.7, normalise, pick the most common patch,
        return it only if its consistency score >= threshold.
        """
        results = self._self_consistency_with_scores(user_prompt)
        return [patch for patch, conf in results if conf >= CONFIDENCE_THRESHOLD]

    def _self_consistency_with_scores(self, user_prompt: str) -> list[tuple[str, float]]:
        """
        Draw N samples, normalise each, compute consistency score per unique
        patch, return (patch, confidence) sorted by confidence descending.
        """
        n = SELF_CONSISTENCY_N
        raw_samples = []
        for i in range(n):
            try:
                raw = self._call_llm(user_prompt, temperature=SELF_CONSISTENCY_TEMP)
                patches = self._parse_response(raw)
                if patches:
                    raw_samples.append(patches[0])
                else:
                    raw_samples.append("")
            except Exception as exc:
                logger.warning("Self-consistency sample %d/%d failed: %s", i + 1, n, exc)
                raw_samples.append("")

        # Normalise: strip whitespace, comments, blank lines for comparison
        normalised = [self._normalise_diff(p) for p in raw_samples]

        # Count occurrences of each normalised form
        counts = Counter(normalised)

        # Map back: for each unique normalised form, pick the first raw sample
        seen = set()
        results = []
        for raw, norm in zip(raw_samples, normalised):
            if norm and norm not in seen:
                seen.add(norm)
                confidence = counts[norm] / n
                results.append((raw, confidence))

        results.sort(key=lambda x: -x[1])

        if results:
            logger.info("Self-consistency: best patch confidence=%.1f (%d/%d samples agree)",
                        results[0][1], counts[normalised[0]], n)

        return results

    @staticmethod
    def _normalise_diff(patch: str) -> str:
        """Strip whitespace-only and comment lines for comparison."""
        lines = []
        for line in patch.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            # Collapse whitespace
            lines.append(re.sub(r"\s+", " ", stripped))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Backend detection
    # ------------------------------------------------------------------

    def _detect_backend(self) -> str:
        if os.getenv("ANTHROPIC_API_KEY"):
            return "anthropic"
        if os.getenv("DEEPSEEK_API_KEY"):
            return "deepseek"
        if os.getenv("OPENROUTER_API_KEY"):
            return "openrouter"
        if os.getenv("OLLAMA_MODEL") or self.model and self._looks_like_ollama(self.model):
            return "ollama"
        if os.getenv("OPENAI_API_KEY"):
            return "openai"
        # Default to ollama if nothing is set (local-first)
        return "ollama"

    @staticmethod
    def _looks_like_ollama(model: str) -> bool:
        """Heuristic: ollama models use name:tag format without slashes."""
        return ":" in model and "/" not in model

    def _effective_model(self) -> str:
        """Return the model to actually use, falling back to backend default."""
        if self.model:
            return self.model
        if self._backend == "deepseek":
            return os.getenv("DEEPSEEK_MODEL", _BACKEND_DEFAULTS["deepseek"])
        if self._backend == "ollama":
            return os.getenv("OLLAMA_MODEL", _BACKEND_DEFAULTS["ollama"])
        return _BACKEND_DEFAULTS[self._backend]

    # ------------------------------------------------------------------
    # LLM dispatch
    # ------------------------------------------------------------------

    def _call_llm(self, user_prompt: str, temperature: float = 0.2) -> str:
        if self._backend == "anthropic":
            return self._call_anthropic(user_prompt, temperature)
        if self._backend == "deepseek":
            return self._call_openai_compatible(
                user_prompt,
                base_url=os.getenv("DEEPSEEK_BASE_URL", DEEPSEEK_BASE_URL),
                api_key=os.environ["DEEPSEEK_API_KEY"],
                temperature=temperature,
                extra_body={
                    "thinking": {
                        "type": os.getenv("DEEPSEEK_THINKING", "disabled")
                    }
                },
            )
        if self._backend == "openrouter":
            return self._call_openai_compatible(
                user_prompt,
                base_url=OPENROUTER_BASE_URL,
                api_key=os.environ["OPENROUTER_API_KEY"],
                temperature=temperature,
                extra_headers={
                    "HTTP-Referer": "https://github.com/pfe-iac-security",
                    "X-Title": "IaC Security Framework",
                },
            )
        if self._backend == "ollama":
            return self._call_openai_compatible(
                user_prompt,
                base_url=os.getenv("OLLAMA_BASE_URL", OLLAMA_BASE_URL),
                api_key="ollama",  # Ollama doesn't need a real key
                temperature=temperature,
            )
        return self._call_openai(user_prompt, temperature)

    def _call_openai(self, user_prompt: str, temperature: float = 0.2) -> str:
        from openai import OpenAI
        client = OpenAI()
        response = client.chat.completions.create(
            model=self._effective_model(),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=temperature,
        )
        return response.choices[0].message.content or ""

    def _call_openai_compatible(
        self,
        user_prompt: str,
        base_url: str,
        api_key: str,
        temperature: float = 0.2,
        extra_headers: dict | None = None,
        extra_body: dict | None = None,
    ) -> str:
        from openai import OpenAI
        client = OpenAI(base_url=base_url, api_key=api_key)
        kwargs: dict = dict(
            model=self._effective_model(),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=temperature,
        )
        if extra_headers:
            kwargs["extra_headers"] = extra_headers
        if extra_body:
            kwargs["extra_body"] = extra_body
        response = client.chat.completions.create(**kwargs)
        return response.choices[0].message.content or ""

    def _call_anthropic(self, user_prompt: str, temperature: float = 0.2) -> str:
        import anthropic
        client = anthropic.Anthropic()
        response = client.messages.create(
            model=self._effective_model(),
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=temperature,
        )
        if response.content and len(response.content) > 0:
            return response.content[0].text
        return ""

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, raw: str) -> list[str]:
        """Extract a unified diff from model output, tolerating markdown fences."""
        text = raw.strip()
        fenced = re.search(r"```(?:diff|patch)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
        if fenced:
            text = fenced.group(1).strip()

        lines = text.splitlines()
        start = next((i for i, line in enumerate(lines) if line.startswith("--- ")), None)
        if start is None:
            return [text] if text else []

        diff_lines = []
        for line in lines[start:]:
            if line.strip().startswith("```"):
                break
            diff_lines.append(line)

        patch = "\n".join(diff_lines).strip()
        if patch:
            return [patch]
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _guess_tool(self, path: Path) -> str:
        if path.suffix == ".tf":
            return "terraform"
        name_lower = path.name.lower()
        if "dockerfile" in name_lower or name_lower == "dockerfile":
            return "docker"
        if path.suffix in (".yml", ".yaml"):
            content = path.read_text(errors="replace")[:500]
            if "apiVersion:" in content and "kind:" in content:
                return "kubernetes"
            if "hosts:" in content or "tasks:" in content:
                return "ansible"
            return "kubernetes"  # default YAML → k8s
        if path.suffix == ".json" and "cloudformation" in name_lower:
            return "cloudformation"
        return "unknown"
