"""
Knowledge Retriever (RAG / CRAG)
---------------------------------
Queries the KnowledgeBase with a smell-aware prompt.
On retry, augments the query with failure feedback (CRAG-style).
"""

from __future__ import annotations

import logging
from .knowledge_base import KnowledgeBase

logger = logging.getLogger(__name__)


class KnowledgeRetriever:
    """
    Translates a list of detected smells into a RAG context string
    ready to be injected into the fix-generator prompt.
    """

    def __init__(self, knowledge_base: KnowledgeBase, n_results: int = 5):
        self.kb = knowledge_base
        self.n_results = n_results

    def retrieve(self, smells: list[dict], iac_tool: str, retry: int = 0) -> str:
        """
        Build a retrieval query from the detected smells and return
        a formatted context string containing relevant knowledge.

        On retry > 0, the query is made more specific to avoid
        retrieving the same unhelpful documents (CRAG strategy).
        """
        query = self._build_query(smells, iac_tool, retry)
        logger.debug("RAG query (retry=%d): %s", retry, query[:120])

        docs = self.kb.query(query, n_results=self.n_results)
        if not docs:
            return "No relevant knowledge found."

        sections = []
        for i, doc in enumerate(docs, 1):
            cwe = doc["metadata"].get("cwe", "N/A")
            sections.append(f"[Doc {i}] CWE={cwe}\n{doc['text']}")

        return "\n\n---\n\n".join(sections)

    def _build_query(self, smells: list[dict], iac_tool: str, retry: int) -> str:
        smell_descriptions = "; ".join(
            s.get("description", s.get("type", "unknown")) for s in smells
        )
        base = f"IaC tool: {iac_tool}. Security issues: {smell_descriptions}. How to fix?"
        if retry == 1:
            base += " Focus on minimal, targeted changes only."
        elif retry >= 2:
            base += " Provide the most conservative and safe remediation possible."
        return base
