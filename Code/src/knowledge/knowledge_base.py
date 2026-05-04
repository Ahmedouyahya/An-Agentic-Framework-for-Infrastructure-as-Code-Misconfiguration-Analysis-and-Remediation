"""
Knowledge Base
--------------
Builds and manages a vector store populated from:
  - The War et al. 62-category IaC security smell taxonomy, extended
    in this implementation to 65 local entries
  - CWE descriptions
  - Fix examples and audit reports

Uses ChromaDB as the default vector store with sentence-transformers embeddings.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Path to the taxonomy JSON file (to be populated)
TAXONOMY_PATH = Path(__file__).parent.parent.parent / "dataset" / "taxonomy" / "smells_taxonomy.json"


class KnowledgeBase:
    """
    Wraps a ChromaDB collection. Call `build()` once to index all documents,
    then use `query()` for similarity search.
    """

    COLLECTION_NAME = "iac_security_smells"

    def __init__(self, persist_dir: str = "./chroma_db"):
        self.persist_dir = persist_dir
        self._collection = None

    def build(self, documents: Optional[list[dict]] = None) -> None:
        """
        Index documents into the vector store.
        Each document dict: {"id": str, "text": str, "metadata": dict}
        Falls back to loading from TAXONOMY_PATH if documents is None.
        """
        try:
            import chromadb
            from chromadb.utils import embedding_functions
        except ImportError:
            raise ImportError("Install chromadb: pip install chromadb")

        client = chromadb.PersistentClient(path=self.persist_dir)
        ef = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        self._collection = client.get_or_create_collection(
            name=self.COLLECTION_NAME, embedding_function=ef
        )

        if documents is None:
            documents = self._load_taxonomy()

        if not documents:
            logger.warning("No documents to index.")
            return

        self._collection.add(
            ids=[d["id"] for d in documents],
            documents=[d["text"] for d in documents],
            metadatas=[d.get("metadata", {}) for d in documents],
        )
        logger.info("Indexed %d documents into knowledge base.", len(documents))

    def query(self, query_text: str, n_results: int = 5) -> list[dict]:
        """Return the top-n most relevant documents for a query string."""
        if self._collection is None:
            raise RuntimeError("Knowledge base not built. Call build() first.")
        results = self._collection.query(query_texts=[query_text], n_results=n_results)
        docs = []
        for doc, meta, dist in zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            docs.append({"text": doc, "metadata": meta, "distance": dist})
        return docs

    def _load_taxonomy(self) -> list[dict]:
        if not TAXONOMY_PATH.exists():
            logger.warning("Taxonomy file not found at %s", TAXONOMY_PATH)
            return []
        with TAXONOMY_PATH.open() as f:
            taxonomy = json.load(f)
        documents = []
        for entry in taxonomy:
            text = (
                f"Smell: {entry.get('name', '')}\n"
                f"Category: {entry.get('category', '')}\n"
                f"Description: {entry.get('description', '')}\n"
                f"CWE: {entry.get('cwe', '')}\n"
                f"Fix example: {entry.get('fix_example', '')}"
            )
            documents.append({
                "id": entry["id"],
                "text": text,
                "metadata": {
                    "category": entry.get("category", ""),
                    "cwe": entry.get("cwe", ""),
                    "iac_tools": ",".join(entry.get("iac_tools", [])),
                },
            })
        return documents
