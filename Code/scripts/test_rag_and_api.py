"""
Quick test: build the RAG knowledge base from the taxonomy
and run a sample query, then test the API connection.

Usage:
    .venv/bin/python scripts/test_rag_and_api.py
"""

import os
import sys
import json
from pathlib import Path

# Load .env
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# ─── 1. Build RAG knowledge base ────────────────────────────────────────────

print("=" * 60)
print("STEP 1 — Building RAG knowledge base from taxonomy")
print("=" * 60)

from knowledge.knowledge_base import KnowledgeBase

kb = KnowledgeBase(persist_dir=str(Path(__file__).parent.parent / "chroma_db"))
kb.build()
print("✓ Knowledge base built successfully\n")

# ─── 2. Test a retrieval query ───────────────────────────────────────────────

print("=" * 60)
print("STEP 2 — Testing RAG retrieval")
print("=" * 60)

from knowledge.retriever import KnowledgeRetriever

retriever = KnowledgeRetriever(kb, n_results=3)

smells = [
    {"type": "hardcoded_credential", "description": "AWS access key hardcoded in provider block"},
    {"type": "overly_permissive_cidr", "description": "Security group allows all traffic from 0.0.0.0/0"},
]
context = retriever.retrieve(smells, iac_tool="terraform")
print("Query: Terraform — hardcoded credential + overly permissive CIDR")
print("─" * 40)
print(context[:800], "...\n")

# ─── 3. Test API connection ───────────────────────────────────────────────────

print("=" * 60)
print("STEP 3 — Testing OpenCode API connection")
print("=" * 60)

api_key = os.getenv("OPENCODE_API_KEY")
api_base = os.getenv("OPENCODE_API_BASE", "https://api.openai.com/v1")

if not api_key:
    print("✗ OPENCODE_API_KEY not set in .env")
    sys.exit(1)

try:
    from openai import OpenAI

    client = OpenAI(api_key=api_key, base_url=api_base)

    # List available models to verify connection
    models = client.models.list()
    model_names = [m.id for m in models.data][:5]
    print(f"✓ Connected to API at: {api_base}")
    print(f"  Available models (first 5): {model_names}\n")

    # Test a small completion
    response = client.chat.completions.create(
        model=model_names[0] if model_names else "gpt-4o-mini",
        messages=[
            {"role": "user", "content": "Say 'IaC security test OK' and nothing else."}
        ],
        max_tokens=20,
    )
    print(f"✓ API response: {response.choices[0].message.content}")

except Exception as e:
    print(f"✗ API connection failed: {e}")
    print()
    print("  → If this is not an OpenAI-compatible API, set OPENCODE_API_BASE in .env")
    print("  → For Ollama (local), use: OPENCODE_API_BASE=http://localhost:11434/v1")
