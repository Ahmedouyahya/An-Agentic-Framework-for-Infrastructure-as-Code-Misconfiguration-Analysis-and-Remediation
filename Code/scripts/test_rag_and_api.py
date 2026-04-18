"""
Quick test: build the RAG knowledge base from the taxonomy
and run a sample query, then test the LLM backend connection.

Supports all backends: Anthropic, OpenRouter, Ollama (local), OpenAI.

Usage:
    .venv/bin/python scripts/test_rag_and_api.py
"""

import os
import sys
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
print("OK — Knowledge base built successfully\n")

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
print("-" * 40)
print(context[:800], "...\n")

# ─── 3. Test LLM backend connection ─────────────────────────────────────────

print("=" * 60)
print("STEP 3 — Testing LLM backend connection")
print("=" * 60)

# Detect backend (same priority as fix_generator.py)
if os.getenv("ANTHROPIC_API_KEY"):
    backend = "anthropic"
    print(f"Backend: Anthropic (ANTHROPIC_API_KEY set)")
    try:
        import anthropic
        client = anthropic.Anthropic()
        response = client.messages.create(
            model="claude-sonnet-4-5-20241022",
            max_tokens=20,
            messages=[{"role": "user", "content": "Say 'IaC security test OK' and nothing else."}],
        )
        print(f"OK — Response: {response.content[0].text}")
    except Exception as e:
        print(f"FAIL — {e}")

elif os.getenv("OPENROUTER_API_KEY"):
    backend = "openrouter"
    print(f"Backend: OpenRouter (OPENROUTER_API_KEY set)")
    try:
        from openai import OpenAI
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.environ["OPENROUTER_API_KEY"],
        )
        response = client.chat.completions.create(
            model="meta-llama/llama-3.1-8b-instruct:free",
            messages=[{"role": "user", "content": "Say 'IaC security test OK' and nothing else."}],
            max_tokens=20,
        )
        print(f"OK — Response: {response.choices[0].message.content}")
    except Exception as e:
        print(f"FAIL — {e}")

elif os.getenv("OLLAMA_MODEL") or True:  # Default to Ollama
    backend = "ollama"
    model = os.getenv("OLLAMA_MODEL", "gemma3:4b")
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    print(f"Backend: Ollama (local) — model={model} base_url={base_url}")

    # Check if Ollama is running
    try:
        from openai import OpenAI
        client = OpenAI(base_url=base_url, api_key="ollama")
        models = client.models.list()
        available = [m.id for m in models.data]
        print(f"  Available models: {available[:10]}")

        if model not in available:
            print(f"\n  Model '{model}' not found. Pull it with:")
            print(f"    ollama pull {model}")
            print(f"\n  Recommended models for your hardware (12 GB RAM, no GPU):")
            print(f"    ollama pull gemma3:4b      # 2.5 GB, good quality")
            print(f"    ollama pull qwen2.5-coder:3b  # 2 GB, code-focused")
            print(f"    ollama pull phi4-mini       # 2.4 GB, fast")
        else:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Say 'IaC security test OK' and nothing else."}],
                max_tokens=20,
            )
            print(f"OK — Response: {response.choices[0].message.content}")
    except Exception as e:
        print(f"FAIL — Cannot connect to Ollama at {base_url}")
        print(f"  Error: {e}")
        print(f"\n  To set up Ollama:")
        print(f"    1. Install: curl -fsSL https://ollama.com/install.sh | sh")
        print(f"    2. Start:   ollama serve")
        print(f"    3. Pull:    ollama pull gemma3:4b")
        print(f"    4. Re-run this test")

elif os.getenv("OPENAI_API_KEY"):
    backend = "openai"
    print(f"Backend: OpenAI (OPENAI_API_KEY set)")
    try:
        from openai import OpenAI
        client = OpenAI()
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Say 'IaC security test OK' and nothing else."}],
            max_tokens=20,
        )
        print(f"OK — Response: {response.choices[0].message.content}")
    except Exception as e:
        print(f"FAIL — {e}")

print()
print("=" * 60)
print("All tests complete.")
print("=" * 60)
