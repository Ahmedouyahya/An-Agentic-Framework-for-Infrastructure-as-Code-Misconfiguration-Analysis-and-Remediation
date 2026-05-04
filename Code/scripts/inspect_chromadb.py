"""
Inspect ChromaDB: Show structure, collections, document count, and sample data.
"""
import json
import sys
from pathlib import Path

try:
    import chromadb
    from chromadb.utils import embedding_functions
except ImportError:
    print("ERROR: chromadb not installed. Run: pip install chromadb")
    sys.exit(1)

CHROMA_DIR = str(Path(__file__).parent.parent / "chroma_db")

print("=" * 80)
print(f"ChromaDB Persistent Directory: {CHROMA_DIR}")
print("=" * 80)

# Connect
client = chromadb.PersistentClient(path=CHROMA_DIR)

# List collections
collections = client.list_collections()
print(f"\nNumber of collections: {len(collections)}")

for col in collections:
    print(f"\n{'─' * 70}")
    print(f"  Collection Name : {col.name}")
    count = col.count()
    print(f"  Document Count  : {count}")
    print(f"  Metadata        : {col.metadata}")
    print(f"{'─' * 70}")

    if count == 0:
        print("  (empty collection)")
        continue

    # Fetch ALL documents (ids, documents, metadatas)
    all_data = col.get(include=["documents", "metadatas"])

    print(f"\n  === ALL {count} Documents ===\n")
    for i, (doc_id, doc_text, doc_meta) in enumerate(
        zip(all_data["ids"], all_data["documents"], all_data["metadatas"])
    ):
        print(f"  [{i+1}/{count}] ID: {doc_id}")
        print(f"  Metadata: {json.dumps(doc_meta, indent=4)}")
        # Show full document text (truncate if very long)
        if len(doc_text) > 500:
            print(f"  Document (first 500 chars):\n    {doc_text[:500]}...")
        else:
            print(f"  Document:\n    {doc_text}")
        print()

print("\n" + "=" * 80)
print("Done.")
