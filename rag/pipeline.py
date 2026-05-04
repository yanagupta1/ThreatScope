import os
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

EMBED_MODEL = "all-MiniLM-L6-v2"
GROQ_MODEL = "llama-3.3-70b-versatile"
CVE_COLLECTION = "cve_intel"
MITRE_COLLECTION = "mitre_attack"
DB_PATH = "./chroma_db"

_embedder = None
_chroma_client = None
_groq_client = None


def get_embedder():
    global _embedder
    if _embedder is None:
        print("Loading embedding model...")
        _embedder = SentenceTransformer(EMBED_MODEL)
    return _embedder


def get_chroma():
    global _chroma_client
    if _chroma_client is None:
        _chroma_client = chromadb.PersistentClient(path=DB_PATH)
    return _chroma_client


def get_groq():
    global _groq_client
    if _groq_client is None:
        _groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    return _groq_client


# ── Ingestion ──────────────────────────────────────────────────────────────────

def ingest_cves(cve_docs: list[dict], document_fn):
    """Embed and store CVE documents in ChromaDB."""
    client = get_chroma()
    embedder = get_embedder()

    collection = client.get_or_create_collection(
        name=CVE_COLLECTION,
        metadata={"hnsw:space": "cosine"}
    )

    existing = set(collection.get()["ids"])
    new_docs = [d for d in cve_docs if d["id"] not in existing]

    if not new_docs:
        print("No new CVEs to ingest.")
        return 0

    print(f"Embedding {len(new_docs)} CVEs...")
    texts = [document_fn(d) for d in new_docs]
    embeddings = embedder.encode(texts, batch_size=64, show_progress_bar=True).tolist()

    metadatas = [
        {
            "id": d["id"],
            "cvss_score": str(d.get("cvss_score") or ""),
            "cvss_severity": d.get("cvss_severity") or "",
            "published": d.get("published") or "",
            "source": "nvd",
        }
        for d in new_docs
    ]

    collection.add(
        ids=[d["id"] for d in new_docs],
        embeddings=embeddings,
        documents=texts,
        metadatas=metadatas,
    )

    print(f"Ingested {len(new_docs)} CVEs into ChromaDB.")
    return len(new_docs)


def ingest_mitre(techniques: list[dict], document_fn):
    """Embed and store MITRE ATT&CK techniques in ChromaDB."""
    client = get_chroma()
    embedder = get_embedder()

    collection = client.get_or_create_collection(
        name=MITRE_COLLECTION,
        metadata={"hnsw:space": "cosine"}
    )

    existing = set(collection.get()["ids"])
    new_docs = [t for t in techniques if t["id"] not in existing]

    if not new_docs:
        print("No new MITRE techniques to ingest.")
        return 0

    print(f"Embedding {len(new_docs)} MITRE techniques...")
    texts = [document_fn(t) for t in new_docs]
    embeddings = embedder.encode(texts, batch_size=64, show_progress_bar=True).tolist()

    metadatas = [
        {
            "id": t["id"],
            "name": t["name"],
            "tactics": ", ".join(t.get("tactics", [])),
            "platforms": ", ".join(t.get("platforms", [])),
            "source": "mitre",
        }
        for t in new_docs
    ]

    collection.add(
        ids=[t["id"] for t in new_docs],
        embeddings=embeddings,
        documents=texts,
        metadatas=metadatas,
    )

    print(f"Ingested {len(new_docs)} MITRE techniques into ChromaDB.")
    return len(new_docs)


# ── Retrieval ──────────────────────────────────────────────────────────────────

def retrieve(query: str, collection_name: str, n_results: int = 5) -> list[dict]:
    """Retrieve top-k relevant documents from a collection."""
    client = get_chroma()
    embedder = get_embedder()

    try:
        collection = client.get_collection(collection_name)
    except Exception:
        return []

    query_embedding = embedder.encode([query]).tolist()
    results = collection.query(
        query_embeddings=query_embedding,
        n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )

    output = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        output.append({
            "text": doc,
            "metadata": meta,
            "score": round(1 - dist, 3),  # cosine similarity
        })

    return output


def retrieve_all(query: str, n_results: int = 4) -> tuple[list, list]:
    """Retrieve from both CVE and MITRE collections."""
    cve_results = retrieve(query, CVE_COLLECTION, n_results)
    mitre_results = retrieve(query, MITRE_COLLECTION, n_results)
    return cve_results, mitre_results


# ── Generation ─────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a cybersecurity threat intelligence analyst assistant. 
You have access to a knowledge base of recent CVEs (Common Vulnerabilities and Exposures) 
from the National Vulnerability Database (NVD) and MITRE ATT&CK techniques.

When answering questions:
- Be precise and technical — your audience is security engineers and analysts
- Always cite specific CVE IDs or ATT&CK technique IDs (e.g., T1566) when referencing them
- Highlight CVSS scores and severity when discussing CVEs
- Connect CVEs to relevant ATT&CK techniques when applicable
- If you don't have enough information in the context, say so clearly
- Structure your answers with clear sections when covering multiple items
- Keep answers concise but complete — no fluff

The context below comes from the knowledge base. Use it as your primary source."""


def query(user_question: str, n_results: int = 5) -> dict:
    """Full RAG pipeline: retrieve + generate."""
    cve_results, mitre_results = retrieve_all(user_question, n_results)

    # Build context block
    context_parts = []

    if cve_results:
        context_parts.append("=== RECENT CVEs FROM NVD ===")
        for r in cve_results:
            context_parts.append(f"[Relevance: {r['score']}]\n{r['text']}")

    if mitre_results:
        context_parts.append("\n=== MITRE ATT&CK TECHNIQUES ===")
        for r in mitre_results:
            context_parts.append(f"[Relevance: {r['score']}]\n{r['text']}")

    context = "\n\n---\n\n".join(context_parts) if context_parts else "No relevant data found in knowledge base."

    prompt = f"""Context from knowledge base:
{context}

---

Question: {user_question}

Answer:"""

    groq = get_groq()
    response = groq.chat.completions.create(
        model=GROQ_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        max_tokens=1024,
    )

    answer = response.choices[0].message.content

    return {
        "answer": answer,
        "cve_sources": cve_results,
        "mitre_sources": mitre_results,
    }


# ── Stats ──────────────────────────────────────────────────────────────────────

def get_collection_stats() -> dict:
    """Return counts for each collection."""
    client = get_chroma()
    stats = {}

    for name in [CVE_COLLECTION, MITRE_COLLECTION]:
        try:
            col = client.get_collection(name)
            stats[name] = col.count()
        except Exception:
            stats[name] = 0

    return stats
