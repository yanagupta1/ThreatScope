# 🛡️ Threat Intel Copilot

A RAG-powered security analyst assistant that answers natural language questions over:
- **NVD CVE data** — recent vulnerabilities with CVSS scores, affected products, and CWEs
- **MITRE ATT&CK** — all enterprise techniques, tactics, detection guidance, and data sources

Built with: `sentence-transformers` + `ChromaDB` + `Llama 3.3 70B (Groq)` + `Streamlit`

---

## Setup

```bash
# 1. Clone and install
pip install -r requirements.txt

# 2. Add your Groq API key
echo "GROQ_API_KEY=your_key_here" > .env

# 3. Ingest data (first run ~10 min)
python ingest_runner.py

# Optional flags:
# --days 60         # fetch CVEs from last 60 days (default: 30)
# --max-cves 500    # max CVEs to fetch (default: 300)
# --skip-mitre      # skip MITRE ingestion
# --skip-cves       # skip CVE ingestion

# 4. Launch the app
streamlit run app.py
```

---

## Example Questions

- "What critical CVEs were published in the last 30 days?"
- "What ATT&CK techniques are associated with ransomware?"
- "Show me high severity vulnerabilities affecting Apache or Nginx"
- "How do attackers establish persistence on Windows?"
- "Are there recent CVEs related to privilege escalation?"
- "What are common techniques for lateral movement in cloud environments?"

---

## Architecture

```
User Query
    │
    ▼
SentenceTransformer (all-MiniLM-L6-v2)
    │  embed query
    ▼
ChromaDB
    ├── cve_intel collection    → top-k CVEs
    └── mitre_attack collection → top-k techniques
    │
    ▼
Context Assembly
    │
    ▼
Groq API (Llama 3.3 70B)
    │
    ▼
Answer + Source Citations
```

## Data Sources

- **NVD CVE API**: https://nvd.nist.gov/developers/vulnerabilities
- **MITRE ATT&CK STIX**: https://github.com/mitre/cti
