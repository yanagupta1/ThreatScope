"""
Run this once to populate the ChromaDB vector store.
Usage: python ingest_runner.py [--days 30] [--max-cves 500]
"""
import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from ingest.nvd import fetch_recent_cves, cve_to_document
from ingest.mitre import fetch_mitre_attack, parse_mitre_attack, technique_to_document
from rag.pipeline import ingest_cves, ingest_mitre, get_collection_stats


def main():
    parser = argparse.ArgumentParser(description="Ingest CVE and MITRE ATT&CK data")
    parser.add_argument("--days", type=int, default=30, help="Days back to fetch CVEs (default: 30)")
    parser.add_argument("--max-cves", type=int, default=300, help="Max CVEs to fetch (default: 300)")
    parser.add_argument("--skip-cves", action="store_true", help="Skip CVE ingestion")
    parser.add_argument("--skip-mitre", action="store_true", help="Skip MITRE ingestion")
    args = parser.parse_args()

    print("=" * 60)
    print("  Threat Intel Copilot — Data Ingestion")
    print("=" * 60)

    if not args.skip_cves:
        print("\n[1/2] Fetching CVEs from NVD...")
        cves = fetch_recent_cves(days_back=args.days, max_results=args.max_cves)
        if cves:
            ingest_cves(cves, cve_to_document)
        else:
            print("No CVEs fetched.")

    if not args.skip_mitre:
        print("\n[2/2] Fetching MITRE ATT&CK...")
        stix_data = fetch_mitre_attack()
        if stix_data:
            techniques = parse_mitre_attack(stix_data)
            ingest_mitre(techniques, technique_to_document)
        else:
            print("Could not fetch MITRE data.")

    print("\n" + "=" * 60)
    print("  Ingestion Complete — Knowledge Base Stats")
    print("=" * 60)
    stats = get_collection_stats()
    print(f"  CVEs indexed:              {stats.get('cve_intel', 0)}")
    print(f"  MITRE techniques indexed:  {stats.get('mitre_attack', 0)}")
    print("=" * 60)
    print("\nReady. Run `streamlit run app.py` to launch the copilot.")


if __name__ == "__main__":
    main()
