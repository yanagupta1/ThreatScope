import requests
import time
from datetime import datetime, timedelta

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_recent_cves(days_back=30, max_results=500):
    """Fetch recent CVEs from NVD API."""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)

    pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

    all_cves = []
    start_index = 0
    results_per_page = 100

    print(f"Fetching CVEs from {start_date.date()} to {end_date.date()}...")

    while len(all_cves) < max_results:
        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }

        try:
            resp = requests.get(NVD_BASE_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"Error fetching CVEs: {e}")
            break

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            cve = item.get("cve", {})
            parsed = parse_cve(cve)
            if parsed:
                all_cves.append(parsed)

        total = data.get("totalResults", 0)
        start_index += results_per_page

        print(f"  Fetched {len(all_cves)} / {min(total, max_results)} CVEs...")

        if start_index >= total or len(all_cves) >= max_results:
            break

        time.sleep(0.6)  # NVD rate limit: ~5 req/sec without API key

    print(f"Done. Total CVEs fetched: {len(all_cves)}")
    return all_cves


def parse_cve(cve: dict) -> dict | None:
    """Extract relevant fields from a CVE entry."""
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # Description
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), ""
    )

    # CVSS score
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_severity = None
    cvss_vector = None

    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version_key in metrics and metrics[version_key]:
            m = metrics[version_key][0].get("cvssData", {})
            cvss_score = m.get("baseScore")
            cvss_severity = m.get("baseSeverity") or metrics[version_key][0].get("baseSeverity")
            cvss_vector = m.get("vectorString")
            break

    # Dates
    published = cve.get("published", "")[:10]
    modified = cve.get("lastModified", "")[:10]

    # Affected products (CPE)
    affected = []
    configs = cve.get("configurations", [])
    for config in configs:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe = cpe_match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) > 4:
                    vendor = parts[3]
                    product = parts[4]
                    if vendor not in affected:
                        affected.append(f"{vendor}/{product}")

    # References
    refs = [r.get("url", "") for r in cve.get("references", [])[:3]]

    # Weaknesses (CWE)
    weaknesses = []
    for w in cve.get("weaknesses", []):
        for desc in w.get("description", []):
            if desc.get("lang") == "en":
                weaknesses.append(desc.get("value", ""))

    return {
        "id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "published": published,
        "modified": modified,
        "affected_products": affected[:10],
        "references": refs,
        "weaknesses": weaknesses,
    }


def cve_to_document(cve: dict) -> str:
    """Convert a CVE dict to a text chunk for embedding."""
    severity = cve.get("cvss_severity") or "UNKNOWN"
    score = cve.get("cvss_score") or "N/A"
    products = ", ".join(cve.get("affected_products", [])) or "N/A"
    weaknesses = ", ".join(cve.get("weaknesses", [])) or "N/A"

    return f"""CVE ID: {cve['id']}
Published: {cve['published']}
CVSS Score: {score} ({severity})
CVSS Vector: {cve.get('cvss_vector') or 'N/A'}
Affected Products: {products}
Weaknesses (CWE): {weaknesses}
Description: {cve['description']}
References: {' | '.join(cve.get('references', []))}"""
