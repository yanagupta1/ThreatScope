import requests
import json

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def fetch_mitre_attack():
    """Fetch MITRE ATT&CK STIX data from GitHub."""
    print("Fetching MITRE ATT&CK data...")
    try:
        resp = requests.get(MITRE_STIX_URL, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        print("Done fetching MITRE ATT&CK data.")
        return data
    except Exception as e:
        print(f"Error fetching MITRE ATT&CK data: {e}")
        return None


def parse_mitre_attack(stix_data: dict) -> list[dict]:
    """Parse techniques and tactics from MITRE ATT&CK STIX bundle."""
    objects = stix_data.get("objects", [])

    # Build tactic lookup: external_id -> name
    tactic_lookup = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            ext_refs = obj.get("external_references", [])
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    tactic_id = ref.get("external_id", "")
                    tactic_lookup[obj.get("x_mitre_shortname", "")] = {
                        "id": tactic_id,
                        "name": obj.get("name", ""),
                    }

    techniques = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            continue

        # External ID and URL
        tech_id = ""
        tech_url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                tech_url = ref.get("url", "")

        if not tech_id:
            continue

        # Tactics
        kill_chain = obj.get("kill_chain_phases", [])
        tactics = []
        for phase in kill_chain:
            shortname = phase.get("phase_name", "")
            tactic_info = tactic_lookup.get(shortname)
            if tactic_info:
                tactics.append(tactic_info["name"])
            else:
                tactics.append(shortname.replace("-", " ").title())

        # Platforms
        platforms = obj.get("x_mitre_platforms", [])

        # Detection
        detection = obj.get("x_mitre_detection", "")

        # Data sources
        data_sources = obj.get("x_mitre_data_sources", [])

        # Is subtechnique
        is_subtechnique = obj.get("x_mitre_is_subtechnique", False)

        techniques.append({
            "id": tech_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "platforms": platforms,
            "detection": detection,
            "data_sources": data_sources[:5],
            "is_subtechnique": is_subtechnique,
            "url": tech_url,
        })

    print(f"Parsed {len(techniques)} ATT&CK techniques.")
    return techniques


def technique_to_document(technique: dict) -> str:
    """Convert a MITRE technique to a text chunk for embedding."""
    tactics = ", ".join(technique.get("tactics", [])) or "N/A"
    platforms = ", ".join(technique.get("platforms", [])) or "N/A"
    data_sources = ", ".join(technique.get("data_sources", [])) or "N/A"
    subtech = "Yes" if technique.get("is_subtechnique") else "No"

    desc = technique.get("description", "")
    # Truncate very long descriptions
    if len(desc) > 1000:
        desc = desc[:1000] + "..."

    detection = technique.get("detection", "")
    if len(detection) > 500:
        detection = detection[:500] + "..."

    return f"""MITRE ATT&CK Technique ID: {technique['id']}
Name: {technique['name']}
Subtechnique: {subtech}
Tactics: {tactics}
Platforms: {platforms}
Data Sources: {data_sources}
Description: {desc}
Detection: {detection}
Reference URL: {technique.get('url', '')}"""
