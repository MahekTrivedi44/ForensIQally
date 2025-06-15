# rag/mitre_loader.py
import json
import os
def load_mitre_attack_docs(json_path="data/enterprise-attack.json"):
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"❌ MITRE file not found: {json_path}")
    with open(json_path, "r") as f:
        stix = json.load(f)

    docs = []
    for obj in stix.get("objects", []):
        if obj.get("type") == "attack-pattern":
            text = f"{obj.get('name', '')}: {obj.get('description', '')}"
            docs.append(text)
    return docs
