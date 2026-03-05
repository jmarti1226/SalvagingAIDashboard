from __future__ import annotations
from typing import Iterable
from datetime import datetime
import requests

# Shared app configuration and relevance filtering.
from app.config import settings
from app.relevance import is_ai_ml_related

# MITRE ATLAS ingestor.
def fetch_mitre_atlas() -> Iterable[dict]:
    """
    Ingest ATLAS STIX JSON hosted on GitHub.
    We normalize "attack-pattern" objects as techniques.
    """
    r = requests.get(settings.ATLAS_STIX_URL, timeout=30)
    r.raise_for_status()
    stix = r.json()

    # Iterate over STIX objects and keep ATLAS techniques only.
    objects = stix.get("objects", [])
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        # Extract the minimal fields needed for normalization/filtering.
        stix_id = obj.get("id")
        name = obj.get("name", "").strip()
        desc = (obj.get("description") or "").strip()
        if not stix_id or not name:
            continue

        # Apply AI/ML relevance filtering before normalization/upsert.
        if not is_ai_ml_related(name, desc, mode=settings.AI_FILTER_MODE):
            continue

        # STIX often has created/modified timestamps
        published_at = None
        for k in ("modified", "created"):
            if obj.get(k):
                try:
                    published_at = datetime.fromisoformat(obj[k].replace("Z", "+00:00"))
                    break
                except Exception:
                    pass

        # External references (prefer atlas.mitre.org URL if present)
        url = ""
        for ref in obj.get("external_references", []) or []:
            if ref.get("url"):
                url = ref["url"]
                break

        # Emit the normalized item shape expected by the pipeline.
        yield {
            "source": "mitre_atlas",
            "source_id": stix_id,
            "title": name,
            "summary": desc[:2000],
            "url": url,
            "published_at": published_at,
            "tags": "mitre,atlas,ai,technique",
        }
