from __future__ import annotations
from typing import Iterable
import requests
from dateutil import parser as dtparse

# Shared app configuration and relevance filtering.
from app.config import settings
from app.relevance import is_ai_ml_kev_related

# CISA Known Exploited Vulnerabilities (KEV) ingestor.
def fetch_cisa_kev() -> Iterable[dict]:
    """
    Returns normalized items:
      {source, source_id, title, summary, url, published_at, tags}
    """
    r = requests.get(settings.CISA_KEV_URL, timeout=30)
    r.raise_for_status()
    data = r.json()

    # Iterate over KEV entries and normalize only AI/ML-related records.
    vulns = data.get("vulnerabilities", [])
    for v in vulns:
        cve = v.get("cveID") or v.get("cve") or ""
        if not cve:
            continue

        # Pull the key fields used for filtering and display.
        vendor = (v.get("vendorProject") or "").strip()
        product = (v.get("product") or "").strip()
        vuln_name = (v.get("vulnerabilityName") or "").strip()
        notes = (v.get("notes") or "").strip()

        # Apply AI/ML relevance filtering before normalization/upsert.
        if not is_ai_ml_kev_related(cve, vendor, product, vuln_name, notes):
            continue

        # Build normalized title/summary strings for downstream storage and search.
        title = f"{cve} - {vuln_name}".strip(" -")
        summary = (
            f"Vendor: {vendor}; Product: {product}; "
            f"Known ransomware use: {v.get('knownRansomwareCampaignUse','')}; "
            f"Notes: {notes}"
        ).strip()

        # Parse the KEV catalog date when available.
        added = v.get("dateAdded")
        published_at = None
        if added:
            try:
                published_at = dtparse.parse(added)
            except Exception:
                published_at = None

        # Emit the normalized item shape expected by the pipeline.
        yield {
            "source": "cisa_kev",
            "source_id": cve,
            "title": title,
            "summary": summary,
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "published_at": published_at,
            "tags": "cve,kev,exploited,ai,ml",
        }
