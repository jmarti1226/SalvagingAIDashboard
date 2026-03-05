from __future__ import annotations
from typing import Iterable

import requests
from dateutil import parser as dtparse

# Shared app configuration and relevance filtering.
from app.config import settings
from app.relevance import is_ai_ml_nvd_related


def _first_english_description(cve: dict) -> str:
    """Return the first English CVE description from NVD payload data."""
    # Prefer the English description text in NVD's descriptions array.
    for desc in cve.get("descriptions", []) or []:
        if (desc.get("lang") or "").lower() == "en":
            return (desc.get("value") or "").strip()
    return ""


def _collect_reference_text(cve: dict) -> str:
    """Flatten NVD reference metadata into one relevance-matching string."""
    # Collect URLs/source names/tags for relevance matching context.
    parts: list[str] = []
    for ref in cve.get("references", []) or []:
        for value in (
            ref.get("url"),
            ref.get("source"),
            " ".join(ref.get("tags", []) or []),
        ):
            if value:
                parts.append(str(value))
    return " ".join(parts)


def _collect_cpe_criteria(value) -> list[str]:
    """Recursively extract CPE criteria strings from nested configuration nodes."""
    # Recursively walk NVD configuration nodes to extract CPE criteria strings.
    found: list[str] = []

    if isinstance(value, dict):
        criteria = value.get("criteria")
        if criteria:
            found.append(str(criteria))
        for child in value.values():
            found.extend(_collect_cpe_criteria(child))
    elif isinstance(value, list):
        for item in value:
            found.extend(_collect_cpe_criteria(item))

    return found


# NIST NVD CVE ingestor for AI/ML-related vulnerabilities.
def fetch_nist_nvd(max_results: int | None = None) -> Iterable[dict]:
    """
    Returns normalized items:
      {source, source_id, title, summary, url, published_at, tags}
    """
    params = {
        "startIndex": 0,
        "resultsPerPage": max_results or settings.NVD_MAX_RESULTS,
    }

    r = requests.get(settings.NVD_API_URL, params=params, timeout=30)
    r.raise_for_status()
    data = r.json()

    # Iterate over NVD CVE wrapper objects and normalize matching entries.
    for wrapper in data.get("vulnerabilities", []) or []:
        cve = wrapper.get("cve") or {}
        cve_id = (cve.get("id") or "").strip()
        if not cve_id:
            continue

        description = _first_english_description(cve)
        reference_text = _collect_reference_text(cve)
        cpe_text = " ".join(_collect_cpe_criteria(cve.get("configurations", [])))

        # Apply the shared AI/ML relevance filter before emitting.
        if not is_ai_ml_nvd_related(cve_id, description, reference_text, cpe_text):
            continue

        title = f"{cve_id} - {description[:180]}".strip(" -")
        summary = description[:2000]

        published_at = None
        for ts in (cve.get("published"), cve.get("lastModified")):
            if ts:
                try:
                    published_at = dtparse.parse(ts)
                    break
                except Exception:
                    pass

        yield {
            "source": "nist_nvd",
            "source_id": cve_id,
            "title": title,
            "summary": summary,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "published_at": published_at,
            "tags": "cve,nvd,ai,ml",
        }
