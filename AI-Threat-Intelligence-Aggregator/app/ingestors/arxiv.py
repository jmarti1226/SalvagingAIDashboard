from __future__ import annotations
from typing import Iterable
import requests
from lxml import etree
from dateutil import parser as dtparse

# Shared app configuration and relevance filtering.
from app.config import settings
from app.relevance import is_ai_ml_related

# XML namespace mapping for the arXiv Atom feed.
ARXIV_NS = {"a": "http://www.w3.org/2005/Atom"}

# arXiv ingestor for AI/ML security research papers.
def fetch_arxiv_ai_security(max_results: int = 25) -> Iterable[dict]:
    """
    Pull recent AI-security-ish papers using arXiv API (Atom feed).
    """
    # Tight-ish query for AI threat topics; adjust freely.
    query = 'all:("prompt injection" OR "jailbreak" OR "LLM security" OR "model extraction" OR "data poisoning")'
    params = {
        "search_query": query,
        "start": 0,
        "max_results": max_results,
        "sortBy": "submittedDate",
        "sortOrder": "descending",
    }

    r = requests.get(settings.ARXIV_API_URL, params=params, timeout=30)
    r.raise_for_status()

    # Parse the Atom feed and normalize each entry.
    root = etree.fromstring(r.content)
    for entry in root.findall("a:entry", namespaces=ARXIV_NS):
        arxiv_id = (entry.findtext("a:id", namespaces=ARXIV_NS) or "").strip()
        title = (entry.findtext("a:title", namespaces=ARXIV_NS) or "").strip()
        summary = (entry.findtext("a:summary", namespaces=ARXIV_NS) or "").strip()
        published = (entry.findtext("a:published", namespaces=ARXIV_NS) or "").strip()

        # Parse the published timestamp when present.
        published_at = None
        if published:
            try:
                published_at = dtparse.parse(published)
            except Exception:
                published_at = None

        # Normalize text fields before filtering and storage.
        normalized_title = " ".join(title.split())
        normalized_summary = " ".join(summary.split())[:2000]

        # Apply AI/ML relevance filtering to keep only matching papers.
        if not is_ai_ml_related(normalized_title, normalized_summary, mode=settings.AI_FILTER_MODE):
            continue

        # Emit the normalized item shape expected by the pipeline.
        yield {
            "source": "arxiv",
            "source_id": arxiv_id,
            "title": normalized_title,
            "summary": normalized_summary,
            "url": arxiv_id,
            "published_at": published_at,
            "tags": "paper,arxiv,ai",
        }
