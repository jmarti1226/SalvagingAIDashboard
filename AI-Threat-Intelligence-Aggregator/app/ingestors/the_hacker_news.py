from __future__ import annotations
from typing import Iterable

import requests
from dateutil import parser as dtparse
from lxml import etree

from app.config import settings
from app.relevance import is_ai_ml_related


def _text(node: etree._Element | None, xpath: str) -> str:
    """Read and trim text for a child node path, returning empty string on miss."""
    if node is None:
        return ""
    value = node.findtext(xpath)
    return (value or "").strip()



def fetch_the_hacker_news(max_items: int = 40) -> Iterable[dict]:
    """
    Pull recent posts from The Hacker News RSS feed.
    Returns normalized items:
      {source, source_id, title, summary, url, published_at, tags}
    """
    r = requests.get(settings.THN_RSS_URL, timeout=30)
    r.raise_for_status()

    root = etree.fromstring(r.content)
    items = root.findall(".//item")

    for item in items[:max_items]:
        guid = _text(item, "guid")
        title = _text(item, "title")
        summary = _text(item, "description")
        url = _text(item, "link")
        pub_date = _text(item, "pubDate")

        if not title:
            continue

        source_id = guid or url or title
        if not source_id:
            continue

        if not is_ai_ml_related(title, summary, mode=settings.AI_FILTER_MODE):
            continue

        published_at = None
        if pub_date:
            try:
                published_at = dtparse.parse(pub_date)
            except Exception:
                published_at = None

        yield {
            "source": "the_hacker_news",
            "source_id": source_id,
            "title": title,
            "summary": summary[:2000],
            "url": url,
            "published_at": published_at,
            "tags": "news,the-hacker-news,ai,ml",
        }
