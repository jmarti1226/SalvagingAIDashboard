from __future__ import annotations
from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field, Index

class IntelItem(SQLModel, table=True):
    """Canonical normalized threat-intel record stored in SQLite."""
    id: Optional[int] = Field(default=None, primary_key=True)

    # de-dup key per source
    source: str = Field(index=True)  # "mitre_atlas" | "cisa_kev" | "arxiv"
    source_id: str = Field(index=True)  # e.g., STIX id, CVE, arXiv id

    title: str
    summary: str = ""
    url: str = ""
    published_at: Optional[datetime] = Field(default=None, index=True)

    # "Hypothetical" | "Demonstrated" | "Active Exploitation"
    category: str = Field(index=True)
    confidence: float = 0.6

    tags: str = ""  # comma-separated convenience

    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    updated_at: datetime = Field(default_factory=datetime.utcnow, index=True)

    __table_args__ = (
        # Enforce one row per upstream source identifier.
        Index("uq_source_source_id", "source", "source_id", unique=True),
    )
