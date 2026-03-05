from __future__ import annotations
from datetime import datetime
from typing import Optional, List
from threading import Lock

from fastapi import FastAPI, Depends, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, select

from apscheduler.schedulers.background import BackgroundScheduler

# App modules: DB/session helpers, models, classification, config, and relevance filtering.
from app.db import init_db, get_session
from app.models import IntelItem
from app.classifier import classify_item
from app.config import settings
from app.relevance import is_ai_ml_kev_related, is_ai_ml_nvd_related

# Ingestion sources.
from app.ingestors.cisa_kev import fetch_cisa_kev
from app.ingestors.atlas import fetch_mitre_atlas
from app.ingestors.arxiv import fetch_arxiv_ai_security
from app.ingestors.nist_nvd import fetch_nist_nvd
from app.ingestors.the_hacker_news import fetch_the_hacker_news

# FastAPI app setup and static dashboard mount.
app = FastAPI(title="AI Threat Intelligence Aggregator (Testing)", version="1.0")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Background scheduler used for periodic refresh jobs.
scheduler = BackgroundScheduler(job_defaults={"max_instances": 1, "coalesce": True})
refresh_lock = Lock()

# Insert/update normalized items and apply source-based classification.
def upsert_item(session: Session, item: dict) -> None:
    """Insert or update one normalized intel item by source/source_id key."""
    category, confidence = classify_item(item["source"], item["title"], item.get("summary", ""))

    existing = session.exec(
        select(IntelItem).where(
            IntelItem.source == item["source"],
            IntelItem.source_id == item["source_id"]
        )
    ).first()

    now = datetime.utcnow()

    if existing:
        existing.title = item["title"]
        existing.summary = item.get("summary", "")
        existing.url = item.get("url", "")
        existing.published_at = item.get("published_at")
        existing.tags = item.get("tags", "")
        existing.category = category
        existing.confidence = confidence
        existing.updated_at = now
        session.add(existing)
    else:
        session.add(IntelItem(
            source=item["source"],
            source_id=item["source_id"],
            title=item["title"],
            summary=item.get("summary", ""),
            url=item.get("url", ""),
            published_at=item.get("published_at"),
            tags=item.get("tags", ""),
            category=category,
            confidence=confidence,
            created_at=now,
            updated_at=now,
        ))

# Run all enabled ingestors, upsert results, and return per-source counts.
def refresh_all() -> dict:
    """Run all ingestors once and return counts for each source."""
    # Prevent overlapping refreshes from scheduler/manual triggers.
    if not refresh_lock.acquire(blocking=False):
        return {"ok": False, "busy": True, "message": "Refresh already in progress"}

    counts = {"mitre_atlas": 0, "cisa_kev": 0, "arxiv": 0, "nist_nvd": 0, "the_hacker_news": 0}

    try:
        from app.db import ENGINE
        with Session(ENGINE) as session:
            # CISA KEV
            for it in fetch_cisa_kev():
                upsert_item(session, it)
                counts["cisa_kev"] += 1

            # MITRE ATLAS
            for it in fetch_mitre_atlas():
                upsert_item(session, it)
                counts["mitre_atlas"] += 1

            # arXiv
            for it in fetch_arxiv_ai_security():
                upsert_item(session, it)
                counts["arxiv"] += 1

            # NIST NVD
            for it in fetch_nist_nvd():
                upsert_item(session, it)
                counts["nist_nvd"] += 1

            # The Hacker News (RSS)
            for it in fetch_the_hacker_news():
                upsert_item(session, it)
                counts["the_hacker_news"] += 1

            session.commit()

        return {"ok": True, "counts": counts, "refreshed_at": datetime.utcnow().isoformat()}
    finally:
        refresh_lock.release()

# Startup lifecycle: initialize DB, perform initial refresh, and schedule recurring refreshes.
@app.on_event("startup")
def on_startup():
    """Initialize storage and schedule periodic refresh jobs."""
    init_db()
    scheduler.add_job(refresh_all, "interval", minutes=settings.REFRESH_MINUTES, id="refresh_job", replace_existing=True)
    if settings.STARTUP_REFRESH_IN_BACKGROUND:
        # Run first refresh asynchronously so the app can start immediately.
        scheduler.add_job(refresh_all, "date", id="startup_refresh", replace_existing=True)
    else:
        try:
            refresh_all()
        except Exception as e:
            # Avoid failing app startup if a feed is temporarily unavailable.
            print(f"[startup] refresh failed: {e}")
    scheduler.start()

# Shutdown lifecycle: stop background scheduler.
@app.on_event("shutdown")
def on_shutdown():
    """Stop scheduler threads during app shutdown."""
    scheduler.shutdown(wait=False)

# Dashboard route serving the static HTML page.
@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Serve the static dashboard HTML."""
    with open("static/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

# Manual refresh endpoint.
@app.post("/api/refresh")
def api_refresh():
    """Trigger a full refresh immediately."""
    return refresh_all()

# Cleanup endpoint to remove previously stored non-AI/ML CISA KEV items.
@app.post("/api/cleanup/cisa-kev-ai-only")
def api_cleanup_cisa_kev_ai_only(
    session: Session = Depends(get_session),
):
    """Delete stored KEV rows that no longer pass AI/ML relevance checks."""
    removed = 0

    items = session.exec(
        select(IntelItem).where(IntelItem.source == "cisa_kev")
    ).all()

    for item in items:
        if not is_ai_ml_kev_related(item.source_id, item.title, item.summary, item.tags, ""):
            session.delete(item)
            removed += 1

    session.commit()
    return {"ok": True, "removed": removed, "remaining": len(items) - removed}


# Cleanup endpoint to remove previously stored non-AI/ML NIST NVD items.
@app.post("/api/cleanup/nist-nvd-ai-only")
def api_cleanup_nist_nvd_ai_only(
    session: Session = Depends(get_session),
):
    """Delete stored NVD rows that no longer pass AI/ML relevance checks."""
    removed = 0

    items = session.exec(
        select(IntelItem).where(IntelItem.source == "nist_nvd")
    ).all()

    for item in items:
        if not is_ai_ml_nvd_related(item.source_id, item.title, item.summary, item.tags):
            session.delete(item)
            removed += 1

    session.commit()
    return {"ok": True, "removed": removed, "remaining": len(items) - removed}

# Query endpoint with optional filters for category, source, and text search.
@app.get("/api/items", response_model=List[IntelItem])
def api_items(
    session: Session = Depends(get_session),
    category: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
    q: Optional[str] = Query(default=None, description="substring search in title/summary"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """Return filtered, newest-first intel items for API consumers."""
    stmt = select(IntelItem)

    if category:
        stmt = stmt.where(IntelItem.category == category)
    if source:
        stmt = stmt.where(IntelItem.source == source)
    if q:
        like = f"%{q}%"
        stmt = stmt.where((IntelItem.title.like(like)) | (IntelItem.summary.like(like)))

    # Include primary-key tie-breaker so offset pagination stays stable.
    stmt = stmt.order_by(
        IntelItem.published_at.desc().nullslast(),
        IntelItem.updated_at.desc(),
        IntelItem.id.desc(),
    )
    stmt = stmt.offset(offset).limit(limit)
    return session.exec(stmt).all()


