from __future__ import annotations
from functools import lru_cache

import requests

from app.config import settings

# Demo/observed indicators that upgrade academic items to "Demonstrated".
DEMO_KEYWORDS = [
    "we demonstrate", "we present", "proof-of-concept", "poc", "evaluation",
    "experiment", "empirical", "in the wild", "exploit", "attack was successful",
]

# Indicators of active exploitation observed/reported in operational contexts.
ACTIVE_EXPLOITATION_STRONG_SIGNALS = {
    "active exploitation": 3,
    "actively exploited": 3,
    "exploited in the wild": 3,
    "in-the-wild exploitation": 3,
    "under active attack": 3,
}

ACTIVE_EXPLOITATION_SUPPORTING_SIGNALS = {
    "zero-day exploited": 2,
    "zero day exploited": 2,
    "ongoing attacks": 2,
    "mass exploitation": 2,
    "being exploited": 2,
    "in the wild": 1,
    "zero-day": 1,
    "zero day": 1,
}

ACTIVE_EXPLOITATION_DISCOUNT_SIGNALS = {
    "proof-of-concept": -2,
    "poc": -2,
    "simulation": -2,
    "hypothetical": -2,
    "could be exploited": -2,
    "may be exploited": -2,
}


def _score_active_exploitation_text(text: str) -> int:
    """Heuristically score evidence that exploitation is active in the wild."""
    score = 0

    for phrase, weight in ACTIVE_EXPLOITATION_STRONG_SIGNALS.items():
        if phrase in text:
            score += weight

    for phrase, weight in ACTIVE_EXPLOITATION_SUPPORTING_SIGNALS.items():
        if phrase in text:
            score += weight

    for phrase, weight in ACTIVE_EXPLOITATION_DISCOUNT_SIGNALS.items():
        if phrase in text:
            score += weight

    return score


def _rule_classify_item(source: str, title: str, summary: str) -> tuple[str, float]:
    """Rule-based fallback classifier for intel category and confidence."""
    text = f"{title}\n{summary}".lower()

    if source == "cisa_kev":
        return "Active Exploitation", 0.95

    if source == "mitre_atlas":
        return "Demonstrated", 0.80

    if source == "nist_nvd":
        return "Demonstrated", 0.78

    if source == "the_hacker_news":
        active_score = _score_active_exploitation_text(text)
        if active_score >= 4:
            confidence = min(0.93, 0.80 + (active_score * 0.02))
            return "Active Exploitation", confidence

    for kw in DEMO_KEYWORDS:
        if kw in text:
            return "Demonstrated", 0.70

    return "Hypothetical", 0.55


def _parse_llama_category(response_text: str) -> str:
    """Parse and validate a single-label classifier response."""
    # Normalize whitespace/casing before strict label matching.
    normalized = (response_text or "").strip()
    normalized_lower = normalized.lower()

    if normalized_lower == "active exploitation":
        return "Active Exploitation"
    if normalized_lower == "demonstrated":
        return "Demonstrated"
    if normalized_lower == "hypothetical":
        return "Hypothetical"

    raise ValueError(f"Could not parse category: {response_text!r}")


@lru_cache(maxsize=4096)
def _llama_classify_item(source: str, title: str, summary: str) -> str:
    """Call Ollama to classify an item into the supported category set."""
    # Keep the prompt explicit and closed-set so the model returns one of 3 labels.
    prompt = (
        "You are a cybersecurity threat-intelligence classifier.\n"
        "Classify the item into exactly one label:\n"
        "1) Active Exploitation\n"
        "2) Demonstrated\n"
        "3) Hypothetical\n\n"
        "Definitions:\n"
        "- Active Exploitation: evidence of attacks currently happening in the wild.\n"
        "- Demonstrated: proven attacks/exploits or validated demonstrations/PoCs.\n"
        "- Hypothetical: speculative, proposed, or unproven threat scenarios.\n\n"
        "Output format: return exactly one label and nothing else.\n\n"
        f"Source: {source}\n"
        f"Title: {title[:500]}\n"
        f"Summary: {summary[:2000]}"
    )

    payload = {
        # Reuse configured model so relevance/classification can share the same local model.
        "model": settings.AI_FILTER_MODEL,
        "prompt": prompt,
        # Non-streaming keeps response parsing simple for this synchronous classifier path.
        "stream": False,
        "options": {
            # Temperature 0 reduces variability for deterministic classification behavior.
            "temperature": 0,
            # Small generation budget nudges the model toward short label-only responses.
            "num_predict": 8,
        },
    }

    # Send request to local Ollama API and fail fast on HTTP errors.
    r = requests.post(
        settings.OLLAMA_API_URL,
        json=payload,
        timeout=settings.AI_FILTER_TIMEOUT_SECONDS,
    )
    r.raise_for_status()
    # Ollama returns generated text in the "response" field.
    response_text = (r.json().get("response") or "").strip()
    # Validate/normalize to canonical app labels or raise for fallback handling upstream.
    return _parse_llama_category(response_text)


def _confidence_for_category(category: str) -> float:
    """Map category label to a fixed confidence baseline."""
    if category == "Active Exploitation":
        return 0.86
    if category == "Demonstrated":
        return 0.76
    return 0.62


def classify_item(source: str, title: str, summary: str) -> tuple[str, float]:
    """Dispatch to configured classifier backend with safe fallback behavior."""
    backend = (settings.AI_CLASSIFIER_BACKEND or "rules").lower()
    if backend == "rules":
        return _rule_classify_item(source, title, summary)

    if backend == "llama":
        try:
            # Primary path: classify with Llama, then map to app-level confidence.
            category = _llama_classify_item(source, title, summary)
            return category, _confidence_for_category(category)
        except Exception:
            # Network/model/parse errors can gracefully fall back to deterministic rules.
            if settings.AI_CLASSIFIER_FALLBACK_TO_RULES:
                return _rule_classify_item(source, title, summary)
            raise

    # Unknown backend names default to rules for safe behavior.
    return _rule_classify_item(source, title, summary)
