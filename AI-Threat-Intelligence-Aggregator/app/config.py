from dataclasses import dataclass


# Application-wide static settings.
@dataclass(frozen=True)
class Settings:
    # Source feed endpoints.
    # MITRE ATLAS STIX (GitHub-hosted)
    ATLAS_STIX_URL: str = (
        "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/"
        "stix-atlas-attack-enterprise.json"
    )

    # CISA KEV JSON feed (commonly used feed endpoint)
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # arXiv API endpoint
    ARXIV_API_URL: str = "https://export.arxiv.org/api/query"
    # NIST NVD CVE API endpoint (v2)
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # The Hacker News RSS feed
    THN_RSS_URL: str = "https://feeds.feedburner.com/TheHackersNews"

    # Filtering behavior.
    # AI relevance matching strictness: "strict" | "broad"
    AI_FILTER_MODE: str = "broad"
    # Relevance backend: "llama" | "keyword"
    AI_FILTER_BACKEND: str = "llama"
    # Ollama model and endpoint used for relevance decisions.
    AI_FILTER_MODEL: str = "llama3.1:8b"
    OLLAMA_API_URL: str = "http://localhost:11434/api/generate"
    AI_FILTER_TIMEOUT_SECONDS: int = 25
    # Safety fallback to keyword matching when LLM calls fail.
    AI_FILTER_FALLBACK_TO_KEYWORDS: bool = False
    # Fast-path: use keyword prefilter before LLM calls.
    # Keep false when you want every item evaluated by Llama.
    AI_FILTER_PREFILTER_KEYWORDS: bool = False
    # Classification backend: "llama" | "rules"
    AI_CLASSIFIER_BACKEND: str = "llama"
    # Safety fallback to rules when LLM classification fails.
    AI_CLASSIFIER_FALLBACK_TO_RULES: bool = True

    # NVD ingestion behavior.
    NVD_MAX_RESULTS: int = 350

    # Scheduler behavior.
    # Real-time-ish refresh cadence
    REFRESH_MINUTES: int = 30
    # If true, do initial refresh in background instead of blocking startup.
    STARTUP_REFRESH_IN_BACKGROUND: bool = True


# Singleton settings instance used across the app.
settings = Settings()
