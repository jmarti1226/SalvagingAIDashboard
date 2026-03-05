from __future__ import annotations
from functools import lru_cache

import requests

from app.config import settings

# Relevance flow summary:
# 1) Build candidate text from source fields.
# 2) Choose backend via settings.AI_FILTER_BACKEND:
#    - "keyword": direct keyword matching only.
#    - "llama": Ollama YES/NO decision (optionally prefiltered by keywords).
# 3) On Llama/API/parse failure, optionally fall back to keyword matching when
#    settings.AI_FILTER_FALLBACK_TO_KEYWORDS is enabled.

# Core AI/ML threat keywords used for strict matching.
STRICT_AI_ML_KEYWORDS = (
    "ai/ml",
    "ai-ml",
    "ai ml",
    "artificial intelligence",
    "machine learning",
    "ml-based",
    "ai-based",
    "deep learning",
    "neural network",
    "neural-net",
    "llm",
    "large language model",
    "generative ai",
    "transformer model",
    "foundation model",
    "adversarial",
    "adversarial example",
    "data poisoning",
    "jailbreak",
    "prompt",
    "prompt injection",
    "model poisoning",
    "model extraction",
    "model inversion",
    "model serving",
    "inference server",
    "embedding model",
    "tensorflow",
    "pytorch",
    "keras",
    "onnx",
    "hugging face",
    "langchain",
    "llama",
    "mlflow",
    "kubeflow",
    "triton inference server",
    "stable diffusion",
    "comfyui",
)

# AI-adjacent platform/product keywords used in broad matching mode.
ADJACENT_AI_KEYWORDS = (
    "nvidia",
    "tensorrt",
    "cudnn",
    "cuda",
    "onnxruntime",
    "openvino",
    "vllm",
    "ollama",
    "jupyter",
    "notebook",
    "anaconda",
    "conda",
    "ray serve",
    "sagemaker",
    "vertex ai",
    "azure machine learning",
    "amazon bedrock",
    "openai",
    "anthropic",
)


# Shared keyword relevance gate used as fallback.
def _keyword_is_ai_ml_related(*texts: str, mode: str = "strict") -> bool:
    # Normalize all candidate fields into one lowercase search string.
    text = " ".join((t or "") for t in texts).lower()

    # Start with strict keywords and optionally widen to adjacent ecosystem terms.
    keywords = STRICT_AI_ML_KEYWORDS
    if (mode or "").lower() == "broad":
        keywords = STRICT_AI_ML_KEYWORDS + ADJACENT_AI_KEYWORDS

    # Match if any configured keyword appears in the combined text.
    return any(keyword in text for keyword in keywords)


def _parse_yes_no(response_text: str) -> bool:
    """Parse a constrained YES/NO model response."""
    # Normalize casing/spacing before parsing model output.
    normalized = (response_text or "").strip().lower()
    if normalized.startswith("yes"):
        return True
    if normalized.startswith("no"):
        return False

    if " yes" in f" {normalized} ":
        return True
    if " no" in f" {normalized} ":
        return False

    raise ValueError(f"Could not parse LLM response as YES/NO: {response_text!r}")


@lru_cache(maxsize=2048)
def _llama_relevance_decision(text: str, mode: str) -> bool:
    """Ask Ollama to decide whether generic text is AI/ML-security related."""
    # Convert mode into explicit prompt guidance so model behavior is transparent.
    mode_name = (mode or "strict").lower()
    mode_guidance = (
        "Use broad matching: include AI-adjacent infrastructure and ML platform context."
        if mode_name == "broad"
        else "Use strict matching: include only direct AI/ML model-related security content."
    )

    # Use a strict binary-output prompt to simplify downstream parsing.
    prompt = (
        "You are a binary classifier for cybersecurity threat-intelligence ingestion.\n"
        "Task: decide if the text is related to AI/ML security threats, vulnerabilities, exploits, or attacks.\n"
        f"Guidance: {mode_guidance}\n"
        "Output format: respond with exactly one token, YES or NO.\n\n"
        f"Text:\n{text[:5000]}"
    )

    payload = {
        # Use configured local model for relevance classification.
        "model": settings.AI_FILTER_MODEL,
        "prompt": prompt,
        # Non-streaming keeps response handling simple for this synchronous call.
        "stream": False,
        "options": {
            # Deterministic, low-variance output for classifier-style prompts.
            "temperature": 0,
            # Tiny token budget encourages one-word YES/NO responses.
            "num_predict": 3,
        },
    }

    # Call Ollama and raise on transport/HTTP failures.
    r = requests.post(
        settings.OLLAMA_API_URL,
        json=payload,
        timeout=settings.AI_FILTER_TIMEOUT_SECONDS,
    )
    r.raise_for_status()
    # Parse generated text from Ollama JSON payload.
    response_text = (r.json().get("response") or "").strip()
    # Enforce strict YES/NO contract or raise for fallback handling.
    return _parse_yes_no(response_text)


@lru_cache(maxsize=4096)
def _llama_kev_relevance_decision(cve: str, vendor: str, product: str, vuln_name: str, notes: str) -> bool:
    """Ask Ollama to decide whether a KEV entry is AI/ML related."""
    # KEV prompt includes structured vulnerability fields to reduce ambiguity.
    prompt = (
        "You are a binary classifier for CISA KEV entries.\n"
        "Task: decide if this KEV vulnerability is specifically related to AI/ML systems.\n"
        "Include vulnerabilities in AI/ML models, inference/serving stacks, training pipelines, "
        "ML frameworks, LLM tooling, and AI-enabled products.\n"
        "Exclude generic enterprise vulnerabilities that have no specific AI/ML component impact.\n"
        "Output format: respond with exactly one token, YES or NO.\n\n"
        f"CVE: {cve}\n"
        f"Vendor: {vendor}\n"
        f"Product: {product}\n"
        f"Vulnerability Name: {vuln_name}\n"
        f"Notes: {notes}"
    )

    payload = {
        # Match generic relevance settings for consistent model behavior.
        "model": settings.AI_FILTER_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0,
            "num_predict": 3,
        },
    }


    # Parse/validation is centralized in _parse_yes_no.
    r = requests.post(
        settings.OLLAMA_API_URL,
        json=payload,
        timeout=settings.AI_FILTER_TIMEOUT_SECONDS,
    )
    r.raise_for_status()
    response_text = (r.json().get("response") or "").strip()
    return _parse_yes_no(response_text)


@lru_cache(maxsize=4096)
def _llama_nvd_relevance_decision(cve_id: str, description: str, reference_text: str, cpe_text: str) -> bool:
    """Ask Ollama to decide whether an NVD CVE is AI/ML related."""
    # NVD prompt includes description, references, and CPE hints for better context.
    prompt = (
        "You are a binary classifier for NIST NVD CVE entries.\n"
        "Task: decide if this CVE is specifically related to AI/ML systems.\n"
        "Include vulnerabilities in ML frameworks, model runtimes, LLM tooling, training/inference pipelines, "
        "or products where the vulnerable component is clearly AI/ML-related.\n"
        "Exclude generic OS, browser, network, database, or enterprise software CVEs with no clear AI/ML tie.\n"
        "Output format: respond with exactly one token, YES or NO.\n\n"
        f"CVE: {cve_id}\n"
        f"Description: {description[:2000]}\n"
        f"References: {reference_text[:2000]}\n"
        f"CPE: {cpe_text[:1500]}"
    )

    payload = {
        # Reuse same deterministic generation settings as other relevance calls.
        "model": settings.AI_FILTER_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0,
            "num_predict": 3,
        },
    }

    r = requests.post(
        settings.OLLAMA_API_URL,
        json=payload,
        timeout=settings.AI_FILTER_TIMEOUT_SECONDS,
    )
    r.raise_for_status()
    response_text = (r.json().get("response") or "").strip()
    return _parse_yes_no(response_text)


# Shared relevance gate for all ingestors.
def is_ai_ml_related(*texts: str, mode: str = "strict") -> bool:
    """Run shared relevance logic with keyword or Llama backend."""
    # Empty input is treated as not relevant.
    text = " ".join((t or "") for t in texts).strip()
    if not text:
        return False

    backend = (settings.AI_FILTER_BACKEND or "keyword").lower()
    if backend == "keyword":
        return _keyword_is_ai_ml_related(*texts, mode=mode)

    if backend == "llama":
        try:
            # Fast-path: reject obvious non-AI items without invoking the LLM.
            if settings.AI_FILTER_PREFILTER_KEYWORDS and not _keyword_is_ai_ml_related(*texts, mode=mode):
                return False
            return _llama_relevance_decision(text, mode)
        except Exception:
            # Optional safety net if Ollama is unavailable or returns invalid output.
            if settings.AI_FILTER_FALLBACK_TO_KEYWORDS:
                return _keyword_is_ai_ml_related(*texts, mode=mode)
            raise

    # Unknown backend: fail safe to keyword behavior.
    return _keyword_is_ai_ml_related(*texts, mode=mode)


def is_ai_ml_kev_related(cve: str, vendor: str, product: str, vuln_name: str, notes: str) -> bool:
    """Specialized relevance gate for CISA KEV records."""
    texts = (cve, vendor, product, vuln_name, notes)
    backend = (settings.AI_FILTER_BACKEND or "keyword").lower()

    if backend == "keyword":
        # Keep KEV matching strict if running keyword-only.
        return _keyword_is_ai_ml_related(*texts, mode="strict")

    if backend == "llama":
        try:
            return _llama_kev_relevance_decision(cve, vendor, product, vuln_name, notes)
        except Exception:
            # Optionally recover to strict keyword logic on model/API failures.
            if settings.AI_FILTER_FALLBACK_TO_KEYWORDS:
                return _keyword_is_ai_ml_related(*texts, mode="strict")
            raise

    return _keyword_is_ai_ml_related(*texts, mode="strict")


def is_ai_ml_nvd_related(cve_id: str, description: str, reference_text: str, cpe_text: str) -> bool:
    """Specialized relevance gate for NVD CVE records."""
    texts = (cve_id, description, reference_text, cpe_text)
    backend = (settings.AI_FILTER_BACKEND or "keyword").lower()

    if backend == "keyword":
        return _keyword_is_ai_ml_related(*texts, mode="strict")

    if backend == "llama":
        try:
            return _llama_nvd_relevance_decision(cve_id, description, reference_text, cpe_text)
        except Exception:
            # Optionally recover to strict keyword logic on model/API failures.
            if settings.AI_FILTER_FALLBACK_TO_KEYWORDS:
                return _keyword_is_ai_ml_related(*texts, mode="strict")
            raise

    return _keyword_is_ai_ml_related(*texts, mode="strict")
