"""
tool: classify_attack
---------------------
Deterministic attack-type classifier for pipeline routing.  Infers
investigation type from title, analyst notes, tags, and input shape
(URLs, files, logs, emails).  No LLM call — pure keyword matching
with weighted scoring.

Each attack type defines a pipeline profile: which steps to skip on
top of the existing input-driven conditions.

Usage:
    from tools.classify_attack import classify_attack_type, PIPELINE_PROFILES

    result = classify_attack_type(
        title="Credential phishing email",
        eml_paths=["phish.eml"],
        urls=["https://fake-login.example.com"],
    )
    # result = {"attack_type": "phishing", "confidence": "high", "signals": [...]}

    profile = PIPELINE_PROFILES[result["attack_type"]]
    if "sandbox_analyse" in profile["skip"]:
        ...  # skip sandbox
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ---------------------------------------------------------------------------
# Attack types and their keyword patterns
# ---------------------------------------------------------------------------

ATTACK_TYPES = (
    "phishing",
    "malware",
    "account_compromise",
    "privilege_escalation",
    "pup_pua",
    "generic",
)

# Each entry: (attack_type, keywords, weight)
# Keywords are matched case-insensitively against title + analyst_notes + tags
_KEYWORD_RULES: list[tuple[str, list[str], int]] = [
    # Phishing — email/URL/credential harvest focused
    ("phishing", [
        "phishing", "phish", "credential harvest", "credential.harvest",
        "fake login", "brand impersonation", "suspicious email",
        "malicious email", "spear phishing", "spearphish", "qr code phish",
        "quishing", "vishing", "smishing", "business email compromise",
        "bec ", "email lure", "consent phishing", "oauth phishing",
        "aitm", "adversary.in.the.middle", "evilginx",
    ], 3),

    # Malware — file/execution/payload focused
    ("malware", [
        "malware", "ransomware", "trojan", "backdoor", " rat ",
        "remote access tool", "dropper", "loader", "cryptominer",
        "crypto miner", "miner detected", "c2 beacon", "cobalt strike",
        "cobaltstrike", "sliver", "brute ratel", "havoc", "mythic",
        "implant", "command and control", "command.and.control",
        "download cradle", "powershell download", "macro execution",
        "malicious macro", "shellcode", "payload execution",
        "suspicious execution", "suspicious process",
        "malicious file", "malicious binary",
    ], 3),

    # Account compromise — identity/auth focused
    ("account_compromise", [
        "account compromise", "compromised account", "stolen credential",
        "password spray", "brute force", "credential stuffing",
        "impossible travel", "suspicious sign-in", "risky sign-in",
        "mfa fatigue", "mfa bombing", "token theft", "session hijack",
        "token replay", "anomalous sign-in", "unfamiliar sign-in",
        "compromised user", "suspicious logon", "atypical travel",
        "leaked credential", "credential leak", "inbox rule",
        "suspicious inbox", "mailbox forwarding", "oauth abuse",
    ], 3),

    # Privilege escalation
    ("privilege_escalation", [
        "privilege escalation", "priv esc", "admin rights",
        "role assignment", "group membership", "elevated access",
        "local admin", "domain admin", "global admin",
        "aad role", "entra role", "sudo abuse", "suid",
        "service account abuse", "token manipulation",
    ], 3),

    # PUP/PUA — handled by detect_pup() separately, but classify here too
    ("pup_pua", [
        "pup", "pua", "potentially unwanted", "adware", "bundleware",
        "browser hijack", "search hijack", "toolbar", "grayware",
        "greyware", "junkware", "bloatware", "unwanted program",
        "unwanted application", "unwanted software",
    ], 3),
]


# ---------------------------------------------------------------------------
# Pipeline profiles — which steps to SKIP per attack type
#
# These are ADDITIONAL exclusions on top of input-driven conditions.
# e.g. domain_investigate already requires URLs — the profile can
# additionally exclude it even when URLs are present.
# ---------------------------------------------------------------------------

PIPELINE_PROFILES: dict[str, dict] = {
    "phishing": {
        "skip": {
            "sandbox_analyse",
            "sandbox_detonate",
        },
        "description": "Email/URL focused — capture pages, detect brand impersonation, enrich IOCs",
    },
    "malware": {
        "skip": {
            "detect_phishing_page",
            "recursive_capture",
        },
        "description": "File/execution focused — static analysis, sandbox, enrich IOCs",
    },
    "account_compromise": {
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
        },
        "description": "Identity/auth focused — log correlation, anomaly detection, enrichment",
    },
    "privilege_escalation": {
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
        },
        "description": "Escalation focused — log correlation, anomaly detection, enrichment",
    },
    "pup_pua": {
        # Full short-circuit handled in chief.py — this profile is for reference
        "skip": {
            "plan",
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
            "log_correlate",
            "correlate",
            "anomaly_detection",
            "campaign_cluster",
            "response_actions",
            "report",
            "query_gen",
            "security_arch",
        },
        "description": "PUP/PUA — lightweight: enrich + PUP report only",
    },
    "generic": {
        "skip": set(),
        "description": "Unknown/mixed type — run all steps permitted by inputs",
    },
}


# ---------------------------------------------------------------------------
# Classification function
# ---------------------------------------------------------------------------

def classify_attack_type(
    title: str = "",
    analyst_notes: str = "",
    tags: list[str] | None = None,
    eml_paths: list[str] | None = None,
    urls: list[str] | None = None,
    zip_path: str | None = None,
    log_paths: list[str] | None = None,
) -> dict:
    """Classify investigation type from available signals.

    Returns:
        {
            "attack_type": str,       # one of ATTACK_TYPES
            "confidence": str,        # "high", "medium", "low"
            "signals": list[str],     # human-readable explanation
            "profile": dict,          # the PIPELINE_PROFILES entry
        }
    """
    scores: dict[str, int] = {t: 0 for t in ATTACK_TYPES}
    signals: dict[str, list[str]] = {t: [] for t in ATTACK_TYPES}

    # --- Keyword matching against text fields ---
    combined = f" {title} {analyst_notes} {' '.join(tags or [])} ".lower()
    # Normalise punctuation for flexible matching
    combined_norm = re.sub(r"[_\-/]", " ", combined)

    for attack_type, keywords, weight in _KEYWORD_RULES:
        for kw in keywords:
            if kw in combined_norm:
                scores[attack_type] += weight
                signals[attack_type].append(f"keyword '{kw}' in title/notes/tags")
                break  # one keyword match per rule is enough

    # --- Input-shape heuristics ---

    # EML files strongly suggest phishing
    if eml_paths:
        scores["phishing"] += 2
        signals["phishing"].append("EML file(s) provided")

    # ZIP with no URLs and no EML leans malware
    if zip_path and not urls and not eml_paths:
        scores["malware"] += 2
        signals["malware"].append("ZIP provided without URLs or EML (file-focused)")
    elif zip_path:
        scores["malware"] += 1
        signals["malware"].append("ZIP file provided")

    # URLs with EML → phishing (email with link)
    if urls and eml_paths:
        scores["phishing"] += 1
        signals["phishing"].append("URLs + EML provided (email with links)")

    # URLs alone → could be phishing or malware download
    if urls and not eml_paths and not zip_path:
        scores["phishing"] += 1
        signals["phishing"].append("URLs provided (possible phishing site)")

    # Logs with no URLs/ZIP/EML → identity/account investigation
    if log_paths and not urls and not zip_path and not eml_paths:
        scores["account_compromise"] += 2
        signals["account_compromise"].append("log paths provided without URLs/ZIP/EML (identity-focused)")

    # --- Pick the winner ---
    best_type = max(scores, key=lambda t: scores[t])
    best_score = scores[best_type]

    # Confidence based on score and margin
    second_best = sorted(scores.values(), reverse=True)[1] if len(scores) > 1 else 0
    margin = best_score - second_best

    if best_score <= 1:
        # A single weak signal (e.g. input-shape heuristic alone) is not
        # enough to route the pipeline — fall through to generic.
        best_type = "generic"
        confidence = "low"
    elif best_score >= 4 and margin >= 2:
        confidence = "high"
    elif best_score >= 2:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "attack_type": best_type,
        "confidence": confidence,
        "signals": signals[best_type],
        "scores": {t: s for t, s in scores.items() if s > 0},
        "profile": PIPELINE_PROFILES[best_type],
    }


def should_skip_step(step_name: str, attack_type: str) -> bool:
    """Check if *step_name* should be skipped for the given attack type."""
    profile = PIPELINE_PROFILES.get(attack_type, PIPELINE_PROFILES["generic"])
    return step_name in profile["skip"]
