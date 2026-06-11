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
    # Order matters: on a score tie, the earlier type wins. More-specific types
    # are placed ahead of the broader types they would otherwise tie with
    # (ransomware before malware, oauth_consent before phishing-adjacent, etc.).
    "phishing",
    "oauth_consent",
    "ransomware",
    "malware",
    "account_compromise",
    "credential_access",
    "privilege_escalation",
    "insider_threat",
    "data_exfiltration",
    "lateral_movement",
    "command_and_control",
    "reconnaissance",
    "persistence",
    "defence_evasion",
    "web_shell",
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

    # Malware — file/execution/payload focused (C2/beacon terms belong to
    # the dedicated command_and_control type below).
    ("malware", [
        "malware", "trojan", "backdoor", " rat ",
        "remote access tool", "dropper", "loader", "cryptominer",
        "crypto miner", "miner detected",
        "download cradle", "powershell download", "macro execution",
        "malicious macro", "shellcode", "payload execution",
        "suspicious execution", "suspicious process",
        "malicious file", "malicious binary",
    ], 3),

    # Account compromise — identity/auth focused (inbound-recon precursors
    # like password spray / brute force / credential stuffing route to the
    # dedicated reconnaissance type below).
    ("account_compromise", [
        "account compromise", "compromised account", "stolen credential",
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

    # Data exfiltration — external-transfer focused (DLP, mass download).
    # Insider-staging terms (insider threat / data staging) route to the
    # dedicated insider_threat type below.
    ("data_exfiltration", [
        "data exfiltration", "data theft", "data leak", "data loss",
        "mass download", "bulk download", "unusual download",
        "dlp alert", "dlp policy", "information protection",
        "unauthorized transfer", "sensitive data", "cloud app anomaly",
        "mass file access", "bulk file", "excessive download",
        "sharepoint mass", "onedrive mass", "email forwarding rule",
    ], 3),

    # Lateral movement — internal pivoting via remote protocols. Pure AD
    # credential-theft tradecraft (kerberoast / DCSync / golden+silver ticket)
    # now routes to the dedicated credential_access type below.
    ("lateral_movement", [
        "lateral movement", "lateral move", "pass the hash", "pass-the-hash",
        "pass the ticket", "pass-the-ticket", "overpass the hash",
        "rdp pivot", "internal rdp", "smb lateral", "psexec",
        "wmi remote", "winrm", "dcom lateral", "host hop",
        "credential relay", "ntlm relay",
        "internal pivot", "network pivot", "host compromise spread",
    ], 3),

    # Command & Control — behavioural C2 (beaconing, tunnelling, callbacks).
    # Note: combined_norm normalises -, _ and / to spaces, so "command-and-
    # control" matches "command and control"; dots are preserved, so the dotted
    # variant is kept separately.
    ("command_and_control", [
        "command and control", "command.and.control",
        # Bare "c2" needs boundaries — plain substring matching hits "EC2".
        re.compile(r"(?<![a-z0-9])c2(?![a-z0-9])"),
        "c2 beacon", "c2 callback", "c2 framework", "beacon", "beaconing",
        "callback", "call back", "implant", "dns tunnel", "dns tunnelling",
        "dns tunneling", "tunnelling", "tunneling", "lolbin", "lolbin callout",
        "lolbas", "living off the land", "cobalt strike", "cobaltstrike",
        "sliver", "brute ratel", "havoc", "mythic", "empire", "covenant",
    ], 3),

    # Reconnaissance — active inbound recon (spray, scanning, enumeration).
    ("reconnaissance", [
        "reconnaissance", "recon ", "password spray", "password spraying",
        "credential stuffing", "port scan", "port scanning", "network scan",
        "service scan", "scanning activity", "enumeration", "enumerate",
        "brute force", "subdomain enumeration", "dns enumeration",
        "mx enumeration", "directory enumeration", "user enumeration",
        "spray attack", "login attempts",
    ], 3),

    # Ransomware / impact — encryption behaviour and recovery inhibition.
    ("ransomware", [
        "ransomware", "ransom note", "ransom demand", "file encryption",
        "files encrypted", "mass file encryption", "extension change",
        "mass file rename", "shadow copy delet", "shadow copies delet",
        "vssadmin", "wbadmin", "bcdedit", "recovery inhibit", "inhibit recovery",
        "double extortion", "lockbit", "blackcat", "alphv", " akira ",
        "royal ransom", " conti ", " ryuk ", "black basta", "rhysida",
        # Family names padded with spaces: substring matching would otherwise
        # fire "conti" on "continues/continuous", "ryuk" on "ryukyu", etc.
    ], 3),

    # Credential access / AD attacks — credential theft tradecraft (distinct
    # from lateral_movement, which is the pivoting that may follow).
    ("credential_access", [
        "credential access", "credential dump", "credential dumping",
        "credential theft", "lsass", "lsass dump", "lsass access",
        "mimikatz", "kerberoast", "as-rep", "asrep roast", "as rep roast",
        "dcsync", "ntds.dit", "ntds dump", "secretsdump", "sam dump",
        "comsvcs", "procdump", "golden ticket", "silver ticket",
        "ticket extraction", "hash dump", "lsa secrets",
    ], 3),

    # Insider threat / data staging — legitimate user staging data (distinct
    # from data_exfiltration, which is the external transfer itself).
    ("insider_threat", [
        "insider threat", "insider risk", "data staging", "departing employee",
        " leaver ", "disgruntled", "mass file copy", "usb exfil", "usb copy",
        "removable media", "personal cloud upload", "archive staging",
        "data hoarding", "rogue employee",
    ], 3),

    # Persistence — autostart / boot-or-logon survival mechanisms.
    ("persistence", [
        "persistence", "scheduled task", "schtasks", "run key", "runonce",
        "registry run", "autostart", " asep ", "new service install",
        "service install", "wmi subscription", "wmi event consumer",
        "startup folder", "boot persistence", "logon persistence",
        "image file execution options", " ifeo ", "registry autostart",
    ], 3),

    # Defence evasion / tamper — blinding detection.
    ("defence_evasion", [
        "defence evasion", "defense evasion", "log cleared", "event log cleared",
        "clear event log", "wevtutil", "event id 1102", "edr disabled",
        "av disabled", "antivirus disabled", "defender disabled",
        "tamper protection", "tampering attempt", "disable security",
        "uninstall agent", "kill security tool", "amsi bypass", "etw bypass",
        "security tool kill",
    ], 3),

    # Web shell / exploited public-facing app.
    ("web_shell", [
        "web shell", "webshell", "aspx shell", "jsp shell", "php shell",
        "china chopper", "behinder", "godzilla", "exploited public",
        "public facing application", "iis exploit", "proxyshell", "proxylogon",
        "server side exploit", "exploited web server", "w3wp spawn",
    ], 3),

    # Illicit OAuth consent / enterprise-app abuse (the consent-investigation
    # itself; consent-phishing lure delivery stays under phishing).
    ("oauth_consent", [
        "oauth consent", "consent grant", "illicit consent",
        "illicit application", "enterprise app abuse", "app consent grant",
        "malicious oauth", "azure app consent", "app registration abuse",
        "service principal credential", "consent to application",
        "illicit oauth", "rogue oauth app",
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
    "data_exfiltration": {
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
        },
        "description": "Data movement focused — DLP alerts, volume anomalies, cloud app activity, network exfiltration",
    },
    "lateral_movement": {
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
        },
        "description": "Internal movement focused — RDP/SMB/WMI connections, credential access, blast radius mapping",
    },
    "command_and_control": {
        # No file artefact — skip all static/file analysis and sandbox steps.
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
            "static_file_analyse",
            "analyse_file",
            "analyse_email",
        },
        "description": "Behavioural C2 hunt — beaconing, DNS tunnelling, long-haul low-volume sessions, LOLBin callbacks; network + process log correlation, no file artefact",
    },
    "reconnaissance": {
        # Identity + network log correlation — no email/file artefact.
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
            "static_file_analyse",
            "analyse_file",
            "analyse_email",
        },
        "description": "Inbound recon detection — credential spray/stuffing, port/service scanning, DNS enumeration; identity + network log correlation",
    },
    "ransomware": {
        # Endpoint behaviour via logs; file analysis allowed but no detonation.
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
        },
        "description": "Ransomware impact — recovery tampering, mass file modification, ransom notes, encryption detections; endpoint log correlation",
    },
    "credential_access": {
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
        },
        "description": "Credential theft — LSASS dumping, Kerberoasting/AS-REP, DCSync; endpoint + AD log correlation",
    },
    "persistence": {
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
        },
        "description": "Persistence sweep — scheduled tasks, Run keys, services, WMI subscriptions, startup folder; endpoint log correlation",
    },
    "defence_evasion": {
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
        },
        "description": "Defence evasion — log clearing, EDR/AV tamper, defensive-tool kills; endpoint log correlation",
    },
    "web_shell": {
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
        },
        "description": "Web shell / exploited public app — web-server spawned shells, web-shell drops, post-exploitation; endpoint log correlation",
    },
    "oauth_consent": {
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
        },
        "description": "Illicit OAuth consent — consent grants, SP sign-ins, app data access, IP sweep; identity/audit log correlation",
    },
    "insider_threat": {
        "skip": {
            "domain_investigate",
            "recursive_capture",
            "detect_phishing_page",
            "sandbox_analyse",
            "sandbox_detonate",
        },
        "description": "Insider / data staging — bulk cloud pull, local archiving, removable media, egress; audit + endpoint log correlation",
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
# Specialist MCP toolset(s) to load for each attack type.
#
# Empty list = the always-on "core" toolset (case mgmt, enrichment, log
# hunting, reporting) fully covers it — true for the log-based investigation
# types. The classify_attack MCP tool surfaces this so the LLM can call
# load_toolset() and have the right specialist tools appear on demand,
# instead of every session loading all 113 tools up front.
# ---------------------------------------------------------------------------

ATTACK_TYPE_TOOLSETS: dict[str, list[str]] = {
    "phishing": ["phishing"],
    "malware": ["malware"],
    "account_compromise": [],
    "privilege_escalation": [],
    "data_exfiltration": [],
    "lateral_movement": [],
    "command_and_control": [],
    "reconnaissance": [],
    "ransomware": [],
    "credential_access": [],
    "persistence": [],
    "defence_evasion": [],
    "web_shell": [],
    "oauth_consent": [],
    "insider_threat": [],
    "pup_pua": [],
    "generic": [],
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
            if isinstance(kw, re.Pattern):
                hit = bool(kw.search(combined_norm))
                label = kw.pattern
            else:
                # Normalise the keyword the same way as the input — hyphenated
                # keywords ("risky sign-in") could otherwise never match the
                # normalised text ("risky sign in") and common Entra alerts
                # fell through to generic.
                hit = re.sub(r"[_\-/]", " ", kw) in combined_norm
                label = kw
            if hit:
                scores[attack_type] += weight
                signals[attack_type].append(f"keyword '{label}' in title/notes/tags")
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
