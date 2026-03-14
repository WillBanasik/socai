"""
Global configuration for SOC-AI.
Override values via environment variables prefixed with SOCAI_.
A .env file at the repo root is loaded automatically (never commit it).
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

BASE_DIR = Path(__file__).resolve().parent.parent

CASES_DIR        = BASE_DIR / "cases"
REPORTS_DIR      = BASE_DIR / "reports"
WEEKLY_REPORTS   = REPORTS_DIR / "weekly"
REGISTRY_FILE    = BASE_DIR / "registry" / "case_index.json"
AUDIT_LOG        = BASE_DIR / "registry" / "audit.log"
ERROR_LOG        = BASE_DIR / "registry" / "error_log.jsonl"
MCP_USAGE_LOG    = BASE_DIR / "registry" / "mcp_usage.jsonl"
MCP_SERVER_LOG   = BASE_DIR / "registry" / "mcp_server.jsonl"
MCP_SERVER_PID   = BASE_DIR / "registry" / "mcp_server.pid"

# MCP server logging
MCP_LOG_LEVEL    = os.getenv("SOCAI_MCP_LOG_LEVEL", "INFO")
MCP_LOG_RESULTS  = os.getenv("SOCAI_MCP_LOG_RESULTS", "1") == "1"
MCP_LOG_MAX_RESULT = int(os.getenv("SOCAI_MCP_LOG_MAX_RESULT", "2000"))

# Web capture
CAPTURE_TIMEOUT  = int(os.getenv("SOCAI_CAPTURE_TIMEOUT", "20"))      # seconds
CAPTURE_SPA_DWELL = int(os.getenv("SOCAI_SPA_DWELL", "5000"))         # ms to wait after networkidle if page text is empty (SPA render)
CAPTURE_UA       = os.getenv(
    "SOCAI_UA",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
)

# Headless browser backend: "playwright" or "requests" (fallback)
BROWSER_BACKEND  = os.getenv("SOCAI_BROWSER", "playwright")

# Static analysis
STRINGS_MIN_LEN  = int(os.getenv("SOCAI_STRINGS_MIN", "6"))

# Enrichment API keys (read from .env or environment)
VIRUSTOTAL_KEY   = os.getenv("SOCAI_VT_KEY", "")
ABUSEIPDB_KEY    = os.getenv("ABUSEIPDB_API_KEY") or os.getenv("SOCAI_ABUSEIPDB_KEY", "")
SHODAN_KEY       = os.getenv("SHODAN_API_KEY", "")
GREYNOISE_KEY    = os.getenv("GREYNOISE_API_KEY", "")
INTEZER_KEY      = os.getenv("INTEZER_API_KEY", "")
URLSCAN_KEY      = os.getenv("URLSCAN_API_KEY", "")
PROXYCHECK_KEY   = os.getenv("PROXYCHECK_API_KEY", "")
OPENCTI_KEY      = os.getenv("OPENCTI_API_KEY", "")
OPENCTI_URL      = os.getenv("OPENCTI_URL", "https://opencti.example.com")

# Optional key for higher rate limits (keyless tier available but heavily rate-limited)
EMAILREP_KEY     = os.getenv("EMAILREP_API_KEY", "")

# Account-required providers (free account; add keys to .env when ready)
ABUSECH_KEY      = os.getenv("ABUSECH_API_KEY", "")          # URLhaus + ThreatFox + MalwareBazaar (one key)
OTX_KEY          = os.getenv("OTX_API_KEY", "")              # AlienVault OTX
HYBRID_KEY       = os.getenv("HYBRID_ANALYSIS_API_KEY", "")  # Hybrid Analysis
CENSYS_TOKEN     = os.getenv("CENSYS_TOKEN", "")      # Personal Access Token from censys.io → API Access
WHOISXML_KEY     = os.getenv("WHOISXML_API_KEY", "")

# Web search fallback (Brave Search API; DuckDuckGo used if no key)
BRAVE_SEARCH_KEY = os.getenv("SOCAI_BRAVE_SEARCH_KEY", "")

# Enrichment performance
ENRICH_CACHE_FILE = BASE_DIR / "registry" / "enrichment_cache.json"
ENRICH_CACHE_TTL  = int(os.getenv("SOCAI_ENRICH_CACHE_TTL", "24"))   # hours; 0 to disable
ENRICH_WORKERS    = int(os.getenv("SOCAI_ENRICH_WORKERS", "10"))      # thread pool size

# Cross-case IOC index
IOC_INDEX_FILE    = BASE_DIR / "registry" / "ioc_index.json"

# Confidence thresholds
CONF_HIGH        = 0.75
CONF_MED         = 0.45
CONF_AUTO_CLOSE  = float(os.getenv("SOCAI_CONF_AUTO_CLOSE", "0.20"))

# Sandbox providers
ANYRUN_KEY       = os.getenv("ANYRUN_API_KEY", "")
JOESANDBOX_KEY   = os.getenv("JOESANDBOX_API_KEY", "")

# Local sandbox detonation
SANDBOX_DOCKER_IMAGE      = os.getenv("SOCAI_SANDBOX_IMAGE", "socai-sandbox:latest")
SANDBOX_WINE_IMAGE        = os.getenv("SOCAI_SANDBOX_WINE_IMAGE", "socai-sandbox-wine:latest")
SANDBOX_DEFAULT_TIMEOUT   = int(os.getenv("SOCAI_SANDBOX_TIMEOUT_LOCAL", "120"))
SANDBOX_MAX_TIMEOUT       = int(os.getenv("SOCAI_SANDBOX_MAX_TIMEOUT", "600"))
SANDBOX_MEMORY_LIMIT      = os.getenv("SOCAI_SANDBOX_MEMORY", "512m")
SANDBOX_CPU_LIMIT         = os.getenv("SOCAI_SANDBOX_CPUS", "1.0")
SANDBOX_DEFAULT_NETWORK   = os.getenv("SOCAI_SANDBOX_NETWORK", "monitor")
SANDBOX_NETWORK_NAME      = os.getenv("SOCAI_SANDBOX_NETWORK_NAME", "socai_sandbox_net")

# Campaign clustering
CAMPAIGNS_FILE   = BASE_DIR / "registry" / "campaigns.json"

# Client domain aliasing for data minimisation
ALIAS_ENABLED     = os.getenv("SOCAI_ALIAS", "0") == "1"
ALIAS_MAP_FILE    = BASE_DIR / "registry" / "alias_map.json"
CLIENT_ENTITIES   = BASE_DIR / "config" / "client_entities.json"
CLIENT_PLAYBOOKS_DIR = BASE_DIR / "config" / "clients"
ROLES_FILE           = BASE_DIR / "config" / "roles.json"
DEFAULT_CLIENT    = os.getenv("SOCAI_DEFAULT_CLIENT", "")

# Claude model for LLM-assisted steps (optional, not required for core)
LLM_MODEL        = os.getenv("SOCAI_LLM_MODEL", "claude-sonnet-4-6")
ANTHROPIC_KEY    = os.getenv("ANTHROPIC_API_KEY", "")

# ---------------------------------------------------------------------------
# Model tiers
# ---------------------------------------------------------------------------
SOCAI_MODEL_HEAVY    = os.getenv("SOCAI_MODEL_HEAVY",    "claude-opus-4-6")
SOCAI_MODEL_STANDARD = os.getenv("SOCAI_MODEL_STANDARD", "claude-sonnet-4-6")
SOCAI_MODEL_FAST     = os.getenv("SOCAI_MODEL_FAST",     "claude-haiku-4-5-20251001")

# Per-task model assignments (value = tier name or full model string)
SOCAI_MODEL_CHAT_ROUTING  = os.getenv("SOCAI_MODEL_CHAT_ROUTING",  "fast")
SOCAI_MODEL_CHAT_RESPONSE = os.getenv("SOCAI_MODEL_CHAT_RESPONSE", "standard")
SOCAI_MODEL_SECARCH       = os.getenv("SOCAI_MODEL_SECARCH",       "standard")
SOCAI_MODEL_REPORT        = os.getenv("SOCAI_MODEL_REPORT",        "fast")
SOCAI_MODEL_EXEC_SUMMARY  = os.getenv("SOCAI_MODEL_EXEC_SUMMARY",  "standard")
SOCAI_MODEL_FP_TICKET     = os.getenv("SOCAI_MODEL_FP_TICKET",     "standard")
SOCAI_MODEL_FP_TUNING_TICKET = os.getenv("SOCAI_MODEL_FP_TUNING_TICKET", "standard")
SOCAI_MODEL_EVTX          = os.getenv("SOCAI_MODEL_EVTX",          "standard")
SOCAI_MODEL_PE_ANALYSIS   = os.getenv("SOCAI_MODEL_PE_ANALYSIS",   "standard")
SOCAI_MODEL_CVE           = os.getenv("SOCAI_MODEL_CVE",           "fast")
SOCAI_MODEL_YARA          = os.getenv("SOCAI_MODEL_YARA",          "standard")
SOCAI_MODEL_TIMELINE      = os.getenv("SOCAI_MODEL_TIMELINE",      "fast")
SOCAI_MODEL_QUERIES       = os.getenv("SOCAI_MODEL_QUERIES",       "fast")
SOCAI_MODEL_MDR_REPORT    = os.getenv("SOCAI_MODEL_MDR_REPORT",    "standard")

# LLM insight helpers (tools/llm_insight.py)
SOCAI_MODEL_REPORT_NARRATIVE    = os.getenv("SOCAI_MODEL_REPORT_NARRATIVE",    "fast")
SOCAI_MODEL_CAMPAIGN_NARRATIVE  = os.getenv("SOCAI_MODEL_CAMPAIGN_NARRATIVE",  "fast")
SOCAI_MODEL_QUERY_REFINEMENT    = os.getenv("SOCAI_MODEL_QUERY_REFINEMENT",    "fast")
SOCAI_MODEL_TRIAGE_CONTEXT      = os.getenv("SOCAI_MODEL_TRIAGE_CONTEXT",      "fast")
SOCAI_MODEL_ANOMALY_CONTEXT     = os.getenv("SOCAI_MODEL_ANOMALY_CONTEXT",     "fast")
SOCAI_MODEL_CORRELATION_INSIGHT = os.getenv("SOCAI_MODEL_CORRELATION_INSIGHT",  "fast")
SOCAI_MODEL_RESPONSE_PRIORITY   = os.getenv("SOCAI_MODEL_RESPONSE_PRIORITY",   "fast")
SOCAI_MODEL_VERDICT_RECONCILE   = os.getenv("SOCAI_MODEL_VERDICT_RECONCILE",   "fast")
SOCAI_MODEL_AUTO_CLOSE_REVIEW   = os.getenv("SOCAI_MODEL_AUTO_CLOSE_REVIEW",   "fast")

# Rumsfeld investigation pipeline (tools/investigation_matrix.py, etc.)
SOCAI_MODEL_MATRIX              = os.getenv("SOCAI_MODEL_MATRIX",              "standard")
SOCAI_MODEL_QUALITY_GATE        = os.getenv("SOCAI_MODEL_QUALITY_GATE",        "fast")
SOCAI_MODEL_ENRICH_DIRECTOR     = os.getenv("SOCAI_MODEL_ENRICH_DIRECTOR",     "fast")
SOCAI_MODEL_DETERMINATION       = os.getenv("SOCAI_MODEL_DETERMINATION",       "standard")
SOCAI_MODEL_GAP_ANALYSIS        = os.getenv("SOCAI_MODEL_GAP_ANALYSIS",        "standard")
SOCAI_ENRICH_DIRECTOR           = os.getenv("SOCAI_ENRICH_DIRECTOR",           "0")  # opt-in

# ---------------------------------------------------------------------------
# Batch API
# ---------------------------------------------------------------------------
BATCH_POLL_INTERVAL = int(os.getenv("SOCAI_BATCH_POLL_INTERVAL", "30"))
BATCH_TIMEOUT = int(os.getenv("SOCAI_BATCH_TIMEOUT", "3600"))
BATCH_DIR = BASE_DIR / "registry" / "batches"

# ---------------------------------------------------------------------------
# Threat articles
# ---------------------------------------------------------------------------
ARTICLES_DIR       = BASE_DIR / "articles"
ARTICLE_INDEX_FILE = BASE_DIR / "registry" / "article_index.json"
SOCAI_MODEL_ARTICLES = os.getenv("SOCAI_MODEL_ARTICLES", "standard")

# ---------------------------------------------------------------------------
# Confluence (read-only, scoped token)
# ---------------------------------------------------------------------------
CONFLUENCE_URL       = os.getenv("CONFLUENCE_URL", "")
CONFLUENCE_CLOUD_ID  = os.getenv("CONFLUENCE_CLOUD_ID", "")
CONFLUENCE_EMAIL     = os.getenv("CONFLUENCE_EMAIL", "")
CONFLUENCE_API_TOKEN = os.getenv("CONFLUENCE_API_TOKEN", "")
CONFLUENCE_SPACE_KEY = os.getenv("CONFLUENCE_SPACE_KEY", "")

# ---------------------------------------------------------------------------
# Cyberint (read-only alert query)
# ---------------------------------------------------------------------------
CYBERINT_API_KEY = os.getenv("CYBERINT_API_KEY", "")
CYBERINT_API_URL = os.getenv("CYBERINT_API_URL", "https://cyberint.example.com")

# ---------------------------------------------------------------------------
# Browser pool (Playwright reuse)
# ---------------------------------------------------------------------------
SOCAI_BROWSER_POOL_MAX_USES = int(os.getenv("SOCAI_BROWSER_POOL_MAX_USES", "50"))
# Auto-close pooled browser after N seconds of inactivity (default 5 min)
SOCAI_BROWSER_POOL_IDLE_SECS = int(os.getenv("SOCAI_BROWSER_POOL_IDLE_SECS", "300"))

