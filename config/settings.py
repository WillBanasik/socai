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

# LLM reasoning is handled exclusively by the local Claude Desktop agent.
# No direct Anthropic API calls — all LLM work uses MCP prompts + save tools.
SOCAI_ENRICH_DIRECTOR           = os.getenv("SOCAI_ENRICH_DIRECTOR",           "0")  # opt-in

# ---------------------------------------------------------------------------
# Case memory index (BM25 semantic recall)
# ---------------------------------------------------------------------------
CASE_MEMORY_INDEX_FILE = BASE_DIR / "registry" / "case_memory.json"

# ---------------------------------------------------------------------------
# Per-client behavioural baselines
# ---------------------------------------------------------------------------
BASELINES_DIR = BASE_DIR / "registry" / "baselines"

# ---------------------------------------------------------------------------
# Local GeoIP database (MaxMind GeoLite2)
# ---------------------------------------------------------------------------
MAXMIND_ACCOUNT_ID = os.getenv("MAXMIND_ACCOUNT_ID", "")
MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY", "")
GEOIP_DB_PATH = BASE_DIR / "registry" / "geoip" / "GeoLite2-City.mmdb"

# ---------------------------------------------------------------------------
# Threat articles
# ---------------------------------------------------------------------------
ARTICLES_DIR       = BASE_DIR / "articles"
ARTICLE_INDEX_FILE = BASE_DIR / "registry" / "article_index.json"

# ---------------------------------------------------------------------------
# OpenCTI publishing & article automation
# ---------------------------------------------------------------------------
# Gate: set to "1" to enable pushing reports to OpenCTI via bundleCreate
OPENCTI_PUBLISH_ENABLED = os.getenv("SOCAI_OPENCTI_PUBLISH", "0") == "1"
# Autonomous discovery: "daily" | "weekly" | "" (disabled)
ARTICLE_AUTO_DISCOVER   = os.getenv("SOCAI_ARTICLE_AUTO_DISCOVER", "")
# Auto-publish written articles to OpenCTI (requires OPENCTI_PUBLISH_ENABLED)
ARTICLE_AUTO_PUBLISH    = os.getenv("SOCAI_ARTICLE_AUTO_PUBLISH", "0") == "1"

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

