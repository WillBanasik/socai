"""
tool: client_query
------------------
Ad-hoc SIEM query generator for client requests.

No case creation. No file writes. No audit log. Stdout only.

Uses the configured LLM to parse a free-text client question, extract
key entities (hostnames, paths, dates, users), and generate ready-to-run
SIEM queries for the requested platforms.

Usage:
    python3 tools/client_query.py --prompt "Was folder 2026 created on SERVER01?" --platforms kql
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import ANTHROPIC_KEY
from tools.common import get_alias_map, get_model, log_error


_SYSTEM_PROMPT = """\
You are a senior SOC analyst and SIEM query specialist.

A client or analyst has submitted a plain-English question about activity \
they want to investigate. Your job is to turn it into precise, ready-to-run \
SIEM queries with no extra steps needed.

Instructions:
1. Extract key entities: hostnames, IPs, usernames, file/folder paths, \
   date ranges, and the core question being asked.
2. Identify the most relevant tables from the available list below.
3. Generate KQL (and other requested platform) queries that directly \
   answer the question.
4. Prefix each query block with a one-line comment describing what it finds.
5. Include a short "Caveats" section if sensor coverage or audit policy \
   requirements apply.

Available Defender / Sentinel tables:
  IdentityAccountInfo, IdentityInfo, IdentityQueryEvents,
  IdentityDirectoryEvents, DeviceTvmInfoGathering,
  DeviceTvmSecureConfigurationAssessment, DeviceTvmSoftwareInventory,
  DeviceTvmSoftwareVulnerabilities, AlertEvidence, DeviceRegistryEvents,
  DeviceLogonEvents, DeviceInfo, DeviceNetworkInfo,
  DeviceFileCertificateInfo, DeviceProcessEvents, DeviceEvents,
  ExposureGraphEdges, ExposureGraphNodes, DeviceNetworkEvents,
  EmailEvents, EmailAttachmentInfo, EmailUrlInfo,
  DeviceImageLoadEvents, IdentityLogonEvents, DeviceFileEvents,
  CloudAppEvents.

Output format:
  **Entities extracted:** <bullet list>
  <KQL/SPL/LogScale blocks as requested>
  **Caveats:** <if any>

Do NOT reference case IDs. Do NOT create or suggest creating a case. \
This output is for immediate analyst use only.\
"""


def client_query(
    prompt: str,
    platforms: list[str] | None = None,
    tables: list[str] | None = None,
) -> None:
    """
    Generate ad-hoc SIEM queries from a free-text client request.

    Parameters
    ----------
    prompt : str
        Free-text description of what the client wants to find.
    platforms : list[str], optional
        SIEM platforms to generate for. Default: ["kql"].
    tables : list[str], optional
        Confirmed available tables — added to the prompt to scope output.
    """
    if not ANTHROPIC_KEY:
        print(
            "[client-query] ERROR: ANTHROPIC_API_KEY not set in .env. "
            "LLM-assisted queries require a valid API key."
        )
        sys.exit(1)

    try:
        import anthropic
    except ImportError as exc:
        log_error("", "client_query.import_anthropic", str(exc), severity="info")
        print("[client-query] ERROR: anthropic package not installed. Run: pip install anthropic")
        sys.exit(1)

    if platforms is None:
        platforms = ["kql"]

    # Build the user message
    user_parts = [prompt.strip()]

    if platforms != ["kql"]:
        user_parts.append(f"Generate queries for: {', '.join(platforms)}.")

    if tables:
        user_parts.append(
            f"The following tables are confirmed available in this environment: "
            f"{', '.join(tables)}. Prioritise these."
        )

    user_message = "\n\n".join(user_parts)

    alias_map = get_alias_map()
    if alias_map:
        user_message = alias_map.alias_text(user_message)

    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    _model = get_model("chat_response")
    print(f"[client-query] Querying {_model} — no case will be created.\n")
    print("=" * 70)

    message = client.messages.create(
        model=_model,
        max_tokens=4096,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    response_text = message.content[0].text
    if alias_map:
        response_text = alias_map.dealias_text(response_text)
    print(response_text)
    print("=" * 70)
    print(f"[client-query] Done. Tokens used: {message.usage.input_tokens} in / "
          f"{message.usage.output_tokens} out.")


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(
        description="Ad-hoc SIEM query generator — no case created, stdout only."
    )
    p.add_argument("--prompt", required=True, help="Free-text client question")
    p.add_argument(
        "--platforms", nargs="*", default=None,
        choices=["kql", "splunk", "logscale"],
        help="Platforms to generate for (default: kql)",
    )
    p.add_argument(
        "--tables", nargs="*", default=None,
        metavar="TABLE",
        help="Confirmed available tables — scopes output to these",
    )
    args = p.parse_args()

    client_query(
        prompt=args.prompt,
        platforms=args.platforms,
        tables=args.tables,
    )
