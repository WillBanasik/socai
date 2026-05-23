"""
Secret resolution shim — bootstrap path reads `.env` via os.environ.

Production path will swap to Azure Key Vault here without changing call sites.
Callers always go through `get_secret(name)` and never read os.environ directly.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Side-effect: ensures .env is loaded (settings calls load_dotenv at import).
import config.settings  # noqa: F401


class SecretMissing(KeyError):
    """Raised when a required secret is not set."""


def get_secret(name: str, default: str | None = None, *, required: bool = False) -> str | None:
    """Fetch a secret by env-var name.

    Today: backed by os.environ (populated from .env at process start).
    Future: swap implementation to read Azure Key Vault references like
    `kv://<vault>/<secret>` — call sites stay unchanged.
    """
    value = os.environ.get(name, default)
    if required and not value:
        raise SecretMissing(f"required secret {name!r} is not set")
    return value
