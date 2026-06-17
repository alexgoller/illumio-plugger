"""Shared helpers for the live scanner-API pullers (Qualys / Tenable).

These talk to the *scanner's* API (not the PCE), each with its own auth scheme.
Mirrors the Ruby `set_https` mixin: TLS verify toggle, optional proxy, trusted CA.
"""

from __future__ import annotations

import getpass
import os
import sys
from typing import Optional

import requests


def make_session(
    verify: bool | str = True,
    proxies: Optional[dict] = None,
    ca_file: Optional[str] = None,
    user_agent: str = "illumio-vuln-import/0.1",
) -> requests.Session:
    """Build a requests.Session configured like the Ruby `set_https` helper."""
    s = requests.Session()
    s.verify = ca_file if ca_file else verify
    if proxies:
        s.proxies.update(proxies)
    s.headers.update({"User-Agent": user_agent})
    return s


def resolve(
    value: Optional[str],
    env_var: Optional[str] = None,
    prompt: Optional[str] = None,
    secret: bool = False,
    required: bool = True,
) -> Optional[str]:
    """Resolve a credential: explicit value -> env var -> interactive prompt.

    Non-interactive (no TTY) and unset -> raise if required, else None.
    """
    if value:
        return value
    if env_var:
        env = os.environ.get(env_var)
        if env:
            return env
    if prompt and sys.stdin.isatty():
        entered = getpass.getpass(prompt) if secret else input(prompt)
        return entered.strip()
    if required:
        hint = f" (set {env_var} or pass it explicitly)" if env_var else ""
        raise ValueError(f"Missing required credential{hint}")
    return None


class ScannerAPIError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.body = body
