"""Remote feature flag: read a GitHub Actions *repository variable* and poll it.

Operators flip AI analysis on or off from GitHub (Settings → Secrets and variables →
Actions → Variables → AIRLOCK_LLM = on|off). No redeploy, nothing exposed in the UI.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

import httpx

log = logging.getLogger("airlock.flags")

ON = {"on", "true", "1", "yes", "enabled"}
OFF = {"off", "false", "0", "no", "disabled"}


def parse_on_off(value: str | None) -> bool | None:
    if value is None:
        return None
    v = value.strip().lower()
    if v in ON:
        return True
    if v in OFF:
        return False
    return None


class GitHubVariableFlag:
    def __init__(self, repo: str, token: str, name: str = "AIRLOCK_LLM", interval: float = 60.0,
                 client: httpx.AsyncClient | None = None):
        self.repo, self.token, self.name, self.interval = repo, token, name, interval
        self.client = client or httpx.AsyncClient(timeout=10)
        self.last_value: bool | None = None
        self.last_error: str | None = None

    @property
    def url(self) -> str:
        return f"https://api.github.com/repos/{self.repo}/actions/variables/{self.name}"

    async def fetch(self) -> bool | None:
        """Current value, or None if unreachable / not a recognised on-off value."""
        try:
            r = await self.client.get(self.url, headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            })
            if r.status_code != 200:
                self.last_error = f"HTTP {r.status_code}"
                return None
            value = parse_on_off(r.json().get("value"))
            if value is None:
                self.last_error = f"unrecognised value {r.json().get('value')!r}"
                return None
            self.last_error = None
            return value
        except Exception as exc:
            self.last_error = f"{exc.__class__.__name__}: {exc}"
            return None

    async def run(self, apply: Callable[[bool], None]) -> None:
        """Poll forever; call apply(value) whenever a valid value is read."""
        while True:
            value = await self.fetch()
            if value is not None:
                if value != self.last_value:
                    log.info("flag %s=%s from GitHub variable", self.name, "on" if value else "off")
                self.last_value = value
                apply(value)
            else:
                log.warning("flag %s unavailable (%s); keeping last known value", self.name, self.last_error)
            await asyncio.sleep(self.interval)
