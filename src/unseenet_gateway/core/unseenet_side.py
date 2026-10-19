"""Everything the gateway does towards Unseenet, shared by all networks.

The gateway talks to Unseenet like any client: over Tor, to one node, with no
special status (UN-RFC 0023, section 6.3).
"""

from __future__ import annotations

import logging

from unseenet.core import crypto
from unseenet.core.article import Article, ArticleError
from unseenet.core.groups import Manifest, make_group_id, manifest_article
from unseenet.nntp import Client, NNTPError

log = logging.getLogger(__name__)


def gateway_manifest(owner: crypto.Identity, gateway: crypto.Identity, name: str, *,
                     network: str, source: str, direction: str, host: str,
                     operator: str, contact: str, abuse: str = "", policy: str = "",
                     title: str = "", description: str = "", serial: int = 1,
                     retention_days: int = 90, submissions: str | None = None,
                     view: str = "", kinds: tuple[str, ...] = (), min_pow: int = 0,
                     peers: list[str] | None = None, requests: str | None = None,
                     pow_bits: int = 18) -> Article:
    """Manifest of a gatewayed group (UN-RFC 0023 section 3.2): moderated, gateway key as moderator."""
    if direction not in ("import", "both"):
        raise ValueError("direction must be 'import' or 'both'")
    gw = {"network": network, "source": source, "direction": direction,
          "host": host, "operator": operator, "contact": contact}
    if abuse:
        gw["abuse"] = abuse
    if requests:
        gw["requests"] = requests            # UN-RFC 0038 3.2: where join requests go
    if policy:
        gw["policy"] = policy[:2048]
    data = {"v": 1, "name": name, "type": "moderated", "owner": owner.key_text,
            "serial": serial, "min_pow": min_pow, "retention_days": retention_days,
            "moderators": [gateway.key_text] + [k for k in (peers or [])
                                                 if k != gateway.key_text],
            "gateway": gw}
    if submissions and not peers:
        # with several gateways, clients send submissions to each one's inbox (0038 3.1)
        data["submissions"] = submissions
    if title:
        data["title"] = title[:128]
    if description:
        data["description"] = description[:2048]
    if view:
        data["view"] = view                  # UN-RFC 0008 section 3.1
    if kinds:
        data["kinds"] = list(kinds)          # UN-RFC 0028 section 4.1
    return manifest_article(owner, make_group_id(name, owner.public_key), data, pow_bits)


class Node:
    """One connection to an Unseenet node, reopened when it drops."""

    def __init__(self, address: str, socks_port: int | None):
        self.address, self.socks_port = address, socks_port
        self.client: Client | None = None

    async def _conn(self) -> Client:
        if self.client is None:
            self.client = await Client.connect(self.address, self.socks_port)
        return self.client

    async def post(self, art: Article) -> str:
        """Post; returns 'ok', 'duplicate' or raises NNTPError for other refusals."""
        for attempt in (1, 2):
            try:
                c = await self._conn()
                code, text = await c.post(art.to_bytes())
                break
            except (ConnectionError, OSError):
                self.client = None
                if attempt == 2:
                    raise
        if code == 240:
            return "ok"
        if code == 441 and text.startswith("duplicate"):
            return "duplicate"
        raise NNTPError(code, text)

    async def manifest(self, group_id: str) -> Manifest | None:
        """The newest valid manifest the node holds for the group, read with HDR Control."""
        c = await self._conn()
        try:
            _, low, high = await c.group(group_id)
        except NNTPError:
            return None
        best = None
        if high < low:
            return None
        for line in await c.multiline(f"HDR Control {low}-{high}", 225):
            number, _, value = line.partition(" ")
            if value.strip().lower() != "manifest":
                continue
            try:
                m = Manifest.from_article(Article.from_bytes(await c.article(number)))
            except (ArticleError, ValueError, TypeError, NNTPError):
                continue
            if m.group_id == group_id and m.supersedes(best):
                best = m
        return best

    async def close(self) -> None:
        if self.client is not None:
            try:
                await self.client.quit()
            except Exception:  # noqa: BLE001
                pass
            self.client = None
