"""Import from NIP-29 Nostr groups into Unseenet."""

from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.request
from dataclasses import dataclass

from unseenet.core import crypto
from unseenet.nntp import NNTPError

from ..core.state import State
from ..core.unseenet_side import Node
from .convert import (COMMENT, DELETION, IMPORTED_KINDS, NETWORK, Skip, cancel_article,
                      convert)
from .event import Event
from .relay import Relay

log = logging.getLogger(__name__)
METADATA, ADMINS = 39000, 39001
VANISHED_PASSES = 2
# Relays that collect profiles (kind 0). NIP-29 relays often refuse queries
# outside a group, so names are looked up here as well.
PROFILE_RELAYS = ["wss://purplepag.es", "wss://relay.damus.io", "wss://nos.lol",
                  "wss://relay.primal.net"]
PROFILE_RETRY = 6 * 3600          # look again for an author without a profile


@dataclass
class RunStats:
    imported: int = 0
    duplicate: int = 0
    skipped: int = 0
    refused: int = 0
    cancelled: int = 0


def relay_pubkey(url: str, timeout: float = 20.0) -> str | None:
    """The relay's own key from its NIP-11 document (the `self` or `pubkey` field)."""
    http = url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
    req = urllib.request.Request(http, headers={"Accept": "application/nostr+json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        info = json.loads(resp.read().decode())
    return info.get("self") or info.get("pubkey")


def source_name(relay_url: str, group: str) -> str:
    """How a source is written in the manifest and the state: <relay>'<group-id>."""
    return f"{relay_url}'{group}"


class Importer:
    def __init__(self, *, state: State, relay: Relay, node: Node, gateway: crypto.Identity,
                 carried: dict[str, str], pow_bits: int, start: str = "new",
                 lookback: int = 7 * 86400, profile_relays: list[str] | None = None,
                 proxy: str | None = None):
        self.state, self.relay, self.node = state, relay, node
        self.gateway, self.carried, self.pow_bits = gateway, carried, pow_bits
        self.start, self.lookback = start, lookback
        self.titles: dict[str, str] = {}
        self.names: dict[str, str | None] = {}
        self.looked: dict[str, float] = {}      # pubkey -> when we last looked
        self.relay_key: str | None = None
        self.profile_relays = PROFILE_RELAYS if profile_relays is None else profile_relays
        self.proxy = proxy

    # --- checks ---
    async def group_is_public(self, group: str) -> bool:
        """The group's metadata must be signed by the relay itself and not private."""
        if self.relay_key is None:
            self.relay_key = relay_pubkey(self.relay.url)
        meta = [e for e in await self.relay.query({"kinds": [METADATA], "#d": [group]})
                if e.pubkey == self.relay_key]
        if not meta:
            log.warning("%s: no metadata signed by the relay", group)
            return False
        if any(t and t[0] == "private" for t in meta[-1].tags):
            log.warning("%s: private group, not gatewayed", group)
            return False
        return True

    # --- lookups ---
    async def _fill_titles(self, events: list[Event]) -> None:
        roots = {e.tag("E") for e in events if e.kind == COMMENT and e.tag("E")}
        for e in events:
            if e.kind == 11:
                self.titles[e.id] = e.tag("title") or e.content.splitlines()[0][:80]
        missing = [r for r in roots if r not in self.titles]
        if missing:
            for e in await self.relay.query({"ids": missing}):
                self.titles[e.id] = e.tag("title") or (e.content.splitlines() or [""])[0][:80]

    async def _fill_names(self, events: list[Event]) -> None:
        now = time.time()
        missing = sorted(pk for pk in {e.pubkey for e in events}
                         if self.names.get(pk) is None
                         and now - self.looked.get(pk, 0) > PROFILE_RETRY)
        if not missing:
            return
        for pk in missing:
            self.looked[pk] = now
        newest: dict[str, int] = {}
        sources = [self.relay] + [Relay(u, proxy=self.proxy) for u in self.profile_relays
                                  if u.rstrip("/") != self.relay.url.rstrip("/")]
        for relay in sources:
            todo = [pk for pk in missing if pk not in newest]
            if not todo:
                break
            try:
                found = await asyncio.wait_for(
                    relay.query({"kinds": [0], "authors": todo}), 20)
            except Exception as exc:  # noqa: BLE001  (relay may refuse or be down)
                log.debug("no profiles from %s: %s", relay.url, exc)
                found = []
            finally:
                if relay is not self.relay:
                    try:
                        await relay.close()
                    except Exception:  # noqa: BLE001
                        pass
            for e in found:                       # signature already checked by Relay
                if e.pubkey not in missing or e.created_at <= newest.get(e.pubkey, -1):
                    continue
                try:
                    meta = json.loads(e.content)
                    name = meta.get("display_name") or meta.get("name") or None
                except (ValueError, AttributeError):
                    continue
                if isinstance(name, str) and name.strip():
                    newest[e.pubkey] = e.created_at
                    self.names[e.pubkey] = " ".join(name.split())[:64]

    # --- import ---
    async def run_group(self, group: str, group_id: str) -> RunStats:
        st = RunStats()
        src = source_name(self.relay.url, group)
        if not await self.group_is_public(group):
            return st
        since = self.state.get_cursor(NETWORK, src)
        flt = {"#h": [group], "kinds": list(IMPORTED_KINDS)}
        if since is not None:
            flt["since"] = since
        elif self.start == "new":
            self.state.set_cursor(NETWORK, src, int(time.time()))
            return st
        events = await self.relay.query(flt)
        await self._fill_titles(events)
        await self._fill_names(events)
        newest = since or 0
        for ev in events:
            newest = max(newest, ev.created_at)
            if self.state.lookup(NETWORK, ev.id):
                st.duplicate += 1
                continue
            try:
                art = convert(ev, group_id=group_id,
                              id_map=lambda eid: self.state.lookup(NETWORK, eid),
                              title_of=self.titles.get, name_of=self.names.get)
            except Skip as s:
                st.skipped += 1
                self.state.count_skip(NETWORK, s.reason)
                continue
            art.finalize(self.gateway, self.pow_bits)
            try:
                result = await self.node.post(art)
            except NNTPError as exc:
                st.refused += 1
                self.state.count_skip(NETWORK, f"node-{exc.text.split(':')[0]}")
                log.warning("node refused %s: %s", ev.id, exc)
                continue
            self.state.remember(NETWORK, ev.id, art.message_id, group_id)
            self.state.remember_author(NETWORK, ev.id, ev.pubkey)
            if ev.kind == 11:
                self.titles[ev.id] = art["Subject"]
            if result == "duplicate":
                st.duplicate += 1
            else:
                st.imported += 1
                log.info("imported %s -> %s %s", ev.id[:16], art.message_id, group_id)
        # Same second may hold more events: step back one second, duplicates are skipped.
        self.state.set_cursor(NETWORK, src, max(newest - 1, 0) if newest else since or 0)
        await self._deletions(group_id, st)
        return st

    async def _deletions(self, group_id: str, st: RunStats) -> None:
        """Messages deleted in the group become Unseenet cancels.

        Two signals count. An author-signed deletion request (NIP-09) for an
        imported event, when the relay still serves it. And, since a NIP-29
        relay is the group's authority and often drops both the event and the
        request: an imported event the relay no longer serves, for
        VANISHED_PASSES passes in a row, while it still serves others from
        the same group. A relay that is down or empty serves none, so that
        never cancels anything.
        """
        rows = self.state.db.execute(
            "SELECT foreign_id, unseenet_id FROM ids WHERE network=? AND group_id=? "
            "AND direction='in' AND at > strftime('%s','now') - ?",
            (NETWORK, group_id, self.lookback)).fetchall()
        imported = {fid: mid for fid, mid in rows if not fid.startswith("cancel:")}
        if not imported:
            return
        served: dict[str, Event] = {}
        ids = list(imported)
        for i in range(0, len(ids), 200):
            for e in await self.relay.query({"ids": ids[i:i + 200]}):
                served[e.id] = e
        to_cancel: dict[str, str] = {}
        for d in await self.relay.query({"kinds": [DELETION], "#e": ids}):
            for eid in d.tag_values("e"):
                if eid in imported and (served.get(eid) or None) and served[eid].pubkey == d.pubkey:
                    to_cancel[eid] = "Deleted by its author on Nostr."
                elif eid in imported and self.state.author_of(NETWORK, eid) == d.pubkey:
                    to_cancel[eid] = "Deleted by its author on Nostr."
        if served:                       # the relay answers for this group at all
            for eid in ids:
                if eid in served:
                    self.state.seen_present(NETWORK, eid)
                elif self.state.seen_missing(NETWORK, eid) >= VANISHED_PASSES:
                    to_cancel.setdefault(eid, "Deleted in the Nostr group.")
            self.state.db.commit()
        for eid, reason in to_cancel.items():
            key = f"cancel:{eid}"
            if self.state.lookup(NETWORK, key):
                continue
            art = cancel_article(group_id, imported[eid], reason)
            art.finalize(self.gateway, self.pow_bits)
            await self.node.post(art)
            self.state.remember(NETWORK, key, art.message_id, group_id, "cancel")
            st.cancelled += 1
            log.info("cancelled %s (%s)", imported[eid], reason)

    async def run(self) -> RunStats:
        total = RunStats()
        for group, group_id in self.carried.items():
            st = await self.run_group(group, group_id)
            for f in total.__dataclass_fields__:
                setattr(total, f, getattr(total, f) + getattr(st, f))
        return total
