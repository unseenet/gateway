"""A small Nostr relay client (NIP-01) over websockets.

Only what the gateway needs: publish an event and wait for OK, and fetch
stored events matching filters until EOSE. Events whose id or signature do
not verify are dropped here, so nothing downstream ever sees them.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging

import websockets

from .event import Event, EventError

log = logging.getLogger(__name__)
_sub_ids = itertools.count(1)


class RelayError(Exception):
    pass


class Relay:
    def __init__(self, url: str, timeout: float = 30.0, proxy: str | None = None):
        self.url, self.timeout, self.proxy = url, timeout, proxy
        self.ws = None

    async def connect(self):
        if self.ws is None:
            kw = {"max_size": 2 ** 21, "open_timeout": self.timeout}
            if self.proxy:
                kw["proxy"] = self.proxy
            self.ws = await websockets.connect(self.url, **kw)
        return self.ws

    async def close(self) -> None:
        if self.ws is not None:
            try:
                await self.ws.close()
            finally:
                self.ws = None

    async def publish(self, ev: Event) -> tuple[bool, str]:
        """Send an event; return (accepted, message) from the relay's OK."""
        ws = await self.connect()
        await ws.send(json.dumps(["EVENT", ev.to_dict()], ensure_ascii=False))
        async with asyncio.timeout(self.timeout):
            while True:
                msg = json.loads(await ws.recv())
                if msg[0] == "OK" and msg[1] == ev.id:
                    return bool(msg[2]), str(msg[3] if len(msg) > 3 else "")
                if msg[0] == "NOTICE":
                    log.info("relay notice: %s", msg[1])

    async def query(self, *filters: dict) -> list[Event]:
        """Stored events matching any filter, verified, oldest first."""
        ws = await self.connect()
        sid = f"q{next(_sub_ids)}"
        await ws.send(json.dumps(["REQ", sid, *filters]))
        out: dict[str, Event] = {}
        try:
            async with asyncio.timeout(self.timeout):
                while True:
                    msg = json.loads(await ws.recv())
                    if msg[0] == "EVENT" and msg[1] == sid:
                        try:
                            ev = Event.from_dict(msg[2])
                        except EventError:
                            continue
                        if ev.verify():
                            out[ev.id] = ev
                        else:
                            log.warning("dropped event with bad id or signature: %s",
                                        msg[2].get("id"))
                    elif msg[0] == "EOSE" and msg[1] == sid:
                        break
                    elif msg[0] == "CLOSED" and msg[1] == sid:
                        raise RelayError(str(msg[2] if len(msg) > 2 else "closed"))
        finally:
            try:
                await ws.send(json.dumps(["CLOSE", sid]))
            except Exception:  # noqa: BLE001
                pass
        return sorted(out.values(), key=lambda e: (e.created_at, e.id))
