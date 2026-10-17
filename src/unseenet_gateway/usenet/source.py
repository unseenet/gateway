"""Reading from the gateway's own news server (normally INN on the same host).

The gateway never talks to the rest of Usenet itself: INN does the peering,
history, Path and spam filtering (Cleanfeed), and the gateway reads new
articles from it as a newsreader would.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from unseenet.nntp import Client, NNTPError


class NewsServer:
    def __init__(self, address: str):
        self.address = address
        self.client: Client | None = None

    async def connect(self) -> Client:
        if self.client is None:
            c = await Client.connect(self.address, None)
            await c.command("MODE READER")
            self.client = c
        return self.client

    async def range(self, group: str) -> tuple[int, int]:
        c = await self.connect()
        _, low, high = await c.group(group)
        return low, high

    async def articles(self, group: str, after: int) -> AsyncIterator[tuple[int, bytes | None]]:
        """Yield (number, raw article) for every article numbered above ``after``.

        ``raw`` is None for numbers that no longer exist or are too large to read.
        """
        c = await self.connect()
        _, low, high = await c.group(group)
        for n in range(max(after + 1, low), high + 1):
            try:
                raw = await c.article(str(n))
            except ValueError:          # larger than the read limit
                raw = None
            yield n, raw

    async def close(self) -> None:
        if self.client is not None:
            try:
                await self.client.quit()
            except (NNTPError, ConnectionError, OSError):
                pass
            self.client = None
