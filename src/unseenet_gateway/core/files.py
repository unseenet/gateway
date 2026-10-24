"""Pictures carried into Unseenet (UN-RFC 0027), for gateway#26.

A feed may give the files a message carries (``Feed.media``); the importer cleans
them as every client does (``unseenet.client.media.prepare``: metadata out), puts
them on the article (``Blobs``, ``Attachment-<n>``) and posts them with it. That
needs a core that posts files (unseenet 0.5); with an older core, or when the
gateway carries no pictures, a message with a picture comes in as its text with a
line saying a picture was left out.
"""

from __future__ import annotations

import asyncio
import inspect
import re
import secrets
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

IMAGE_TYPES = ("image/jpeg", "image/png", "image/gif", "image/webp")


@dataclass(frozen=True)
class Media:
    """A file a message in the other network carries, as downloaded."""
    name: str
    octets: bytes
    alt: str = ""


def core_posts_files() -> bool:
    """Whether this unseenet core can post files (0.5: Session.post_article(blobs=))."""
    try:
        from unseenet.client import media  # noqa: F401
        from unseenet.client.session import Session
        from unseenet.core.blobs import attachment_headers, extra_bits_for  # noqa: F401
    except ImportError:
        return False
    return "blobs" in inspect.signature(Session.post_article).parameters


def attachments_field(max_size: int) -> dict | None:
    """The manifest's ``attachments`` (UN-RFC 0027 section 5.1) for a gatewayed
    group: pictures up to ``max_size`` octets; None when the gateway carries none."""
    if max_size <= 0 or not core_posts_files():
        return None
    return {"max_size": int(max_size), "types": ["image/*"]}


def attach(art, files: list[Media], max_size: int) -> tuple[list, int, list[str]]:
    """Put ``files`` on ``art`` (before it is signed): returns the blobs to send,
    the postage they add, and a note per file left out (too big, not a picture)."""
    from unseenet.client import media
    from unseenet.core.blobs import (MAX_PER_ARTICLE, MAX_TOTAL, attachment_headers, blob_id,
                                     extra_bits_for)
    kept, notes, total = [], [], 0
    for f in files:
        try:
            p = media.prepare(f.name, f.octets)
        except ValueError as exc:
            notes.append(f"{f.name}: {exc}")
            continue
        if p.media_type not in IMAGE_TYPES:
            notes.append(f"{f.name}: not a picture")
        elif len(p.octets) > max_size:
            notes.append(f"{f.name}: {len(p.octets) // 1024} KiB, more than this group takes")
        elif len(kept) >= MAX_PER_ARTICLE or total + len(p.octets) > MAX_TOTAL:
            notes.append(f"{f.name}: too many files on one message")
        else:
            kept.append((p.name, p.media_type, p.octets, f.alt or "", p.dim))
            total += len(p.octets)
    for name, value in attachment_headers(kept):
        art.set(name, value)
    return [(blob_id(o), o) for _, _, o, _, _ in kept], extra_bits_for(total) if kept else 0, notes


# --- a picture linked from another network, fetched over Tor (gateway#26) ----------

PICTURE_URL = re.compile(r"https://[^\s<>()\[\]\"']+?\.(?:jpe?g|png|gif|webp)(?:\?[^\s<>()\[\]\"']*)?",
                         re.IGNORECASE)
FETCH_TIMEOUT = 90


async def fetch_over_tor(url: str, socks_port: int | None, limit: int,
                         redirects: int = 3) -> bytes:
    """GET a picture at an https URL through Tor, at most ``limit`` octets: the
    gateway never shows its own address to a picture host. No Tor: nothing is
    fetched. Only https, only a picture type, and at most ``redirects`` redirects."""
    if not socks_port:
        raise OSError("no Tor to fetch through")
    for _ in range(redirects + 1):
        u = urlsplit(url)
        if u.scheme != "https" or not u.hostname:
            raise ValueError("only https pictures")
        from python_socks.async_.asyncio import Proxy
        cred = secrets.token_hex(8)                    # a circuit of its own
        proxy = Proxy.from_url(f"socks5://{cred}:{cred}@127.0.0.1:{socks_port}", rdns=True)
        sock = await asyncio.wait_for(proxy.connect(dest_host=u.hostname, dest_port=u.port or 443),
                                      FETCH_TIMEOUT)
        r, w = await asyncio.wait_for(asyncio.open_connection(
            sock=sock, ssl=ssl.create_default_context(), server_hostname=u.hostname),
            FETCH_TIMEOUT)
        try:
            path = (u.path or "/") + (f"?{u.query}" if u.query else "")
            w.write((f"GET {path} HTTP/1.1\r\nHost: {u.netloc}\r\nAccept: image/*\r\n"
                     "User-Agent: unseenet-gateway\r\nAccept-Encoding: identity\r\n"
                     "Connection: close\r\n\r\n").encode())
            await w.drain()
            status = int((await asyncio.wait_for(r.readline(), FETCH_TIMEOUT)).split()[1])
            headers = {}
            while (line := (await r.readline()).decode("latin-1").rstrip("\r\n")):
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
            if status in (301, 302, 303, 307, 308) and headers.get("location"):
                from urllib.parse import urljoin
                url = urljoin(url, headers["location"])
                continue
            if status != 200:
                raise OSError(f"HTTP {status}")
            if not headers.get("content-type", "").lower().startswith("image/"):
                raise ValueError("not a picture")
            n = int(headers.get("content-length", "-1"))
            if n > limit:
                raise ValueError("too big")
            data = await asyncio.wait_for(r.read(limit + 1), FETCH_TIMEOUT)
            if len(data) > limit:
                raise ValueError("too big")
            return data
        finally:
            w.close()
    raise ValueError("too many redirects")
