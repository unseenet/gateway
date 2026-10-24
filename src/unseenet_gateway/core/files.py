"""Pictures carried into Unseenet (UN-RFC 0027), for gateway#26.

A feed may give the files a message carries (``Feed.media``); the importer cleans
them as every client does (``unseenet.client.media.prepare``: metadata out), puts
them on the article (``Blobs``, ``Attachment-<n>``) and posts them with it. That
needs a core that posts files (unseenet 0.5); with an older core, or when the
gateway carries no pictures, a message with a picture comes in as its text with a
line saying a picture was left out.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass

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
