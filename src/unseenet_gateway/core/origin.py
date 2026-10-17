"""Origin headers, common to every gateway (UN-RFC 0023, section 4.3).

Values are copied as the other network gives them and are not checked; they
are information for the reader, not facts the gateway vouches for.
"""

from __future__ import annotations

import re

MAX_VALUE = 998
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _clean(value: str) -> str:
    value = _CTRL.sub(" ", " ".join(str(value).split()))
    return value[:MAX_VALUE]


def origin_headers(network: str, ident: str, date: str | None = None,
                   author: str | None = None) -> list[tuple[str, str]]:
    """Origin-Network, Origin-ID and, when known, Origin-Date and Origin-From."""
    out = [("Origin-Network", network), ("Origin-ID", _clean(ident))]
    if date:
        out.append(("Origin-Date", _clean(date)))
    if author:
        out.append(("Origin-From", _clean(author)))
    return out
