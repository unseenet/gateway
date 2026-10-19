"""Which network adapters are installed.

The adapters in this package are always there; other packages add theirs as
entry points in the ``unseenet_gateway.adapters`` group (see ``adapter.py``).
"""

from __future__ import annotations

import importlib
import logging
from importlib.metadata import entry_points

from .adapter import Adapter

log = logging.getLogger(__name__)
GROUP = "unseenet_gateway.adapters"
BUILTIN = {
    "usenet": "unseenet_gateway.usenet.adapter:UsenetAdapter",
    "nostr": "unseenet_gateway.nostr.adapter:NostrAdapter",
    "matrix": "unseenet_gateway.matrix.adapter:MatrixAdapter",
}


def _load(spec: str) -> type[Adapter]:
    module, _, name = spec.partition(":")
    return getattr(importlib.import_module(module), name)


def adapters() -> dict[str, type[Adapter]]:
    """Network name -> adapter class; built-in ones first, in a fixed order."""
    out = {name: _load(spec) for name, spec in BUILTIN.items()}
    for ep in entry_points(group=GROUP):
        if ep.name in out:
            continue
        try:
            cls = ep.load()
        except Exception as exc:  # noqa: BLE001  (a broken plugin must not stop the gateway)
            log.warning("adapter %s cannot be loaded: %s", ep.name, exc)
            continue
        if getattr(cls, "network", None) != ep.name:
            log.warning("adapter %s names its network %r; ignored", ep.name,
                        getattr(cls, "network", None))
            continue
        out[ep.name] = cls
    return out
