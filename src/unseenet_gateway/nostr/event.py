"""Nostr events (NIP-01): serialization, id, BIP-340 Schnorr signatures.

Pure Python, so it runs everywhere the gateway runs. Uses coincurve for
speed when it is installed, and falls back to a plain implementation of
BIP-340 over secp256k1 otherwise. Gateway volumes are small: a pure-Python
verification takes a few milliseconds.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field

try:  # optional acceleration
    from coincurve import PrivateKey as _CCPriv, PublicKeyXOnly as _CCXOnly
except Exception:  # noqa: BLE001
    _CCPriv = _CCXOnly = None

# --- secp256k1 / BIP-340 ------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _tagged(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def _mul(pt, k: int):
    out = None
    while k:
        if k & 1:
            out = _add(out, pt)
        pt = _add(pt, pt)
        k >>= 1
    return out


def _lift_x(x: int):
    if x >= P:
        return None
    c = (pow(x, 3, P) + 7) % P
    y = pow(c, (P + 1) // 4, P)
    if y * y % P != c:
        return None
    return x, y if y % 2 == 0 else P - y


def _b32(i: int) -> bytes:
    return i.to_bytes(32, "big")


def pubkey_of(secret: bytes) -> bytes:
    """32-byte x-only public key for a 32-byte secret."""
    d = int.from_bytes(secret, "big")
    if not 0 < d < N:
        raise ValueError("bad secret key")
    return _b32(_mul(G, d)[0])


def schnorr_verify(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pubkey) != 32 or len(msg) != 32 or len(sig) != 64:
        return False
    if _CCXOnly is not None:
        try:
            return _CCXOnly(pubkey).verify(sig, msg)
        except Exception:  # noqa: BLE001
            return False
    pt = _lift_x(int.from_bytes(pubkey, "big"))
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if pt is None or r >= P or s >= N:
        return False
    e = int.from_bytes(_tagged("BIP0340/challenge", sig[:32] + pubkey + msg), "big") % N
    R = _add(_mul(G, s), _mul((pt[0], P - pt[1]), e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def schnorr_sign(secret: bytes, msg: bytes, aux: bytes | None = None) -> bytes:
    if _CCPriv is not None:
        return _CCPriv(secret).sign_schnorr(msg, aux)
    aux = aux if aux is not None else os.urandom(32)
    d0 = int.from_bytes(secret, "big")
    if not 0 < d0 < N:
        raise ValueError("bad secret key")
    pt = _mul(G, d0)
    d = d0 if pt[1] % 2 == 0 else N - d0
    t = bytes(a ^ b for a, b in zip(_b32(d), _tagged("BIP0340/aux", aux)))
    k0 = int.from_bytes(_tagged("BIP0340/nonce", t + _b32(pt[0]) + msg), "big") % N
    if k0 == 0:
        raise ValueError("bad nonce")
    R = _mul(G, k0)
    k = k0 if R[1] % 2 == 0 else N - k0
    e = int.from_bytes(_tagged("BIP0340/challenge", _b32(R[0]) + _b32(pt[0]) + msg), "big") % N
    return _b32(R[0]) + _b32((k + e * d) % N)


# --- events -------------------------------------------------------------------

class EventError(ValueError):
    pass


def serialize(pubkey: str, created_at: int, kind: int, tags: list, content: str) -> bytes:
    """NIP-01 serialization: compact JSON, UTF-8, non-ASCII verbatim."""
    return json.dumps([0, pubkey, created_at, kind, tags, content],
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass
class Event:
    pubkey: str
    created_at: int
    kind: int
    tags: list = field(default_factory=list)
    content: str = ""
    id: str = ""
    sig: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        try:
            ev = cls(pubkey=d["pubkey"], created_at=int(d["created_at"]), kind=int(d["kind"]),
                     tags=[[str(x) for x in t] for t in d.get("tags", [])],
                     content=str(d.get("content", "")), id=d["id"], sig=d["sig"])
        except (KeyError, TypeError, ValueError) as exc:
            raise EventError(f"malformed event: {exc}") from exc
        return ev

    def to_dict(self) -> dict:
        return {"id": self.id, "pubkey": self.pubkey, "created_at": self.created_at,
                "kind": self.kind, "tags": self.tags, "content": self.content, "sig": self.sig}

    def to_json(self) -> str:
        """Compact JSON of the whole event, as carried in Origin-Proof."""
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)

    def compute_id(self) -> str:
        return hashlib.sha256(serialize(self.pubkey, self.created_at, self.kind,
                                        self.tags, self.content)).hexdigest()

    def verify(self) -> bool:
        """True if the id matches the content and the signature is valid."""
        try:
            if self.compute_id() != self.id:
                return False
            return schnorr_verify(bytes.fromhex(self.pubkey), bytes.fromhex(self.id),
                                  bytes.fromhex(self.sig))
        except ValueError:
            return False

    def tag(self, name: str) -> str | None:
        for t in self.tags:
            if t and t[0] == name and len(t) > 1:
                return t[1]
        return None

    def tag_values(self, name: str) -> list[str]:
        return [t[1] for t in self.tags if t and t[0] == name and len(t) > 1]


def sign_event(secret: bytes, kind: int, content: str, tags: list | None = None,
               created_at: int | None = None) -> Event:
    pub = pubkey_of(secret).hex()
    ev = Event(pubkey=pub, created_at=created_at or int(time.time()), kind=kind,
               tags=tags or [], content=content)
    ev.id = ev.compute_id()
    ev.sig = schnorr_sign(secret, bytes.fromhex(ev.id)).hex()
    return ev
