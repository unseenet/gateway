"""The gateway's two identities (UN-RFC 0023, section 3.2).

- the **group key** owns the gatewayed groups. It is only needed to create a
  group or change its manifest, so it lives in its own file that SHOULD be
  kept offline (moved off the gateway host after setup);
- the **gateway key** is the groups' moderator: it signs imported articles and
  approves exports. It stays on the gateway host.

Each file is sealed with a passphrase (Argon2id + XSalsa20-Poly1305, the same
as the Unseenet vault).
"""

from __future__ import annotations

import getpass
import json
import os
from pathlib import Path

from unseenet.core import crypto
from unseenet.core.vault import seal, unseal


def passphrase(env: str, prompt: str) -> str:
    """From the environment variable ``env``, or asked for."""
    return os.environ.get(env) or getpass.getpass(prompt)

def create(path: Path, passphrase: str, label: str) -> crypto.Identity:
    path = Path(path)
    if path.exists():
        raise FileExistsError(path)
    ident = crypto.Identity.generate()
    payload = json.dumps({"v": 1, "label": label, "seed": ident.seed.hex()}).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(seal(payload, passphrase))
    return ident


def load(path: Path, passphrase: str) -> crypto.Identity:
    data = json.loads(unseal(Path(path).read_bytes(), passphrase))
    return crypto.Identity.from_seed(bytes.fromhex(data["seed"]))


def create_secret(path: Path, passphrase: str, label: str, valid=lambda b: True) -> bytes:
    """A raw 32-byte secret for another network's key (e.g. Nostr's secp256k1)."""
    path = Path(path)
    if path.exists():
        raise FileExistsError(path)
    secret = os.urandom(32)
    while not valid(secret):
        secret = os.urandom(32)
    payload = json.dumps({"v": 1, "label": label, "secret": secret.hex()}).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(seal(payload, passphrase))
    return secret


def load_secret(path: Path, passphrase: str) -> bytes:
    return bytes.fromhex(json.loads(unseal(Path(path).read_bytes(), passphrase))["secret"])
