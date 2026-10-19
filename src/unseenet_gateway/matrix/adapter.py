"""The Matrix adapter: public, unencrypted rooms (UN-RFC 0037).

Configuration, section [matrix]::

    homeserver = "https://matrix.example.org"   # where the gateway's account lives
    user       = "@unseenet-gateway:example.org"
    prefix     = "matrix"            # `test.matrix` on test nodes
    direction  = "import"            # or "both"
    start      = "new"               # or "all" (at most max_pages * 100 messages back)
    rooms      = ["#python:matrix.org", {room = "!abc:example.org", name = "chosen.name"}]

The access token is read from UNSEENET_GATEWAY_MATRIX_TOKEN or from the file
`gateway.matrix_token` (default: `matrix.token` beside the gateway key),
which `unseenet-gateway matrix-login` writes. Optional: `proxy` (an HTTP
proxy for reaching the homeserver).

The gateway only reads rooms whose moderators invited its account
(UN-RFC 0023 section 6.1), and leaves them alone once it is kicked.

Portals (UN-RFC 0037 section 7), one [[portals]] table each::

    [[portals]]
    group   = "unseenet@ph5fc5hop5232qsz"
    network = "matrix"
    room    = "#unseenet:unseenet.org"     # created on the gateway's own server
    admins  = ["@someone:example.org"]     # optional: invited, full power in the room
"""

from __future__ import annotations

import asyncio
import getpass
import os
from pathlib import Path

from unseenet.core import crypto

from ..core.adapter import Adapter, Capabilities, Carried, Feed, Send
from .client import Matrix
from .convert import NETWORK, unseenet_name
from .exporter import MatrixSender
from .feed import MatrixFeed
from .portal import MatrixCounterpart

TOKEN_ENV = "UNSEENET_GATEWAY_MATRIX_TOKEN"
PASSWORD_ENV = "UNSEENET_GATEWAY_MATRIX_PASSWORD"


class MatrixAdapter(Adapter):
    network = NETWORK
    capabilities = Capabilities(export=True, retractions=True, portals=True)
    commands = {"matrix-login": "log the gateway's Matrix account in and save its token"}

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self._matrix: Matrix | None = None

    # --- configuration ---
    def token_path(self) -> Path:
        default = Path(self.gw["gateway_key"]).with_name("matrix.token")
        return Path(self.gw.get("matrix_token", str(default)))

    def token(self) -> str:
        tok = os.environ.get(TOKEN_ENV)
        if tok:
            return tok.strip()
        path = self.token_path()
        if not path.exists():
            raise SystemExit(f"no Matrix token: run `unseenet-gateway matrix-login` or set {TOKEN_ENV}")
        return path.read_text().strip()

    def matrix(self) -> Matrix:
        if self._matrix is None:
            self._matrix = Matrix(self.section["homeserver"], self.token(),
                                  proxy=self.section.get("proxy"))
        return self._matrix

    def direction(self) -> str:
        return self.section.get("direction", "import")

    def host(self) -> str:
        """The gateway's Matrix user id (UN-RFC 0037 section 2)."""
        return self.section.get("user", super().host())

    def rooms(self) -> list[tuple[str, Carried]]:
        """(room alias or id, Carried) for each configured room."""
        out, host = [], self.host()
        for r in self.section.get("rooms", []):
            room, wanted = (r["room"], r.get("name")) if isinstance(r, dict) else (r, None)
            name = f"{self.prefix}.{wanted}" if wanted else unseenet_name(room, self.prefix)
            if name is None:
                raise SystemExit(f"matrix room {room}: give it a name (rooms = [{{room = ..., "
                                 "name = ...}}]); a room id has no name of its own")
            out.append((room, Carried(
                source=room, name=name, group_id=self.group_id(name),
                direction=self.direction(), title=f"Matrix: {room}",
                description=(f"Gatewayed from the Matrix room {room} by {host}. Messages "
                             "are signed by the gateway and arrive seconds to minutes late "
                             "in both directions, on purpose. Media is left out."),
                view="chat", kinds=("chat",))))
        return out

    def announcement(self, room: str, group: str) -> str:
        how = ("Messages from there appear here too, posted by this account with the "
               "author's name. " if self.direction() == "both" else "")
        contact = self.gw.get("abuse") or self.gw.get("contact", "")
        return (f"This room is now gatewayed to the Unseenet group {group} "
                f"(https://unseenet.org). Messages in this room are copied there. {how}"
                "Copies arrive seconds to minutes late in both directions, on purpose. "
                "Images and files are not carried. To stop the gateway, kick this account."
                + (f" Operator: {contact}" if contact else ""))

    # --- the adapter ---
    def carried(self) -> list[Carried]:
        return [c for _, c in self.rooms()]

    def feeds(self, *, state, node, gateway: crypto.Identity, pow_bits: int) -> list[Feed]:
        rooms = self.rooms()
        return [MatrixFeed(
            state=state, matrix=self.matrix(),
            carried={r: c.group_id for r, c in rooms},
            start=self.section.get("start", "new"),
            max_pages=int(self.section.get("max_pages", 10)),
            announce={r: self.announcement(r, c.name) for r, c in rooms})]

    def export_targets(self, *, state, feeds: list[Feed]) -> dict[str, Send]:
        if self.direction() != "both":
            return {}
        feed = next((f for f in feeds if isinstance(f, MatrixFeed)), None)
        if feed is None:
            return {}
        rooms = {c.group_id: r for r, c in self.rooms()}
        sender = MatrixSender(matrix=feed.matrix, state=state, rooms=rooms,
                              room_id_of=feed.room_id)
        return {gid: sender.send for gid in rooms}

    def counterpart(self, entry: dict, *, state, feeds: list[Feed]) -> MatrixCounterpart:
        """[[portals]] entry: group, network = "matrix", room (an alias on the gateway's
        own server), optional admins (Matrix users invited with full power)."""
        feed = next((f for f in feeds if isinstance(f, MatrixFeed)), None)
        matrix = feed.matrix if feed else self.matrix()
        return MatrixCounterpart(state=state, matrix=matrix, alias=entry["room"],
                                 group_id=entry["group"], admins=entry.get("admins", []),
                                 max_pages=int(self.section.get("max_pages", 10)))

    def run_command(self, name: str) -> None:
        if name != "matrix-login":
            raise NotImplementedError(name)
        user = self.section["user"]
        password = os.environ.get(PASSWORD_ENV) or getpass.getpass(f"Password for {user}: ")
        m = Matrix(self.section["homeserver"], proxy=self.section.get("proxy"))
        r = asyncio.run(m.login(user, password, "unseenet-gateway"))
        path = self.token_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(r["access_token"] + "\n")
        print(f"logged in as {r['user_id']}; token saved to {path}")
