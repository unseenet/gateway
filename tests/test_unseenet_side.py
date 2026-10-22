"""The gateway posts through the core's Session (gateway#19): ripening, Key-Ripening and
postage as everywhere else (UN-RFC 0025)."""
import asyncio

import pytest

from unseenet.core import crypto
from unseenet.core import ripening as rp
from unseenet.core.article import new_article
from unseenet.core.groups import make_group_id, make_manifest
from unseenet.core.store import Store
from unseenet.node.server import Node as UnseenetNode, NodeConfig

from unseenet_gateway.core.unseenet_side import Node

pytest.importorskip("chiavdf")
pytestmark = pytest.mark.usefixtures("ripening_rules")


def test_imports_ripen_carry_the_header_and_pay_the_level(tmp_path):
    asyncio.run(_imports(tmp_path))


async def _imports(tmp_path):
    owner, gateway = crypto.Identity.generate(), crypto.Identity.generate()
    store = UnseenetNode(Store(), NodeConfig(min_pow=8, forward_delay=(0, 0)))
    server = await store.serve("127.0.0.1", 0)
    addr = f"127.0.0.1:{server.sockets[0].getsockname()[1]}"
    node = Node(addr, None)
    node.use_key(gateway, tmp_path / "gateway.key.state.json")
    node.use_key(owner, tmp_path / "group.key.state.json")

    # the group key's manifest: ripened first, like any article of ours
    manifest = make_manifest(owner, "alt.gw.test", "moderated", moderators=[gateway.key_text],
                             pow_bits=12)
    assert await node.post(manifest) == "ok"
    gid = make_group_id("alt.gw.test", owner.public_key)

    art = new_article(gid, "Imported", "From the other network\n", from_name="someone",
                      extra=[("Content-Type", "text/plain; charset=utf-8")])
    art.finalize(gateway, 8)                       # what the importer does; too little now
    assert await node.post(art) == "ok"
    raw = store.store.get(art.message_id).decode()
    assert "Key-Ripening: vdf-cg1; t=" in raw
    assert store.store.manifest(make_group_id(rp.GROUP_NAME, gateway.public_key)) is not None
    assert await node.post(art) == "duplicate"
    assert (tmp_path / "gateway.key.state.json").exists()
    await node.shutdown()
    server.close()
