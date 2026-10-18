# Unseenet gateway

Gateways between [Unseenet](https://unseenet.org) and other networks, as
specified in [UN-RFC 0023](https://github.com/unseenet/unseenet/blob/main/rfc/un-rfc-0023.md)
(what every gateway shares) and one profile per network.

The gateway is a generic core with one **adapter** per network. The core does
everything Unseenet's rules ask of every gateway; an adapter only reaches its
network and converts messages. Two adapters come with it, and they are also
the reference for writing new ones:

| Adapter  | Network               | Hierarchy  | Profile     | Status in the lab               |
|----------|-----------------------|------------|-------------|---------------------------------|
| `usenet` | Usenet, through INN   | `usenet.*` | UN-RFC 0024 | import                          |
| `nostr`  | Nostr groups (NIP-29) | `nostr.*`  | UN-RFC 0026 | import, export, portals         |

Adapters for other networks – FidoNet, Matrix, IRC, XMPP, the fediverse and
others whose names UN-RFC 0023 section 9 reserves – are meant to be easy to
add, also by others and in their own repositories, without any change to
this one. See [Writing an adapter](#writing-an-adapter).

> **Pre-alpha.** Everything above runs against a lab setup only. Export to
> Usenet is not implemented yet. Do not point this at a real Usenet peer
> without an agreement with its administrators.

## How it works

Groups from another network live in Unseenet under a top-level hierarchy named
after that network: the Usenet group `comp.misc` becomes `usenet.comp.misc`.
Each is an ordinary **moderated** group whose moderator is the gateway, so
nodes and clients carry it without knowing anything about gateways.

```
 Usenet peers ──NNTP──▶ INN (on the gateway host) ──▶ unseenet-gateway ──Tor──▶ Unseenet node
```

The gateway does not talk to Usenet itself. A local news server (INN) does
the peering, history, `Path` and spam filtering, and the gateway reads new
articles from it like a newsreader. Each article is converted (UN-RFC 0024), signed with the gateway key, given its postage and posted to an
Unseenet node over Tor.

```
src/unseenet_gateway/
  core/      shared by all networks: the adapter contract, the import loop,
             export queue, portals, keys, state, Origin-* headers, the Unseenet side
  usenet/    Usenet adapter: conversion, reading from INN
  nostr/     Nostr adapter: NIP-29 groups, BIP-340 signatures, export, portals
```

The core does what UN-RFC 0023 asks of every gateway; an adapter does only
what its network needs, as its profile specifies (UN-RFC 0023 section 9).
The core knows no network by name: adapters are found through the
`unseenet_gateway.adapters` entry point group, and each reads its own section
of `gateway.toml`. See [Writing an adapter](#writing-an-adapter).

**Nostr.** The adapter reads public NIP-29 groups from a relay. It checks that
the group's metadata is signed by the relay and that the group is not private,
drops events whose id or signature do not verify, and imports threads (kind
11), comments (kind 1111) and chat (kind 9) into `nostr.<group-id>`. The
original signed event goes into `Origin-Proof`, so a reader can check that the
gateway did not change it. Messages the group deletes are cancelled in
Unseenet. Signatures are pure Python; `pip install unseenet-gateway[fast]`
adds coincurve for speed.

Every imported article carries the shared `Origin-Network`, `Origin-ID`,
`Origin-Date` and `Origin-From` headers (UN-RFC 0023 section 4.3), so a
client can show gatewayed articles from any network the same way. Headers that
only make sense for one network keep its prefix (`Usenet-Newsgroups`, …).

Planned networks: FidoNet (`fido.*`) and Matrix (`matrix.*`,
unseenet/unseenet#116).

What a gateway never does: learn or record anything about who wrote an
Unseenet post or where it came from. It can stop a key; it cannot identify a
person (UN-RFC 0023 section 6.2).

## Setup

Requires Python 3.11+, Tor, and INN carrying the groups you want.

```
python3 -m venv .venv
.venv/bin/pip install git+https://github.com/unseenet/gateway.git
cp gateway.example.toml gateway.toml          # and edit it

unseenet-gateway -c gateway.toml keys            # creates the group key and the gateway key
# put the printed group key in gateway.group_owner
unseenet-gateway -c gateway.toml create-groups   # publishes one manifest per group
unseenet-gateway -c gateway.toml import-once -v
unseenet-gateway -c gateway.toml run             # every `interval` seconds
unseenet-gateway -c gateway.toml stats
unseenet-gateway -c gateway.toml -n nostr import-once -v   # one network only
```

Passphrases are read from `UNSEENET_GATEWAY_PASSPHRASE` (gateway key) and
`UNSEENET_GATEWAY_GROUP_PASSPHRASE` (group key), or asked for. After
`create-groups`, move the group key file off the gateway host: it is only
needed again to change a group's manifest.

## Writing an adapter

Usenet and Nostr are reference adapters, not the limit: an adapter for
another network can be written by anyone and live in its own package;
nothing here has to change. Usenet shows a network reached through a local
server and read by article number; Nostr shows one with several relays,
signed messages, deletions, export and portals. The contract is in `src/unseenet_gateway/core/adapter.py`, and the
smallest complete example is the loopback adapter in
`tests/test_adapter_core.py`. In short:

- a subclass of `Adapter` with `network` (its hierarchy, reserved in
  UN-RFC 0023 section 9) and `capabilities` (export, retractions, portals);
- `carried()`: which foreign groups become which Unseenet groups, for the
  manifests;
- `feeds()`: one `Feed` per connection. A feed yields `Incoming` messages
  from `fetch()` and converts each with `convert()` (or raises `Skip`). The
  core skips duplicates, signs, pays postage, posts, threads and cancels;
- optionally `export_targets()` (a `send` per group) and `counterpart()`
  for portals;
- an entry point:

  ```toml
  [project.entry-points."unseenet_gateway.adapters"]
  matrix = "unseenet_gateway_matrix:MatrixAdapter"
  ```

The Python API belongs to this implementation, not to the UN-RFCs: they
specify what a gateway does, so a gateway written in another language is
just as correct. A new network also needs a profile UN-RFC and its hierarchy
reserved in the root list.

This is all the documentation for adapter authors so far: the contract in
`core/adapter.py`, this section and the two reference adapters. The API may
still change before Unseenet 1.0, and fuller documentation will follow once
it has settled.

## Development

```
python3 -m venv .venv
.venv/bin/pip install -e ../unseenet pytest   # a checkout of unseenet/unseenet
.venv/bin/pip install --no-deps -e .
.venv/bin/pytest
```

The tests use synthetic articles only.

## License

Apache-2.0, like the rest of Unseenet.
