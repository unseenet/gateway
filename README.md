# Unseenet gateway

Gateways between [Unseenet](https://unseenet.org) and other networks, as
specified in [UN-RFC 0023](https://github.com/unseenet/unseenet/blob/main/rfc/un-rfc-0023.md).
Usenet is the first network; FidoNet (`fido.*`) may follow on the same
principle.

> **Pre-alpha.** Import from Usenet works against a lab setup. Export is not
> implemented yet. Do not point this at a real Usenet peer without an agreement
> with its administrators.

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
articles from it like a newsreader. Each article is converted (UN-RFC 0023
section 4), signed with the gateway key, given its postage and posted to an
Unseenet node over Tor.

```
src/unseenet_gateway/
  core/      shared by all networks: keys, state, the Unseenet side
  usenet/    Usenet adapter: conversion, reading from INN, import
```

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
```

Passphrases are read from `UNSEENET_GATEWAY_PASSPHRASE` (gateway key) and
`UNSEENET_GATEWAY_GROUP_PASSPHRASE` (group key), or asked for. After
`create-groups`, move the group key file off the gateway host: it is only
needed again to change a group's manifest.

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
