# Changelog

All notable changes to unseenet-gateway are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[semantic versioning](https://semver.org/) on the same principles as
[unseenet](https://github.com/unseenet/unseenet/blob/main/docs/development.md#versioning).
The rules gateways follow are in the [UN-RFC series](https://github.com/unseenet/unseenet/tree/main/rfc):
UN-RFC 0023 for all gateways, 0024 for Usenet, 0026 for Nostr, 0038 for
several gateways per group.

## [Unreleased]

## [0.1.0] - 2026-10-22

The first release. Works with unseenet 0.4 (`unseenet>=0.4.1,<0.5`); nodes
from 0.4.0 need the gateway's keys ripened once (`unseenet-gateway ripen`).

### Added

- A generic core with one adapter per network, found through the
  `unseenet_gateway.adapters` entry point, so other packages can add their
  own; groups from another network appear under its own hierarchy
  (`usenet.*`, `nostr.*`, `matrix.*`) with `Origin-*` headers
  (UN-RFC 0023).
- **Usenet:** import from an INN server (UN-RFC 0024).
- **Nostr:** import from NIP-29 groups on one or more relays, author names
  from profile relays, NIP-40 expiration, cancels for messages a relay no
  longer serves, reconnecting after a dropped connection (UN-RFC 0026).
- **Matrix:** import from rooms, Unseenet Markdown exported as formatted
  Matrix messages; spaces are never gatewayed, and a room where the gateway
  may not write does not stop the import.
- **Export:** posts from Unseenet go to the other network through a
  submission queue, after asking the group (UN-RFC 0023 section 5).
  When the node still refuses the approved copy (its own postage, a block
  in the hierarchy), the message is taken back on the other network: a
  redaction on Matrix, a NIP-09 deletion on Nostr, and only what this
  gateway sent (#18).
- **Portals:** an Unseenet group mirrored to Nostr or Matrix with the owner's
  consent, its counterpart named "<group> (Unseenet)".
- **Requests:** rooms that invite the gateway become requests the operator
  decides from their Unseenet inbox.
- **Several gateways per group:** turns, admission and a directory of
  gateways (UN-RFC 0038).
- The gateway's inbox manifest is published at start and weekly.
- `unseenet-gateway ripen [--to N] [--group-key]`: ripen the gateway key, and
  the group key when it is on this host (UN-RFC 0025).

### Changed

- Everything the gateway posts goes through the core's `Session`, so key
  ripening, the `Key-Ripening` header and postage are the same code as in
  every client (gateway#19).
- The repository is now
  [unseenet/unseenet-gateway](https://github.com/unseenet/unseenet-gateway)
  (the old address redirects).

[Unreleased]: https://github.com/unseenet/unseenet-gateway/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/unseenet/unseenet-gateway/releases/tag/v0.1.0
