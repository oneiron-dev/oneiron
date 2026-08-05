# WORKLOG — ONE-1437 [SURF-ENG-04] Reactive local-first data layer

branch: `ONE-1437` cut off `f199af8` (ONE-1259 CY-CLOSED tip; #580 merged to main as `ee4a481`)
worktree: `/Volumes/Cinema/w5-lt/surfaces-wire`
blueprint: `/Users/olety/.claude-wave5/blueprints/SURFACES-WIRE/ONE-1437.md`

## Packet (claims)

- `crates/oneiron-server/src/api/reactive.rs` (new)
- `crates/oneiron-server/src/api.rs` (mod + re-export seam only)
- `crates/oneiron-server/src/api/tests.rs` (fixtures)
- `crates/oneiron-server/src/broadcast.rs` (`ReactiveChangeSubscriber` arm)
- `crates/oneiron-server/src/server.rs` (Observer-A producer wire)

Not touched: `protocol.rs`, `sync/transport.rs`, `sync/bridge.rs`, `handler.rs`,
`lib.rs`, `Cargo.toml`, `Cargo.lock`.

## State

- [x] read blueprint + anchors end-to-end
- [ ] api/reactive.rs
- [ ] broadcast.rs ReactiveChangeSubscriber
- [ ] server.rs Observer-A producer
- [ ] api.rs seam
- [ ] api/tests.rs fixtures
- [ ] gates

## Design notes

(filled in as work lands)
