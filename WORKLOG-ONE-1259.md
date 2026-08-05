# WORKLOG — ONE-1259 (SURFACES-WIRE, layer 1 of the SURF-api stack)

Branch: `ONE-1259` · worktree `/Volumes/Cinema/w5-lt/surfaces-wire`
Blueprint: `/Users/olety/.claude-wave5/blueprints/SURFACES-WIRE/ONE-1259.md`

## Plan

1. Engine envelope — `surface_event.rs` schema v2: closed `SurfaceSourceApp`,
   `SurfaceEventSource`, typed `SurfaceEventAction`, public `correlation_id`,
   bounded queue run-id derivation.
2. Engine ack-first handoff — once-per-correlation admission in one LMDB write
   txn over the existing `AttemptQueue`/run-index APIs, durable status read, and
   the test-only worker leg behind `SurfaceEventDispatcher`.
3. Server surface — `api/surface_events.rs` domain module + mechanical `api.rs`
   registration for `POST /v1/core/surface-events` and
   `GET /v1/core/surface-events/{correlation_id}`.

## Notes

(filled in as the lane runs)
