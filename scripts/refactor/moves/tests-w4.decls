## crate
crates/oneiron-server

## allowed
crates/oneiron-server/src/auth.rs
crates/oneiron-server/src/auth/tests.rs
crates/oneiron-server/src/commands.rs
crates/oneiron-server/src/commands/tests.rs
crates/oneiron-server/src/config.rs
crates/oneiron-server/src/config/tests.rs
crates/oneiron-server/src/error.rs
crates/oneiron-server/src/error/tests.rs
crates/oneiron-server/src/handler.rs
crates/oneiron-server/src/handler/tests.rs
crates/oneiron-server/src/idempotency.rs
crates/oneiron-server/src/idempotency/tests.rs
crates/oneiron-server/src/mcp.rs
crates/oneiron-server/src/mcp/tests.rs
crates/oneiron-server/src/projection.rs
crates/oneiron-server/src/projection/tests.rs
crates/oneiron-server/src/runtime.rs
crates/oneiron-server/src/runtime/tests.rs
crates/oneiron-server/src/server.rs
crates/oneiron-server/src/server/tests.rs
crates/oneiron-server/src/usage.rs
crates/oneiron-server/src/usage/tests.rs

## forbid

## anchors

## uniqueness

## error-literal

## decl

## impl-delta
- crates/oneiron-server/src/idempotency.rs	impl IdempotencyClock for ManualClock
- crates/oneiron-server/src/idempotency.rs	impl ManualClock
- crates/oneiron-server/src/usage.rs	impl TelemetryCapture
- crates/oneiron-server/src/usage.rs	impl tracing :: Subscriber for TelemetryCapture
- crates/oneiron-server/src/usage.rs	impl tracing :: field :: Visit for TelemetryVisitor < ' _ >
+ crates/oneiron-server/src/idempotency/tests.rs	impl IdempotencyClock for ManualClock
+ crates/oneiron-server/src/idempotency/tests.rs	impl ManualClock
+ crates/oneiron-server/src/usage/tests.rs	impl TelemetryCapture
+ crates/oneiron-server/src/usage/tests.rs	impl tracing :: Subscriber for TelemetryCapture
+ crates/oneiron-server/src/usage/tests.rs	impl tracing :: field :: Visit for TelemetryVisitor < ' _ >
## frag-edit
crates/oneiron-server/src/mcp.rs	"../tests/fixtures/mcp_tool_args.validation.json"	"../../tests/fixtures/mcp_tool_args.validation.json"
