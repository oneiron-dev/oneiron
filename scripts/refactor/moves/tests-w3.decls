## crate
crates/oneiron

## allowed
crates/oneiron/src/analyzer/japanese.rs
crates/oneiron/src/analyzer/japanese/tests.rs
crates/oneiron/src/analyzer/mod.rs
crates/oneiron/src/analyzer/script.rs
crates/oneiron/src/analyzer/script/tests.rs
crates/oneiron/src/analyzer/tests.rs
crates/oneiron/src/edit_roundtrip/opc.rs
crates/oneiron/src/edit_roundtrip/opc/tests.rs
crates/oneiron/src/llm/budget.rs
crates/oneiron/src/llm/budget/tests.rs
crates/oneiron/src/settings/model_versioning.rs
crates/oneiron/src/settings/model_versioning/tests.rs
crates/oneiron/src/sync/bridge.rs
crates/oneiron/src/sync/bridge/tests.rs
crates/oneiron/src/sync/client.rs
crates/oneiron/src/sync/client/tests.rs
crates/oneiron/src/sync/connection.rs
crates/oneiron/src/sync/connection/tests.rs
crates/oneiron/src/sync/lease.rs
crates/oneiron/src/sync/lease/tests.rs
crates/oneiron/src/sync/manager.rs
crates/oneiron/src/sync/manager/tests.rs
crates/oneiron/src/sync/quarantine.rs
crates/oneiron/src/sync/quarantine/tests.rs
crates/oneiron/src/sync/queue.rs
crates/oneiron/src/sync/queue/tests.rs
crates/oneiron/src/sync/quota.rs
crates/oneiron/src/sync/quota/tests.rs
crates/oneiron/src/sync/selector.rs
crates/oneiron/src/sync/selector/tests.rs
crates/oneiron/src/sync/transport.rs
crates/oneiron/src/sync/transport/tests.rs
crates/oneiron/src/sync/window.rs
crates/oneiron/src/sync/window/tests.rs

## forbid

## anchors

## uniqueness

## error-literal

## decl

## impl-delta
- crates/oneiron/src/edit_roundtrip/opc.rs	impl RawEntry
- crates/oneiron/src/sync/bridge.rs	impl tracing :: Subscriber for WarnCapture
- crates/oneiron/src/sync/bridge.rs	impl tracing :: field :: Visit for MessageVisitor
- crates/oneiron/src/sync/connection.rs	impl FakeServer
- crates/oneiron/src/sync/queue.rs	impl Drop for PurgeFailureReset
- crates/oneiron/src/sync/queue.rs	impl Drop for ReceiverScrubFailureReset
+ crates/oneiron/src/edit_roundtrip/opc/tests.rs	impl RawEntry
+ crates/oneiron/src/sync/bridge/tests.rs	impl tracing :: Subscriber for WarnCapture
+ crates/oneiron/src/sync/bridge/tests.rs	impl tracing :: field :: Visit for MessageVisitor
+ crates/oneiron/src/sync/connection/tests.rs	impl FakeServer
+ crates/oneiron/src/sync/queue/tests.rs	impl Drop for PurgeFailureReset
+ crates/oneiron/src/sync/queue/tests.rs	impl Drop for ReceiverScrubFailureReset
