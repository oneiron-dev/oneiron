// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1645 — the `FacetOf` type table on the FEDERATED REPLAY door.
//!
//! The write-time table (`CLAIM | TURN | EVENT -> FACET`) is enforced on the
//! local batch door, which aborts atomically. Replay cannot abort: a hard
//! failure on a replicated shape wedges sync permanently (H2), so
//! `BatchOp::EdgeWithCreatedAt` is deliberately ungated and forward
//! rematerialization runs the table at the write chokepoint, QUARANTINING an
//! off-table row and continuing the window.
//!
//! Why this is an authorization boundary and not schema hygiene: an off-table
//! stamp injected by a member/guest peer — say `PERSON -> FACET`, a shape no
//! local public writer can produce — would otherwise land in LMDB, the
//! retrieval truth every local disclosure surface reads. The grant-backed
//! federation selector mirrors this same table on its read side
//! (`sync::selector::facet_scope_by_source`) and so will not honor such a
//! source as a facet seed; keeping the unwritable shape out of storage in the
//! first place is THIS door's job.
//!
//! This suite drives the REAL member/guest entry point
//! (`admit_federated_window_update` → forward rematerialization) rather than
//! hand-built docs, so it fails if the admission door stops routing through
//! the chokepoint.

#![cfg(feature = "sync")]
