//! Exact retained operation identity across a scratch document import.
//!
//! A successful Loro import can ignore operation ids it already holds. Its
//! status alone therefore cannot prove that the selected source's bytes were
//! the bytes joined. This comparison is data integrity, not write admission.

use super::super::{EntityDoc, invalid};
use crate::error::Result;
use crate::store::checkpoint_payload::loro::prove_loro_equivalent;

pub(super) fn require_current_state(document: &EntityDoc) -> Result<()> {
    if document.doc.state_frontiers() != document.doc.oplog_frontiers() {
        return Err(invalid("record document state is not its head"));
    }
    Ok(())
}

/// Compare every operation retained on both sides at its exact typed
/// payload, change message and causal coordinates. History already below
/// the local floor is not required to reappear from an older full source.
/// This does not validate either shallow floor's state or admit its source.
/// The owner-authorized purge, if any, runs after both comparisons.
pub(super) fn require_retained_extension(source: &EntityDoc, joined: &EntityDoc) -> Result<()> {
    require_current_state(source)?;
    require_current_state(joined)?;
    let mut start = source.doc.shallow_since_vv().to_vv();
    start.merge(&joined.doc.shallow_since_vv().to_vv());
    let end = source.doc.oplog_vv();
    if !joined.doc.oplog_vv().includes_vv(&end) {
        return Err(invalid("record document import lost source version"));
    }
    // Use the same causal interval on both documents. In particular, do
    // not compare whole changes exported at different shallow boundaries.
    let expected = source
        .doc
        .export_json_updates_without_peer_compression(&start, &end);
    let actual = joined
        .doc
        .export_json_updates_without_peer_compression(&start, &end);
    prove_loro_equivalent(&expected.changes, &actual.changes)
        .map_err(|_| invalid("record document retained operations differ"))
}
