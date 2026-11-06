//! The opaque delete-bearing delta a tombstone commit queues, and its single
//! constructor.

use crate::loro_document::export_updates_from;
use loro::LoroDoc;
use oneiron_base::error::Result;

/// A tombstone-commit delta authorized to be queued as DELETE-BEARING.
///
/// The `d:{seq:8BE}` sidecar marker exempts its `q:` row from every
/// unconfirmed clear and from the carrier-15 scrub — protections built for
/// tombstone deltas, not arbitrary payloads. The private field plus the
/// single constructor ([`export_tombstone_commit_delta`]) are the
/// type-system pin that delete-bearing = a real tombstone-commit delta:
/// nothing outside the tombstone-commit path can mark bytes delete-bearing
/// (ONE-1135 review item 14).
pub struct DeleteBearingUpdate(Vec<u8>);

impl DeleteBearingUpdate {
    /// The delta bytes stored in the `q:` row.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Test-only escape hatch so queue unit tests can exercise the `d:`
    /// row machinery with synthetic bytes. NOT part of the public API and
    /// compiled out of every non-test build.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Exports the tombstone commit's delta as the [`DeleteBearingUpdate`]
/// queued for transmission — the ONLY constructor of that type.
///
/// Call IMMEDIATELY after `sync::window::apply_tombstone_to_window_doc` +
/// commit; `vv_before` must be the doc's oplog version vector captured before
/// the tombstone was applied. Returns `None` when the commit was a no-op
/// (e.g. a blocked downgrade of an existing hard tombstone) — there is
/// nothing to queue.
pub fn export_tombstone_commit_delta(
    doc: &LoroDoc,
    vv_before: &loro::VersionVector,
) -> Result<Option<DeleteBearingUpdate>> {
    if doc.oplog_vv() == *vv_before {
        return Ok(None);
    }
    Ok(Some(DeleteBearingUpdate(export_updates_from(
        doc, vv_before,
    )?)))
}
