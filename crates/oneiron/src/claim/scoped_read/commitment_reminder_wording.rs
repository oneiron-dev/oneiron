//! Source admission for attempt-filed reminder wording (FIX 4997).
//!
//! A wording version quotes the commitment body its attempt fenced; the
//! binding rides the version's immutable ledger-bound MadeBy. A served read
//! serves the version's bytes only while this lane natively admits the
//! persisted source row and that row still holds the persisted revision.
//! History, not the current head: an older version answers under its own
//! persisted source, judged by this lane's ordinary Recorded policy, and a
//! withdrawn source reads as absent through the lane's own semantics.

use super::*;
use crate::commitment_wake::wording_source_binding;
use crate::registry::ENTITY_TYPE_CLAIM;

impl ScopedRead<'_> {
    /// Whether this lane serves `artifact_id`'s exact `version` (FIX 4997):
    /// a version no wording attempt filed reads as it always has, and an
    /// attempt filing reads only while this lane admits its persisted
    /// source row and that row still holds the persisted revision, judged
    /// in one snapshot beside the version's own binding. The MadeBy names
    /// the row; only this lane's admission serves it. A marked-but-malformed
    /// binding, a missing version, a dead proof, or a source this lane
    /// withholds reads as absent, never as unmarked.
    ///
    /// # Errors
    ///
    /// The store failed, or the version record mismatches its ledger claim.
    pub fn commitment_reminder_wording_source_readable(
        &self,
        artifact_id: &EntityId,
        version: u64,
    ) -> Result<bool> {
        self.persist_grant_clock()?;
        let txn = self.vault.store.env.read_txn()?;
        let Some(record) =
            self.vault
                .blob_artifact_version_metadata_in_txn(&txn, artifact_id, version)?
        else {
            return Ok(false);
        };
        let binding = match wording_source_binding(&record) {
            Ok(Some(binding)) => binding,
            Ok(None) => return Ok(true),
            Err(_) => return Ok(false),
        };
        if !self.proof_live_in(&txn)? {
            return Ok(false);
        }
        let mut parts = self
            .get_entities_parts_in_txn(&txn, &[binding.source])?
            .into_iter();
        let Some((kind, _, _)) = parts.next().flatten() else {
            return Ok(false);
        };
        if kind != ENTITY_TYPE_CLAIM {
            return Ok(false);
        }
        // Native admission passed: the fenced revision hashes the RAW stored
        // body, so re-read this same row raw in this same snapshot for the
        // consistency check alone. The admitted projection may mask, and a
        // masked projection must never withhold a permitted read; raw bytes
        // hash here and are never exposed.
        let row = self
            .vault
            .port_entity_record(&txn, &binding.source)?
            .filter(|row| row.entity_type == ENTITY_TYPE_CLAIM);
        let Some(row) = row else {
            return Ok(false);
        };
        Ok(*blake3::hash(&row.body).as_bytes() == binding.revision)
    }
}
