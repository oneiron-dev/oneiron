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
        self.reminder_wording_source_readable_in(&txn, &binding.source, &binding.revision)
    }

    /// Judges the persisted source in the caller's cut. The raw body is
    /// used only for its type and fenced revision; the ordinary point read
    /// still decides whether this lane may receive its projection.
    pub(super) fn reminder_wording_source_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        source: &EntityId,
        revision: &[u8; 32],
    ) -> Result<bool> {
        if !self.proof_live_in(txn)? {
            return Ok(false);
        }
        let Some(row) = self
            .entity_record_in(txn, source)?
            .filter(|row| row.entity_type == ENTITY_TYPE_CLAIM)
        else {
            return Ok(false);
        };
        if blake3::hash(&row.body).as_bytes() != revision {
            return Ok(false);
        }
        Ok(matches!(
            self.get_entities_parts_in_txn(txn, std::slice::from_ref(source))?
                .pop()
                .flatten(),
            Some((ENTITY_TYPE_CLAIM, _, _))
        ))
    }

    /// Whether the ASSET row `(id, raw)` reads under the wording source
    /// contract (FIX 4997 R2): true for every non-wording row. A
    /// content-addressed ASSET with no local protected version reads as
    /// before; one with a local protected version reads only while some
    /// complete local alternative does — a protected version whose source
    /// and revision this same lane admits, or a genuine body-owning
    /// default raw at the same hash this lane reads. Alternatives are OR,
    /// malformed never authorizes, and replica-only holdings never clear.
    pub(super) fn reminder_wording_asset_sources_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        let Some(hash) =
            crate::blob_artifact::carrier_content_hash(&self.vault.store, txn, id, raw)?
        else {
            return Ok(true);
        };
        let versions = crate::blob_artifact::local_hash_versions_in_txn(self.vault, txn, &hash)?;
        let mut saw_protected = false;
        for version in &versions {
            match wording_source_binding(&version.record) {
                Ok(Some(binding)) => {
                    saw_protected = true;
                    if self.reminder_wording_source_readable_in(
                        txn,
                        &binding.source,
                        &binding.revision,
                    )? {
                        return Ok(true);
                    }
                }
                Err(_) => {
                    saw_protected = true;
                }
                Ok(None) => {}
            }
        }
        if !saw_protected {
            return Ok(true);
        }
        for version in &versions {
            if !version.is_default_raw {
                continue;
            }
            if !matches!(wording_source_binding(&version.record), Ok(None)) {
                continue;
            }
            if !self
                .vault
                .blob_artifact_bytes_readable_in_txn(txn, &version.artifact)?
            {
                continue;
            }
            if self.entities_readable_in_txn(txn, &[version.artifact, version.record.claim_id])?
                == [true, true]
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
