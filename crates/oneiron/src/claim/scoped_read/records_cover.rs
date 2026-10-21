//! FIX 8245 (Engine 10-22, CALLS `FIX 8245 records cover`): a credential's
//! records caveat that names an artifact covers that artifact's own version
//! rows, each version's CLAIM and its content's ASSET, for the RECORDS check
//! alone.
//!
//! Off unless the lane opts in ([`ScopedRead::with_artifact_records_cover`]),
//! and only the typed artifact read doors do. The cover replaces nothing but
//! the records conjunct of the credential check: the channel caveat, the
//! proof's liveness, Scope and facets, the entity-type band, staleness and
//! withdrawal, surfaceability and lifecycle, the Grant alternatives and the
//! owner exemptions still judge each version row as they judge any row. The
//! lane holds artifact ids only, never a list of admitted rows, and the cover
//! holds only where the version metadata in the read's own snapshot binds the
//! row to that artifact. A lookup or decode failure there covers nothing: the
//! row keeps its ordinary records check, and the read its answer.

use super::*;

/// The artifacts whose own version rows this lane's records check covers
/// (FIX 8245): artifact ids, sorted and distinct. Empty on every lane that
/// did not opt in.
#[derive(Debug, Clone, Default)]
pub(super) struct ArtifactRecordsCover(Vec<EntityId>);

impl ScopedRead<'_> {
    /// This lane, its records check covering each of `artifacts`' own
    /// version rows where the credential's records caveat names that
    /// artifact (FIX 8245). Every other check still judges each of those
    /// rows; another artifact, or any other row, gains nothing.
    #[must_use]
    pub fn with_artifact_records_cover(mut self, artifacts: &[EntityId]) -> Self {
        let mut ids = artifacts.to_vec();
        ids.sort_unstable();
        ids.dedup();
        self.records_cover = ArtifactRecordsCover(ids);
        self
    }

    /// The credential's channel and records caveats on the row `id`, read
    /// in `rtxn`: the channel caveat as `Self::credential_allows_id` holds
    /// it, and the records caveat met by naming `id`, or by naming an
    /// artifact this lane's cover holds whose own version row `id` is
    /// (FIX 8245). Membership and deletion shells keep
    /// `Self::credential_allows_id`.
    pub(super) fn credential_allows_row_in(&self, rtxn: &heed::RoTxn<'_>, id: &EntityId) -> bool {
        let Some(proof) = self.actor_key.proof.as_ref() else {
            return true;
        };
        let claims = proof.claims();
        self.credential_channel_allows(claims)
            && (claims.records.is_empty()
                || claims.records.contains(&id.to_hex())
                || self.records_cover_allows_in(rtxn, claims, id))
    }

    /// Whether an artifact this lane's cover holds, and `claims`' records
    /// caveat names, has `id` as one of its own version rows in `rtxn`. A
    /// failure to judge it is no cover, and never the read's error.
    fn records_cover_allows_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        claims: &crate::authority::SlipClaims,
        id: &EntityId,
    ) -> bool {
        self.records_cover.0.iter().any(|artifact| {
            claims.records.contains(&artifact.to_hex())
                && self
                    .vault
                    .artifact_version_covers_record_in(rtxn, artifact, id)
                    .unwrap_or_else(|error| {
                        tracing::warn!(
                            error_kind = ?error.kind(),
                            "an artifact's records cover could not be judged; the row keeps its \
                             ordinary records check (FIX 8245)"
                        );
                        false
                    })
        })
    }
}
