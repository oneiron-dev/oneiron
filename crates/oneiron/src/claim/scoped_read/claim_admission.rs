//! Claim admission on the scoped lane: the lane's claim-status mode, then the
//! reader, credential, ceiling, audience and grant checks every claim meets.

use super::*;

/// Which claim statuses a scoped read lane admits.
///
/// The status half of claim admission, and nothing else: every other check
/// (reader, credential, ceiling, audience, relationship and grant) applies in
/// both modes. Actor-owned exact-store claims are never admitted in either.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ClaimReadStatus {
    /// Retrieval channels: `auto`/`approved`, active, and not stale unless
    /// the resolved filter includes stale claims (the D19 read-path gate).
    #[default]
    Surfaceable,
    /// The record verbs (get, list, history): proposed and closed claims are
    /// part of those verbs' contract, so the status half admits every status.
    Recorded,
}

impl ClaimReadStatus {
    /// Whether `body`'s status passes this mode.
    pub(crate) fn admits(self, filter: &ResolvedRetrievalFilter, body: &ClaimBody) -> bool {
        crate::claim::claim_generic_readable(body)
            && match self {
                Self::Surfaceable => {
                    matches!(
                        body.approval,
                        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
                    ) && body.lifecycle == ClaimLifecycleStatus::Active
                        && (filter.include_stale || !body.stale)
                }
                Self::Recorded => true,
            }
    }
}

impl ScopedRead<'_> {
    /// The same lane admitting claims of every status the record verbs serve.
    #[must_use]
    pub(crate) fn with_claim_status(mut self, status: ClaimReadStatus) -> Self {
        self.claim_status = status;
        self
    }

    pub(super) fn is_claim_raw_readable_with_policy_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
    ) -> Result<bool> {
        if raw.len() == ENTITY_METADATA_HEADER_LEN
            && self.vault.store.entity_deletion_present_in_txn(
                rtxn,
                id,
                EntityMetadataHeader::parse(raw)
                    .ok_or(Error::CorruptedIndex("entity header"))?
                    .learned_at,
            )?
        {
            return Ok(false);
        }
        let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        self.is_claim_readable_with_body_and_policy_in(rtxn, policy, id, &body, filter)
    }

    fn is_claim_readable_with_body_and_policy_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        body: &ClaimBody,
        filter: &ResolvedRetrievalFilter,
    ) -> Result<bool> {
        let principal = claim_principal_id(body)?;
        let reader = EntityId::from_hex(self.actor_key.actor_ref()).ok();
        if principal.is_some() && principal != reader {
            return Ok(false);
        }
        if crate::edit_distance::miner::is_mined_preference(&body.predicate) {
            if principal.is_none() {
                return Ok(false);
            }
            let learned_at = self
                .entity_record_in(rtxn, id)?
                .ok_or(Error::CorruptedIndex("preference entity"))?
                .learned_at;
            if !preference_in_force(body, learned_at, crate::unix_seconds_now())? {
                return Ok(false);
            }
        }
        if !self.credential_allows_id(id) || !self.proof_live_in(rtxn)? {
            return Ok(false);
        }
        if !crate::authority::claim_causal_admitted(
            &self.vault.authority_fold_readonly_in_txn(rtxn)?,
            body,
        ) {
            return Ok(false);
        }
        let admitted = self.claim_status.admits(filter, body)
            && crate::pipeline::claim_ceiling_allowed(filter, body);
        if !admitted
            || !self.audience_readable_in(rtxn, id)?
            || !self.relationship_claim_allowed_in(rtxn, body)?
        {
            return Ok(false);
        }
        let claim_facets = self.claim_facet_refs_in(rtxn, id)?;
        Ok(crate::gate::scoped_read_claim_allowed(
            policy,
            &self.actor_key,
            body,
            &claim_facets,
        ))
    }
}
