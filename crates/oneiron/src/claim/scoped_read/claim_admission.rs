//! Claim admission on the scoped lane: the lane's claim-status mode, then the
//! reader, credential, ceiling, audience and grant checks every claim meets.

use super::access_gate::HeldAuthority;
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

impl<'v> ScopedRead<'v> {
    /// This lane as the record verbs read it: the same key, its status half
    /// admitting claims of every status, and the same reader's own owner
    /// authority when it opted into it (FIX 7461). Only a plain lane has one;
    /// a lane composed with a room audience, peer reads or a session view
    /// refuses.
    pub fn recorded_lane(&self) -> Result<ScopedRead<'v>> {
        if self.audience.is_some() || !self.peer_reads.is_empty() || self.session_view.is_some() {
            return Err(Error::InvariantViolation(
                "recorded lane of a composed read",
            ));
        }
        let mut lane = self
            .vault
            .scoped_read(self.actor_key.clone())
            .with_claim_status(ClaimReadStatus::Recorded);
        lane.own_owner_authority = self.own_owner_authority;
        lane.records_cover = self.records_cover.clone();
        Ok(lane)
    }
}

impl<'v> ScopedRead<'v> {
    /// The same lane admitting claims of every status the record verbs serve.
    #[must_use]
    pub(crate) fn with_claim_status(mut self, status: ClaimReadStatus) -> Self {
        self.claim_status = status;
        self
    }

    /// Whether a claim whose principal audience is `principal` admits this
    /// reader: one that names a principal admits that principal alone.
    pub(crate) fn principal_admits(&self, principal: Option<EntityId>) -> bool {
        principal.is_none() || principal == EntityId::from_hex(self.actor_key.actor_ref()).ok()
    }

    /// A CLAIM row's admission. Under `grant`, one live Grant of the reader's
    /// own (FIX 7462), that Grant stands in for the relationship check and
    /// the positive claim check; `None` is today's admission.
    #[expect(
        clippy::too_many_arguments,
        reason = "a claim row's admission under its filter, held authority and an optional Grant"
    )]
    pub(super) fn is_claim_raw_readable_with_policy_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
        authority: &HeldAuthority<'v>,
        grant: Option<&crate::federation::Scope>,
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
        self.is_claim_readable_with_body_and_policy_in(
            rtxn, policy, id, raw, &body, filter, authority, grant,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "a claim's admission under its filter, held authority and an optional Grant"
    )]
    fn is_claim_readable_with_body_and_policy_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        body: &ClaimBody,
        filter: &ResolvedRetrievalFilter,
        authority: &HeldAuthority<'v>,
        grant: Option<&crate::federation::Scope>,
    ) -> Result<bool> {
        // History controls travel through scoped sync/export, never ordinary
        // claim recall. Their binary value contains signed birth payloads.
        if crate::claim::history_store::machine_history_kind(&body.predicate).is_some() {
            return Ok(false);
        }
        if !crate::claim::has_live_support_in_txn(&self.store_read(), rtxn, body)? {
            return Ok(false);
        }
        let principal = claim_principal_id(body)?;
        if !self.principal_admits(principal) {
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
        if !self.credential_allows_row_in(rtxn, id)
            || !self.proof_live_in(rtxn)?
            || !self.guest_bound_admits_in(rtxn, id, raw)
        {
            return Ok(false);
        }
        let causal_admitted = {
            let cached = self
                .recall_authority
                .lock()
                .map_err(|_| Error::InvariantViolation("recall authority lock"))?;
            match cached.as_ref() {
                Some(fold) => crate::authority::claim_causal_admitted(
                    &self.vault.store,
                    rtxn,
                    fold,
                    id,
                    body,
                )?,
                // The shared view of this snapshot's fold, not a copy: this
                // runs per claim, and a copy grows with the vault's agents.
                None => crate::authority::claim_causal_admitted(
                    &self.vault.store,
                    rtxn,
                    &*self.vault.authority_view_readonly_in_txn(rtxn)?,
                    id,
                    body,
                )?,
            }
        };
        if !causal_admitted {
            return Ok(false);
        }
        let admitted = self.claim_status.admits(filter, body)
            && crate::pipeline::claim_ceiling_allowed(filter, body);
        if !admitted
            || !self.audience_readable_raw_in(rtxn, id, raw, authority)?
            || (grant.is_none()
                && !self.relationship_claim_allowed_in(rtxn, id, body, authority)?)
        {
            return Ok(false);
        }
        let claim_facets = self.claim_facet_refs_in(rtxn, id)?;
        Ok(match grant {
            None => {
                crate::gate::scoped_read_claim_allowed(policy, &self.actor_key, body, &claim_facets)
            }
            Some(grant) => crate::gate::scoped_read_claim_allowed_with_scope(
                policy,
                &self.actor_key,
                body,
                &claim_facets,
                Some(grant),
            ),
        })
    }
}
