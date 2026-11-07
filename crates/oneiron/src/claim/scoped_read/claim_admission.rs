//! Claim admission on the scoped lane: the lane's claim-status mode, then the
//! reader, credential, ceiling, audience and grant checks every claim meets.

use super::access_gate::HeldAuthority;
use super::*;

pub(crate) use crate::ports::ClaimReadStatus;

pub(crate) trait ClaimReadStatusExt {
    fn admits(self, filter: &ResolvedRetrievalFilter, body: &ClaimBody) -> bool;
    fn admits_status(
        self,
        filter: &ResolvedRetrievalFilter,
        generic_readable: bool,
        approval: ClaimApprovalStatus,
        lifecycle: ClaimLifecycleStatus,
        stale: bool,
    ) -> bool;
}

impl ClaimReadStatusExt for ClaimReadStatus {
    /// Whether `body`'s status passes this mode.
    fn admits(self, filter: &ResolvedRetrievalFilter, body: &ClaimBody) -> bool {
        self.admits_status(
            filter,
            crate::claim::claim_generic_readable(body),
            body.approval,
            body.lifecycle,
            body.stale,
        )
    }

    /// [`Self::admits`] over the status a claim's access class carries
    /// (FIX 11915): whether its predicate reads generically, its approval,
    /// its lifecycle and its staleness.
    fn admits_status(
        self,
        filter: &ResolvedRetrievalFilter,
        generic_readable: bool,
        approval: ClaimApprovalStatus,
        lifecycle: ClaimLifecycleStatus,
        stale: bool,
    ) -> bool {
        generic_readable
            && match self {
                Self::Surfaceable => {
                    matches!(
                        approval,
                        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
                    ) && lifecycle == ClaimLifecycleStatus::Active
                        && (filter.include_stale || !stale)
                }
                Self::Recorded => true,
            }
    }
}

impl ScopedReadActorKey {
    /// Whether a claim whose principal audience is `principal` admits this
    /// key's reader: one that names a principal admits that principal alone.
    pub(super) fn admits_principal(&self, principal: Option<EntityId>) -> bool {
        principal.is_none() || principal == EntityId::from_hex(self.actor_ref()).ok()
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
        lane.judged_at = self.judged_at;
        Ok(lane)
    }
}

impl ScopedRead<'_> {
    /// The same lane admitting claims of every status the record verbs serve.
    #[must_use]
    pub(crate) fn with_claim_status(mut self, status: ClaimReadStatus) -> Self {
        self.claim_status = status;
        self
    }

    /// The same lane judging a claim's time-bound standing (a learned
    /// preference's decay, a world's stale age) at `at`, Unix seconds: an
    /// `as_of` read judges at its `as_of`, never at the wall clock (Engine
    /// ruling, FIX 12226). `None` judges at now, and a later `at` judges at
    /// now too (L02 04:20): the recall door takes a future `as_of`, but no
    /// claim stands at a time that has not come. Authorization is not
    /// time-bound standing: grants and credentials stay judged at now.
    #[must_use]
    pub(crate) fn with_judged_at(mut self, at: Option<u64>) -> Self {
        self.judged_at = at.map(|at| at.min(crate::unix_seconds_now()));
        self
    }

    /// When this lane judges a claim's time-bound standing; `None` is now.
    pub(crate) fn judged_at(&self) -> Option<u64> {
        self.judged_at
    }

    /// Whether a claim whose principal audience is `principal` admits this
    /// reader: one that names a principal admits that principal alone.
    pub(crate) fn principal_admits(&self, principal: Option<EntityId>) -> bool {
        self.actor_key.admits_principal(principal)
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
        authority: &HeldAuthority,
        grant: Option<&oneiron_authority::federation::Scope>,
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
        authority: &HeldAuthority,
        grant: Option<&oneiron_authority::federation::Scope>,
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
            if !self.preference_in_force_in(rtxn, id, body)? {
                return Ok(false);
            }
        }
        if !self.credential_allows_row_in(rtxn, id)
            || !self.proof_live_in(rtxn)?
            || !self.guest_bound_admits_in(rtxn, id, raw)
        {
            return Ok(false);
        }
        if !self.claim_causally_admitted_in(rtxn, id, body)? {
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
        let allowed = match grant {
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
        };
        Ok(allowed && self.provenance_cited_readable_in(rtxn, policy, body, authority)?)
    }

    /// Whether this lane reads every record the claim `body` names beside its
    /// edge when it is an `edge.provenance` Claim (FIX 3959): its actor, and
    /// the record its `source_revision_ref` cites, at that revision. The last
    /// conjunct of every CLAIM's admission, on the row path and the class
    /// path alike, and never a class's: what it reads is the row's own. One
    /// named record this lane may not read withholds the Claim whole, as any
    /// withheld row is, and a body that does not decode as a provenance
    /// record is withheld too. A cited revision no record retains (an opaque
    /// legacy value, such as a Dreamer evidence hash) names no record and
    /// is shown as stored. Every other predicate passes, and so do the vault
    /// owner and a record judged as one such Claim names: the named records
    /// are judged under this lane's ordinary admission at its own floor,
    /// with this rule not re-entered (`HeldAuthority::judge_cited`), so the
    /// rule runs one level deep. A sealed secret custody row reads as absent
    /// here, as a ref to it does.
    pub(super) fn provenance_cited_readable_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        body: &ClaimBody,
        authority: &HeldAuthority,
    ) -> Result<bool> {
        if body.predicate != crate::provenance::PREDICATE_EDGE_PROVENANCE
            || self.actor_key.vault_owner_ref().is_some()
            || authority.judges_cited()
        {
            return Ok(true);
        }
        let Ok(record) = crate::provenance::decode_edge_provenance_body(&body.value) else {
            return Ok(false);
        };
        let floor = self.actor_retrieval_floor(policy)?;
        let readable = authority.judge_cited(|cited| {
            if !self.is_entity_readable_held_in(
                rtxn,
                policy,
                &record.actor_entity_ref,
                &floor,
                cited,
            )? {
                return Ok(false);
            }
            let Some(revision) = record.source_revision_ref.map(crate::vault::RevisionRef) else {
                return Ok(true);
            };
            let Some(document) = self.vault.revision_record_in(rtxn, revision)? else {
                return Ok(true);
            };
            Ok(self
                .admitted_raw_in(
                    rtxn,
                    policy,
                    &floor,
                    &document,
                    crate::vault::ReadMode::Pinned(revision),
                    cited,
                )?
                .is_some())
        });
        match readable {
            Err(error) if error.kind() == crate::ErrorKind::InvalidSecretCustodyBody => Ok(false),
            readable => readable,
        }
    }

    /// Whether the mined preference `body` of `id` stands at this lane's
    /// judged time: its decay and evidence from when it was learned.
    pub(super) fn preference_in_force_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
    ) -> Result<bool> {
        let learned_at = self
            .entity_record_in(rtxn, id)?
            .ok_or(Error::CorruptedIndex("preference entity"))?
            .learned_at;
        let now = self.judged_at.unwrap_or_else(crate::unix_seconds_now);
        preference_in_force(body, learned_at, now)
    }

    /// Whether the claim `body` of `id` stands causally: its machine read
    /// standing and its writers' revocations under this snapshot's fold.
    pub(super) fn claim_causally_admitted_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        body: &ClaimBody,
    ) -> Result<bool> {
        let cached = self
            .recall_authority
            .lock()
            .map_err(|_| Error::InvariantViolation("recall authority lock"))?;
        match cached.as_ref() {
            Some(fold) => {
                crate::authority::claim_causal_admitted(&self.vault.store, rtxn, fold, id, body)
            }
            // The shared view of this snapshot's fold, not a copy: this runs
            // per claim, and a copy grows with the vault's agents.
            None => crate::authority::claim_causal_admitted(
                &self.vault.store,
                rtxn,
                &*self.vault.authority_view_readonly_in_txn(rtxn)?,
                id,
                body,
            ),
        }
    }
}
