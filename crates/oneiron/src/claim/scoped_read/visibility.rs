use super::access_gate::HeldAuthority;
use super::agent_grants::AskedFilter;
use super::owner_authority::OwnAdmission;
use super::*;
use crate::federation::record_scope::asset_text;

impl<'v> ScopedRead<'v> {
    /// Whether this lane reads `id` now, an owner lane's standing rechecked
    /// in the snapshot it reads (see `Self::live_policy_manifest_in`).
    pub fn is_entity_readable(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.grant_read_txn()?;
        let policy = self.live_policy_manifest_in(&rtxn)?;
        self.is_entity_readable_with_policy_in(&rtxn, &policy, id)
    }

    /// Whether a ref a caller names resolves for this lane now. As
    /// [`Self::is_entity_readable`], except that sealed secret custody is no
    /// row a ref resolves to: it reads as absent here rather than refusing,
    /// so a named custody id answers as a missing one does. A raw read of it
    /// still refuses.
    pub fn is_ref_readable(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.grant_read_txn()?;
        let policy = self.live_policy_manifest_in(&rtxn)?;
        self.is_ref_readable_with_policy_in(&rtxn, &policy, id)
    }

    /// Whether every one of `ids` resolves for this lane, judged in one
    /// snapshot as [`Self::is_ref_readable`] judges each.
    pub fn all_refs_readable(&self, ids: &[EntityId]) -> Result<bool> {
        let rtxn = self.grant_read_txn()?;
        let policy = self.live_policy_manifest_in(&rtxn)?;
        for id in ids {
            if !self.is_ref_readable_with_policy_in(&rtxn, &policy, id)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Which of `sets` resolve whole for this lane, one answer for each set:
    /// each judged as [`Self::all_refs_readable`] judges its ids, every set
    /// in one snapshot under one policy, so a listing that admits its rows
    /// one by one admits them all at one instant (FIX 7645).
    pub fn refs_readable_each(&self, sets: &[Vec<EntityId>]) -> Result<Vec<bool>> {
        let rtxn = self.grant_read_txn()?;
        let policy = self.live_policy_manifest_in(&rtxn)?;
        let mut each = Vec::with_capacity(sets.len());
        for ids in sets {
            let mut readable = true;
            for id in ids {
                if !self.is_ref_readable_with_policy_in(&rtxn, &policy, id)? {
                    readable = false;
                    break;
                }
            }
            each.push(readable);
        }
        Ok(each)
    }

    /// [`Self::is_ref_readable`] in the caller's snapshot, under `policy`
    /// (`Self::live_policy_manifest_in`).
    pub(crate) fn is_ref_readable_with_policy_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
    ) -> Result<bool> {
        match self.is_entity_readable_with_policy_in(rtxn, policy, id) {
            Err(error) if error.kind() == crate::ErrorKind::InvalidSecretCustodyBody => Ok(false),
            readable => readable,
        }
    }

    pub(crate) fn is_entity_readable_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let policy = self.policy_manifest_in(rtxn)?;
        self.is_entity_readable_with_policy_in(rtxn, &policy, id)
    }

    pub(crate) fn is_entity_readable_with_policy_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
    ) -> Result<bool> {
        // A read by id matches no meaning, so it takes the row predicate
        // alone; the doors that find rows take the TURN rule as well
        // (`is_entity_retrievable_with_policy_in`).
        let filter = self.actor_retrieval_floor(policy)?;
        let authority = HeldAuthority::for_request(None);
        self.is_entity_readable_held_in(rtxn, policy, id, &filter, &authority)
    }

    /// The actor's own retrieval floor, with no request narrowing.
    pub(super) fn actor_retrieval_floor(
        &self,
        policy: &PolicyManifestResolution,
    ) -> Result<ResolvedRetrievalFilter> {
        Ok(crate::gate::narrow_retrieval_filter(
            &policy.retrieval_floor_for_actor(Some(&self.actor_key)),
            None,
        )?
        .under_credential_of(&self.actor_key))
    }

    pub(super) fn is_entity_readable_with_filter_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        filter: &ResolvedRetrievalFilter,
    ) -> Result<bool> {
        self.is_entity_readable_held_in(rtxn, policy, id, filter, &HeldAuthority::default())
    }

    /// [`Self::is_entity_readable_with_filter_in`] for one row of a batch
    /// read in `rtxn`, under the relationship authority the batch holds.
    pub(super) fn is_entity_readable_held_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        filter: &ResolvedRetrievalFilter,
        authority: &HeldAuthority<'v>,
    ) -> Result<bool> {
        let Some(raw) = self.entity_record_in(rtxn, id)?.map(|row| row.encode()) else {
            return Ok(false);
        };
        self.is_entity_raw_readable_held_in(rtxn, policy, id, &raw, filter, authority)
    }

    pub(super) fn is_entity_raw_readable_with_filter_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
    ) -> Result<bool> {
        self.is_entity_raw_readable_held_in(
            rtxn,
            policy,
            id,
            raw,
            filter,
            &HeldAuthority::default(),
        )
    }

    pub(super) fn is_entity_raw_readable_held_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
        authority: &HeldAuthority<'v>,
    ) -> Result<bool> {
        let asked = authority.grants().asked();
        let own = self.own_admission_in(rtxn, policy, id, raw, filter, authority, asked)?;
        if !own.admitted() {
            return Ok(false);
        }
        if self.derived_sources_readable_in(rtxn, policy, id, raw, authority)? {
            return Ok(true);
        }
        // FIX 7661: a row only the reader's own owner authority admitted
        // reads what it was written from as that same owner lane reads it,
        // in this snapshot, once today's check refused it. A refusal or a
        // failure there keeps today's answer.
        let OwnAdmission::ByOwner(lane) = own else {
            return Ok(false);
        };
        Ok(lane
            .derived_sources_readable_in(rtxn, policy, id, raw, authority)
            .unwrap_or_else(|error| {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "an owner lane read no sources it could not judge; the read keeps its own \
                     answer (FIX 7661)"
                );
                false
            }))
    }

    /// A summary, the reply copied from it and its merge header carry words
    /// from every record and MESSAGE the summary was written from, so this
    /// reader reads one only while it reads each of those, under the same
    /// policy and its own floor (ARCH-0006a); a request's narrowing applies
    /// to the row, not to what it was written from. Each source is judged by
    /// its own row admission; a body whose sources no longer resolve refuses.
    fn derived_sources_readable_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        authority: &HeldAuthority<'v>,
    ) -> Result<bool> {
        if self.actor_key.vault_owner_ref().is_some() {
            // The owner reads every source but a private thread's turn,
            // which meets his own cut there (FIX 6410).
            return self.private_threads_readable_in(rtxn, id, raw);
        }
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type == crate::registry::ENTITY_TYPE_ASSET_TEXT {
            return self.text_sources_readable_in(rtxn, policy, id, authority);
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_SUMMARY
            && let Some(admitted) = self.epoch_sources_readable_in(
                rtxn,
                policy,
                id,
                &raw[ENTITY_METADATA_HEADER_LEN..],
                authority,
            )?
        {
            return Ok(admitted);
        }
        let sources = match crate::scope_summary::word_sources_in(self.vault, rtxn, id, raw)? {
            crate::scope_summary::WordSources::Own => return Ok(true),
            crate::scope_summary::WordSources::Unresolved => return Ok(false),
            crate::scope_summary::WordSources::From(sources) => sources,
        };
        let floor = self.actor_retrieval_floor(policy)?;
        for source in &sources {
            let Some(raw) = self.entity_record_in(rtxn, source)?.map(|row| row.encode()) else {
                return Ok(false);
            };
            let floor_only = AskedFilter::Known(None);
            if !self.is_entity_raw_readable_own_in(
                rtxn,
                policy,
                source,
                &raw,
                &floor,
                authority,
                &floor_only,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// An epoch summary's sources are its `DerivedFrom` targets, through any
    /// nested epoch summary (agent-runtime-v1 §d7); `None` for any other
    /// SUMMARY body. A source that carries words of its own sources (a scope
    /// summary, a reply copying one, a merge header) keeps that conjunct.
    fn epoch_sources_readable_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        body: &[u8],
        authority: &HeldAuthority<'v>,
    ) -> Result<Option<bool>> {
        let floor = self.actor_retrieval_floor(policy)?;
        let admit = |source: &EntityId, row: &crate::ports::EntityRecord| {
            let raw = row.encode();
            let floor_only = AskedFilter::Known(None);
            if !self.is_entity_raw_readable_own_in(
                rtxn,
                policy,
                source,
                &raw,
                &floor,
                authority,
                &floor_only,
            )? {
                return Ok(false);
            }
            // The walk itself expands a nested epoch summary, in any form.
            if row.entity_type == crate::registry::ENTITY_TYPE_SUMMARY
                && match self.session_view {
                    Some(view) => crate::compaction::stored_epoch_in(view, rtxn, source, &row.body),
                    None => crate::compaction::stored_epoch_in(
                        &self.vault.store,
                        rtxn,
                        source,
                        &row.body,
                    ),
                }?
                .may_be()
            {
                return Ok(true);
            }
            self.derived_sources_readable_in(rtxn, policy, source, &raw, authority)
        };
        match self.session_view {
            Some(view) => crate::compaction::epoch_sources_admitted_in(view, rtxn, id, body, admit),
            None => crate::compaction::epoch_sources_admitted_in(
                &self.vault.store,
                rtxn,
                id,
                body,
                admit,
            ),
        }
    }

    /// Facet rule C: an ASSET_TEXT written from source ASSETs is read only
    /// beside every one of them, each judged by its own row admission under
    /// the same policy and this reader's floor. A text bound to no source
    /// reads by its own row alone. The sources are its current `DerivedFrom`
    /// targets, so the same check holds for any revision of it. The owner
    /// reads every text, as it reads every summary.
    pub(super) fn text_sources_readable_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        authority: &HeldAuthority<'v>,
    ) -> Result<bool> {
        if self.actor_key.vault_owner_ref().is_some() {
            return Ok(true);
        }
        let floor = self.actor_retrieval_floor(policy)?;
        let admit = |source: &EntityId, row: &crate::ports::EntityRecord| {
            let raw = row.encode();
            let floor_only = AskedFilter::Known(None);
            self.is_entity_raw_readable_own_in(
                rtxn,
                policy,
                source,
                &raw,
                &floor,
                authority,
                &floor_only,
            )
        };
        let admitted = match self.session_view {
            Some(view) => asset_text::sources_admitted_in(view, rtxn, id, admit),
            None => asset_text::sources_admitted_in(&self.vault.store, rtxn, id, admit),
        }?;
        Ok(admitted.unwrap_or(true))
    }

    /// The row's own admission, before what it was written from: today's
    /// (B), and only once B refuses, the same row under one of the reader's
    /// own live Grants (A, FIX 7462; `agent_grants`), and only once both
    /// refuse, on a lane opted into it, the same row under the reader's own
    /// live owner authority (FIX 7461; `owner_authority`). B's error is the
    /// read's; neither alternative fails or hides it. `asked` is what the
    /// read asked beyond its key's floor.
    #[expect(
        clippy::too_many_arguments,
        reason = "B else A over one row, its filter, held authority and request"
    )]
    fn is_entity_raw_readable_own_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
        authority: &HeldAuthority<'v>,
        asked: &AskedFilter,
    ) -> Result<bool> {
        Ok(self
            .own_admission_in(rtxn, policy, id, raw, filter, authority, asked)?
            .admitted())
    }

    /// [`Self::is_entity_raw_readable_own_in`], keeping which alternative
    /// admitted the row: one only the owner alternative admitted keeps the
    /// owner lane that did (FIX 7661).
    #[expect(
        clippy::too_many_arguments,
        reason = "B else A else the owner over one row, its filter, held authority and request"
    )]
    fn own_admission_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
        authority: &HeldAuthority<'v>,
        asked: &AskedFilter,
    ) -> Result<OwnAdmission<'v>> {
        if self.own_row_readable_in(rtxn, policy, id, raw, filter, authority, None)?
            || self.own_row_readable_by_grant_in(rtxn, policy, id, raw, filter, authority, asked)
        {
            return Ok(OwnAdmission::Admitted);
        }
        Ok(self
            .own_row_owner_lane_in(rtxn, policy, id, raw, filter, authority, asked)
            .map_or(OwnAdmission::Refused, |lane| {
                OwnAdmission::ByOwner(Box::new(lane))
            }))
    }

    /// The row's own admission under `grant`, one live Grant of the
    /// reader's own (FIX 7462): it stands in for the relationship checks
    /// and the positive CLAIM or record check, and every other check binds
    /// as before. `None` is today's admission, exactly.
    #[expect(
        clippy::too_many_arguments,
        reason = "one row's admission under its filter, held authority and an optional Grant"
    )]
    pub(super) fn own_row_readable_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
        authority: &HeldAuthority<'v>,
        grant: Option<&crate::federation::Scope>,
    ) -> Result<bool> {
        // A legal use limit keeps the bytes as storage only: no ordinary
        // reader sees the row, the owner included. A named read asks it on
        // its own, once every other gate admits the row (FIX 5226).
        let use_asked = authority.asks_use_of(id);
        if !use_asked
            && crate::store::legal_hold::use_limit_in_txn(&self.vault.store, rtxn, id)?.is_some()
        {
            return Ok(false);
        }
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if filter.deny_all
            || self
                .vault
                .store
                .validate_entity_type(header.entity_type)
                .is_err()
            || !filter.read_scope().bands.contains(&header.entity_type)
        {
            return Ok(false);
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
            return Err(crate::secret_custody::reject_secret_custody_byte());
        }
        // Grant bodies contain both private diary ids. They are authority,
        // never a readable graph/search result of their own.
        if header.entity_type == crate::registry::ENTITY_TYPE_ACCESS_GRANT
            && !crate::access_grant::decode_access_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])
                .is_ok_and(|grant| {
                    !matches!(
                        grant.scope,
                        crate::access_grant::AccessGrantScope::DiaryCoreference { .. }
                    )
                })
        {
            return Ok(false);
        }
        // A non-CLAIM body carries its own `stale: true` once withdrawn; a
        // CLAIM's staleness is judged by its claim read below. A recorded
        // source that no longer stands withdraws the row, the owner's too.
        let readable = match (self.session_view, use_asked) {
            (Some(view), false) => crate::ports::raw_readable_in_txn(view, rtxn, id, raw)?,
            (None, false) => crate::ports::raw_readable_in_txn(&self.vault.store, rtxn, id, raw)?,
            (Some(view), true) => {
                crate::ports::raw_readable_apart_from_use_in_txn(view, rtxn, id, raw)?
            }
            (None, true) => {
                crate::ports::raw_readable_apart_from_use_in_txn(&self.vault.store, rtxn, id, raw)?
            }
        };
        if !readable
            || self.vault.archive_tombstone_in_txn(rtxn, id)?.is_some()
            || (raw.len() == ENTITY_METADATA_HEADER_LEN
                && self
                    .vault
                    .store
                    .entity_deletion_present_in_txn(rtxn, id, header.learned_at)?)
        {
            return Ok(false);
        }
        if grant.is_none() && !self.relationship_raw_allowed_in(rtxn, id, raw, authority)? {
            return Ok(false);
        }
        if !self.audience_readable_raw_in(rtxn, id, raw, authority)? {
            return Ok(false);
        }
        if !self.credential_allows_row_in(rtxn, id)
            || !self.proof_live_in(rtxn)?
            || !self.guest_bound_admits_in(rtxn, id, raw)
            || !self.facets_allow_in(rtxn, id, raw)?
        {
            return Ok(false);
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE {
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            return self.note_readable_under_in(rtxn, id, body, policy, grant);
        }
        if header.entity_type == ENTITY_TYPE_CLAIM {
            self.is_claim_raw_readable_with_policy_in(
                rtxn, policy, id, raw, filter, authority, grant,
            )
        } else if self.actor_key.vault_owner_ref().is_some() {
            // The owner's ceiling is all of the owner's vault, stamped or not.
            Ok(true)
        } else {
            let scope = match self.session_view {
                Some(view) => {
                    crate::federation::record_scope::scope_for_blob(view, rtxn, *id, raw)?
                }
                None => crate::federation::record_scope::scope_for_blob(
                    &self.vault.store,
                    rtxn,
                    *id,
                    raw,
                )?,
            };
            let Some(scope) = scope else {
                return Ok(false);
            };
            Ok(match grant {
                None => crate::gate::scoped_read_record_allowed(policy, &self.actor_key, &scope),
                Some(grant) => crate::gate::scoped_read_record_allowed_with_scope(
                    policy,
                    &self.actor_key,
                    &scope,
                    Some(grant),
                ),
            })
        }
    }

    /// Whether `viewers` read the revision `raw` when it is a private
    /// thread's notice (FIX 6473; CALLS `FIX 6473 private-thread notice
    /// readers`): only its recipient, and a reader of the thread whose root
    /// it names under the CURRENT rule a root is read by (FIX 5545), in its
    /// audience now and still in the room or the vault's Owner or an Admin.
    /// The notice names the thread, who acted and what happened, so no broad
    /// credential reads it, the owner's included. Every other row, every
    /// other notice included, is `true` here.
    pub(super) fn thread_notice_readable_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        raw: &[u8],
        viewers: &[EntityId],
    ) -> Result<bool> {
        if EntityMetadataHeader::parse(raw).map(|header| header.entity_type)
            != Some(crate::registry::ENTITY_TYPE_NOTIFICATION)
        {
            return Ok(true);
        }
        let body = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        let Ok(notice) = crate::inbox::decode_notification_body(body) else {
            return Ok(true);
        };
        if notice.source.producer != crate::workspace_roster::THREAD_NOTICE_PRODUCER {
            return Ok(true);
        }
        let id = |text: Option<&str>| text.and_then(|text| EntityId::from_hex(text).ok());
        let recipient = id(notice.recipient.as_deref());
        if !viewers.is_empty() && viewers.iter().all(|viewer| Some(*viewer) == recipient) {
            return Ok(true);
        }
        let Some(root) = id(notice.source.result.as_deref()) else {
            return Ok(false);
        };
        crate::workspace_roster::thread_root_readable_with_read_in(
            self.vault,
            &self.store_read(),
            rtxn,
            root,
            viewers,
        )
    }

    pub(crate) fn is_claim_raw_readable_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        let (filter, policy) = self.resolve_retrieval_filter_in(rtxn, None)?;
        let authority = HeldAuthority::for_request(None);
        self.is_entity_raw_readable_held_in(rtxn, &policy, id, raw, &filter, &authority)
    }

    pub(crate) fn policy_manifest_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<PolicyManifestResolution> {
        crate::gate::resolve_policy_manifest(&self.vault.store, rtxn)
    }

    /// The policy in `rtxn` for a door that opens its own snapshot and judges
    /// rows under it, with an owner lane's standing rechecked in that
    /// snapshot, as every point read does: a lane kept past its owner's
    /// revocation refuses.
    pub(crate) fn live_policy_manifest_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<PolicyManifestResolution> {
        self.owner_live_in(rtxn)?;
        self.policy_manifest_in(rtxn)
    }
}

/// ONE-1608 / ARCH-0050 R6 L2: the L2 pull ranks over an ACTOR-SCOPED walk,
/// so `crate::ppr` asks this lane whether a node may carry PPR mass at all.
///
/// The predicate is exactly the retrieval predicate the result-filtering doors
/// apply, under the actor's floor, so a scoped walk can neither widen nor
/// narrow what this lane already admits: a CLAIM is traversable exactly when
/// this actor could read it, a TURN only when it may read each of its
/// messages, and an entity kind that carries no CLAIM clamp stays visible
/// exactly as everywhere else. The authority is resolved in the caller's
/// snapshot, never cached across reads.
///
/// IN THE CALLER'S TRANSACTION, deliberately: the walk hands over the `RoTxn`
/// it is already reading from, matching
/// [`ScopedRead::filter_scored_entities`] and
/// [`ScopedRead::filter_context_pack`]. That is why this is not
/// `get_entity_parts_with_receipt`, which opens a transaction of its own.
impl crate::ppr::PprNodeVisibility for ScopedRead<'_> {
    fn ppr_node_visible(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        let policy = self.policy_manifest_in(txn)?;
        let filter = self.actor_retrieval_floor(&policy)?;
        self.is_entity_retrievable_with_policy_in(txn, &policy, &filter, id)
    }
}
