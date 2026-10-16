use super::access_gate::HeldAuthority;
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
        self.is_entity_readable_with_filter_in(rtxn, policy, id, &filter)
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

    fn is_entity_raw_readable_held_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
        authority: &HeldAuthority<'v>,
    ) -> Result<bool> {
        Ok(
            self.is_entity_raw_readable_own_in(rtxn, policy, id, raw, filter, authority)?
                && self.derived_sources_readable_in(rtxn, policy, id, raw, authority)?,
        )
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
            return Ok(true);
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
            if !self.is_entity_raw_readable_own_in(rtxn, policy, source, &raw, &floor, authority)? {
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
            if !self.is_entity_raw_readable_own_in(rtxn, policy, source, &raw, &floor, authority)? {
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
            self.is_entity_raw_readable_own_in(rtxn, policy, source, &raw, &floor, authority)
        };
        let admitted = match self.session_view {
            Some(view) => asset_text::sources_admitted_in(view, rtxn, id, admit),
            None => asset_text::sources_admitted_in(&self.vault.store, rtxn, id, admit),
        }?;
        Ok(admitted.unwrap_or(true))
    }

    /// The row's own admission, before what it was written from.
    fn is_entity_raw_readable_own_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
        authority: &HeldAuthority<'v>,
    ) -> Result<bool> {
        // A legal use limit keeps the bytes as storage only: no ordinary
        // reader sees the row, the owner included.
        if crate::store::legal_hold::use_limit_in_txn(&self.vault.store, rtxn, id)?.is_some() {
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
        let deletion = match self.session_view {
            Some(view) => crate::ports::TombstoneStoreRead::port_deletion_state(view, rtxn, id)?,
            None => crate::ports::TombstoneStoreRead::port_deletion_state(self.vault, rtxn, id)?,
        };
        // A non-CLAIM body carries its own `stale: true` once withdrawn; a
        // CLAIM's staleness is judged by its claim read below.
        if deletion.deleted
            || deletion.stale
            || (header.entity_type != ENTITY_TYPE_CLAIM
                && crate::ports::body_is_stale(&raw[ENTITY_METADATA_HEADER_LEN..]))
            || self.vault.archive_tombstone_in_txn(rtxn, id)?.is_some()
            || (raw.len() == ENTITY_METADATA_HEADER_LEN
                && self
                    .vault
                    .store
                    .entity_deletion_present_in_txn(rtxn, id, header.learned_at)?)
        {
            return Ok(false);
        }
        if !self.relationship_raw_allowed_in(rtxn, id, raw, authority)? {
            return Ok(false);
        }
        if !self.audience_readable_raw_in(rtxn, id, raw)? {
            return Ok(false);
        }
        if !self.credential_allows_id(id)
            || !self.proof_live_in(rtxn)?
            || !self.facets_allow_in(rtxn, id, raw)?
        {
            return Ok(false);
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE {
            return self.note_readable_in(rtxn, id, &raw[ENTITY_METADATA_HEADER_LEN..], policy);
        }
        if header.entity_type == ENTITY_TYPE_CLAIM {
            self.is_claim_raw_readable_with_policy_in(rtxn, policy, id, raw, filter)
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
            Ok(crate::gate::scoped_read_record_allowed(
                policy,
                &self.actor_key,
                &scope,
            ))
        }
    }

    pub(crate) fn is_claim_raw_readable_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        let (filter, policy) = self.resolve_retrieval_filter_in(rtxn, None)?;
        self.is_entity_raw_readable_with_filter_in(rtxn, &policy, id, raw, &filter)
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
