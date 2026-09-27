use super::*;

impl ScopedRead<'_> {
    pub fn is_entity_readable(&self, id: &EntityId) -> Result<bool> {
        let rtxn = self.grant_read_txn()?;
        self.is_entity_readable_in(&rtxn, id)
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
        let filter = crate::gate::narrow_retrieval_filter(
            &policy.retrieval_floor_for_actor(Some(&self.actor_key)),
            None,
        )?;
        self.is_entity_retrievable_with_policy_in(rtxn, policy, &filter, id)
    }

    pub(super) fn is_entity_readable_with_filter_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        filter: &ResolvedRetrievalFilter,
    ) -> Result<bool> {
        let Some(raw) = self.entity_record_in(rtxn, id)?.map(|row| row.encode()) else {
            return Ok(false);
        };
        self.is_entity_raw_readable_with_filter_in(rtxn, policy, id, &raw, filter)
    }

    pub(super) fn is_entity_raw_readable_with_filter_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        id: &EntityId,
        raw: &[u8],
        filter: &ResolvedRetrievalFilter,
    ) -> Result<bool> {
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if filter.deny_all
            || self
                .vault
                .store
                .validate_entity_type(header.entity_type)
                .is_err()
            || filter
                .entity_types
                .as_ref()
                .is_some_and(|types| !types.contains(&header.entity_type))
        {
            return Ok(false);
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY {
            return Err(crate::secret_custody::reject_secret_custody_byte());
        }
        let deletion = match self.session_view {
            Some(view) => crate::ports::TombstoneStoreRead::port_deletion_state(view, rtxn, id)?,
            None => crate::ports::TombstoneStoreRead::port_deletion_state(self.vault, rtxn, id)?,
        };
        if deletion.deleted
            || deletion.stale
            || self.vault.archive_tombstone_in_txn(rtxn, id)?.is_some()
            || (raw.len() == ENTITY_METADATA_HEADER_LEN
                && self
                    .vault
                    .store
                    .entity_deletion_present_in_txn(rtxn, id, header.learned_at)?)
        {
            return Ok(false);
        }
        if !self.relationship_raw_allowed_in(rtxn, id, raw)? {
            return Ok(false);
        }
        if !self.audience_readable_in(rtxn, id)? {
            return Ok(false);
        }
        if !self.credential_allows_id(id) || !self.proof_live_in(rtxn)? {
            return Ok(false);
        }
        if header.entity_type == crate::registry::ENTITY_TYPE_NOTE {
            return self.note_readable_in(rtxn, id, &raw[ENTITY_METADATA_HEADER_LEN..]);
        }
        if header.entity_type == ENTITY_TYPE_CLAIM {
            self.is_claim_raw_readable_with_policy_in(rtxn, policy, id, raw, filter)
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

    fn is_claim_raw_readable_with_policy_in(
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
        let admitted = crate::pipeline::retrieval_claim_allowed(filter, body);
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

    pub(crate) fn policy_manifest_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<PolicyManifestResolution> {
        crate::gate::resolve_policy_manifest(&self.vault.store, rtxn)
    }
}

/// ONE-1608 / ARCH-0050 R6 L2: the L2 pull ranks over an ACTOR-SCOPED walk,
/// so `crate::ppr` asks this lane whether a node may carry PPR mass at all.
///
/// The predicate is exactly [`ScopedRead::is_entity_readable_with_policy_in`],
/// the same admission the result-filtering doors above apply, so a scoped walk
/// can neither widen nor narrow what this lane already admits: a CLAIM is
/// traversable exactly when this actor could read it, and an entity kind that
/// carries no CLAIM clamp stays visible exactly as everywhere else. The
/// authority is resolved in the caller's snapshot, never cached across reads.
///
/// IN THE CALLER'S TRANSACTION, deliberately: the walk hands over the `RoTxn`
/// it is already reading from, matching
/// [`ScopedRead::filter_scored_entities`] and
/// [`ScopedRead::filter_context_pack`]. That is why this is not
/// `get_entity_parts_with_receipt`, which opens a transaction of its own.
impl crate::ppr::PprNodeVisibility for ScopedRead<'_> {
    fn ppr_node_visible(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        let policy = self.policy_manifest_in(txn)?;
        self.is_entity_readable_with_policy_in(txn, &policy, id)
    }
}
