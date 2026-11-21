//! Hub sync with an injectable dependency advisory query.

use super::*;

impl Vault {
    #[expect(
        clippy::too_many_arguments,
        reason = "typed hub update plus an injectable dependency advisory transport"
    )]
    pub(in crate::skill_hub) fn sync_skill_from_hub_with_query(
        &self,
        entity: &EntityId,
        hub_ref: &HubRef,
        package: &HubPackage,
        sync_policy: HubSyncPolicy,
        occurred: TimeRange,
        learned_at: u64,
        query: &dyn super::super::osv::OsvQuery,
    ) -> Result<HubSyncDisposition> {
        hub_ref.validate()?;
        encode_skill_record(&package.record)?;
        let content_hash = package.content_hash()?;
        let inventory = super::super::osv::dependency_inventory(package)?;
        let (_, _, scans) =
            self.dependency_advisories(content_hash, &inventory, query, learned_at)?;
        let mut wtxn = self.store.env.write_txn()?;
        let current = self.read_skill_record_in_txn(&wtxn, entity)?;
        validate_sync_package(&current, package, hub_ref, content_hash, sync_policy)?;
        if !sync_policy.allows_automatic_update() {
            return Ok(HubSyncDisposition::RefusedByPolicy);
        }

        let provenance_rows =
            self.active_claims_for_predicate_in_txn(&wtxn, entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
        // Legacy direct imports remain permissive until vault-bound authority lands in ONE-1751.
        if !provenance_rows.is_empty() {
            let mut matches_provenance_alias = false;
            for (_, body, _) in &provenance_rows {
                let stored_ref = HubRef::from_value(map_value(&body.value, "hubRef").ok_or(
                    Error::Artifact(ArtifactError::InvalidSkillBody(
                        "hub provenance claim is missing hubRef",
                    )),
                )?)?;
                if same_hub_ref(&stored_ref, hub_ref) {
                    matches_provenance_alias = true;
                    break;
                }
            }
            if !matches_provenance_alias {
                return Ok(HubSyncDisposition::RefusedByPolicy);
            }
        }

        let admitted = self
            .read_admitted_capability_surface_in_txn(&wtxn, entity)?
            .unwrap_or_default();
        let mut proposed_record = package.record.clone();
        proposed_record.content_hash = Some(content_hash);
        let requires_held_out = current.lifecycle_status == SkillLifecycle::Active
            && crate::skill_optimize::skill_body_binding_digest(&current)?
                != crate::skill_optimize::skill_body_binding_digest(&proposed_record)?;
        let widens = !package.capabilities.is_same_or_narrower_than(&admitted);
        let hash_held_elsewhere = current.content_hash != Some(content_hash)
            && self
                .skill_entity_for_content_hash_in_txn(&wtxn, content_hash)?
                .is_some_and(|holder| holder != *entity);
        let hub_value = hub_ref.to_value()?;
        let hash_hex = content_hash.to_hex();
        let encoded_caps = encode_capability_surface_value(&package.capabilities);
        if !widens && !hash_held_elsewhere {
            // A changed Active body lands in a savepoint and stays only when
            // the update's own admission passes in it; otherwise the live
            // bytes stay and the update is proposed below.
            let mut savepoint = self.store.env.nested_write_txn(&mut wtxn)?;
            let passed = self.apply_hub_sync_in_txn(
                &mut savepoint,
                entity,
                &current,
                hub_ref,
                package,
                content_hash,
                &scans,
                occurred,
                learned_at,
                None,
            )?;
            if passed || !requires_held_out {
                savepoint.commit()?;
                for (proposal_id, mut body, proposal_start) in self
                    .active_claims_for_predicate_in_txn(
                        &wtxn,
                        entity,
                        PREDICATE_SKILL_HUB_UPDATE_PROPOSAL,
                    )?
                {
                    if body.approval != ClaimApprovalStatus::Proposed
                        || map_value(&body.value, "hubRef") != Some(&hub_value)
                        || map_text(&body.value, "contentHash") != Some(hash_hex.as_str())
                        || map_text(&body.value, "version") != Some(package.record.version.as_str())
                        || map_value(&body.value, "capabilities") != Some(&encoded_caps)
                    {
                        continue;
                    }
                    let original = crate::ports::EntityStoreRead::port_entity_record(
                        &self.store,
                        &wtxn,
                        &proposal_id,
                    )?
                    .ok_or(Error::EntityNotFound)?;
                    let closed_at = learned_at.max(proposal_start);
                    // The update request is moot, not an approval or held-out verdict.
                    body.lifecycle = ClaimLifecycleStatus::Retracted;
                    body.valid_to = Some(closed_at);
                    self.put_reserved_claim_in_txn(
                        &mut wtxn,
                        &proposal_id,
                        &body,
                        TimeRange {
                            start: proposal_start,
                            end: closed_at,
                        },
                        original.learned_at,
                    )?;
                }
                wtxn.commit()?;
                return Ok(HubSyncDisposition::Applied);
            }
        } else if !widens && !requires_held_out {
            return Ok(HubSyncDisposition::RefusedByPolicy);
        }
        for (proposal_id, body, _) in self.active_claims_for_predicate_in_txn(
            &wtxn,
            entity,
            PREDICATE_SKILL_HUB_UPDATE_PROPOSAL,
        )? {
            if map_value(&body.value, "hubRef") == Some(&hub_value)
                && map_text(&body.value, "contentHash") == Some(hash_hex.as_str())
                && map_text(&body.value, "version") == Some(package.record.version.as_str())
                && map_value(&body.value, "capabilities") == Some(&encoded_caps)
                && map_value(&body.value, "requiresHeldOut")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    == requires_held_out
            {
                return Ok(HubSyncDisposition::Proposed {
                    proposal_id,
                    approval: ClaimApprovalStatus::Proposed,
                });
            }
        }

        let proposal_id = self.store.clock.entity_id()?;
        let mut proposal = ClaimBody::new(
            PREDICATE_SKILL_HUB_UPDATE_PROPOSAL,
            ClaimSubject::Entity(*entity),
            Value::Map(vec![
                (Value::from("hubRef"), hub_value),
                (
                    Value::from("version"),
                    Value::from(package.record.version.as_str()),
                ),
                (Value::from("contentHash"), Value::from(hash_hex)),
                (Value::from("capabilities"), encoded_caps),
                (
                    Value::from("requiresHeldOut"),
                    Value::Boolean(requires_held_out),
                ),
            ]),
            1.0,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        )?;
        proposal.source = Some(ClaimSource::Imported);
        proposal.scope_facet = self.default_facet_in_txn(&wtxn)?;
        self.put_reserved_claim_in_txn(&mut wtxn, &proposal_id, &proposal, occurred, learned_at)?;
        wtxn.commit()?;
        Ok(HubSyncDisposition::Proposed {
            proposal_id,
            approval: ClaimApprovalStatus::Proposed,
        })
    }
}
