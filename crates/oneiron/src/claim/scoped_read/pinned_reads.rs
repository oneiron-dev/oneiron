//! Manifest-derived safety pins bypass query relevance, never actor authority.
use super::{ScopedRead, ScopedReadResult};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::decode_claim_body;
use crate::ports::ShortIdStoreRead;
use crate::{Error, Result};

impl ScopedRead<'_> {
    /// Current engine-issued refs for live claims in declared critical classes.
    /// Policy, row admission and reference binding share one read snapshot,
    /// and every pinned posting is judged, however many (FIX 8659).
    pub fn manifest_pinned_refs(&self) -> Result<ScopedReadResult<Vec<String>>> {
        let txn = self.grant_read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
        let mut value = Vec::new();
        // One relationship authority for every pinned row (FIX 11648),
        // held under the key's own floor and then each of its own live
        // Grants alone, as its point reads (FIX-LIST
        // SCOPED-READ-UNKNOWN-AUTHORITY-CALLERS).
        let held = self.held_for(None);
        crate::claim::projection_index::for_each_pinned_claim_id_in_txn(
            &self.vault.store,
            &txn,
            &policy,
            |id| {
                let Some(raw) = self.entity_record_in(&txn, &id)?.map(|row| row.encode()) else {
                    return Ok(());
                };
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("pin entity header"))?;
                if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                    || raw.len() == ENTITY_METADATA_HEADER_LEN
                {
                    return Ok(());
                }
                let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
                if !policy.pins_predicate(&body.predicate) {
                    return Ok(());
                }
                // No requested filter: a pin neither this key's floor nor one
                // of its live Grants admits stays opaque.
                if !self.is_entity_retrievable_held_in(&txn, &policy, &filter, &id, &held)? {
                    return Ok(());
                }
                let Some((short_id, hash)) = self.vault.store.port_short_id_reference(&txn, &id)?
                else {
                    return Ok(());
                };
                value.push(format!("{short_id}:{hash:02x}"));
                Ok(())
            },
        )?;
        Ok(ScopedReadResult {
            value,
            receipt: self.receipt_in(&txn, None, &policy, &filter, 0, Some(&held)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EntityId;
    use crate::claim::{ClaimBody, ClaimSource, ClaimSubject, ScopedReadActorKey};
    #[test]
    fn manifest_critical_claims_are_pinned_without_query_selection() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let subject = EntityId::now();
        let id = EntityId::now();
        let when = crate::TimeRange { start: 1, end: 1 };
        vault.put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            when,
            1,
            b"person",
        )?;
        let mut claim = ClaimBody::new(
            "profile.name",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("stored safety fact"),
            1.0,
            crate::ClaimApprovalStatus::Auto,
            crate::ClaimLifecycleStatus::Active,
        )?;
        claim.source = Some(ClaimSource::UserStated);
        vault.put_claim(&id, &claim, when, 1)?;
        let reader = vault.scoped_read(ScopedReadActorKey::new("pin-reader").unwrap());
        assert!(reader.manifest_pinned_refs()?.value.is_empty());
        // A rule declaring the `profile.` class critical replaces the normal
        // one: the declared class now classifies this existing approved row
        // without rewriting its bytes.
        let mut policy = policy_replacing_profile_rule(critical_rule("profile.", false))?;
        put_policy(&vault, &policy)?;
        // A targeted pin lookup must not decode unrelated entity rows. This
        // malformed legacy row is outside every claim posting list.
        let unrelated = EntityId::now();
        {
            let mut txn = vault.store.env.write_txn()?;
            vault
                .store
                .entities
                .put(&mut txn, unrelated.as_bytes(), b"bad")?;
            txn.commit()?;
        }
        let pins = reader.manifest_pinned_refs()?;
        assert_eq!(pins.value.len(), 1);
        assert_eq!(pins.receipt.suppressed_count, 0);
        let mut section = crate::context_board::project_memories_section(
            &vault.context_pack().run()?,
            crate::MemoriesBudget::default().with_shared_total(0),
            None,
            None,
        );
        section.include_pinned_refs(&reader, &pins.value)?;
        assert_eq!(section.rows.len(), 1);
        assert_eq!(section.rows[0].id, id.to_hex());
        assert_eq!(
            section.rows[0].tier,
            crate::context_board::MemoryTier::Pinned
        );

        // Pinning bypasses relevance only: a manifest ceiling that excludes
        // CLAIM still suppresses the same stored critical row, with a receipt.
        let rmpv::Value::Map(fields) = &mut policy else {
            unreachable!()
        };
        fields.retain(|(key, _)| key.as_str() != Some("scoped_grants"));
        fields.push((
            rmpv::Value::from("scoped_grants"),
            rmpv::Value::Array(vec![pin_reader_grant(Some(rmpv::Value::Map(vec![(
                rmpv::Value::from("entity_types"),
                rmpv::Value::Array(vec![rmpv::Value::from(crate::registry::ENTITY_TYPE_PERSON)]),
            )])))?]),
        ));
        put_policy(&vault, &policy)?;
        let hidden = reader.manifest_pinned_refs()?;
        assert!(hidden.value.is_empty());
        assert_eq!(hidden.receipt.suppressed_count, 1);
        assert!(!hidden.receipt.narrowed_axes.is_empty());
        vault.batch().delete(&id).commit()?;
        let deleted = reader.manifest_pinned_refs()?;
        assert!(deleted.value.is_empty());
        assert_eq!(deleted.receipt.suppressed_count, 0);
        Ok(())
    }

    /// A pack's default criticality is a legibility floor and never pins;
    /// only a rule that declares a class critical does (Engine N31A = A).
    /// Both facts are stored under the shipped normal `profile.` rule. The
    /// policy then declares `profile.name` critical and names no rule for
    /// `profile.nickname`, which falls to the pack's critical default.
    #[test]
    fn a_predicate_no_rule_names_is_not_pinned_by_the_pack_default() -> Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let subject = EntityId::now();
        let when = crate::TimeRange { start: 1, end: 1 };
        vault.put_entity(
            &subject,
            crate::registry::ENTITY_TYPE_PERSON,
            when,
            1,
            b"person",
        )?;
        let put_fact = |predicate: &str, value: &str| -> Result<EntityId> {
            let id = EntityId::now();
            let mut claim = ClaimBody::new(
                predicate,
                ClaimSubject::Entity(subject),
                rmpv::Value::from(value),
                1.0,
                crate::ClaimApprovalStatus::Auto,
                crate::ClaimLifecycleStatus::Active,
            )?;
            claim.source = Some(ClaimSource::UserStated);
            vault.put_claim(&id, &claim, when, 1)?;
            Ok(id)
        };
        let declared = put_fact("profile.name", "declared critical fact")?;
        let defaulted = put_fact("profile.nickname", "default critical fact")?;
        put_policy(
            &vault,
            &policy_replacing_profile_rule(critical_rule("profile.name", true))?,
        )?;
        let reference = |id: &EntityId| -> Result<String> {
            let txn = vault.store.env.read_txn()?;
            let (short_id, hash) =
                crate::ports::ShortIdStoreRead::port_short_id_reference(&vault.store, &txn, id)?
                    .unwrap();
            Ok(format!("{short_id}:{hash:02x}"))
        };
        let pins = vault
            .scoped_read(ScopedReadActorKey::new("pin-reader").unwrap())
            .manifest_pinned_refs()?
            .value;
        assert!(
            pins.contains(&reference(&declared)?),
            "a declared critical class pins: {pins:?}"
        );
        assert!(
            !pins.contains(&reference(&defaulted)?),
            "the pack's critical default never pins: {pins:?}"
        );
        Ok(())
    }

    /// The pin reader's read grant, narrowed by `selectors` when given.
    fn pin_reader_grant(selectors: Option<rmpv::Value>) -> Result<rmpv::Value> {
        let mut grant = vec![
            (
                rmpv::Value::from("actor_ref"),
                rmpv::Value::from("pin-reader"),
            ),
            (
                rmpv::Value::from("effector"),
                rmpv::Value::from("core:read"),
            ),
            (
                rmpv::Value::from("scope"),
                crate::federation::scope_codec::encode_scope_value(
                    &crate::federation::scope_codec::read_preset(),
                )?,
            ),
            (
                rmpv::Value::from("receipt_required"),
                rmpv::Value::Boolean(false),
            ),
        ];
        grant.extend(selectors.map(|selectors| (rmpv::Value::from("selectors"), selectors)));
        Ok(rmpv::Value::Map(grant))
    }

    /// A manifest rule declaring `prefix`'s class critical, shaped as the
    /// shipped critical class rules are.
    fn critical_rule(prefix: &str, exact: bool) -> rmpv::Value {
        let mut rule = vec![(rmpv::Value::from("prefix"), rmpv::Value::from(prefix))];
        if exact {
            rule.push((rmpv::Value::from("exact"), rmpv::Value::Boolean(true)));
        }
        rule.push((
            rmpv::Value::from("axes"),
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("criticality"),
                    rmpv::Value::from("critical"),
                ),
                (
                    rmpv::Value::from("sensitivity"),
                    rmpv::Value::from("normal"),
                ),
            ]),
        ));
        rmpv::Value::Map(rule)
    }

    /// The shipped manifest with its normal `profile.` rule replaced by
    /// `rule`, granting the pin reader its read. Seeded skill-hub claims keep
    /// their own normal rows.
    fn policy_replacing_profile_rule(rule: rmpv::Value) -> Result<rmpv::Value> {
        let mut policy = rmpv::decode::read_value(&mut std::io::Cursor::new(
            crate::gate::default_policy_manifest()?,
        ))
        .unwrap();
        let rmpv::Value::Map(fields) = &mut policy else {
            unreachable!()
        };
        let rules = fields
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("rules"))
            .unwrap();
        let rmpv::Value::Array(rows) = &mut rules.1 else {
            unreachable!()
        };
        rows.retain(|row| {
            row.as_map().is_none_or(|entries| {
                !entries.iter().any(|(key, value)| {
                    key.as_str() == Some("prefix") && value.as_str() == Some("profile.")
                })
            })
        });
        rows.push(rule);
        fields.retain(|(key, _)| key.as_str() != Some("scoped_grants"));
        fields.push((
            rmpv::Value::from("scoped_grants"),
            rmpv::Value::Array(vec![pin_reader_grant(None)?]),
        ));
        Ok(policy)
    }

    fn put_policy(vault: &crate::Vault, policy: &rmpv::Value) -> Result<()> {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, policy).unwrap();
        crate::test_util::put_policy_manifest_bytes(
            vault,
            crate::gate::default_policy_manifest_id()?,
            &bytes,
        )
    }
}
