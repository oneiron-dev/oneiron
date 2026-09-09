//! Binding freshness after authorized replacements and unbound writes.

use super::*;

fn closing_op(vault: &Vault, id: EntityId) -> Result<BatchOp> {
    let raw = vault.get_raw(&id)?.expect("current claim");
    let header = EntityMetadataHeader::parse(&raw).expect("header");
    let mut body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
    body.lifecycle = ClaimLifecycleStatus::Retracted;
    body.valid_to = Some(30);
    Ok(BatchOp::Put {
        id,
        entity_type: crate::registry::ENTITY_TYPE_CLAIM,
        occurred: TimeRange {
            start: header.occurred_start,
            end: 30,
        },
        learned_at: header.learned_at,
        data: encode_claim_body(&body)?,
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    })
}

fn current_binding(vault: &Vault, id: EntityId) -> Result<Option<Vec<u8>>> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .get(&txn, &authored_key(&id))?
        .map(|bytes| bytes.to_vec()))
}

fn assert_finalized_binding(vault: &Vault, id: EntityId) -> Result<()> {
    let raw = vault.get_raw(&id)?.expect("stored claim");
    assert_eq!(current_binding(vault, id)?, Some(row_digest(&raw).to_vec()));
    Ok(())
}

#[test]
fn authorized_replacement_refreshes_actor_source_lineage_and_rejects_old_operation() -> Result<()> {
    let (_dir, vault, first_actor) = fixture()?;
    let id = entity(0x64);
    candidate(&vault, first_actor, id)?;
    let old_op = closing_op(&vault, id)?;
    let old_binding = {
        let txn = vault.store.env.read_txn()?;
        ClaimMaterialization::lifecycle(&vault.store, &txn, &old_op)?.expect("first binding")
    };
    let old_digest = current_binding(&vault, id)?;
    let next_actor = WriteActor::new(entity(0x63), EdgeActorClass::Human);
    permit(
        &vault,
        next_actor.entity_ref(),
        &[ClaimSource::Imported, ClaimSource::ToolOutput],
    )?;
    let next_envelope = WriteEnvelope::with_lineage(
        next_actor,
        ClaimSource::Imported,
        WriteProvenance::new(Value::from("replacement host operation"))?,
        ClaimApprovalStatus::Auto,
        SourceLineage::of(ClaimSource::Imported).with(ClaimSource::ToolOutput),
    );
    let next_candidate = ClaimCandidate::new(
        "test.replacement",
        ClaimSubject::Entity(entity(0x62)),
        Value::from("new fact"),
        0.9,
    )
    .with_evidence(Value::from("new evidence"))
    .with_stale(true);
    vault
        .batch()
        .claim_candidate(
            &id,
            next_candidate,
            &next_envelope,
            TimeRange { start: 11, end: 99 },
            12,
        )
        .commit()?;
    assert_ne!(current_binding(&vault, id)?, old_digest);
    assert_finalized_binding(&vault, id)?;
    let next_raw = vault.get_raw(&id)?.expect("replacement");
    let current = vault.get_claim(&id)?.expect("replacement");
    {
        let txn = vault.store.env.read_txn()?;
        let envelope = lifecycle_envelope(&vault.store, &txn, &id, &current)?.expect("new binding");
        assert_eq!(envelope.actor(), next_actor);
        assert_eq!(envelope.source(), ClaimSource::Imported);
        assert_eq!(envelope.lineage(), next_envelope.lineage());
        assert_eq!(envelope.provenance(), next_envelope.provenance());
    }
    let error = vault
        .with_write_txn(|txn| {
            apply_owner_bound_claim_puts(&vault, txn, vec![old_op], vec![old_binding], false)
        })
        .expect_err("an old operation cannot close the replacement");
    assert!(matches!(error, Error::InvalidClaimBody(_)));
    assert_eq!(vault.get_raw(&id)?.expect("unchanged"), next_raw);
    vault.retract_claim(&id, 30)?;
    assert_eq!(
        vault.get_claim(&id)?.expect("closed").lifecycle,
        ClaimLifecycleStatus::Retracted
    );
    assert_finalized_binding(&vault, id)?;
    Ok(())
}

#[test]
fn raw_replacement_rejects_copied_evidence_and_cannot_reuse_a_sealed_operation() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    // Even UserStated claims require an envelope at the raw-claim door.
    // Copying a host-authored row's evidence cannot supply that authority.
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("original write"))?,
        ClaimApprovalStatus::Auto,
    );
    vault
        .batch()
        .claim_candidate(
            &id,
            ClaimCandidate::new(
                "test.materialization",
                ClaimSubject::Entity(entity(0x62)),
                Value::from("fact"),
                1.0,
            ),
            &envelope,
            TimeRange { start: 10, end: 99 },
            10,
        )
        .commit()?;
    let op = closing_op(&vault, id)?;
    let binding = {
        let txn = vault.store.env.read_txn()?;
        ClaimMaterialization::lifecycle(&vault.store, &txn, &op)?.expect("sealed before raw write")
    };
    let raw = vault.get_raw(&id)?.expect("authored row");
    let before_binding = current_binding(&vault, id)?;
    let error = vault
        .batch()
        .put(
            &id,
            crate::registry::ENTITY_TYPE_CLAIM,
            TimeRange { start: 10, end: 99 },
            10,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )
        .commit()
        .expect_err("copied evidence cannot authorize a raw claim put");
    assert!(matches!(error, Error::InvalidClaimBody(_)));
    assert_eq!(vault.get_raw(&id)?.expect("original remains"), raw);
    // Preserve the original seal for the actor-only replacement below.
    assert_eq!(current_binding(&vault, id)?, before_binding);
    {
        let txn = vault.store.env.read_txn()?;
        let current_binding = ClaimMaterialization::lifecycle(&vault.store, &txn, &op)?
            .expect("original authority remains");
        assert!(current_binding.matches_op(&op));
        assert_eq!(current_binding.envelope().actor(), actor);
    }

    // The denied raw write did not stale the seal. Replace through the
    // authorized door with a distinct actor before testing stale authority.
    let next_actor = WriteActor::new(entity(0x63), EdgeActorClass::Human);
    let next_envelope = WriteEnvelope::new(
        next_actor,
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("original write"))?,
        ClaimApprovalStatus::Auto,
    );
    vault
        .batch()
        .claim_candidate(
            &id,
            ClaimCandidate::new(
                "test.materialization",
                ClaimSubject::Entity(entity(0x62)),
                Value::from("fact"),
                1.0,
            ),
            &next_envelope,
            TimeRange { start: 10, end: 99 },
            10,
        )
        .commit()?;
    let next_raw = vault.get_raw(&id)?.expect("authorized replacement");
    assert_ne!(next_raw, raw);
    {
        let next_op = closing_op(&vault, id)?;
        let txn = vault.store.env.read_txn()?;
        let current_binding = ClaimMaterialization::lifecycle(&vault.store, &txn, &next_op)?
            .expect("replacement authority");
        assert!(current_binding.matches_op(&next_op));
        assert_eq!(current_binding.envelope().actor(), next_actor);
    }
    assert!(binding.matches_op(&op));
    let error = vault
        .with_write_txn(|txn| {
            apply_owner_bound_claim_puts(&vault, txn, vec![op], vec![binding], false)
        })
        .expect_err("the original seal cannot consume a distinct author's replacement binding");
    assert!(matches!(error, Error::InvalidClaimBody(_)));
    assert_eq!(vault.get_raw(&id)?.expect("replacement remains"), next_raw);
    // Successful retraction observes preservation of the current authority.
    vault.retract_claim(&id, 30)?;
    assert_eq!(
        vault.get_claim(&id)?.expect("closed").lifecycle,
        ClaimLifecycleStatus::Retracted,
    );
    Ok(())
}

#[test]
fn rejected_and_aborted_replacements_preserve_the_current_binding() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    candidate(&vault, actor, id)?;
    let before_raw = vault.get_raw(&id)?.expect("original");
    let before_binding = current_binding(&vault, id)?;
    let unauthorized = WriteEnvelope::new(
        WriteActor::new(entity(0x63), EdgeActorClass::Human),
        ClaimSource::ToolOutput,
        WriteProvenance::new(Value::from("no matching permit"))?,
        ClaimApprovalStatus::Auto,
    );
    assert!(
        vault
            .batch()
            .claim_candidate(
                &id,
                ClaimCandidate::new(
                    "test.replacement",
                    ClaimSubject::Entity(entity(0x62)),
                    Value::from("denied"),
                    1.0,
                ),
                &unauthorized,
                TimeRange { start: 10, end: 99 },
                10
            )
            .commit()
            .is_err()
    );
    assert_eq!(vault.get_raw(&id)?.expect("original remains"), before_raw);
    assert_eq!(current_binding(&vault, id)?, before_binding);
    let replacement = WriteEnvelope::new(
        actor,
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("authorized but aborted"))?,
        ClaimApprovalStatus::Auto,
    );
    let error = vault
        .with_write_txn(|txn| {
            vault
                .batch_in()
                .claim_candidate(
                    &id,
                    ClaimCandidate::new(
                        "test.replacement",
                        ClaimSubject::Entity(entity(0x62)),
                        Value::from("aborted"),
                        1.0,
                    ),
                    &replacement,
                    TimeRange { start: 11, end: 99 },
                    12,
                )
                .apply(txn)?;
            Err::<(), _>(Error::InvariantViolation("abort replacement"))
        })
        .expect_err("caller aborts after staging body and binding");
    assert!(matches!(
        error,
        Error::InvariantViolation("abort replacement")
    ));
    assert_eq!(vault.get_raw(&id)?.expect("original remains"), before_raw);
    assert_eq!(current_binding(&vault, id)?, before_binding);
    vault.retract_claim(&id, 30)?;
    Ok(())
}

#[test]
fn copied_evidence_with_changed_body_or_flags_does_not_match_a_stale_binding() -> Result<()> {
    let (_dir, vault, actor) = fixture()?;
    let id = entity(0x64);
    candidate(&vault, actor, id)?;
    let original = vault.get_raw(&id)?.expect("original row");
    let original_body = vault.get_claim(&id)?.expect("original body");
    for change in 0..6 {
        // Corruption fixture: simulate a writer that bypassed binding upkeep.
        // No production door is skipped in any positive authority test.
        let mut body = original_body.clone();
        match change {
            0 => body.value = Value::from("different claim with copied evidence"),
            1 => body.stale = !body.stale,
            2 => body.approval = ClaimApprovalStatus::Proposed,
            3 => body.source = Some(ClaimSource::Observed),
            4 => {
                let Some(Value::Map(entries)) = &mut body.evidence else {
                    panic!("host stamp");
                };
                entries
                    .iter_mut()
                    .find(|(key, _)| key.as_str() == Some("actor_entity_ref"))
                    .expect("actor stamp")
                    .1 = Value::Binary(entity(0x63).as_bytes().to_vec());
            }
            _ => {}
        }
        let mut raw = original[..ENTITY_METADATA_HEADER_LEN].to_vec();
        if change == 5 {
            // A changed learned_at is also a different row, even when every
            // body byte and every actor/source field stays the same.
            raw[ENTITY_METADATA_HEADER_LEN - 1] ^= 1;
        }
        raw.extend_from_slice(&encode_claim_body(&body)?);
        vault.with_write_txn(|txn| {
            vault.store.entities.put(txn, id.as_bytes(), &raw)?;
            Ok(())
        })?;
        let error = vault
            .retract_claim(&id, 30)
            .expect_err("a corrupted row cannot authorize retraction");
        assert!(matches!(error, Error::InvalidClaimBody(_)));
        assert_eq!(vault.get_raw(&id)?.expect("corrupted row remains"), raw);
        vault.with_write_txn(|txn| {
            vault.store.entities.put(txn, id.as_bytes(), &original)?;
            Ok(())
        })?;
    }
    vault.retract_claim(&id, 30)?;
    assert_eq!(
        vault
            .get_claim(&id)?
            .expect("closed original row")
            .lifecycle,
        ClaimLifecycleStatus::Retracted,
    );
    Ok(())
}
