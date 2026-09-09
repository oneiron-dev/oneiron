//! Commitment schema, codec and transition tests plus shared test helpers.

use rmpv::Value;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::commitment::*;
use crate::config::{HnswConfig, VaultConfig};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};

pub(crate) fn temp_vault() -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    let vault = Vault::open(dir.path(), config)?;
    Ok((dir, vault))
}

pub(crate) fn time(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

pub(crate) fn schedule(due: u64) -> Value {
    Value::Map(vec![
        (Value::from("kind"), Value::from("once")),
        (Value::from("due"), Value::from(due)),
    ])
}

pub(crate) fn seed_entities(vault: &Vault, ids: &[EntityId]) -> Result<()> {
    for id in ids {
        vault.put_entity(id, ENTITY_TYPE_PERSON, time(1, 1), 1, b"person")?;
    }
    Ok(())
}

fn seed_agent(vault: &Vault, id: &EntityId) -> Result<()> {
    vault.put_entity(id, ENTITY_TYPE_MACHINE, time(1, 1), 1, b"agent")
}

pub(crate) fn envelope(actor: EntityId) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("test commitment write"))?,
        ClaimApprovalStatus::Auto,
    ))
}

pub(crate) fn record(
    obligor: EntityId,
    beneficiary: EntityId,
    strength: CommitmentStrength,
) -> Result<CommitmentRecord> {
    CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, obligor),
        beneficiary,
        CommitmentContent::new("send the signed document", Some("payload:doc-1".to_owned()))?,
        schedule(10_000),
        strength,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::RunTreeNode, "run:turn-7")?,
    )
}

fn value_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).expect("encode MessagePack value");
    bytes
}

#[test]
fn commitment_status_verbs_round_trip_and_emit_gate_receipts() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let actor = crate::test_util::entity(0x51);
    let beneficiary = crate::test_util::entity(0xE2);
    seed_entities(&vault, &[actor, beneficiary])?;
    let envelope = envelope(actor)?;

    let fulfilled = crate::test_util::entity(0xB1);
    vault.put_commitment_claim(
        &fulfilled,
        &record(actor, beneficiary, CommitmentStrength::Commitment)?,
        &envelope,
        time(100, 200),
        300,
    )?;
    vault.fulfill_commitment(&fulfilled, &envelope, 301)?;
    assert_eq!(
        vault
            .get_commitment_claim(&fulfilled)?
            .expect("fulfilled commitment")
            .status,
        CommitmentStatus::Fulfilled
    );

    let released = crate::test_util::entity(0xB2);
    vault.put_commitment_claim(
        &released,
        &record(actor, beneficiary, CommitmentStrength::Decision)?,
        &envelope,
        time(110, 210),
        310,
    )?;
    vault.release_commitment(&released, &envelope, 311)?;
    assert_eq!(
        vault
            .get_commitment_claim(&released)?
            .expect("released commitment")
            .status,
        CommitmentStatus::Released
    );

    let superseded = crate::test_util::entity(0xB3);
    vault.put_commitment_claim(
        &superseded,
        &record(actor, beneficiary, CommitmentStrength::StatedIntention)?,
        &envelope,
        time(120, 220),
        320,
    )?;
    vault.supersede_commitment(&superseded, &envelope, 321)?;
    assert_eq!(
        vault
            .get_commitment_claim(&superseded)?
            .expect("superseded commitment")
            .status,
        CommitmentStatus::Superseded
    );

    let receipts = vault.receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Gate))?;
    for id in [fulfilled, released, superseded] {
        let trigger = format!("claim:{}", id.to_hex());
        assert!(
            receipts.iter().any(|receipt| {
                receipt.trigger_ref.as_deref() == Some(trigger.as_str())
                    && receipt.outcome == "allow"
            }),
            "missing allow gate receipt for {trigger}"
        );
    }
    Ok(())
}

#[test]
fn retro_dated_commitment_keeps_valid_time_and_learned_time_separate() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let actor = crate::test_util::entity(0xC1);
    let beneficiary = crate::test_util::entity(0xC2);
    seed_entities(&vault, &[actor, beneficiary])?;
    let id = crate::test_util::entity(0xC3);
    let due_time = time(1_700_000_000, 1_700_000_000);
    let learned_at = 1_700_604_800;
    vault.put_commitment_claim(
        &id,
        &record(actor, beneficiary, CommitmentStrength::Commitment)?,
        &envelope(actor)?,
        due_time,
        learned_at,
    )?;

    let raw = vault.get_raw(&id)?.expect("raw commitment");
    let header = EntityMetadataHeader::parse(&raw).expect("entity header");
    assert_eq!(header.occurred_start, due_time.start);
    assert_eq!(header.occurred_end, due_time.end);
    assert_eq!(header.learned_at, learned_at);
    let stored = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
    assert_eq!(stored.valid_from, Some(due_time.start));
    assert_eq!(stored.valid_to, Some(due_time.end));
    Ok(())
}

#[test]
fn user_strength_override_beats_extractor_and_agent_owed_is_commitment() -> Result<()> {
    let owner_strength = CommitmentStrength::resolve(
        CommitmentObligorKind::Owner,
        CommitmentStrength::StatedIntention,
        Some(CommitmentStrength::Decision),
    );
    assert_eq!(owner_strength, CommitmentStrength::Decision);

    let agent_strength = CommitmentStrength::resolve(
        CommitmentObligorKind::Agent,
        CommitmentStrength::StatedIntention,
        Some(CommitmentStrength::Decision),
    );
    assert_eq!(agent_strength, CommitmentStrength::Commitment);

    let (_dir, vault) = temp_vault()?;
    let owner = crate::test_util::entity(0xD1);
    let beneficiary = crate::test_util::entity(0xD2);
    let agent = crate::test_util::entity(0xD3);
    seed_entities(&vault, &[owner, beneficiary])?;
    seed_agent(&vault, &agent)?;

    let owner_id = crate::test_util::entity(0xD4);
    let owner_record = record(owner, beneficiary, owner_strength)?;
    vault.put_commitment_claim(
        &owner_id,
        &owner_record,
        &envelope(owner)?,
        time(400, 500),
        600,
    )?;
    assert_eq!(
        vault
            .get_commitment_claim(&owner_id)?
            .expect("owner commitment")
            .strength,
        CommitmentStrength::Decision
    );

    let agent_record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Agent, agent),
        owner,
        CommitmentContent::new("check in on Friday", None)?,
        schedule(700),
        CommitmentStrength::StatedIntention,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, "brief:check-in")?,
    )?;
    assert_eq!(agent_record.strength, CommitmentStrength::Commitment);
    Ok(())
}

#[test]
fn commitment_value_round_trips_closed_schema() -> Result<()> {
    let record = record(
        crate::test_util::entity(0x61),
        crate::test_util::entity(0x62),
        CommitmentStrength::Decision,
    )?;
    let value = encode_commitment_value(&record)?;
    assert_eq!(decode_commitment_value(&value)?, record);
    let Value::Map(entries) = value else {
        unreachable!()
    };
    for malformed in [
        Value::Map(entries[..7].to_vec()),
        Value::Map({
            let mut rows = entries.clone();
            rows.push((Value::from("extra"), Value::Nil));
            rows
        }),
        Value::Map({
            let mut rows = entries.clone();
            rows.push(rows[0].clone());
            rows
        }),
    ] {
        assert!(matches!(
            decode_commitment_value(&malformed),
            Err(Error::InvalidClaimBody(_))
        ));
    }
    Ok(())
}

#[test]
fn commitment_status_transition_matrix_is_closed() {
    let statuses = [
        CommitmentStatus::Open,
        CommitmentStatus::Fulfilled,
        CommitmentStatus::Released,
        CommitmentStatus::Lapsed,
        CommitmentStatus::Superseded,
    ];
    for from in statuses {
        for to in statuses {
            assert_eq!(
                from.can_transition_to(to),
                matches!(
                    (from, to),
                    (
                        CommitmentStatus::Open,
                        CommitmentStatus::Fulfilled
                            | CommitmentStatus::Released
                            | CommitmentStatus::Lapsed
                            | CommitmentStatus::Superseded
                    )
                )
            );
        }
    }
}

#[test]
fn terminal_candidate_and_strength_rules_are_enforced() -> Result<()> {
    let obligor = crate::test_util::entity(0x63);
    let beneficiary = crate::test_util::entity(0x64);
    let terminal = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, obligor),
        beneficiary,
        CommitmentContent::new("x", None)?,
        schedule(9),
        CommitmentStrength::Decision,
        CommitmentStatus::Fulfilled,
        CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, "b")?,
    )?;
    assert!(matches!(
        commitment_claim_candidate(&terminal),
        Err(Error::InvalidClaimBody(_))
    ));
    assert_eq!(
        CommitmentStrength::resolve(
            CommitmentObligorKind::Owner,
            CommitmentStrength::Decision,
            None,
        ),
        CommitmentStrength::Decision
    );
    assert_eq!(
        CommitmentStrength::resolve(
            CommitmentObligorKind::Agent,
            CommitmentStrength::Decision,
            None,
        ),
        CommitmentStrength::Commitment
    );
    Ok(())
}

#[test]
fn opaque_schedule_round_trips_byte_identical() -> Result<()> {
    let actor = crate::test_util::entity(0x65);
    let schedule = Value::Map(vec![(
        Value::from("unknown"),
        Value::Array(vec![Value::from(1), Value::from("nested")]),
    )]);
    let expected = value_bytes(&schedule);
    let rec = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, actor),
        crate::test_util::entity(0x66),
        CommitmentContent::new("x", None)?,
        schedule,
        CommitmentStrength::Decision,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, "b")?,
    )?;
    assert_eq!(
        value_bytes(&decode_commitment_value(&encode_commitment_value(&rec)?)?.schedule),
        expected
    );
    Ok(())
}

#[test]
fn duplicate_id_is_immutable_and_absent_write_does_not_receipt() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let actor = crate::test_util::entity(0x67);
    let beneficiary = crate::test_util::entity(0x68);
    let id = crate::test_util::entity(0x69);
    seed_entities(&vault, &[actor, beneficiary])?;
    let env = envelope(actor)?;
    vault.put_commitment_claim(
        &id,
        &record(actor, beneficiary, CommitmentStrength::Decision)?,
        &env,
        time(1, 2),
        3,
    )?;
    let raw = vault.get_raw(&id)?;
    let receipts = vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?;
    assert!(matches!(
        vault.put_commitment_claim(
            &id,
            &record(actor, beneficiary, CommitmentStrength::Decision)?,
            &env,
            time(1, 2),
            4,
        ),
        Err(Error::InvalidClaimBody(_))
    ));
    assert_eq!(vault.get_raw(&id)?, raw);
    assert_eq!(
        vault
            .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Gate))?
            .len(),
        receipts.len()
    );
    Ok(())
}

#[test]
fn superseding_future_due_commitment_via_generic_lifecycle_succeeds() -> Result<()> {
    let (_dir, vault) = temp_vault()?;
    let actor = crate::test_util::entity(0x6A);
    let beneficiary = crate::test_util::entity(0x6B);
    let old = crate::test_util::entity(0x6C);
    let successor = crate::test_util::entity(0x6D);
    seed_entities(&vault, &[actor, beneficiary])?;
    let rec = record(actor, beneficiary, CommitmentStrength::Decision)?;
    vault.put_commitment_claim(&old, &rec, &envelope(actor)?, time(100, 200), 1)?;
    vault.put_commitment_claim(&successor, &rec, &envelope(actor)?, time(100, 200), 2)?;
    let old_raw = vault.get_raw(&old)?;
    let successor_raw = vault.get_raw(&successor)?;
    // A future due end does not permit closing before the occurred start.
    assert!(matches!(
        vault.supersede_claim(&successor, &old, 50),
        Err(Error::InvalidTimeRange {
            start: 100,
            end: 50
        })
    ));
    assert_eq!(vault.get_raw(&old)?, old_raw);
    assert_eq!(vault.get_raw(&successor)?, successor_raw);

    // Start 100 has occurred, while due end 200 is still in the future.
    vault.supersede_claim(&successor, &old, 150)?;
    assert_eq!(
        vault.get_claim(&old)?.expect("old").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    Ok(())
}
