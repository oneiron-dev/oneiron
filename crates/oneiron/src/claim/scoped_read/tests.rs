//! The one point-read entry and the read-grant holes it keeps closed.
use super::*;
use crate::authority::{HostSlipIssuer, SlipCaveat};
use crate::federation::{Scope, ScopeAxis, ScopeId};
use crate::vault::ReadMode;
use rmpv::Value;
use std::collections::BTreeSet;

fn claim(subject: EntityId, world: Option<EntityId>, text: &str) -> ClaimBody {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        Value::from(text),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = world;
    body.source = Some(ClaimSource::UserStated);
    body
}

/// Replicated, not gated: these fixtures isolate the read door.
fn put_claim(vault: &crate::Vault, id: EntityId, body: &ClaimBody, at: u64) -> Result<()> {
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_CLAIM,
            crate::TimeRange { start: at, end: at },
            at,
            &encode_claim_body(body)?,
        )
        .commit()
}

fn text(row: &Option<ReadRow>) -> Result<String> {
    let body = row
        .as_ref()
        .and_then(|row| row.body.as_deref())
        .ok_or(Error::EntityNotFound)?;
    Ok(decode_claim_body(body, true)?
        .value
        .as_str()
        .unwrap_or_default()
        .to_owned())
}

/// The shipped default manifest with one `core:read` grant whose selectors
/// name `world`: the grant's reader may read that world and nothing else.
fn grant_world(vault: &crate::Vault, reader: &str, world: EntityId) -> Result<()> {
    let grant = Value::Map(vec![
        (Value::from("actor_ref"), Value::from(reader)),
        (Value::from("effector"), Value::from("core:read")),
        (
            Value::from("scope"),
            crate::federation::scope_codec::encode_scope_value(
                &crate::federation::scope_codec::read_preset(),
            )?,
        ),
        (
            Value::from("selectors"),
            Value::Map(vec![(
                Value::from("world_ref"),
                Value::from(world.to_hex()),
            )]),
        ),
        (Value::from("receipt_required"), Value::Boolean(false)),
    ]);
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut std::io::Cursor::new(
        crate::gate::default_policy_manifest()?,
    ))
    .map_err(|_| Error::InvalidClaimBody("default manifest"))?
    else {
        return Err(Error::InvalidClaimBody("default manifest"));
    };
    entries.retain(|(key, _)| key.as_str() != Some("scoped_grants"));
    entries.push((Value::from("scoped_grants"), Value::Array(vec![grant])));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries))
        .map_err(|_| Error::InvalidClaimBody("manifest encode"))?;
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

fn short_ref(vault: &crate::Vault, id: &EntityId) -> Result<(String, u8)> {
    let txn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .short_ids_reverse
        .get(&txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let (short_id, content_hash) = crate::batch::parse_short_id_value(&raw)?;
    Ok((short_id.to_owned(), content_hash))
}

#[test]
fn one_read_entry_serves_single_many_and_moded_reads() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    crate::test_util::authorize_readers(&vault, &["reader"]);
    let subject = EntityId::now();
    let (first, second, missing) = (EntityId::now(), EntityId::now(), EntityId::now());
    put_claim(&vault, first, &claim(subject, None, "first"), 1)?;
    put_claim(&vault, second, &claim(subject, None, "second"), 1)?;
    let read = vault.scoped_read(ScopedReadActorKey::new("reader").unwrap());

    // One id: its row and a receipt that withheld nothing.
    let one = read.read(&[PointRead::id(first)], None)?.single();
    assert_eq!(one.value.as_ref().map(|row| row.id), Some(first));
    assert_eq!(text(&one.value)?, "first");
    assert_eq!(one.receipt.suppressed_count, 0);

    // Many ids: one slot per read, in order, under one receipt. A missing id
    // is an empty slot, never a withheld row.
    let many = read.read(
        &[
            PointRead::id(second),
            PointRead::id(missing),
            PointRead::id(first),
        ],
        None,
    )?;
    assert_eq!(
        many.value
            .iter()
            .map(|row| row.as_ref().map(|row| row.id))
            .collect::<Vec<_>>(),
        vec![Some(second), None, Some(first)]
    );
    assert_eq!(many.receipt.suppressed_count, 0);

    // Moded: a pinned revision and the live body of the same id, and a short
    // reference to it, in one slice.
    let pin = vault.pin_entity_revision(&first)?;
    put_claim(&vault, first, &claim(subject, None, "first, revised"), 2)?;
    let (short_id, content_hash) = short_ref(&vault, &first)?;
    let moded = read.read(
        &[
            PointRead::id(first).at(ReadMode::Pinned(pin)),
            PointRead::id(first),
            PointRead::short(&short_id, content_hash),
        ],
        None,
    )?;
    assert_eq!(text(&moded.value[0])?, "first");
    assert_eq!(text(&moded.value[1])?, "first, revised");
    assert_eq!(moded.value[2].as_ref().map(|row| row.id), Some(first));
    assert_eq!(moded.receipt.suppressed_count, 0);

    // A reader without a grant gets the same slots empty, and the one
    // receipt counts each stored row it withheld.
    let outsider = vault.scoped_read(ScopedReadActorKey::new("outsider").unwrap());
    let withheld = outsider.read(
        &[
            PointRead::id(first).at(ReadMode::Pinned(pin)),
            PointRead::id(second),
            PointRead::id(missing),
        ],
        None,
    )?;
    assert_eq!(withheld.value, vec![None, None, None]);
    assert_eq!(withheld.receipt.suppressed_count, 2);
    assert!(
        withheld
            .receipt
            .narrowed_axes
            .contains(&"row_authority".to_owned())
    );
    Ok(())
}

#[test]
fn a_world_scoped_grant_never_reads_a_base_world_claim() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (subject, world) = (EntityId::now(), EntityId::now());
    let (base, in_world) = (EntityId::now(), EntityId::now());
    put_claim(&vault, base, &claim(subject, None, "base reality"), 1)?;
    put_claim(
        &vault,
        in_world,
        &claim(subject, Some(world), "in the world"),
        1,
    )?;
    grant_world(&vault, "world-reader", world)?;

    let read = vault.scoped_read(ScopedReadActorKey::new("world-reader").unwrap());
    let rows = read.read(&[PointRead::id(base), PointRead::id(in_world)], None)?;
    assert!(rows.value[0].is_none(), "base reality needs its own grant");
    assert_eq!(text(&rows.value[1])?, "in the world");
    assert_eq!(rows.receipt.suppressed_count, 1);
    // The ranked lane agrees with the point read.
    let ranked = read.filter_scored_entities(vec![
        ScoredEntity {
            id: base,
            score: 1.0,
        },
        ScoredEntity {
            id: in_world,
            score: 0.5,
        },
    ])?;
    assert_eq!(
        ranked.value.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        vec![in_world]
    );
    assert_eq!(ranked.receipt.suppressed_count, 1);
    Ok(())
}

#[test]
fn a_manifest_without_a_read_grant_admits_only_what_a_verified_slip_scope_admits() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
    let (subject, world) = (EntityId::now(), EntityId::from_bytes([0x33; 16])?);
    let (base, in_world) = (EntityId::now(), EntityId::now());
    put_claim(&vault, base, &claim(subject, None, "base reality"), 1)?;
    put_claim(
        &vault,
        in_world,
        &claim(subject, Some(world), "in the world"),
        1,
    )?;
    let reads = [PointRead::id(base), PointRead::id(in_world)];

    let issuer = HostSlipIssuer::from_secret(b"t49 slip-scoped read")?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let proof = vault.verified_host_root_slip(&issuer)?;

    // No `core:read` grant names this reader: a plain key reads nothing.
    let plain = vault
        .scoped_read(ScopedReadActorKey::new(proof.claims().holder_ref.clone()).expect("nonblank"));
    let nothing = plain.read(&reads, None)?;
    assert_eq!(nothing.value, vec![None, None]);
    assert_eq!(nothing.receipt.suppressed_count, 2);

    // A key built from a verified slip reads exactly the slip's scope.
    let mut world_only = root;
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(world)]));
    world_only.attenuate(SlipCaveat {
        scope: Some(scope),
        ..Default::default()
    })?;
    let narrowed = vault.verify_capability_slip(
        &issuer,
        &world_only,
        b"t49-world",
        &issuer.binding_proof(&world_only, b"t49-world")?,
    )?;
    let scoped = vault
        .scoped_read(ScopedReadActorKey::from_verified_slip(&narrowed).expect("read proof"))
        .read(&reads, None)?;
    assert!(scoped.value[0].is_none());
    assert_eq!(text(&scoped.value[1])?, "in the world");
    assert_eq!(scoped.receipt.suppressed_count, 1);

    // The unattenuated root scope admits both positions.
    let root_read = vault
        .scoped_read(ScopedReadActorKey::from_verified_slip(&proof).expect("read proof"))
        .read(&reads, None)?;
    assert_eq!(text(&root_read.value[0])?, "base reality");
    assert_eq!(text(&root_read.value[1])?, "in the world");
    assert_eq!(root_read.receipt.suppressed_count, 0);
    Ok(())
}

#[test]
fn diagnostic_event_reads_keep_their_receipt() -> Result<()> {
    use crate::self_heal::{
        DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
        DiagnosticSourceKind, diagnostic_event_id, encode_diagnostic_event_body,
    };
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let event = DiagnosticEvent {
        detector_id: "test.failure".into(),
        event_class: DiagnosticEventClass::TestFailure,
        actor_class: "system".into(),
        actor_ref: None,
        source: DiagnosticSourceKind::Receipt,
        criticality: DiagnosticCriticality::Critical,
        expected: Value::from(1),
        actual: Value::from(0),
        delta: Value::from(-1),
        replay: DiagnosticReplayCoordinate {
            content_hash: [7; 32],
            run_ref: Some("build".into()),
            checkpoint_ref: None,
        },
        evidence_refs: vec![],
        untrusted_detail: None,
        valid_from: 1,
        valid_to: None,
    };
    let id = diagnostic_event_id(&event.detector_id, &encode_diagnostic_event_body(&event)?);
    vault.emit_diagnostic_event(&id, &event)?;
    crate::test_util::authorize_readers(&vault, &["runner"]);

    let granted = vault
        .scoped_read(ScopedReadActorKey::new("runner").unwrap())
        .diagnostic_events()?;
    assert_eq!(granted.value.len(), 1);
    assert_eq!(granted.value[0].0, id);
    assert_eq!(granted.receipt.suppressed_count, 0);

    let withheld = vault
        .scoped_read(ScopedReadActorKey::new("stranger").unwrap())
        .diagnostic_events()?;
    assert!(withheld.value.is_empty());
    assert_eq!(withheld.receipt.suppressed_count, 1);
    assert!(
        withheld
            .receipt
            .narrowed_axes
            .contains(&"row_authority".to_owned())
    );
    Ok(())
}

#[test]
fn a_slip_granting_core_read_builds_a_read_key_and_a_write_slip_does_not() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
    let issuer = HostSlipIssuer::from_secret(b"t49 core read verb")?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let key_for = |verb: &str| -> Result<Option<ScopedReadActorKey>> {
        let mut slip = root.clone();
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from([verb.to_owned()]));
        slip.attenuate(SlipCaveat {
            scope: Some(scope),
            ..Default::default()
        })?;
        let proof = vault.verify_capability_slip(
            &issuer,
            &slip,
            verb.as_bytes(),
            &issuer.binding_proof(&slip, verb.as_bytes())?,
        )?;
        Ok(ScopedReadActorKey::from_verified_slip(&proof))
    };
    assert!(key_for("read")?.is_some());
    assert!(key_for("core:read")?.is_some());
    assert!(key_for("core:write")?.is_none());
    Ok(())
}
