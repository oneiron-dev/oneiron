//! Seeded and pinned actors, agent ceilings and fork gating.

use super::*;
use crate::error::GateError;

/// A minimal valid policy manifest carrying only the supplied `actor_ceilings`
/// rows (mirrors the gate/dispatch test fixture shape).
fn put_actor_ceiling_manifest(vault: &Vault, seed: u8, actor_rows: Vec<Value>) -> Result<()> {
    let manifest = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(crate::gate::POLICY_SCHEMA_VERSION),
        ),
        (Value::from("pack_id"), Value::from("agent-def-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(Vec::new())),
        (Value::from("actor_ceilings"), Value::Array(actor_rows)),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest)
        .map_err(|_| Error::InvariantViolation("encode test manifest"))?;
    crate::test_util::put_policy_manifest_bytes(vault, crate::test_util::entity(seed), &data)
}

fn agent_class_auto_row() -> Value {
    Value::Map(vec![
        (Value::from("actor_class"), Value::from("agent")),
        (Value::from("ceiling"), Value::from("auto")),
    ])
}

fn seeded_row(vault: &Vault, logical_id: &str) -> (EntityId, crate::agent_def::AgentDefinition) {
    vault
        .get_seeded_agent_definition_by_logical_id(logical_id)
        .expect("seeded roster resolves")
        .expect("seeded row exists")
}

fn agent_envelope(actor: EntityId, approval: ClaimApprovalStatus) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("fixture"))?,
        approval,
    ))
}

/// ONE-1890: a seeded actor id is neither privileged nor forbidden by its
/// bytes. The write-door lockout and the reserved-actor census are gone, so a
/// write AT a pinned id is admitted by the normal door, and a write BY a
/// seeded actor is judged by the ordinary gate lattice from that actor's own
/// stored row — Auto row passes, Proposed row gets the normal typed gate
/// rejection, never `Error::InvalidKey`.
#[test]
fn seeded_actor_uses_normal_authority_path() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_actor_ceiling_manifest(&vault, 0x2E, vec![agent_class_auto_row()])?;

    // No reserved-id lockout: an ordinary update lands AT a pinned row id.
    let (scout_id, scout) = seeded_row(&vault, "sys.scout");
    let mut edited = scout;
    edited.version = "2".to_owned();
    edited.desc = "edited at a pinned id".to_owned();
    vault.update_agent_definition(&scout_id, &edited, test_time_range(2, 2), 2)?;
    assert_eq!(vault.get_agent_definition(&scout_id)?, Some(edited));

    let subject = crate::test_util::entity(0x2F);
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, test_time_range(1, 1), 1, b"s")?;

    // Authorized: the sys.scout row's stored ceiling is Auto, so the
    // class-wide Auto grant survives the clamp and the write commits.
    let allowed_claim = crate::test_util::entity(0x30);
    vault
        .batch()
        .claim_candidate(
            &allowed_claim,
            ClaimCandidate::new(
                "profile.preference",
                ClaimSubject::Entity(subject),
                Value::from("sencha"),
                0.9,
            ),
            &agent_envelope(scout_id, ClaimApprovalStatus::Auto)?,
            test_time_range(10, 10),
            11,
        )
        .commit()?;
    assert!(vault.get_claim(&allowed_claim)?.is_some());

    // Unauthorized: the sys.herald row self-limits to Proposed, so the same
    // Auto request is HELD by the ordinary gate — a typed gate rejection, not
    // an id-based `InvalidKey` lockout.
    let (herald_id, _) = seeded_row(&vault, "sys.herald");
    let held_claim = crate::test_util::entity(0x31);
    let err = vault
        .batch()
        .claim_candidate(
            &held_claim,
            ClaimCandidate::new(
                "profile.preference",
                ClaimSubject::Entity(subject),
                Value::from("hojicha"),
                0.9,
            ),
            &agent_envelope(herald_id, ClaimApprovalStatus::Auto)?,
            test_time_range(12, 12),
            13,
        )
        .commit()
        .expect_err("a Proposed-ceiling actor must be held, not auto-written");
    assert!(
        matches!(err, Error::Gate(GateError::GateWriteRejected { outcome, .. }) if outcome == "pending"),
        "expected the ordinary gate rejection, got {err:?}"
    );
    assert!(vault.get_claim(&held_claim)?.is_none());
    Ok(())
}

/// ONE-1890 GATE seam (a): the AGENT_DEF create arm mirrors SKILL's fork gate
/// one entity type over — LOCAL creates only, `forkedFrom` must name a real
/// type-17 parent ROW that is not the fork itself, and the child's ceiling may
/// not widen beyond that parent's STORED ceiling (the relocated no-widen).
#[test]
fn fork_parent_gate() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let (herald_id, herald) = seeded_row(&vault, "sys.herald");
    assert_eq!(herald.ceiling, crate::agent_def::AgentCeiling::Proposed);

    let fork_of = |parent: Option<EntityId>, ceiling| {
        let mut fork = herald.clone();
        fork.agent_id = "oneiron.agent.fork".to_owned();
        fork.version = "1".to_owned();
        fork.logical_id = None;
        fork.display_name = None;
        fork.source = ClaimSource::UserStated;
        fork.forked_from = parent;
        fork.ceiling = ceiling;
        fork
    };
    let reject = |id: &EntityId, fork: &crate::agent_def::AgentDefinition, case: &str| {
        let err = vault
            .put_agent_definition(id, fork, test_time_range(1, 1), 1)
            .expect_err(case);
        assert_eq!(
            err.kind(),
            crate::error::ErrorKind::InvalidAgentDefBody,
            "{case}"
        );
        assert_eq!(
            vault.get_agent_definition(id).expect("read back"),
            None,
            "{case}"
        );
    };

    // forkedFrom naming the fork itself.
    let self_fork = crate::test_util::entity(0x32);
    reject(
        &self_fork,
        &fork_of(Some(self_fork), crate::agent_def::AgentCeiling::Proposed),
        "forkedFrom cannot name the fork itself",
    );

    // forkedFrom naming an id with no stored row.
    let missing_parent = crate::test_util::entity(0x33);
    assert!(vault.get_raw(&missing_parent)?.is_none());
    reject(
        &crate::test_util::entity(0x34),
        &fork_of(
            Some(missing_parent),
            crate::agent_def::AgentCeiling::Proposed,
        ),
        "forkedFrom parent must exist",
    );

    // forkedFrom naming a stored row of another entity type.
    let person_parent = crate::test_util::entity(0x35);
    vault.put_entity(
        &person_parent,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"p",
    )?;
    reject(
        &crate::test_util::entity(0x36),
        &fork_of(
            Some(person_parent),
            crate::agent_def::AgentCeiling::Proposed,
        ),
        "forkedFrom parent must be a type-17 AGENT_DEF",
    );

    // The relocated no-widen: a fork cannot exceed its PARENT ROW's ceiling.
    reject(
        &crate::test_util::entity(0x37),
        &fork_of(Some(herald_id), crate::agent_def::AgentCeiling::Auto),
        "a fork cannot widen beyond its parent row ceiling",
    );

    // Control: the same shape at or below the parent's ceiling is admitted,
    // and a fork off an Auto parent may itself be Auto.
    let narrow_fork = crate::test_util::entity(0x38);
    let narrow = fork_of(Some(herald_id), crate::agent_def::AgentCeiling::Proposed);
    vault.put_agent_definition(&narrow_fork, &narrow, test_time_range(1, 1), 1)?;
    assert_eq!(vault.get_agent_definition(&narrow_fork)?, Some(narrow));

    let (scout_id, _) = seeded_row(&vault, "sys.scout");
    let wide_fork = crate::test_util::entity(0x39);
    let wide = fork_of(Some(scout_id), crate::agent_def::AgentCeiling::Auto);
    vault.put_agent_definition(&wide_fork, &wide, test_time_range(1, 1), 1)?;
    assert_eq!(vault.get_agent_definition(&wide_fork)?, Some(wide));
    Ok(())
}

/// Asks for an `Auto` claim written by `actor`.
fn auto_write(vault: &Vault, actor: EntityId, claim: EntityId, at: u64) -> Result<()> {
    let subject = crate::test_util::entity(0x2F);
    if vault.get_raw(&subject)?.is_none() {
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, test_time_range(1, 1), 1, b"s")?;
    }
    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "profile.preference",
                ClaimSubject::Entity(subject),
                Value::from("genmaicha"),
                0.9,
            ),
            &agent_envelope(actor, ClaimApprovalStatus::Auto)?,
            test_time_range(at, at),
            at + 1,
        )
        .commit()
}

/// Asks for an `Auto` claim written by `actor`, and asserts the ordinary gate
/// holds it as `pending`: the actor's own row bounds it at Proposed.
fn auto_write_is_held(vault: &Vault, actor: EntityId, claim_seed: u8, at: u64) -> Result<()> {
    let claim = crate::test_util::entity(claim_seed);
    let err = auto_write(vault, actor, claim, at)
        .expect_err("a Proposed-ceiling actor must be held, not auto-written");
    assert!(
        matches!(err, Error::Gate(GateError::GateWriteRejected { outcome, .. }) if outcome == "pending"),
        "expected the ordinary gate rejection, got {err:?}"
    );
    assert!(vault.get_claim(&claim)?.is_none());
    Ok(())
}

fn refused_as_body(result: Result<()>, road: &str) {
    let err = result.expect_err(road);
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidAgentDefBody,
        "{road}: {err:?}"
    );
}

/// H215 (security scan, W2-T7): the agent a seeded ceiling binds may hold
/// `core:write`, and the gate reads its bound off its own row. An update that
/// widens that row is refused, typed, on the raw batch door, the typed door
/// and the replicated road, and the gate keeps holding the agent's `Auto`
/// writes. Narrowing still lands, and a narrowed row cannot widen back even
/// within its seed.
#[test]
fn an_update_never_widens_an_agent_ceiling() -> Result<()> {
    use crate::agent_def::{AgentCeiling, encode_agent_definition};

    let (_dir, vault) = open_test_vault();
    put_actor_ceiling_manifest(&vault, 0x2E, vec![agent_class_auto_row()])?;
    let (herald_id, herald) = seeded_row(&vault, "sys.herald");
    assert_eq!(herald.ceiling, AgentCeiling::Proposed);
    auto_write_is_held(&vault, herald_id, 0x40, 10)?;

    let mut widened = herald.clone();
    widened.version = "2".to_owned();
    widened.ceiling = AgentCeiling::Auto;
    let widened_body = encode_agent_definition(&widened)?;
    refused_as_body(
        vault
            .batch()
            .put(
                &herald_id,
                ENTITY_TYPE_AGENT_DEF,
                test_time_range(2, 2),
                2,
                &widened_body,
            )
            .commit(),
        "raw batch update",
    );
    refused_as_body(
        vault.update_agent_definition(&herald_id, &widened, test_time_range(2, 2), 2),
        "typed update",
    );
    refused_as_body(
        vault
            .batch()
            .put_replicated(
                &herald_id,
                ENTITY_TYPE_AGENT_DEF,
                test_time_range(3, 3),
                3,
                &widened_body,
            )
            .commit(),
        "replicated update",
    );
    assert_eq!(vault.get_agent_definition(&herald_id)?, Some(herald));
    auto_write_is_held(&vault, herald_id, 0x41, 12)?;

    // Control: the same edit at the stored ceiling lands, so the ceiling is
    // what the three roads refused.
    let mut edited = widened;
    edited.ceiling = AgentCeiling::Proposed;
    vault
        .batch()
        .put(
            &herald_id,
            ENTITY_TYPE_AGENT_DEF,
            test_time_range(4, 4),
            4,
            &encode_agent_definition(&edited)?,
        )
        .commit()?;
    assert_eq!(vault.get_agent_definition(&herald_id)?, Some(edited));

    // Narrowing still lands, and the gate reads the narrowed row at once.
    let (scout_id, scout) = seeded_row(&vault, "sys.scout");
    assert_eq!(scout.ceiling, AgentCeiling::Auto);
    let mut narrowed = scout;
    narrowed.version = "2".to_owned();
    narrowed.ceiling = AgentCeiling::Proposed;
    vault.update_agent_definition(&scout_id, &narrowed, test_time_range(5, 5), 5)?;
    auto_write_is_held(&vault, scout_id, 0x42, 14)?;
    // Its seed allows Auto, but the row it is now does not: no widening back.
    let mut rewidened = narrowed.clone();
    rewidened.version = "3".to_owned();
    rewidened.ceiling = AgentCeiling::Auto;
    refused_as_body(
        vault
            .batch()
            .put(
                &scout_id,
                ENTITY_TYPE_AGENT_DEF,
                test_time_range(6, 6),
                6,
                &encode_agent_definition(&rewidened)?,
            )
            .commit(),
        "widening a narrowed row back",
    );
    assert_eq!(vault.get_agent_definition(&scout_id)?, Some(narrowed));
    auto_write_is_held(&vault, scout_id, 0x43, 16)?;
    Ok(())
}

/// A from-scratch agent born at `ceiling`, the shape an owner authors.
fn custom_agent(
    vault: &Vault,
    ceiling: crate::agent_def::AgentCeiling,
) -> Result<(EntityId, crate::agent_def::AgentDefinition)> {
    let id = EntityId::now();
    Ok((id, custom_agent_at(vault, id, ceiling)?))
}

/// [`custom_agent`], born at `id`.
fn custom_agent_at(
    vault: &Vault,
    id: EntityId,
    ceiling: crate::agent_def::AgentCeiling,
) -> Result<crate::agent_def::AgentDefinition> {
    let (_, herald) = seeded_row(vault, "sys.herald");
    let mut custom = herald;
    custom.agent_id = "oneiron.agent.custom".to_owned();
    custom.version = "1".to_owned();
    custom.logical_id = None;
    custom.display_name = None;
    custom.source = ClaimSource::UserStated;
    custom.ceiling = ceiling;
    vault.put_agent_definition(&id, &custom, test_time_range(1, 1), 1)?;
    Ok(custom)
}

/// H215 (W2-T7), its second road: a delete ends the row, so a put at the same
/// id afterwards has no prior to compare with. The id keeps a pin across the
/// delete: a row reborn there is no wider than the narrowest ceiling the id
/// has held and keeps the lineage it was born with, for a seeded id, an
/// owner's own agent and a seeded row the owner narrowed, and the next open
/// re-seeds a deleted row within its pin.
#[test]
fn a_deleted_agent_id_comes_back_no_wider_and_on_its_own_lineage() -> Result<()> {
    use crate::agent_def::AgentCeiling;

    let (dir, vault) = open_test_vault();
    put_actor_ceiling_manifest(&vault, 0x2E, vec![agent_class_auto_row()])?;
    let reborn = |id: &EntityId, def: &crate::agent_def::AgentDefinition, road: &str| {
        refused_as_body(
            vault.put_agent_definition(id, def, test_time_range(3, 3), 3),
            road,
        );
        assert_eq!(
            vault.get_agent_definition(id).expect("read back"),
            None,
            "{road}"
        );
    };

    // A seeded id answers to its seed, with or without the reserved name.
    let (herald_id, herald) = seeded_row(&vault, "sys.herald");
    vault.batch().delete(&herald_id).commit()?;
    let mut widened = herald.clone();
    widened.version = "2".to_owned();
    widened.ceiling = AgentCeiling::Auto;
    reborn(&herald_id, &widened, "seeded id reborn wider");
    widened.logical_id = None;
    widened.display_name = None;
    reborn(
        &herald_id,
        &widened,
        "seeded id reborn wider without its name",
    );
    let mut restored = herald;
    restored.version = "2".to_owned();
    vault.put_agent_definition(&herald_id, &restored, test_time_range(4, 4), 4)?;
    assert_eq!(vault.get_agent_definition(&herald_id)?, Some(restored));
    auto_write_is_held(&vault, herald_id, 0x44, 10)?;

    // An owner's own agent answers to the ceiling and the lineage it was born with.
    let (custom_id, custom) = custom_agent(&vault, AgentCeiling::Proposed)?;
    vault.batch().delete(&custom_id).commit()?;
    let mut wider = custom.clone();
    wider.ceiling = AgentCeiling::Auto;
    reborn(&custom_id, &wider, "custom id reborn wider");
    let (scout_id, scout) = seeded_row(&vault, "sys.scout");
    let mut grafted = custom.clone();
    grafted.forked_from = Some(scout_id);
    reborn(
        &custom_id,
        &grafted,
        "custom id reborn under another parent",
    );
    vault.put_agent_definition(&custom_id, &custom, test_time_range(5, 5), 5)?;
    auto_write_is_held(&vault, custom_id, 0x45, 12)?;

    // A seeded row the owner narrowed keeps the narrower bound: its seed would
    // allow Auto, the id has held no wider than Proposed since.
    let mut narrowed = scout;
    narrowed.version = "2".to_owned();
    narrowed.ceiling = AgentCeiling::Proposed;
    vault.update_agent_definition(&scout_id, &narrowed, test_time_range(6, 6), 6)?;
    vault.batch().delete(&scout_id).commit()?;
    let mut seed_wide = narrowed.clone();
    seed_wide.version = "3".to_owned();
    seed_wide.ceiling = AgentCeiling::Auto;
    reborn(
        &scout_id,
        &seed_wide,
        "narrowed seeded id reborn at its seed",
    );

    // The next open re-seeds the deleted row within its pin, not at its seed.
    drop(vault);
    let vault = Vault::open(dir.path(), embedding_test_config())?;
    let (_, reseeded) = seeded_row(&vault, "sys.scout");
    assert_eq!(reseeded.ceiling, AgentCeiling::Proposed);
    Ok(())
}

/// H215 (W2-T7), the third road: a delete followed by a put of another entity
/// type at the same id would leave a row the gate reads no ceiling off, so an
/// id that has been an agent stays one.
#[test]
fn a_deleted_agent_id_cannot_come_back_as_another_type() -> Result<()> {
    use crate::agent_def::AgentCeiling;

    let (_dir, vault) = open_test_vault();
    let (herald_id, _) = seeded_row(&vault, "sys.herald");
    let (custom_id, _) = custom_agent(&vault, AgentCeiling::Proposed)?;
    for (id, road) in [(herald_id, "seeded id"), (custom_id, "custom id")] {
        vault.batch().delete(&id).commit()?;
        let err = vault
            .put_entity(&id, ENTITY_TYPE_PERSON, test_time_range(2, 2), 2, b"reborn")
            .expect_err(road);
        assert_eq!(
            err.kind(),
            ErrorKind::EntityTypeImmutable,
            "{road}: {err:?}"
        );
        assert!(vault.get_raw(&id)?.is_none(), "{road}");
    }
    // Control: an id that was never an agent takes a PERSON as before.
    let person = crate::test_util::entity(0x46);
    vault.put_entity(&person, ENTITY_TYPE_PERSON, test_time_range(2, 2), 2, b"p")?;
    Ok(())
}

/// The embedded owner's proof, as a native host authenticates it.
fn owner_proof(vault: &Vault) -> Result<crate::consent::AuthenticatedOwner> {
    let actor = vault.ensure_embedded_owner_actor().expect("owner actor");
    vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )
}

/// H215 keeps the owner's capability: the one door that widens an agent's
/// ceiling is the owner's, and it rechecks the owner's proof. It widens a
/// seeded row and an owner's own agent, the gate reads the wider bound, and
/// the id's pin follows, so a later put at that ceiling lands on the generic
/// road, across a delete too. A generic put of the same widening, on every
/// road, is still refused, and a proof whose actor does not own the vault
/// widens nothing.
#[test]
fn only_the_owners_door_widens_an_agent_and_the_pin_follows() -> Result<()> {
    use crate::agent_def::{AgentCeiling, encode_agent_definition};
    use crate::store::GateDecisionId;

    let (_dir, vault) = open_test_vault();
    put_actor_ceiling_manifest(&vault, 0x2E, vec![agent_class_auto_row()])?;
    let owner = owner_proof(&vault)?;
    let stranger = crate::test_util::entity(0x47);
    vault.put_entity(
        &stranger,
        ENTITY_TYPE_PERSON,
        test_time_range(1, 1),
        1,
        b"stranger",
    )?;
    let stranger =
        vault.authenticate_owner(stranger, &stranger.to_hex(), true, GateDecisionId::now())?;

    let (herald_id, herald) = seeded_row(&vault, "sys.herald");
    let mut widened = herald.clone();
    widened.version = "2".to_owned();
    widened.ceiling = AgentCeiling::Auto;
    let err = vault
        .update_agent_definition_as(&stranger, &herald_id, &widened, test_time_range(2, 2), 2)
        .expect_err("a proof whose actor does not own the vault");
    assert_eq!(
        err.kind(),
        ErrorKind::ConsentOwnerNotAuthenticated,
        "{err:?}"
    );
    assert_eq!(vault.get_agent_definition(&herald_id)?, Some(herald));
    auto_write_is_held(&vault, herald_id, 0x48, 10)?;

    vault.update_agent_definition_as(&owner, &herald_id, &widened, test_time_range(2, 2), 2)?;
    assert_eq!(
        vault.get_agent_definition(&herald_id)?,
        Some(widened.clone())
    );
    auto_write(&vault, herald_id, crate::test_util::entity(0x49), 12)?;
    // The pin follows the owner: an edit at the widened ceiling lands on the
    // raw batch door, and so does a recreate at it after a delete.
    let mut edited = widened;
    edited.version = "3".to_owned();
    vault
        .batch()
        .put(
            &herald_id,
            ENTITY_TYPE_AGENT_DEF,
            test_time_range(3, 3),
            3,
            &encode_agent_definition(&edited)?,
        )
        .commit()?;
    vault.batch().delete(&herald_id).commit()?;
    edited.version = "4".to_owned();
    vault.put_agent_definition(&herald_id, &edited, test_time_range(4, 4), 4)?;
    assert_eq!(vault.get_agent_definition(&herald_id)?, Some(edited));

    // The same widening of an agent the owner did not widen is refused on
    // every generic road; the owner's door widens it.
    let (custom_id, custom) = custom_agent(&vault, AgentCeiling::Proposed)?;
    let mut wider = custom.clone();
    wider.version = "2".to_owned();
    wider.ceiling = AgentCeiling::Auto;
    let wider_body = encode_agent_definition(&wider)?;
    refused_as_body(
        vault.update_agent_definition(&custom_id, &wider, test_time_range(5, 5), 5),
        "typed update",
    );
    refused_as_body(
        vault
            .batch()
            .put(
                &custom_id,
                ENTITY_TYPE_AGENT_DEF,
                test_time_range(5, 5),
                5,
                &wider_body,
            )
            .commit(),
        "raw batch update",
    );
    refused_as_body(
        vault
            .batch()
            .put_replicated(
                &custom_id,
                ENTITY_TYPE_AGENT_DEF,
                test_time_range(5, 5),
                5,
                &wider_body,
            )
            .commit(),
        "replicated update",
    );
    assert_eq!(vault.get_agent_definition(&custom_id)?, Some(custom));
    auto_write_is_held(&vault, custom_id, 0x4A, 14)?;
    vault.update_agent_definition_as(&owner, &custom_id, &wider, test_time_range(6, 6), 6)?;
    auto_write(&vault, custom_id, crate::test_util::entity(0x4B), 16)?;
    Ok(())
}

/// A header-only row of `entity_type`, the shape a retained shell carries.
fn header_row(entity_type: u8) -> Vec<u8> {
    let mut row = vec![entity_type];
    for stamp in [2_u64, 2, 2] {
        row.extend_from_slice(&stamp.to_be_bytes());
    }
    row
}

/// H215, round 2: a retained soft-delete shell a sync window carries is
/// installed header-only, never through a put. A shell of another type at an
/// agent id is refused there too.
#[cfg(feature = "sync")]
#[test]
fn a_retained_shell_cannot_retype_an_agent_id() -> Result<()> {
    use crate::deletion::{TombstoneReason, TombstoneValueV2};

    let (_dir, vault) = open_test_vault();
    put_actor_ceiling_manifest(&vault, 0x2E, vec![agent_class_auto_row()])?;
    let (custom_id, _) = custom_agent(&vault, crate::agent_def::AgentCeiling::Proposed)?;
    vault.batch().delete(&custom_id).commit()?;
    let tombstone = TombstoneValueV2 {
        reason: TombstoneReason::UserDelete,
        deleted_at: 2,
        request_id: [7; 16],
    }
    .encode();
    let err = vault
        .with_write_txn(|txn| {
            crate::batch::restore_recovery_shell_in_txn(
                &vault,
                txn,
                &custom_id,
                &header_row(ENTITY_TYPE_PERSON),
                &tombstone,
            )
        })
        .expect_err("a PERSON shell at an agent id");
    assert_eq!(err.kind(), ErrorKind::EntityTypeImmutable, "{err:?}");
    assert!(vault.get_raw(&custom_id)?.is_none());
    auto_write_is_held(&vault, custom_id, 0x4C, 10)?;
    Ok(())
}

/// H215, round 2: whatever row a writer no door knows of leaves at an agent
/// id, the gate holds the agent there at `Proposed` rather than reading no
/// bound off a row that is not its definition.
#[test]
fn an_agent_id_holding_another_row_stays_held() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_actor_ceiling_manifest(&vault, 0x2E, vec![agent_class_auto_row()])?;
    let (custom_id, _) = custom_agent(&vault, crate::agent_def::AgentCeiling::Auto)?;
    vault.batch().delete(&custom_id).commit()?;
    let mut person = header_row(ENTITY_TYPE_PERSON);
    person.extend_from_slice(b"planted");
    vault.with_write_txn(|txn| {
        vault
            .store
            .entities
            .put(txn, custom_id.as_bytes(), &person)?;
        Ok(())
    })?;
    auto_write_is_held(&vault, custom_id, 0x4D, 12)?;
    Ok(())
}

/// H215, round 2: a PERSON's substrate FACET lands at an id derived from the
/// PERSON's, which a caller can compute and give an agent first. With that
/// agent deleted, the PERSON's put is refused rather than install a FACET at
/// the agent's id. A PERSON elsewhere still takes its substrate.
#[test]
fn a_person_substrate_cannot_land_on_an_agent_id() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_actor_ceiling_manifest(&vault, 0x2E, vec![agent_class_auto_row()])?;
    let person = crate::test_util::entity(0x4E);
    let facet = crate::claim::substrate_facet_id(person)?;
    custom_agent_at(&vault, facet, crate::agent_def::AgentCeiling::Proposed)?;
    vault.batch().delete(&facet).commit()?;
    let err = vault
        .put_entity(&person, ENTITY_TYPE_PERSON, test_time_range(2, 2), 2, b"p")
        .expect_err("a PERSON whose substrate id is an agent's");
    assert_eq!(err.kind(), ErrorKind::EntityTypeImmutable, "{err:?}");
    assert!(vault.get_raw(&facet)?.is_none());
    assert!(vault.get_raw(&person)?.is_none());
    auto_write_is_held(&vault, facet, 0x4F, 10)?;

    let other = crate::test_util::entity(0x50);
    vault.put_entity(&other, ENTITY_TYPE_PERSON, test_time_range(2, 2), 2, b"p")?;
    assert!(
        vault
            .get_raw(&crate::claim::substrate_facet_id(other)?)?
            .is_some()
    );
    Ok(())
}

/// The backup at `image` restored over `vault`, keeping its authority.
fn restore_keeping_authority(
    vault: &Vault,
    image: &std::path::Path,
    destination: &std::path::Path,
) -> Result<Vault> {
    Vault::restore_checkpoint_keeping_authority(
        image,
        destination,
        vault.config.clone(),
        vault,
        1_000,
    )
    .map(|(restored, _)| restored)
}

/// H215, round 2: an agent id's pin is live authority, so a restore that
/// keeps authority keeps it. An agent born and deleted since the backup
/// leaves its id pinned in the restored vault: a wider recreate or a PERSON
/// there is refused as in the live vault, and one within the pin lands.
#[test]
fn a_restore_keeps_every_agent_id_pin() -> Result<()> {
    use crate::agent_def::AgentCeiling;

    let (_dir, vault) = open_test_vault();
    let backups = tempfile::tempdir()?;
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100)?;
    let (custom_id, custom) = custom_agent(&vault, AgentCeiling::Proposed)?;
    vault.batch().delete(&custom_id).commit()?;
    let restored = restore_keeping_authority(&vault, &image, &backups.path().join("restored"))?;
    let mut wider = custom.clone();
    wider.ceiling = AgentCeiling::Auto;
    refused_as_body(
        restored.put_agent_definition(&custom_id, &wider, test_time_range(3, 3), 3),
        "wider recreate after the restore",
    );
    let err = restored
        .put_entity(
            &custom_id,
            ENTITY_TYPE_PERSON,
            test_time_range(3, 3),
            3,
            b"p",
        )
        .expect_err("a PERSON at the agent id after the restore");
    assert_eq!(err.kind(), ErrorKind::EntityTypeImmutable, "{err:?}");
    restored.put_agent_definition(&custom_id, &custom, test_time_range(4, 4), 4)?;
    Ok(())
}

/// H215, round 3: a row a restore brings back narrower than its live pin
/// narrows the pin, as a put of it would. An agent the owner widened since
/// the backup, then deleted, comes back at the backup's ceiling and cannot
/// widen itself back without the owner.
#[test]
fn a_restored_row_narrows_its_pin() -> Result<()> {
    use crate::agent_def::AgentCeiling;

    let (_dir, vault) = open_test_vault();
    let (kept_id, kept) = custom_agent(&vault, AgentCeiling::Proposed)?;
    let backups = tempfile::tempdir()?;
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100)?;
    let mut widened = kept.clone();
    widened.version = "2".to_owned();
    widened.ceiling = AgentCeiling::Auto;
    vault.update_agent_definition_as(
        &owner_proof(&vault)?,
        &kept_id,
        &widened,
        test_time_range(2, 2),
        2,
    )?;
    vault.batch().delete(&kept_id).commit()?;
    let restored = restore_keeping_authority(&vault, &image, &backups.path().join("restored"))?;
    assert_eq!(restored.get_agent_definition(&kept_id)?, Some(kept));
    refused_as_body(
        restored.update_agent_definition(&kept_id, &widened, test_time_range(5, 5), 5),
        "the restored row widened back without the owner",
    );
    Ok(())
}

/// H215, round 3: a pin a restore cannot read is no pin to pass. An agent
/// narrowed and deleted since the backup, whose live pin no longer reads, is
/// not brought back at the backup's wider ceiling: the restore refuses.
#[test]
fn a_restore_refuses_past_a_pin_it_cannot_read() -> Result<()> {
    use crate::agent_def::AgentCeiling;

    let (_dir, vault) = open_test_vault();
    let (agent_id, agent) = custom_agent(&vault, AgentCeiling::Auto)?;
    let backups = tempfile::tempdir()?;
    let image = backups.path().join("backup");
    vault.snapshot_checkpoint(&image, 100)?;
    let mut narrowed = agent;
    narrowed.version = "2".to_owned();
    narrowed.ceiling = AgentCeiling::Proposed;
    vault.update_agent_definition(&agent_id, &narrowed, test_time_range(2, 2), 2)?;
    vault.batch().delete(&agent_id).commit()?;
    let pin_key = [&b"agent_def/id-pin/v1\0"[..], agent_id.as_bytes()].concat();
    vault.with_write_txn(|txn| {
        vault.store.vault_meta.put(txn, &pin_key, &[2])?;
        Ok(())
    })?;
    let destination = backups.path().join("restored");
    assert!(restore_keeping_authority(&vault, &image, &destination).is_err());
    assert!(!destination.exists());
    Ok(())
}

/// H215, round 3: a restore that keeps a live vault's authority can bring
/// back a definition that vault never held, so no pin of its own comes with
/// it. The restore pins it as a put would have: deleted, it comes back no
/// wider and as nothing else.
#[test]
fn a_restore_pins_a_definition_its_live_vault_never_held() -> Result<()> {
    use crate::agent_def::AgentCeiling;
    use crate::recovery::checkpoint::RestoreReason;

    let (_dir, vault) = open_test_vault();
    let backups = tempfile::tempdir()?;
    let before = backups.path().join("before");
    vault.snapshot_checkpoint(&before, 100)?;
    let (custom_id, custom) = custom_agent(&vault, AgentCeiling::Proposed)?;
    let after = backups.path().join("after");
    vault.snapshot_checkpoint(&after, 200)?;
    let (rolled_back, _) = Vault::restore_checkpoint(
        &before,
        &backups.path().join("rolled-back"),
        vault.config.clone(),
        RestoreReason::Restore,
        1_000,
    )?;
    let restored =
        restore_keeping_authority(&rolled_back, &after, &backups.path().join("restored"))?;
    assert_eq!(
        restored.get_agent_definition(&custom_id)?,
        Some(custom.clone())
    );
    restored.batch().delete(&custom_id).commit()?;
    let mut wider = custom.clone();
    wider.ceiling = AgentCeiling::Auto;
    refused_as_body(
        restored.put_agent_definition(&custom_id, &wider, test_time_range(3, 3), 3),
        "wider recreate of a restored definition",
    );
    let err = restored
        .put_entity(
            &custom_id,
            ENTITY_TYPE_PERSON,
            test_time_range(3, 3),
            3,
            b"p",
        )
        .expect_err("a PERSON at a restored agent id");
    assert_eq!(err.kind(), ErrorKind::EntityTypeImmutable, "{err:?}");
    Ok(())
}

/// H215, round 3: a row older than the pin holds no pin until something pins
/// it, and could be deleted and come back wider or as another type. The next
/// open pins it before any caller holds the vault.
#[test]
fn an_open_pins_a_row_older_than_the_pin() -> Result<()> {
    use crate::agent_def::AgentCeiling;

    let (dir, vault) = open_test_vault();
    let (custom_id, custom) = custom_agent(&vault, AgentCeiling::Proposed)?;
    // The row as a build without the pin left it: no pin row at its id.
    let pin_key = [&b"agent_def/id-pin/v1\0"[..], custom_id.as_bytes()].concat();
    vault.with_write_txn(|txn| {
        vault.store.vault_meta.delete(txn, &pin_key)?;
        Ok(())
    })?;
    drop(vault);
    let vault = Vault::open(dir.path(), embedding_test_config())?;
    vault.batch().delete(&custom_id).commit()?;
    let mut wider = custom.clone();
    wider.ceiling = AgentCeiling::Auto;
    refused_as_body(
        vault.put_agent_definition(&custom_id, &wider, test_time_range(3, 3), 3),
        "wider recreate of a row older than the pin",
    );
    let err = vault
        .put_entity(
            &custom_id,
            ENTITY_TYPE_PERSON,
            test_time_range(3, 3),
            3,
            b"p",
        )
        .expect_err("a PERSON at the id of a row older than the pin");
    assert_eq!(err.kind(), ErrorKind::EntityTypeImmutable, "{err:?}");
    vault.put_agent_definition(&custom_id, &custom, test_time_range(4, 4), 4)?;
    Ok(())
}
