//! Seeded and pinned actors, agent ceilings and fork gating.

use super::*;
use crate::error::{GateError, RegistryError};

/// A minimal valid policy manifest carrying only the supplied `actor_ceilings`
/// rows (mirrors the gate/dispatch test fixture shape).
fn put_actor_ceiling_manifest(vault: &Vault, seed: u8, actor_rows: Vec<Value>) -> Result<()> {
    let manifest = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.1")),
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

/// One of the pinned seeded actor ids, `[0xA1; 16]`..`[0xA6; 16]`. Constructed
/// directly (with intent) because `test_util::entity` refuses production-pinned
/// seed bytes; these ARE the manifest's pinned identities, not generic fixtures.
fn pinned_seeded_actor_id(byte: u8) -> EntityId {
    assert!(
        (0xA1..=0xA6).contains(&byte),
        "pinned seeded actor id bytes are 0xA1..=0xA6, got {byte:#04x}"
    );
    EntityId::from_bytes([byte; 16]).expect("pinned seeded actor id is non-reserved")
}

/// ONE-1890 successor to the deleted `gate::tests::pinned_actor_ids_not_storable`
/// (AGENT-2 AC test 14, pin E18), relocated here to the chokepoint that owned
/// the behaviour. That test proved `apply_put`'s id-based write door refused
/// ANY entity at `[0xA1; 16]`..`[0xA6; 16]` with `Error::InvalidKey`. This
/// ticket deletes that lockout, so its evidence INVERTS: a pinned id is an
/// ordinary write target and only ordinary rules speak. The seeded type-17
/// occupant makes a re-typed put the ordinary `EntityTypeImmutable`; with that
/// occupant gone the same put simply lands. `InvalidKey` appears in neither arm,
/// and no id-keyed allowlist, denylist, or census survives to produce it.
#[test]
fn pinned_actor_ids_are_ordinary_write_targets() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();

    for byte in 0xA1..=0xA6 {
        let id = pinned_seeded_actor_id(byte);
        let err = vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                test_time_range(1, 1),
                1,
                b"squatter",
            )
            .expect_err("the seeded AGENT_DEF occupant holds the row");
        assert!(
            matches!(
                err,
                Error::Registry(RegistryError::EntityTypeImmutable { existing, attempted, .. })
                    if existing == ENTITY_TYPE_AGENT_DEF && attempted == ENTITY_TYPE_PERSON
            ),
            "expected the ordinary entity-type rule for {byte:#04x}, got {err:?}"
        );
    }

    let scout = pinned_seeded_actor_id(0xA1);
    vault.with_write_txn(|wtxn| {
        crate::batch::deindex_entity_for_test(&vault.store, wtxn, &scout)?;
        Ok(())
    })?;
    vault.put_entity(
        &scout,
        ENTITY_TYPE_PERSON,
        test_time_range(2, 2),
        2,
        b"ordinary",
    )?;
    assert!(vault.get_raw(&scout)?.is_some());
    Ok(())
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
