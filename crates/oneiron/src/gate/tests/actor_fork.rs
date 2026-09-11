//! Actor identity and fork clamp: resolver mapping, herald fork, and effect-actor binding.

use super::*;

#[test]
fn resolver_maps_actors() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let store = &vault.store;

    // The fork parent: an Auto definition stored at Scout's pinned actor id.
    let scout_parent_id = pinned_actor_id(0xA1);
    put_agent_def_row(
        &vault,
        &scout_parent_id,
        "sys.scout",
        AgentCeiling::Auto,
        None,
    )?;
    let scout_fork_id = test_id(0x51);
    put_agent_def_row(
        &vault,
        &scout_fork_id,
        "eiri.scout.fork",
        AgentCeiling::Auto,
        Some("sys.scout"),
    )?;
    let person_id = test_id(0x52);
    vault.put_entity(&person_id, ENTITY_TYPE_PERSON, test_time(1), 1, b"person")?;

    {
        let rtxn = store.env.read_txn()?;
        // A stored Scout fork resolves to its effective ceiling (Auto ∧ Auto).
        assert_eq!(
            agent_definition_ceiling_for_actor(
                store,
                &rtxn,
                WriteActor::new(scout_fork_id, EdgeActorClass::Agent),
            ),
            Some(PolicyApprovalCeiling::Auto)
        );
        // Non-agent classes carry no definition bound.
        assert_eq!(
            agent_definition_ceiling_for_actor(
                store,
                &rtxn,
                WriteActor::new(scout_fork_id, EdgeActorClass::Human),
            ),
            None
        );
        // Absent/deleted agent entity fails closed to Proposed (B3).
        assert_eq!(
            agent_definition_ceiling_for_actor(
                store,
                &rtxn,
                WriteActor::new(test_id(0x53), EdgeActorClass::Agent),
            ),
            Some(PolicyApprovalCeiling::Proposed)
        );
        // Present-but-non-type-17 keeps today's semantics.
        assert_eq!(
            agent_definition_ceiling_for_actor(
                store,
                &rtxn,
                WriteActor::new(person_id, EdgeActorClass::Agent),
            ),
            None
        );
    }

    // Narrowing the stored fork bites the next resolution (live authority).
    put_agent_def_row(
        &vault,
        &scout_fork_id,
        "eiri.scout.fork",
        AgentCeiling::Proposed,
        Some("sys.scout"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, scout_fork_id)?,
        Some(PolicyApprovalCeiling::Proposed)
    );

    // OF-074 symmetry helper: effective = definition ∧ manifest projection.
    assert_eq!(
        dispatched_agent_effective_ceiling(
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Auto
        ),
        PolicyApprovalCeiling::Auto
    );
    assert_eq!(
        dispatched_agent_effective_ceiling(
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Proposed
        ),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(
        dispatched_agent_effective_ceiling(
            PolicyApprovalCeiling::Proposed,
            PolicyApprovalCeiling::Auto
        ),
        PolicyApprovalCeiling::Proposed
    );
    Ok(())
}

#[test]
fn herald_fork_claim_held_to_proposed_under_agent_auto_manifest() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut data = encode_policy_manifest(vec![]);
    append_actor_ceiling(&mut data, actor_ceiling_row("agent", "auto"));
    put_policy_manifest_bytes(&vault, test_id(0xC4), &data)?;

    put_agent_def_row(
        &vault,
        &pinned_actor_id(0xA4),
        "sys.herald",
        AgentCeiling::Proposed,
        None,
    )?;
    let herald_id = test_id(0x61);
    put_agent_def_row(
        &vault,
        &herald_id,
        "eiri.herald.custom",
        AgentCeiling::Auto,
        Some("sys.herald"),
    )?;

    let mut body = source_trust_claim(ClaimSource::UserStated);
    body.approval = ClaimApprovalStatus::Proposed;
    if let ClaimSubject::Entity(subject) = body.subject {
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, test_time(1), 1, b"subject")?;
    }

    let claim_id = test_id(0x62);
    let envelope = WriteEnvelope::new(
        WriteActor::new(herald_id, EdgeActorClass::Agent),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("herald-fork-write"))?,
        ClaimApprovalStatus::Proposed,
    );
    vault
        .batch()
        .claim_candidate(
            &claim_id,
            claim_candidate_from_body(&body),
            &envelope,
            test_time(3),
            3,
        )
        .commit()?;

    // Held to proposal: pending consent recorded with the actor-ceiling
    // reason, approval NOT auto-widened.
    assert!(has_pending_gate_consent(&vault, &claim_id)?);
    let pending = vault.with_write_txn(|wtxn| {
        vault
            .store
            .pending_gate_consent_in_txn(wtxn, &claim_id)?
            .ok_or(Error::CorruptedIndex("pending gate consent"))
    })?;
    assert_eq!(pending.reason_codes, vec!["gate.pending.actor_ceiling"]);
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("held claim").approval,
        ClaimApprovalStatus::Proposed
    );

    // Control: a Scout fork's effective ceiling is Auto under the same
    // manifest — the identical write is not held.
    put_agent_def_row(
        &vault,
        &pinned_actor_id(0xA1),
        "sys.scout",
        AgentCeiling::Auto,
        None,
    )?;
    let scout_id = test_id(0x63);
    put_agent_def_row(
        &vault,
        &scout_id,
        "eiri.scout.custom",
        AgentCeiling::Auto,
        Some("sys.scout"),
    )?;
    let control_id = test_id(0x64);
    let control_envelope = WriteEnvelope::new(
        WriteActor::new(scout_id, EdgeActorClass::Agent),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("scout-fork-write"))?,
        ClaimApprovalStatus::Proposed,
    );
    vault
        .batch()
        .claim_candidate(
            &control_id,
            claim_candidate_from_body(&body),
            &control_envelope,
            test_time(4),
            4,
        )
        .commit()?;
    assert!(!has_pending_gate_consent(&vault, &control_id)?);
    Ok(())
}

#[test]
fn effect_actor_identity_binding_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let auto_id = test_id(0x55);
    vault.put_agent_definition(
        &auto_id,
        &agent_def_fixture("eiri.scout.auto", AgentCeiling::Auto),
        test_time(1),
        1,
    )?;
    let herald_id = test_id(0x56);
    vault.put_agent_definition(
        &herald_id,
        &agent_def_fixture("eiri.herald.proposed", AgentCeiling::Proposed),
        test_time(1),
        1,
    )?;

    // Manifest: the AUTO identity gets an agent-class Auto row plus a scoped
    // grant covering the send verb — fully auto-eligible when bound.
    let mut data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        &auto_id.to_hex(),
        "external:send",
        Value::Map(vec![(Value::from("channel"), Value::from("email"))]),
        None,
    )]);
    append_actor_ceiling(
        &mut data,
        actor_ceiling_row_for_ref("agent", &auto_id.to_hex(), "auto"),
    );
    put_policy_manifest_bytes(&vault, test_id(0xC5), &data)?;
    let policy = resolve(&vault)?;

    let effect_for = |actor_ref: Option<String>, entity_ref: Option<EntityId>| {
        let mut effect = external_effect_gate_input("unused", "send", "email");
        effect.actor.actor_class = "agent".to_owned();
        effect.actor.actor_ref = actor_ref;
        effect.provenance.actor_entity_ref = entity_ref;
        effect
    };

    let mut wtxn = vault.store.env.write_txn()?;

    // Control: the bound pair on the Auto identity is auto-eligible.
    let (_, decision, _) = check_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &effect_for(Some(auto_id.to_hex()), Some(auto_id)),
        &policy,
        true,
    )?;
    assert_eq!(decision.outcome(), GateOutcome::Allow, "bound Auto pair");

    // Borrow attempt: the Proposed identity's provenance under the Auto
    // identity's actor_ref must NOT reach execution.
    let (_, decision, _) = check_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &effect_for(Some(auto_id.to_hex()), Some(herald_id)),
        &policy,
        true,
    )?;
    assert_eq!(
        decision.outcome(),
        GateOutcome::Pending,
        "mismatched pair (auto ref, proposed identity) must hold"
    );

    // Reverse mismatch fails closed the same way.
    let (_, decision, _) = check_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &effect_for(Some(herald_id.to_hex()), Some(auto_id)),
        &policy,
        true,
    )?;
    assert_eq!(
        decision.outcome(),
        GateOutcome::Pending,
        "mismatched pair (proposed ref, auto identity) must hold"
    );

    // An unparsable actor_ref with a real identity is a disagreement.
    let (_, decision, _) = check_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &effect_for(Some("not-an-entity-id".to_owned()), Some(auto_id)),
        &policy,
        true,
    )?;
    assert_eq!(
        decision.outcome(),
        GateOutcome::Pending,
        "unparsable actor_ref must hold"
    );
    drop(wtxn);
    Ok(())
}

#[test]
fn pinned_actor_without_row_is_proposed() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // Delete the ONE-1890 seeded rows so every pinned id is row-less again —
    // including the two whose deleted compiled ceilings were Auto (0xA1 Scout,
    // 0xA2 Keeper) — so nothing can act with preset authority.
    vault.with_write_txn(|wtxn| {
        for byte in 0xA1..=0xA6 {
            crate::batch::deindex_entity_for_test(&vault.store, wtxn, &pinned_actor_id(byte))?;
        }
        Ok(())
    })?;
    for byte in 0xA1..=0xA6 {
        assert_eq!(
            resolved_ceiling(&vault, pinned_actor_id(byte))?,
            Some(PolicyApprovalCeiling::Proposed),
            "pinned id {byte:#04x} without a stored row must fail closed"
        );
    }

    // With a row, the pinned id carries exactly that row's authority — the
    // data-over-rows shape ONE-1890 seeds.
    let scout_id = pinned_actor_id(0xA1);
    put_agent_def_row(&vault, &scout_id, "sys.scout", AgentCeiling::Auto, None)?;
    assert_eq!(
        resolved_ceiling(&vault, scout_id)?,
        Some(PolicyApprovalCeiling::Auto)
    );

    let herald_id = pinned_actor_id(0xA4);
    put_agent_def_row(
        &vault,
        &herald_id,
        "sys.herald",
        AgentCeiling::Proposed,
        None,
    )?;
    assert_eq!(
        resolved_ceiling(&vault, herald_id)?,
        Some(PolicyApprovalCeiling::Proposed)
    );

    // A non-type-17 row at a pinned id is simply not agent-bearing (`None`),
    // the same answer any other non-agent entity gives. Reachable only through
    // the raw store door: the batch.rs write-door lockout still rejects it.
    let keeper_id = pinned_actor_id(0xA2);
    put_raw_entity_row(&vault, &keeper_id, ENTITY_TYPE_PERSON, b"occupant")?;
    assert_eq!(resolved_ceiling(&vault, keeper_id)?, None);
    Ok(())
}

#[test]
fn effect_actor_class_spoof_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let herald_id = test_id(0x57);
    vault.put_agent_definition(
        &herald_id,
        &agent_def_fixture("eiri.herald.proposed", AgentCeiling::Proposed),
        test_time(1),
        1,
    )?;
    let person_id = test_id(0x58);
    vault.put_entity(&person_id, ENTITY_TYPE_PERSON, test_time(1), 1, b"person")?;

    // Every actor ref below is granted class-wide Auto plus a matching send
    // grant, so nothing but the definition clamp (or the class fail-closed
    // arm) can hold these effects.
    let send_grant = |actor_ref: &str| {
        Value::Map(vec![
            (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
            (Value::from(GRANT_EFFECTOR_KEY), Value::from("external:*")),
            (
                Value::from(GRANT_SCOPE_KEY),
                Value::Map(vec![(Value::from("channel"), Value::from("email"))]),
            ),
        ])
    };
    let mut data = encode_policy_manifest(vec![(
        Value::from(POLICY_SCOPED_GRANTS_KEY),
        Value::Array(vec![
            send_grant(&herald_id.to_hex()),
            send_grant(&person_id.to_hex()),
        ]),
    )]);
    replace_actor_ceilings(
        &mut data,
        vec![
            actor_ceiling_row("agent", "auto"),
            actor_ceiling_row("first_party", "auto"),
            actor_ceiling_row("human", "auto"),
        ],
    );
    put_policy_manifest_bytes(&vault, test_id(0xC6), &data)?;
    let policy = resolve(&vault)?;

    let effect_for = |class: &str, id: EntityId| {
        let mut effect = external_effect_gate_input(&id.to_hex(), "send", "email");
        effect.actor.actor_class = class.to_owned();
        effect.provenance.actor_entity_ref = Some(id);
        effect
    };

    let mut wtxn = vault.store.env.write_txn()?;

    // A stored AGENT_DEF is clamped under ANY class string the caller asserts
    // (entity-type-wins), including case variants of "agent" and a class that
    // names something else entirely.
    for spoof in [
        "agent",
        "Agent",
        "AGENT",
        "  AgEnT  ",
        "person",
        "human",
        "system",
        "",
    ] {
        let (_, decision, _) = check_external_effect_policy(
            &vault.store,
            &mut wtxn,
            &effect_for(spoof, herald_id),
            &policy,
            true,
        )?;
        assert_ne!(
            decision.outcome(),
            GateOutcome::Allow,
            "a Proposed-ceiling AGENT_DEF must never auto-fire under class {spoof:?}"
        );
    }

    // An unrecognized class over a NON-agent entity also fails closed rather
    // than skipping the clamp.
    let (_, decision, _) = check_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &effect_for("person", person_id),
        &policy,
        true,
    )?;
    assert_ne!(
        decision.outcome(),
        GateOutcome::Allow,
        "an unrecognized actor class must fail closed"
    );

    // Control: a RECOGNIZED non-agent principal over a non-agent entity keeps
    // today's semantics — the clamp does not over-reach, so the identical
    // request that class "person" fails closed on is auto-allowed here.
    let (_, decision, _) = check_external_effect_policy(
        &vault.store,
        &mut wtxn,
        &effect_for("first_party", person_id),
        &policy,
        true,
    )?;
    assert_eq!(
        decision.outcome(),
        GateOutcome::Allow,
        "a first_party principal over a non-agent entity is not clamped"
    );
    drop(wtxn);
    Ok(())
}

#[test]
fn fork_clamp_reads_parent_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // Parent row NARROWER than the deleted compiled entry: the row clamps an
    // otherwise-Auto fork down.
    put_agent_def_row(
        &vault,
        &pinned_actor_id(0xA1),
        "sys.scout",
        AgentCeiling::Proposed,
        None,
    )?;
    let narrowed_fork = test_id(0x71);
    put_agent_def_row(
        &vault,
        &narrowed_fork,
        "fork.of.scout",
        AgentCeiling::Auto,
        Some("sys.scout"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, narrowed_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "the clamp must take the parent ROW's Proposed, not Scout's compiled Auto"
    );

    // Parent row WIDER than the deleted compiled entry: the fork keeps Auto.
    put_agent_def_row(
        &vault,
        &pinned_actor_id(0xA4),
        "sys.herald",
        AgentCeiling::Auto,
        None,
    )?;
    let widened_fork = test_id(0x72);
    put_agent_def_row(
        &vault,
        &widened_fork,
        "fork.of.herald",
        AgentCeiling::Auto,
        Some("sys.herald"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, widened_fork)?,
        Some(PolicyApprovalCeiling::Auto),
        "the clamp must take the parent ROW's Auto, not Herald's compiled Proposed"
    );

    // The clamp is a MEET, not a replacement: a fork's own Proposed stands
    // against an Auto parent row.
    let self_limited_fork = test_id(0x73);
    put_agent_def_row(
        &vault,
        &self_limited_fork,
        "fork.self.limited",
        AgentCeiling::Proposed,
        Some("sys.herald"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, self_limited_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "min(own, parent-stored): an Auto parent cannot widen a Proposed fork"
    );

    // Live authority: narrowing the PARENT row bites the child's next
    // resolution without the child being touched.
    put_agent_def_row(
        &vault,
        &pinned_actor_id(0xA4),
        "sys.herald",
        AgentCeiling::Proposed,
        None,
    )?;
    assert_eq!(
        resolved_ceiling(&vault, widened_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "the parent row is read live, never snapshotted into the fork"
    );
    Ok(())
}

#[test]
fn fork_clamp_fails_closed_without_parent_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // 1. No parent row at all: an ordinary id that was never written.
    let absent_parent = test_id(0x7F);
    assert!(vault.get_raw(&absent_parent)?.is_none());
    let orphan_fork = test_id(0x74);
    put_agent_def_row(
        &vault,
        &orphan_fork,
        "fork.orphan",
        AgentCeiling::Auto,
        Some(&absent_parent.to_hex()),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, orphan_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "absent parent row must fail closed"
    );

    // 2. Parent row present but not agent-bearing.
    put_raw_entity_row(
        &vault,
        &pinned_actor_id(0xA2),
        ENTITY_TYPE_PERSON,
        b"occupant",
    )?;
    let keeper_fork = test_id(0x75);
    put_agent_def_row(
        &vault,
        &keeper_fork,
        "fork.of.keeper",
        AgentCeiling::Auto,
        Some("sys.keeper"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, keeper_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "non-type-17 parent row must fail closed"
    );

    // 3. Parent row is type-17 but its body does not decode (0xC1 is the
    //    never-used MessagePack byte).
    put_raw_entity_row(
        &vault,
        &pinned_actor_id(0xA3),
        ENTITY_TYPE_AGENT_DEF,
        &[0xC1],
    )?;
    let creative_fork = test_id(0x76);
    put_agent_def_row(
        &vault,
        &creative_fork,
        "fork.of.creative",
        AgentCeiling::Auto,
        Some("sys.creative"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, creative_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "undecodable parent body must fail closed"
    );

    // 4. Parent record too short to carry an entity metadata header.
    let guide_parent_id = pinned_actor_id(0xA5);
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .entities
            .put(wtxn, guide_parent_id.as_bytes(), &[ENTITY_TYPE_AGENT_DEF])?;
        Ok(())
    })?;
    let guide_fork = test_id(0x77);
    put_agent_def_row(
        &vault,
        &guide_fork,
        "fork.of.guide",
        AgentCeiling::Auto,
        Some("sys.guide"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, guide_fork)?,
        Some(PolicyApprovalCeiling::Proposed),
        "unparsable parent header must fail closed"
    );

    // Control: the identical fork shape over a READABLE Auto parent row is not
    // held, so the four clamps above come from the parent arm, not the fixture.
    put_agent_def_row(
        &vault,
        &pinned_actor_id(0xA6),
        "sys.default",
        AgentCeiling::Auto,
        None,
    )?;
    let default_fork = test_id(0x78);
    put_agent_def_row(
        &vault,
        &default_fork,
        "fork.of.default",
        AgentCeiling::Auto,
        Some("sys.default"),
    )?;
    assert_eq!(
        resolved_ceiling(&vault, default_fork)?,
        Some(PolicyApprovalCeiling::Auto),
        "a readable Auto parent row leaves the fork Auto"
    );
    Ok(())
}

#[test]
fn charter_drift_degrades_to_pending_without_debits() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD0), &connector_key_line_send_manifest())?;
    let key_id = test_id(0x7E);
    vault.register_connector_key(
        &key_id,
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::connector_key::EffectorBudget::sends(
                5,
                day_window(),
                crate::connector_key::EffectorBudgetOnExhaust::Suspend,
            )],
            1_000,
        ),
    )?;
    let pending = vault.propose_connector_charter(&key_id, "never delete on line", 1_001)?;
    vault.approve_connector_charter(&key_id, pending.compiled_hash, "owner", 1_002)?;
    let policy = resolve(&vault)?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.send_ref = Some("intent:one".to_owned());

    // Hand-corrupt the stored charter text while keeping the stale stamp.
    let mut record = vault.get_connector_key(&key_id)?.expect("record");
    record.charter.as_mut().expect("charter").text = "never delete on line (edited)".to_owned();
    vault.with_write_txn(|wtxn| {
        crate::connector_key::rewrite_connector_key_in_txn(&vault.store, wtxn, &key_id, &record)
    })?;

    let pending_before = vault
        .diagnostics()
        .gate
        .snapshot()
        .count(GateOutcome::Pending, GateMetricReasonClass::CharterPolicy);
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.pending.charter_drift"]
    );
    assert!(decision.receipt_reasons().contains(&"charter_drift"));
    assert!(charge.is_none(), "drift skips ALL debits");
    let read = vault
        .effector_budget_read("line", None)?
        .expect("governing key");
    assert_eq!(read.rows[0].used, 0, "no debit occurred under drift");
    let pending_after = vault
        .diagnostics()
        .gate
        .snapshot()
        .count(GateOutcome::Pending, GateMetricReasonClass::CharterPolicy);
    assert!(
        pending_after > pending_before,
        "CharterPolicy pending metric counts"
    );

    // A fresh propose/approve cycle re-stamps and restores enforcement.
    let restamp = vault.propose_connector_charter(&key_id, "never delete on line", 1_010)?;
    vault.approve_connector_charter(&key_id, restamp.compiled_hash, "owner", 1_011)?;
    let (decision, charge) = check_effect(&vault, &effect, &policy)?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert!(charge.expect("budget stage ran").matched_rows.contains(&0));
    Ok(())
}

#[test]
fn admitted_wrapper_charges_budget_and_denies_exhausted_key() -> Result<()> {
    // Exercises the PRODUCTION `check_external_effect_policy` (not the
    // `_with_budget` test helper): when admit_for_execution is set the caller
    // applies the effect immediately, so the wrapper itself must debit the
    // governing connector key and flip to a budget-exhausted denial. Before the
    // fix the wrapper ignored the flag and never charged, so an exhausted key
    // could not block an immediately-applied lifecycle effect.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0xD0),
        &connector_key_two_verb_manifest("line"),
    )?;
    vault.register_connector_key(
        &test_id(0x7E),
        crate::connector_key::ConnectorKeyRecord::active(
            "line",
            None,
            vec![crate::connector_key::EffectorBudget::rate(1, 3_600)],
            1_000,
        ),
    )?;
    let policy = resolve(&vault)?;
    // A lifecycle-shaped effect applied immediately: send_ref None.
    let effect = external_effect_gate_input("sender", "provision", "line");
    assert!(effect.send_ref.is_none());

    // First admitted call charges the rate-1 budget through the wrapper.
    let (_, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert!(
        charge.is_some(),
        "the admitted wrapper debited the governing key"
    );

    // The now-exhausted rate row blocks the next admitted lifecycle effect.
    let (_, decision, _) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Deny);
    assert_eq!(
        gate_reason_strs(&decision),
        vec!["gate.deny.effector_budget_exhausted"]
    );

    // Governance-only callers (admit_for_execution = false) still never debit.
    let (_, decision, charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, false)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert!(charge.is_none(), "governance-only checks must not debit");
    Ok(())
}

/// Manual external-effect input composition preserves typed consent reasons:
/// an ungranted irreversible send stays pending, a covering grant yields
/// consent-Auto, and explicit None contributes no consent reasons.
#[test]
fn external_effect_gate_input_composes_consent_context() -> Result<()> {
    // Ungranted: the composed context holds the irreversible send at Ask.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xD5), &encode_policy_manifest(vec![]))?;
    let policy = resolve(&vault)?;
    let effect = external_effect_gate_input("sender", "send", "line");
    let consent = external_effect_consent_context(&effect, None, &[])
        .expect("a send effect composes an honest consent context");
    assert!(matches!(
        consent.decision,
        crate::consent::ConsentDecision::Ask,
    ));
    assert!(matches!(
        consent.reason,
        Some(ConsentPendingReason::IrreversibleEffect),
    ));
    let consent_reasons = consent_ladder_reasons(Some(&consent));
    assert!(!consent_reasons.is_empty());
    let decision = policy.evaluate_gate(&effect.gate_input(None, Some(consent)));
    assert!(matches!(decision.outcome(), GateOutcome::Pending));
    assert!(
        consent_reasons
            .iter()
            .all(|reason| decision.reason_codes().contains(reason)),
    );

    // Covered: a remembered grant auto-runs INSIDE its bound (invariant 1/3).
    let request = external_effect_action_requirement(&effect).expect("requirement");
    let covering = crate::consent::StandingConsentGrant::from_bound(request)
        .expect("a bound mints a standing grant");
    let consent = external_effect_consent_context(&effect, None, &[covering])
        .expect("covered effect composes");
    assert!(matches!(
        consent.decision,
        crate::consent::ConsentDecision::Auto,
    ));
    let decision = policy.evaluate_gate(&effect.gate_input(None, Some(consent)));
    assert!(
        consent_reasons
            .iter()
            .all(|reason| !decision.reason_codes().contains(reason)),
    );

    // Explicit None must not acquire the ungranted send's consent reasons.
    let decision = policy.evaluate_gate(&effect.gate_input(None, None));
    assert!(
        consent_reasons
            .iter()
            .all(|reason| !decision.reason_codes().contains(reason)),
    );
    Ok(())
}

/// TARGET A pin: the store marker is spent by the transaction that authorizes
/// delivery, not by minting or by caller-supplied digest equality.
#[test]
fn approve_once_not_atomic_is_closed_for_production_and_public_evaluation() -> Result<()> {
    const EFFECT_RAN_KEY: &[u8] = b"test.approve_once.production_effect";

    let (_tmp, vault) = temp_vault();
    let owner_id = test_id(0xE0);
    vault.put_entity(&owner_id, ENTITY_TYPE_PERSON, test_time(1), 1, b"owner")?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let actor_ref = owner_id.to_hex();
    let policy_data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
        &actor_ref,
        "external:send",
        Value::Map(vec![(
            Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
            Value::from("line"),
        )]),
        None,
    )]);
    put_policy_manifest_bytes(&vault, test_id(0xD5), &policy_data)?;
    let policy = resolve(&vault)?;

    let production_effect = external_effect_gate_input(&actor_ref, "send", "line");
    let production_digest = external_effect_composed_effect(&production_effect)
        .expect("production effect composes")
        .digest();
    vault.approve_once(&owner, production_digest)?;

    vault.with_write_txn(|wtxn| {
        let governance =
            evaluate_external_effect_policy(&vault.store, wtxn, &production_effect, &policy, None)?;
        assert_eq!(governance.outcome(), GateOutcome::Allow);
        vault.store.vault_meta.put(wtxn, EFFECT_RAN_KEY, b"once")?;
        record_external_effect_policy(&vault.store, wtxn, governance)?;
        Ok(())
    })?;
    let replay = vault
        .with_write_txn(|wtxn| {
            evaluate_external_effect_policy(&vault.store, wtxn, &production_effect, &policy, None)
                .map(|_| ())
        })
        .expect_err("production replay must stop before a second effect");
    assert_eq!(replay.kind(), ErrorKind::ConsentApproveOnceSpent);
    let rtxn = vault.store.env.read_txn()?;
    let effect_ran = vault.store.vault_meta.get(&rtxn, EFFECT_RAN_KEY)?;
    assert_eq!(
        effect_ran.as_deref(),
        Some(b"once".as_slice()),
        "the production effect marker was written exactly once"
    );
    drop(rtxn);

    let public_effect = external_effect_composed_effect(&external_effect_gate_input(
        &owner_id.to_hex(),
        "send",
        "email",
    ))
    .expect("public effect composes");
    let public_digest = public_effect.digest();
    vault.approve_once(&owner, public_digest)?;
    assert_eq!(
        vault
            .evaluate_consent_for(&public_effect, Some(&public_digest))?
            .decision,
        crate::consent::ConsentDecision::Auto
    );
    assert_eq!(
        vault
            .evaluate_consent_for(&public_effect, Some(&public_digest))
            .expect_err("public replay must reject")
            .kind(),
        ErrorKind::ConsentApproveOnceSpent
    );
    Ok(())
}
