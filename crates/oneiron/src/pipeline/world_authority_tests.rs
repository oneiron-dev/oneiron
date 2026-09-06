//! ONE-1420 principal binding, durable default authorship, and authority reuse.

use super::*;
use crate::code_run::HostSelfDispatcher;
use crate::edge::EdgeActorClass;
use crate::pipeline::filters::apply_world_filter;
use crate::pipeline::world_authority::resolve_world_authority;
use crate::write_envelope::{
    ClaimCandidate, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
    WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

#[test]
fn active_set_rejects_missing_principal_and_forged_agent() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    let other = entity_id(0xAD);
    put_entity(&vault, other, crate::registry::ENTITY_TYPE_PERSON, 1, 1, 1)?;
    WorldAccessRowSpec::owner_grant(entity_id(0xB0), fixture.agent, false, &[fixture.world_w])
        .put(&vault)?;
    WorldAccessRowSpec::owner_grant(
        entity_id(0xB1),
        other,
        true,
        &[fixture.world_w, fixture.world_v],
    )
    .put(&vault)?;
    WorldAccessRowSpec::agent_default(entity_id(0xB2), other, false, &[fixture.world_v])
        .put(&vault)?;

    for explicit in [false, true] {
        let unbound = vault.query().search_vector(&FACET_QUERY, 10);
        let unbound = if explicit {
            unbound.active_worlds(other, WorldAuthoritySet::new(false, [fixture.world_v])?)
        } else {
            unbound.default_active_worlds(other)
        };
        assert_matches!(
            unbound.run(),
            Err(Error::InvalidConfig(message)) if message.contains("host-bound execution")
        );

        // This query is bound to A by the host's dispatcher. B's grants and
        // default both exist, but supplying B's id cannot borrow either one.
        let bound = world_access_query(&vault, WORLD_ACCESS_NOW);
        let forged = if explicit {
            bound.active_worlds(other, WorldAuthoritySet::new(false, [fixture.world_v])?)
        } else {
            bound.default_active_worlds(other)
        };
        assert_matches!(
            forged.run(),
            Err(Error::InvalidConfig(message)) if message.contains("executing principal")
        );
    }
    assert_eq!(
        world_access_ids(
            &world_access_query(&vault, WORLD_ACCESS_NOW)
                .active_worlds(
                    fixture.agent,
                    WorldAuthoritySet::new(false, [fixture.world_w])?,
                )
                .run()?
        ),
        HashSet::from([fixture.claim_w])
    );
    // The ordinary unbound scopes are still filters, not new authority doors.
    assert_eq!(
        vault.query().search_vector(&FACET_QUERY, 10).run()?.len(),
        4
    );
    assert!(
        vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .world(WorldScope::WorldSet([0x7B; CODEBASE_SCOPE_KEY_LEN]))
            .run()?
            .is_empty()
    );
    Ok(())
}

#[test]
fn world_query_rejects_foreign_execution_capability() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let (_other_dir, other_vault) = open_test_vault();
    let actor = WriteActor::new(entity_id(0xA0), EdgeActorClass::Agent);
    let execution = HostSelfDispatcher::new(&other_vault, actor, "foreign-world-query")?;
    assert!(matches!(
        vault.query_for_execution(&execution),
        Err(Error::InvalidConfig(message)) if message.contains("different vault")
    ));
    Ok(())
}

#[test]
fn unauthorized_defaults_neither_hijack_selection_nor_deny_reads() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    let other = entity_id(0xAD);
    put_entity(&vault, other, crate::registry::ENTITY_TYPE_PERSON, 1, 1, 1)?;
    WorldAccessRowSpec::owner_grant(
        entity_id(0xB0),
        fixture.agent,
        false,
        &[fixture.world_w, fixture.world_v],
    )
    .put(&vault)?;
    let legitimate_id = entity_id(0xB1);
    WorldAccessRowSpec::agent_default(legitimate_id, fixture.agent, false, &[fixture.world_w])
        .put(&vault)?;

    let mut duplicate_actor = world_default_evidence(fixture.agent)?;
    let Value::Map(entries) = &mut duplicate_actor else {
        unreachable!("envelope evidence is a map");
    };
    entries.push((
        Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
        Value::Binary(fixture.agent.as_bytes().to_vec()),
    ));
    let mut nested_spoof = world_default_evidence(other)?;
    let Value::Map(entries) = &mut nested_spoof else {
        unreachable!("envelope evidence is a map");
    };
    entries.push((
        Value::from(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY),
        world_default_evidence(fixture.agent)?,
    ));
    for (index, (name, evidence)) in [
        ("another agent", Some(world_default_evidence(other)?)),
        ("missing stamp", None),
        ("non-map stamp", Some(Value::from("not-an-envelope"))),
        (
            "short actor ref",
            Some(Value::Map(vec![(
                Value::from(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY),
                Value::Binary(vec![0xA0; 15]),
            )])),
        ),
        ("duplicate actor ref", Some(duplicate_actor)),
        ("nested candidate spoof", Some(nested_spoof)),
        (
            "candidate-only stamp",
            Some(Value::Map(vec![(
                Value::from(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY),
                world_default_evidence(fixture.agent)?,
            )])),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        for malformed in [false, true] {
            let mut row = world_access_claim_body(
                PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
                fixture.agent,
                &WorldAuthoritySet::new(false, [fixture.world_v])?,
                ClaimSource::Inferred,
                ClaimApprovalStatus::Auto,
                Some(WORLD_ACCESS_NOW - 1),
                None,
            )?;
            row.evidence = evidence.clone();
            if malformed {
                row.value = Value::from("not-a-world-access-map");
            }
            // Raw stored-row fixture bypasses candidate admission, as old or
            // replayed rows can. Resolution must still reject its authority.
            let id = entity_id(0xC0 + u8::try_from(index).expect("small matrix"));
            vault.put_claim(&id, &row, TimeRange { start: 1, end: 1 }, WORLD_ACCESS_NOW)?;
            for explicit in [false, true] {
                let query = world_access_query(&vault, WORLD_ACCESS_NOW);
                let query = if explicit {
                    query.active_worlds(
                        fixture.agent,
                        WorldAuthoritySet::new(false, [fixture.world_w])?,
                    )
                } else {
                    query.default_active_worlds(fixture.agent)
                };
                assert_eq!(
                    world_access_ids(&query.run()?),
                    HashSet::from([fixture.claim_w]),
                    "{name}, malformed={malformed}, explicit={explicit}"
                );
            }
            let rtxn = vault.store.env.read_txn()?;
            let resolved = resolve_world_authority(
                &vault.store,
                &rtxn,
                &ActiveWorldSelection {
                    agent_ref: fixture.agent,
                    selected: None,
                },
                WORLD_ACCESS_NOW,
            )?;
            assert_eq!(resolved.default_claim_id, Some(legitimate_id));
        }
    }
    Ok(())
}

#[test]
fn default_candidate_admission_binds_envelope_not_candidate_evidence() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    let other = entity_id(0xAD);
    put_entity(&vault, other, crate::registry::ENTITY_TYPE_PERSON, 1, 1, 1)?;
    WorldAccessRowSpec::owner_grant(entity_id(0xB0), fixture.agent, false, &[fixture.world_w])
        .put(&vault)?;
    let row = world_access_claim_body(
        PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
        fixture.agent,
        &WorldAuthoritySet::new(false, [fixture.world_w])?,
        ClaimSource::Inferred,
        ClaimApprovalStatus::Auto,
        None,
        None,
    )?;
    let other_envelope = WriteEnvelope::new(
        WriteActor::new(other, EdgeActorClass::Agent),
        ClaimSource::Inferred,
        WriteProvenance::new(Value::from("world-default-admission"))?,
        ClaimApprovalStatus::Auto,
    );
    for malformed in [false, true] {
        let id = entity_id(0xB2);
        let value = if malformed {
            Value::from("not-a-world-access-map")
        } else {
            row.value.clone()
        };
        let candidate = ClaimCandidate::new(
            PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
            row.subject,
            value,
            1.0,
        )
        .with_evidence(world_default_evidence(fixture.agent)?);
        assert_matches!(
            vault
                .batch()
                .claim_candidate(
                    &id,
                    candidate,
                    &other_envelope,
                    TimeRange { start: 1, end: 1 },
                    1,
                )
                .commit(),
            Err(Error::InvalidClaimBody(
                "world default subset must be authored by its subject agent"
            ))
        );
        assert!(vault.get_claim(&id)?.is_none());
        assert!(!vault.claims_for_subject(&fixture.agent)?.contains(&id));
    }

    let own_envelope = WriteEnvelope::new(
        WriteActor::new(fixture.agent, EdgeActorClass::Agent),
        ClaimSource::Inferred,
        WriteProvenance::new(Value::from("world-default-admission"))?,
        ClaimApprovalStatus::Auto,
    );
    let own_id = entity_id(0xB3);
    vault
        .batch()
        .claim_candidate(
            &own_id,
            ClaimCandidate::new(
                PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
                row.subject,
                row.value,
                1.0,
            )
            .with_evidence(world_default_evidence(other)?),
            &own_envelope,
            TimeRange { start: 1, end: 1 },
            1,
        )
        .commit()?;
    let stored = vault.get_claim(&own_id)?.expect("self-authored default");
    assert_eq!(
        crate::claim::session_claim_producer(&stored),
        Some(fixture.agent)
    );
    assert_eq!(
        world_access_ids(
            &world_access_query(&vault, WORLD_ACCESS_NOW)
                .default_active_worlds(fixture.agent)
                .run()?
        ),
        HashSet::from([fixture.claim_w]),
        "legitimate envelope identity wins over unrelated candidate-local evidence"
    );
    Ok(())
}

#[test]
fn postfusion_world_filter_uses_resolved_authority_without_a_second_scan() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = world_access_fixture(&vault)?;
    WorldAccessRowSpec::owner_grant(entity_id(0xB0), fixture.agent, false, &[fixture.world_w])
        .put(&vault)?;
    let selection = ActiveWorldSelection {
        agent_ref: fixture.agent,
        selected: Some(WorldAuthoritySet::new(false, [fixture.world_w])?),
    };
    let resolved = {
        let rtxn = vault.store.env.read_txn()?;
        resolve_world_authority(&vault.store, &rtxn, &selection, WORLD_ACCESS_NOW)?
    };
    // Poison the authority adjacency after resolution. A second resolution
    // would fail, but the post-fusion filter consumes only the captured set.
    // Production keeps both stages under one read transaction; splitting the
    // fixture snapshots makes any accidental scan observable here.
    let mut malformed = world_access_body(Value::from("not-a-world-access-map"));
    malformed.source = Some(ClaimSource::UserStated);
    vault.put_claim(
        &entity_id(0xB1),
        &malformed,
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let rtxn = vault.store.env.read_txn()?;
    assert_matches!(
        resolve_world_authority(&vault.store, &rtxn, &selection, WORLD_ACCESS_NOW),
        Err(Error::InvalidConfig(_))
    );
    let mut scores = [
        fixture.claim_base,
        fixture.claim_w,
        fixture.claim_v,
        fixture.plain,
    ]
    .into_iter()
    .map(|id| ScoredEntity { id, score: 1.0 })
    .collect();
    apply_world_filter(
        &mut scores,
        &vault.store,
        &rtxn,
        WorldScope::ActiveSet,
        Some(&resolved.active_set),
    )?;
    assert_eq!(world_access_ids(&scores), HashSet::from([fixture.claim_w]));
    scores.clear();
    assert_matches!(
        apply_world_filter(
            &mut scores,
            &vault.store,
            &rtxn,
            WorldScope::ActiveSet,
            None
        ),
        Err(Error::InvalidConfig(_))
    );
    Ok(())
}
