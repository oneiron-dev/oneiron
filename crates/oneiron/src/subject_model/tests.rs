use super::*;
use crate::claim::ClaimSource;
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::error::ErrorKind;
use crate::identity_topology::{
    IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
    ReassignmentMap, SplitOp, SurvivorshipPlan,
};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_FACET, ENTITY_TYPE_PLACE};
use crate::temporal::TimeRange;
use crate::test_util::{entity, open_test_vault_with, seed_agent_definition};

pub(crate) mod authorization;

fn ensure_actor_subject(
    vault: &Vault,
    actor: EntityId,
    subject: EntityId,
    writer: WriteActor,
    at: u64,
) -> Result<()> {
    vault.with_write_txn(|txn| {
        validate_writer_in_txn(vault, txn, writer)?;
        vault.verify_owner_write_actor_in_txn(txn, &writer)?;
        ensure_actor_subject_in_txn(vault, txn, actor, subject, writer, at)
    })
}

fn ensure_model_person(vault: &Vault, person: EntityId, writer: WriteActor, at: u64) -> Result<()> {
    vault.with_write_txn(|txn| {
        validate_writer_in_txn(vault, txn, writer)?;
        vault.verify_owner_write_actor_in_txn(txn, &writer)?;
        ensure_model_person_in_txn(vault, txn, person, writer, at)
    })
}

fn unrooted_test_vault() -> (tempfile::TempDir, Vault) {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    open_test_vault_with(cfg)
}

fn test_vault() -> (tempfile::TempDir, Vault) {
    let (dir, vault) = unrooted_test_vault();
    seed(&vault, writer().entity_ref(), ENTITY_TYPE_PERSON);
    authorization::root_owner(&vault, writer(), 0xE1).expect("root owner fixture");
    (dir, vault)
}

fn seed(vault: &Vault, id: EntityId, entity_type: u8) -> EntityId {
    if entity_type == ENTITY_TYPE_AGENT_DEF {
        return seed_agent_definition(vault, id, "subject_model");
    }
    vault
        .put_entity(
            &id,
            entity_type,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"subject model fixture",
        )
        .expect("seed entity");
    id
}

fn writer() -> WriteActor {
    WriteActor::new(entity(0x9F), EdgeActorClass::Human)
}

#[test]
fn anchor_to_person_round_trips() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x21), ENTITY_TYPE_AGENT_DEF);
    let person = seed(&vault, entity(0xB1), ENTITY_TYPE_PERSON);

    anchor_actor_subject(&vault, actor, person, writer(), 1_800_000_000)?;

    assert_eq!(actor_subject_anchor(&vault, &actor)?, Some(person));
    Ok(())
}

#[test]
fn anchor_to_org_round_trips() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x22), ENTITY_TYPE_AGENT_DEF);
    let org = seed(&vault, entity(0xB2), ENTITY_TYPE_ORG);

    anchor_actor_subject(&vault, actor, org, writer(), 1_800_000_000)?;

    assert_eq!(actor_subject_anchor(&vault, &actor)?, Some(org));
    Ok(())
}

/// An actor with no anchor is PLUMBING, and plumbing is a legal, complete
/// answer — not a missing record to be repaired with a placeholder someone.
#[test]
fn plumbing_actor_has_no_anchor_and_is_not_an_error() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x23), ENTITY_TYPE_AGENT_DEF);

    assert_eq!(actor_subject_anchor(&vault, &actor)?, None);

    // Nothing was minted to fill the hole.
    assert!(vault.claims_for_subject(&actor)?.is_empty());
    Ok(())
}

#[test]
fn anchor_subject_must_be_person_or_org() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x24), ENTITY_TYPE_AGENT_DEF);

    for (seed_id, wrong_type) in [
        (entity(0xC1), ENTITY_TYPE_PLACE),
        (entity(0xC2), ENTITY_TYPE_FACET),
        (entity(0xC3), ENTITY_TYPE_AGENT_DEF),
    ] {
        let wrong = seed(&vault, seed_id, wrong_type);
        let err = anchor_actor_subject(&vault, actor, wrong, writer(), 1_800_000_000)
            .expect_err("non person/org subject must be refused");
        assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    }

    // A subject that does not exist at all is refused on the same axis.
    let err = anchor_actor_subject(&vault, actor, entity(0xC9), writer(), 1_800_000_000)
        .expect_err("absent subject must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    // Nothing landed on any rejection.
    assert_eq!(actor_subject_anchor(&vault, &actor)?, None);
    Ok(())
}

/// One actor, one active anchor: re-anchoring closes the prior head rather
/// than leaving two live answers to "who is this".
#[test]
fn reanchoring_supersedes_the_prior_anchor() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x25), ENTITY_TYPE_AGENT_DEF);
    let first = seed(&vault, entity(0xB5), ENTITY_TYPE_PERSON);
    let second = seed(&vault, entity(0xB6), ENTITY_TYPE_ORG);

    anchor_actor_subject(&vault, actor, first, writer(), 1_800_000_000)?;
    anchor_actor_subject(&vault, actor, second, writer(), 1_800_000_100)?;

    assert_eq!(actor_subject_anchor(&vault, &actor)?, Some(second));
    Ok(())
}

#[test]
fn substrate_accepts_exactly_meat_and_model_on_a_person() -> Result<()> {
    let (_dir, vault) = test_vault();
    let person = seed(&vault, entity(0xD1), ENTITY_TYPE_PERSON);

    for substrate in [PersonSubstrate::Meat, PersonSubstrate::Model] {
        set_person_substrate(&vault, person, substrate, writer(), 1_800_000_000)?;
        assert_eq!(person_substrate(&vault, &person)?, Some(substrate));
    }

    // The wire vocabulary is closed at exactly two spellings.
    assert_eq!(PersonSubstrate::parse("meat"), Some(PersonSubstrate::Meat));
    assert_eq!(
        PersonSubstrate::parse("model"),
        Some(PersonSubstrate::Model)
    );
    for rejected in ["human", "ai", "Meat", "MODEL", "flesh", ""] {
        assert_eq!(PersonSubstrate::parse(rejected), None, "{rejected}");
    }
    Ok(())
}

/// Substrate is a property of a PERSON, not a fork of the entity kind: an ORG
/// has no substrate, and neither does a bare actor.
#[test]
fn substrate_is_person_only() -> Result<()> {
    let (_dir, vault) = test_vault();
    let org = seed(&vault, entity(0xD2), ENTITY_TYPE_ORG);
    let agent = seed(&vault, entity(0xD3), ENTITY_TYPE_AGENT_DEF);

    for subject in [org, agent] {
        let err = set_person_substrate(
            &vault,
            subject,
            PersonSubstrate::Model,
            writer(),
            1_800_000_000,
        )
        .expect_err("non-PERSON substrate must be refused");
        assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
        // The refusal is total: no partial row landed on the subject.
        assert_eq!(person_substrate(&vault, &subject)?, None);
    }
    Ok(())
}

/// A `model` person is still a PERSON: the substrate claim never changes the
/// stored entity type, so no ACTOR/AI kind is minted behind the scenes.
#[test]
fn substrate_never_forks_the_entity_kind() -> Result<()> {
    let (_dir, vault) = test_vault();
    let person = seed(&vault, entity(0xD4), ENTITY_TYPE_PERSON);
    let actor = seed(&vault, entity(0xD5), ENTITY_TYPE_AGENT_DEF);

    set_person_substrate(
        &vault,
        person,
        PersonSubstrate::Model,
        writer(),
        1_800_000_000,
    )?;
    anchor_actor_subject(&vault, actor, person, writer(), 1_800_000_000)?;

    assert_eq!(vault.get_entity_type(&person)?, Some(ENTITY_TYPE_PERSON));
    assert_eq!(vault.get_entity_type(&actor)?, Some(ENTITY_TYPE_AGENT_DEF));
    Ok(())
}

/// Both writes carry the authenticated writer into durable evidence.
#[test]
fn writes_stamp_the_authenticated_writer() -> Result<()> {
    let (_dir, vault) = unrooted_test_vault();
    let person = seed(&vault, entity(0x31), ENTITY_TYPE_PERSON);
    let actor = seed(&vault, entity(0x32), ENTITY_TYPE_AGENT_DEF);
    let author_ref = seed(&vault, entity(0x33), ENTITY_TYPE_PERSON);
    let author = WriteActor::new(author_ref, EdgeActorClass::Human);
    authorization::root_owner(&vault, author, 0xE7)?;

    let anchor_claim = anchor_actor_subject(&vault, actor, person, author, 1_800_000_000)?;
    let substrate_claim =
        set_person_substrate(&vault, person, PersonSubstrate::Meat, author, 1_800_000_000)?;

    for claim_id in [anchor_claim, substrate_claim] {
        let body = vault.get_claim(&claim_id)?.expect("claim body");
        let evidence = body.evidence.expect("writer evidence stamped");
        let rendered = format!("{evidence:?}");
        assert!(rendered.contains(&entity(0x33).to_hex()), "{rendered}");
        assert!(rendered.contains("human"), "{rendered}");
        assert_eq!(body.source, Some(ClaimSource::Observed));
    }
    Ok(())
}

/// GAP-3: split-record repair is the EXISTING merge redirect read at
/// resolution time. After merging two PERSON records, the anchor written
/// against the absorbed one resolves to the survivor — and the stored claim
/// subject is never rewritten, which is what keeps an unmerge possible.
#[test]
fn merged_subject_resolves_to_survivor() -> Result<()> {
    for entity_type in [ENTITY_TYPE_PERSON, ENTITY_TYPE_ORG] {
        let (_dir, vault) = test_vault();
        let actor = seed(&vault, entity(0xF1), ENTITY_TYPE_AGENT_DEF);
        let absorbed = seed(&vault, entity(0xF2), entity_type);
        let survivor = seed(&vault, entity(0xF3), entity_type);

        let claim_id = anchor_actor_subject(&vault, actor, absorbed, writer(), 1_800_000_000)?;
        assert_eq!(actor_subject_anchor(&vault, &actor)?, Some(absorbed));

        let outcome = vault.apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![absorbed],
                survivor,
                evidence: IdentityOpEvidence {
                    refs: Vec::new(),
                    rationale: "same someone".to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            1_800_000_500,
        )?;
        assert!(matches!(outcome, IdentityOpOutcome::Applied { .. }));

        // The READ canonicalizes...
        assert_eq!(actor_subject_anchor(&vault, &actor)?, Some(survivor));

        // ...while the LEDGER still says exactly what the writer stated. No second
        // same-as table, no historical claim rewrite.
        let body = vault.get_claim(&claim_id)?.expect("anchor claim body");
        assert_eq!(body.value.as_str(), Some(absorbed.to_hex()).as_deref());
    }
    Ok(())
}

/// A subject that split into several someones has no determinate answer, so
/// the anchor reads as `None` rather than guessing one of the heads.
#[test]
fn ambiguous_split_subject_resolves_to_no_determinate_someone() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x41), ENTITY_TYPE_AGENT_DEF);
    let conflated = seed(&vault, entity(0x45), ENTITY_TYPE_PERSON);
    let head_a = seed(&vault, entity(0x43), ENTITY_TYPE_PERSON);
    let head_b = seed(&vault, entity(0x44), ENTITY_TYPE_PERSON);

    let claim_id = anchor_actor_subject(&vault, actor, conflated, writer(), 1_800_000_000)?;
    assert_eq!(actor_subject_anchor(&vault, &actor)?, Some(conflated));

    vault.apply_identity_topology_op(
        &IdentityTopologyOp::Split(SplitOp {
            entity: conflated,
            heads: vec![head_a, head_b],
            reassignment: ReassignmentMap::default(),
            evidence: IdentityOpEvidence {
                refs: Vec::new(),
                rationale: "two people wearing one record".to_owned(),
            },
        }),
        &IdentityOpWrite::auto(ClaimSource::Inferred),
        1_800_000_500,
    )?;

    assert_eq!(
        actor_subject_anchor(&vault, &actor)?,
        None,
        "two candidate someones is not one someone"
    );
    let body = vault.get_claim(&claim_id)?.expect("historical anchor");
    assert_eq!(body.value, Value::from(conflated.to_hex()));
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(vault.resolve_entity(&conflated)?, vec![head_a, head_b]);
    Ok(())
}

#[test]
fn typed_vault_subject_doors_check_kind_and_provenance() -> Result<()> {
    let (_dir, vault) = unrooted_test_vault();
    let actor = seed(&vault, entity(0x61), ENTITY_TYPE_AGENT_DEF);
    let person = seed(&vault, entity(0x62), ENTITY_TYPE_PERSON);
    let anchor = ActorSubjectAnchor {
        actor_ref: actor,
        subject_ref: person,
        subject_kind: SubjectKind::Person,
    };
    let author = WriteActor::new(person, EdgeActorClass::Human);
    authorization::root_owner(&vault, author, 0xE8)?;
    let claim_id = vault.set_actor_subject_anchor(anchor, &author, 1_800_000_000)?;
    assert_eq!(vault.actor_subject_anchor(&actor)?, Some(anchor));
    let substrate_id =
        vault.set_person_substrate(person, PersonSubstrate::Model, &author, 1_800_000_000)?;
    assert_eq!(
        vault.person_substrate(&person)?,
        Some(PersonSubstrate::Model)
    );
    for id in [claim_id, substrate_id] {
        let body = vault.get_claim(&id)?.expect("claim stored");
        assert_eq!(body.evidence, Some(writer_evidence(author)));
        assert_eq!(body.source, Some(ClaimSource::Observed));
        assert_eq!(body.valid_from, Some(1_800_000_000));
    }
    assert_eq!(
        vault
            .set_actor_subject_anchor(
                ActorSubjectAnchor {
                    subject_kind: SubjectKind::Org,
                    ..anchor
                },
                &author,
                1_800_000_100,
            )
            .expect_err("declared kind must match stored kind")
            .kind(),
        ErrorKind::InvalidClaimBody,
    );
    assert_eq!(vault.actor_subject_anchor(&actor)?, Some(anchor));
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("old anchor").lifecycle,
        ClaimLifecycleStatus::Active,
    );
    Ok(())
}

#[test]
fn typed_anchor_door_requires_the_same_owner_as_the_free_door() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0xA1), ENTITY_TYPE_AGENT_DEF);
    let person = seed(&vault, entity(0xA2), ENTITY_TYPE_PERSON);
    let other = seed(&vault, entity(0xA3), ENTITY_TYPE_ORG);
    let stranger = seed(&vault, entity(0xA4), ENTITY_TYPE_PERSON);
    let machine = seed(&vault, entity(0xA5), crate::registry::ENTITY_TYPE_MACHINE);
    let anchor = ActorSubjectAnchor {
        actor_ref: actor,
        subject_ref: person,
        subject_kind: SubjectKind::Person,
    };
    let outsiders = [
        WriteActor::new(stranger, EdgeActorClass::Human),
        WriteActor::new(actor, EdgeActorClass::Agent),
        WriteActor::new(machine, EdgeActorClass::System),
    ];
    for outsider in outsiders {
        assert!(vault.set_actor_subject_anchor(anchor, &outsider, 100).is_err());
        assert!(vault.claims_for_subject(&actor)?.is_empty());
    }
    let claim = vault.set_actor_subject_anchor(anchor, &writer(), 100)?;
    let before = vault.get_claim(&claim)?;
    let claims = vault.claims_for_subject(&actor)?;
    let replacement = ActorSubjectAnchor {
        subject_ref: other,
        subject_kind: SubjectKind::Org,
        ..anchor
    };
    for outsider in outsiders {
        assert!(vault.set_actor_subject_anchor(replacement, &outsider, 101).is_err());
        assert_eq!(vault.actor_subject_anchor(&actor)?, Some(anchor));
        assert_eq!(vault.get_claim(&claim)?, before);
        assert_eq!(vault.claims_for_subject(&actor)?, claims);
    }
    vault.set_actor_subject_anchor(replacement, &writer(), 102)?;
    assert_eq!(vault.actor_subject_anchor(&actor)?, Some(replacement));
    Ok(())
}

#[test]
fn missing_or_misclassified_writer_cannot_change_subject_claims() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x63), ENTITY_TYPE_AGENT_DEF);
    let person = seed(&vault, entity(0x64), ENTITY_TYPE_PERSON);
    let anchor = ActorSubjectAnchor {
        actor_ref: actor,
        subject_ref: person,
        subject_kind: SubjectKind::Person,
    };
    let first = vault.set_actor_subject_anchor(anchor, &writer(), 1_800_000_000)?;
    let substrate =
        vault.set_person_substrate(person, PersonSubstrate::Meat, &writer(), 1_800_000_000)?;
    for (author, expected) in [
        (
            WriteActor::new(entity(0x65), EdgeActorClass::Human),
            ErrorKind::EntityNotFound,
        ),
        (
            WriteActor::new(actor, EdgeActorClass::Human),
            ErrorKind::ActorClassMismatch,
        ),
    ] {
        assert_eq!(
            vault
                .set_actor_subject_anchor(anchor, &author, 1_800_000_100)
                .expect_err("writer binding must be checked")
                .kind(),
            expected,
        );
        assert_eq!(
            vault
                .set_person_substrate(person, PersonSubstrate::Model, &author, 1_800_000_100)
                .expect_err("substrate uses the same writer check")
                .kind(),
            expected,
        );
        assert_eq!(
            ensure_actor_subject(&vault, actor, person, author, 1_800_000_100)
                .expect_err("an idempotent ensure still checks its writer")
                .kind(),
            expected,
        );
        assert_eq!(
            ensure_model_person(&vault, person, author, 1_800_000_100)
                .expect_err("model ensure checks its writer before the prior fact")
                .kind(),
            expected,
        );
    }
    for id in [first, substrate] {
        assert_eq!(
            vault.get_claim(&id)?.expect("original claim").lifecycle,
            ClaimLifecycleStatus::Active,
        );
    }
    assert_eq!(
        vault.person_substrate(&person)?,
        Some(PersonSubstrate::Meat)
    );
    Ok(())
}

#[test]
fn conflicting_anchor_heads_fail_closed_and_reanchoring_closes_them_all() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x66), ENTITY_TYPE_AGENT_DEF);
    let first_subject = seed(&vault, entity(0x67), ENTITY_TYPE_PERSON);
    let second_subject = seed(&vault, entity(0x68), ENTITY_TYPE_ORG);
    let first = anchor_actor_subject(&vault, actor, first_subject, writer(), 1_800_000_000)?;
    let second = entity(0x69);
    let mut competing = vault.get_claim(&first)?.expect("anchor claim");
    competing.value = Value::from(second_subject.to_hex());
    vault.with_write_txn(|wtxn| {
        vault.put_reserved_claim_in_txn(
            wtxn,
            &second,
            &competing,
            TimeRange {
                start: 1_800_000_000,
                end: 1_800_000_000,
            },
            1_800_000_000,
        )
    })?;
    assert_eq!(
        vault
            .actor_subject_anchor(&actor)
            .expect_err("never choose the first active head")
            .kind(),
        ErrorKind::InvalidClaimBody,
    );
    let replacement = anchor_actor_subject(&vault, actor, second_subject, writer(), 1_800_000_100)?;
    assert_eq!(actor_subject_anchor(&vault, &actor)?, Some(second_subject));
    for id in [first, second] {
        let body = vault.get_claim(&id)?.expect("historical claim");
        assert_eq!(body.lifecycle, ClaimLifecycleStatus::Superseded);
        assert_eq!(body.valid_to, Some(1_800_000_100));
    }
    assert_eq!(
        vault.get_claim(&replacement)?.expect("new head").lifecycle,
        ClaimLifecycleStatus::Active,
    );
    Ok(())
}

#[test]
fn malformed_subject_values_are_not_projected_as_plumbing() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x6A), ENTITY_TYPE_AGENT_DEF);
    let person = seed(&vault, entity(0x6B), ENTITY_TYPE_PERSON);
    let place = seed(&vault, entity(0x6C), ENTITY_TYPE_PLACE);
    let id = anchor_actor_subject(&vault, actor, person, writer(), 1_800_000_000)?;
    let mut body = vault.get_claim(&id)?.expect("anchor claim");
    for value in [Value::from("not-an-id"), Value::from(place.to_hex())] {
        body.value = value;
        vault.with_write_txn(|wtxn| {
            vault.put_reserved_claim_in_txn(
                wtxn,
                &id,
                &body,
                TimeRange {
                    start: 1_800_000_000,
                    end: 1_800_000_000,
                },
                1_800_000_000,
            )
        })?;
        assert_eq!(
            vault
                .actor_subject_anchor(&actor)
                .expect_err("corrupt anchor")
                .kind(),
            ErrorKind::InvalidClaimBody,
        );
    }
    Ok(())
}

#[test]
fn substrate_reader_refuses_generic_claims_with_invalid_value_or_subject() -> Result<()> {
    let (_dir, vault) = test_vault();
    let person = seed(&vault, entity(0x6D), ENTITY_TYPE_PERSON);
    let org = seed(&vault, entity(0x6E), ENTITY_TYPE_ORG);
    for (id, subject, value) in [
        (entity(0x71), person, "human"),
        (entity(0x72), org, "model"),
    ] {
        let mut body = ClaimBody::new(
            PREDICATE_PERSON_SUBSTRATE,
            ClaimSubject::Entity(subject),
            Value::from(value),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::Observed);
        vault.put_claim(
            &id,
            &body,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )?;
        assert_eq!(
            vault
                .person_substrate(&subject)
                .expect_err("invalid substrate must not project")
                .kind(),
            ErrorKind::InvalidClaimBody,
        );
    }
    Ok(())
}

fn merge_substrate_person(vault: &Vault, source: EntityId, survivor: EntityId) -> Result<EntityId> {
    let outcome = vault.apply_identity_topology_op(
        &IdentityTopologyOp::Merge(MergeOp {
            sources: vec![source],
            survivor,
            evidence: IdentityOpEvidence {
                refs: Vec::new(),
                rationale: "substrate merge fixture".to_owned(),
            },
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }),
        &IdentityOpWrite::auto(ClaimSource::Inferred),
        300,
    )?;
    let IdentityOpOutcome::Applied { event, .. } = outcome else {
        panic!("merge must apply: {outcome:?}");
    };
    Ok(event)
}

#[test]
fn substrate_follows_merged_anchor_and_supersedes_across_historical_subjects() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x81), ENTITY_TYPE_AGENT_DEF);
    let absorbed = seed(&vault, entity(0x82), ENTITY_TYPE_PERSON);
    let middle = seed(&vault, entity(0x83), ENTITY_TYPE_PERSON);
    let survivor = seed(&vault, entity(0x84), ENTITY_TYPE_PERSON);
    anchor_actor_subject(&vault, actor, absorbed, writer(), 100)?;
    let first = vault.set_person_substrate(absorbed, PersonSubstrate::Model, &writer(), 100)?;
    let original = vault.get_claim(&first)?.expect("original substrate");
    merge_substrate_person(&vault, absorbed, middle)?;
    merge_substrate_person(&vault, middle, survivor)?;
    let canonical = vault
        .actor_subject_anchor(&actor)?
        .expect("canonical anchor")
        .subject_ref;
    assert_eq!(canonical, survivor);
    for id in [absorbed, middle, canonical] {
        assert_eq!(vault.person_substrate(&id)?, Some(PersonSubstrate::Model));
    }
    assert_eq!(vault.get_claim(&first)?, Some(original.clone()));

    let second = vault.set_person_substrate(canonical, PersonSubstrate::Meat, &writer(), 400)?;
    let third = vault.set_person_substrate(absorbed, PersonSubstrate::Model, &writer(), 500)?;
    for (id, subject, valid_to) in [(first, absorbed, 400), (second, survivor, 500)] {
        let historical = vault.get_claim(&id)?.expect("historical substrate");
        assert_eq!(historical.subject, ClaimSubject::Entity(subject));
        assert_eq!(historical.lifecycle, ClaimLifecycleStatus::Superseded);
        assert_eq!(historical.valid_to, Some(valid_to));
        assert_eq!(historical.evidence, original.evidence);
    }
    let latest = vault.get_claim(&third)?.expect("new substrate");
    assert_eq!(latest.subject, ClaimSubject::Entity(absorbed));
    assert_eq!(latest.lifecycle, ClaimLifecycleStatus::Active);
    for id in [absorbed, middle, survivor] {
        assert_eq!(vault.person_substrate(&id)?, Some(PersonSubstrate::Model));
    }
    Ok(())
}

#[test]
fn substrate_merge_undo_restores_original_subject_without_rewriting_claims() -> Result<()> {
    let (_dir, vault) = test_vault();
    let absorbed = seed(&vault, entity(0x85), ENTITY_TYPE_PERSON);
    let survivor = seed(&vault, entity(0x86), ENTITY_TYPE_PERSON);
    let claim = vault.set_person_substrate(absorbed, PersonSubstrate::Meat, &writer(), 100)?;
    let original = vault.get_claim(&claim)?;
    let merge = merge_substrate_person(&vault, absorbed, survivor)?;
    assert_eq!(
        vault.person_substrate(&survivor)?,
        Some(PersonSubstrate::Meat)
    );
    vault.undo_identity_topology_event(
        &merge,
        &IdentityOpWrite::auto(ClaimSource::Inferred),
        400,
    )?;
    assert_eq!(vault.person_substrate(&survivor)?, None);
    assert_eq!(
        vault.person_substrate(&absorbed)?,
        Some(PersonSubstrate::Meat)
    );
    assert_eq!(vault.get_claim(&claim)?, original);
    Ok(())
}

#[test]
fn substrate_split_refuses_ambiguous_reads_and_writes_without_closing_history() -> Result<()> {
    for head_count in [0, 2] {
        let (_dir, vault) = test_vault();
        let original = seed(&vault, entity(0x87), ENTITY_TYPE_PERSON);
        let heads = [
            seed(&vault, entity(0x88), ENTITY_TYPE_PERSON),
            seed(&vault, entity(0x89), ENTITY_TYPE_PERSON),
        ];
        let claim = vault.set_person_substrate(original, PersonSubstrate::Model, &writer(), 100)?;
        let historical = vault.get_claim(&claim)?;
        vault.apply_identity_topology_op(
            &IdentityTopologyOp::Split(SplitOp {
                entity: original,
                heads: heads[..head_count].to_vec(),
                reassignment: ReassignmentMap::default(),
                evidence: IdentityOpEvidence {
                    refs: Vec::new(),
                    rationale: "no single person".to_owned(),
                },
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            300,
        )?;
        for subject in std::iter::once(original).chain(heads[..head_count].iter().copied()) {
            assert_eq!(
                vault
                    .person_substrate(&subject)
                    .expect_err("split is not one person")
                    .kind(),
                ErrorKind::InvalidClaimBody,
            );
            assert_eq!(
                vault
                    .set_person_substrate(subject, PersonSubstrate::Meat, &writer(), 400)
                    .expect_err("a split must not be guessed or superseded")
                    .kind(),
                ErrorKind::InvalidClaimBody,
            );
        }
        assert_eq!(vault.get_claim(&claim)?, historical);
    }
    Ok(())
}

#[test]
fn substrate_merged_conflicting_or_malformed_heads_fail_closed_atomically() -> Result<()> {
    for competing in [Some("meat"), Some("model"), None] {
        let (_dir, vault) = test_vault();
        let absorbed = seed(&vault, entity(0x8A), ENTITY_TYPE_PERSON);
        let survivor = seed(&vault, entity(0x8B), ENTITY_TYPE_PERSON);
        let first = vault.set_person_substrate(absorbed, PersonSubstrate::Model, &writer(), 100)?;
        let mut claims = vec![first];
        if let Some(value) = competing {
            let second = entity(0x8C);
            let mut body = vault.get_claim(&first)?.expect("substrate");
            body.subject = ClaimSubject::Entity(survivor);
            body.value = Value::from(value);
            vault.put_claim(
                &second,
                &body,
                TimeRange {
                    start: 100,
                    end: 100,
                },
                100,
            )?;
            claims.push(second);
        } else {
            let mut body = vault.get_claim(&first)?.expect("substrate");
            body.value = Value::from("not-a-substrate");
            vault.put_claim(
                &first,
                &body,
                TimeRange {
                    start: 100,
                    end: 100,
                },
                100,
            )?;
        }
        merge_substrate_person(&vault, absorbed, survivor)?;
        let before = claims
            .iter()
            .map(|id| vault.get_claim(id))
            .collect::<Result<Vec<_>>>()?;
        for subject in [absorbed, survivor] {
            assert_eq!(
                vault
                    .person_substrate(&subject)
                    .expect_err("no arbitrary head")
                    .kind(),
                ErrorKind::InvalidClaimBody,
            );
            let before_ids = vault.claims_for_subject(&subject)?;
            assert_eq!(
                vault
                    .set_person_substrate(subject, PersonSubstrate::Meat, &writer(), 400)
                    .expect_err("invalid active heads require explicit repair")
                    .kind(),
                ErrorKind::InvalidClaimBody,
            );
            assert_eq!(vault.claims_for_subject(&subject)?, before_ids);
        }
        assert_eq!(
            claims
                .iter()
                .map(|id| vault.get_claim(id))
                .collect::<Result<Vec<_>>>()?,
            before
        );
    }
    Ok(())
}

#[test]
fn substrate_rejects_malformed_dangling_wrong_kind_and_cyclic_redirects() -> Result<()> {
    let (_dir, vault) = test_vault();
    let person = seed(&vault, entity(0x8D), ENTITY_TYPE_PERSON);
    let org = seed(&vault, entity(0x8E), ENTITY_TYPE_ORG);
    let claim = vault.set_person_substrate(person, PersonSubstrate::Meat, &writer(), 100)?;
    let historical = vault.get_claim(&claim)?;
    let mut key = crate::identity_redirect::REDIRECT_TABLE_META_PREFIX.to_vec();
    key.extend_from_slice(person.as_bytes());
    let row = |target: EntityId| {
        let mut bytes = vec![1];
        bytes.extend_from_slice(target.as_bytes());
        bytes
    };
    for (bytes, kind) in [
        (vec![0xFF], ErrorKind::CorruptedIndex),
        (row(entity(0x8F)), ErrorKind::InvalidClaimBody),
        (row(org), ErrorKind::InvalidClaimBody),
        (row(person), ErrorKind::CorruptedIndex),
    ] {
        vault.with_write_txn(|wtxn| {
            vault.store.vault_meta.put(wtxn, &key, &bytes)?;
            Ok(())
        })?;
        assert_eq!(
            vault
                .person_substrate(&person)
                .expect_err("bad redirect")
                .kind(),
            kind
        );
        assert_eq!(
            vault
                .set_person_substrate(person, PersonSubstrate::Model, &writer(), 400)
                .expect_err("bad redirect must not admit a replacement")
                .kind(),
            kind,
        );
        assert_eq!(vault.get_claim(&claim)?, historical);
    }
    Ok(())
}

#[test]
fn onboarding_anchor_ensure_is_idempotent_and_never_reanchors() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x61), ENTITY_TYPE_AGENT_DEF);
    let first = seed(&vault, entity(0x62), ENTITY_TYPE_PERSON);
    let second = seed(&vault, entity(0x63), ENTITY_TYPE_ORG);
    ensure_actor_subject(&vault, actor, first, writer(), 100)?;
    let claims = vault.claims_for_subject(&actor)?;
    ensure_actor_subject(&vault, actor, first, writer(), 100)?;
    assert_eq!(vault.claims_for_subject(&actor)?.len(), claims.len());
    let err = ensure_actor_subject(&vault, actor, second, writer(), 101)
        .expect_err("ensure cannot re-anchor");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(actor_subject_anchor(&vault, &actor)?, Some(first));
    let claim = vault.get_claim(&claims[0])?.expect("onboarding anchor");
    assert_eq!(claim.evidence, Some(writer_evidence(writer())));
    assert_eq!(claim.source, Some(ClaimSource::Observed));
    let survivor = seed(&vault, entity(0x64), ENTITY_TYPE_PERSON);
    merge_substrate_person(&vault, first, survivor)?;
    ensure_actor_subject(&vault, actor, first, writer(), 400)?;
    assert_eq!(
        ensure_actor_subject(&vault, actor, survivor, writer(), 400)
            .expect_err("a canonical read must not rewrite the stored anchor")
            .kind(),
        ErrorKind::InvalidClaimBody,
    );
    assert_eq!(actor_subject_anchor(&vault, &actor)?, Some(survivor));
    assert_eq!(vault.get_claim(&claims[0])?, Some(claim));
    assert_eq!(vault.claims_for_subject(&actor)?, claims);
    Ok(())
}

#[test]
fn model_ensure_never_reclassifies_a_meat_person() -> Result<()> {
    let (_dir, vault) = test_vault();
    let person = seed(&vault, entity(0x64), ENTITY_TYPE_PERSON);
    set_person_substrate(&vault, person, PersonSubstrate::Meat, writer(), 100)?;
    let err = ensure_model_person(&vault, person, writer(), 101)
        .expect_err("a meat person cannot become a companion");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(
        person_substrate(&vault, &person)?,
        Some(PersonSubstrate::Meat)
    );
    let survivor = seed(&vault, entity(0x65), ENTITY_TYPE_PERSON);
    merge_substrate_person(&vault, person, survivor)?;
    let history = vault.claims_for_subject(&person)?;
    let survivor_claims = vault.claims_for_subject(&survivor)?;
    assert_eq!(
        ensure_model_person(&vault, survivor, writer(), 400)
            .expect_err("merged meat is not an absent substrate")
            .kind(),
        ErrorKind::InvalidClaimBody,
    );
    assert_eq!(vault.claims_for_subject(&person)?, history);
    assert_eq!(vault.claims_for_subject(&survivor)?, survivor_claims);
    let model = seed(&vault, entity(0x66), ENTITY_TYPE_PERSON);
    ensure_model_person(&vault, model, writer(), 100)?;
    let claims = vault.claims_for_subject(&model)?;
    ensure_model_person(&vault, model, writer(), 101)?;
    assert_eq!(vault.claims_for_subject(&model)?, claims);
    assert_eq!(person_substrate(&vault, &model)?, Some(PersonSubstrate::Model));
    Ok(())
}

#[test]
fn concurrent_onboarding_cannot_reanchor_the_same_house() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x65), ENTITY_TYPE_AGENT_DEF);
    let first = seed(&vault, entity(0x66), ENTITY_TYPE_ORG);
    let second = seed(&vault, entity(0x67), ENTITY_TYPE_ORG);
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            barrier.wait();
            ensure_actor_subject(&vault, actor, first, writer(), 100)
        });
        let two = scope.spawn(|| {
            barrier.wait();
            ensure_actor_subject(&vault, actor, second, writer(), 100)
        });
        [
            one.join().expect("first thread"),
            two.join().expect("second thread"),
        ]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(vault.claims_for_subject(&actor)?.len(), 1);
    Ok(())
}

#[test]
fn conflicting_or_malformed_active_substrates_fail_closed() -> Result<()> {
    let (_dir, vault) = test_vault();
    let person = seed(&vault, entity(0x68), ENTITY_TYPE_PERSON);
    for (id, value) in [(entity(0x69), "meat"), (entity(0x6A), "model")] {
        let body = subject_fact(
            PREDICATE_PERSON_SUBSTRATE,
            person,
            Value::from(value),
            writer(),
            100,
        );
        vault.put_claim(
            &id,
            &body,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )?;
    }
    assert_eq!(
        person_substrate(&vault, &person)
            .expect_err("ambiguous fact")
            .kind(),
        ErrorKind::InvalidClaimBody
    );
    assert_eq!(
        ensure_model_person(&vault, person, writer(), 100)
            .expect_err("not absent")
            .kind(),
        ErrorKind::InvalidClaimBody
    );

    let other = seed(&vault, entity(0x6B), ENTITY_TYPE_PERSON);
    let body = subject_fact(
        PREDICATE_PERSON_SUBSTRATE,
        other,
        Value::from("unknown"),
        writer(),
        100,
    );
    vault.put_claim(
        &entity(0x6C),
        &body,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
    )?;
    assert_eq!(
        person_substrate(&vault, &other)
            .expect_err("malformed fact")
            .kind(),
        ErrorKind::InvalidClaimBody
    );
    Ok(())
}
