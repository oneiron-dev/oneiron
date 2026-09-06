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

fn test_vault() -> (tempfile::TempDir, Vault) {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    let (dir, vault) = open_test_vault_with(cfg);
    seed(&vault, entity(0x9F), crate::registry::ENTITY_TYPE_MACHINE);
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
    WriteActor::new(entity(0x9F), EdgeActorClass::System)
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
    let (_dir, vault) = test_vault();
    let person = seed(&vault, entity(0x31), ENTITY_TYPE_PERSON);
    let actor = seed(&vault, entity(0x32), ENTITY_TYPE_AGENT_DEF);
    let author_ref = seed(&vault, entity(0x33), ENTITY_TYPE_PERSON);
    let author = WriteActor::new(author_ref, EdgeActorClass::Human);

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
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0x61), ENTITY_TYPE_AGENT_DEF);
    let person = seed(&vault, entity(0x62), ENTITY_TYPE_PERSON);
    let anchor = ActorSubjectAnchor {
        actor_ref: actor,
        subject_ref: person,
        subject_kind: SubjectKind::Person,
    };
    let author = WriteActor::new(person, EdgeActorClass::Human);
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
