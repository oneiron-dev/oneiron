//! The table's arms for actor, attribution and vault-default readers. Each
//! head is a reserved write, so each lands on a claim id whose owner-answer
//! obligation is open.

use super::skill::{observed, put_reserved};
use super::*;

const HELD: u8 = 0x50;

/// A held fit is no learned fit for the pair.
pub(super) fn actor_skill_fit(
    vault: &Vault,
    subject: EntityId,
    reader: ConsolidationReader,
) -> Result<()> {
    let skill = test_id(0x52);
    let session = test_id(0x45);
    let turn = test_id(0x46);
    put_raw_entity_row(vault, &skill, crate::registry::ENTITY_TYPE_SKILL, b"skill")?;
    put_raw_entity_row(
        vault,
        &session,
        crate::registry::ENTITY_TYPE_SESSION,
        b"session",
    )?;
    put_raw_entity_row(vault, &turn, ENTITY_TYPE_TURN, b"turn")?;
    let mut body = observed(
        crate::actor_claims::PREDICATE_ACTOR_SKILL_FIT,
        subject,
        Value::F32(0.8),
    )?;
    body.valid_from = Some(1);
    body.evidence =
        Some(crate::actor_claims::ActorClaimEvidence::chat(session, vec![turn], 1)?.to_value());
    body.scope = Some(Value::Map(vec![
        (
            Value::from("skill"),
            Value::Binary(skill.as_bytes().to_vec()),
        ),
        (Value::from("evidence_taint"), Value::from("generated")),
    ]));
    put_reserved(vault, test_id(HELD), &body)?;
    check_transition(vault, test_id(HELD), reader, |v, _| {
        Ok(crate::actor_claims::skill_fit_for(v, &subject, &skill)? == Some(0.8))
    })
}

/// A held edit cost is no cost estimate.
pub(super) fn edit_cost(
    vault: &Vault,
    subject: EntityId,
    reader: ConsolidationReader,
) -> Result<()> {
    let mut body = observed(
        crate::claim::PREDICATE_ACTOR_EDIT_COST,
        subject,
        Value::F32(0.75),
    )?;
    body.valid_from = Some(10);
    body.scope = Some(crate::actor_claims::edit_cost_scope("outbound"));
    put_reserved(vault, test_id(HELD), &body)?;
    check_transition(vault, test_id(HELD), reader, |v, _| {
        Ok(
            crate::edit_distance::attribution::edit_cost_for(v, &subject, "outbound")?
                == Some(0.75),
        )
    })
}

/// A held binding attributes none of its peer's changes, and honours no stamp.
pub(super) fn peer_binding(
    vault: &Vault,
    principal: EntityId,
    reader: ConsolidationReader,
) -> Result<()> {
    let mut body = observed(
        "actor.peer_binding",
        principal,
        Value::Map(vec![
            (Value::from("peer"), Value::from(17_u64)),
            (Value::from("class"), Value::from("human")),
        ]),
    )?;
    body.valid_from = Some(100);
    put_reserved(vault, test_id(HELD), &body)?;
    let actor = WriteActor::new(principal, EdgeActorClass::Human);
    check_transition(vault, test_id(HELD), reader, |v, _| {
        let resolved = crate::edit_distance::peer_actor_at(v, 17, 150)? == Some(actor);
        let honored = crate::edit_distance::peer_actor_stamp_is_honored(v, 17, 150, &actor)?;
        assert_eq!(
            resolved, honored,
            "{reader:?}: attribution and stamp disagree"
        );
        Ok(resolved)
    })
}

/// A held anchor names no subject for its actor.
pub(super) fn actor_subject_anchor(
    vault: &Vault,
    principal: EntityId,
    subject: EntityId,
    reader: ConsolidationReader,
) -> Result<()> {
    let mut body = observed(
        "actor.subject_ref",
        principal,
        Value::from(subject.to_hex()),
    )?;
    body.valid_from = Some(100);
    put_reserved(vault, test_id(HELD), &body)?;
    check_transition(vault, test_id(HELD), reader, |v, _| {
        Ok(v.actor_subject_anchor(&principal, 150)?
            .is_some_and(|anchor| anchor.subject_ref == subject))
    })
}

/// A held default facet stamps no new claim: the owner's substrate facet does.
pub(super) fn default_facet(vault: &Vault, reader: ConsolidationReader) -> Result<()> {
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    let facet = test_id(0x53);
    vault.put_entity(
        &facet,
        crate::registry::ENTITY_TYPE_FACET,
        crate::temporal::TimeRange { start: 1, end: 1 },
        10,
        b"facet",
    )?;
    let mut body = ClaimBody::new(
        crate::claim::PREDICATE_VAULT_DEFAULT_FACET,
        ClaimSubject::Entity(owner),
        Value::Binary(facet.as_bytes().to_vec()),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    put_reserved(vault, test_id(HELD), &body)?;
    check_transition(vault, test_id(HELD), reader, |v, _| {
        Ok(v.default_facet()? == facet)
    })
}

/// A held provenance claim stamps no flags on its edge: the next write's
/// winner is chosen without it, and the answered claim wins again.
pub(super) fn edge_provenance(reader: ConsolidationReader) -> Result<()> {
    use crate::provenance::{EdgeProvenanceClaimBody, SupersessionStatus};
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let [source, target, actor] = [test_id(0x21), test_id(0x52), test_id(0x43)];
    for id in [source, target, actor] {
        vault.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    vault.put_edge(&source, EdgeKind::Mentions, &target, 0.6)?;
    let edge = EdgeRef::new(source, EdgeKind::Mentions, target);
    let held = test_id(HELD);
    vault.put_edge_provenance(
        &held,
        &edge,
        &EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        2000,
    )?;
    let confirmed = crate::edge::EdgeProvenanceFlags {
        confirmation_status: crate::edge::EdgeConfirmationStatus::Confirmed,
        actor_class: EdgeActorClass::Human,
    };
    check_transition(&vault, held, reader, |v, _| {
        v.put_edge_provenance(
            &EntityId::now(),
            &edge,
            &EdgeProvenanceClaimBody::new(actor, 0.1, SupersessionStatus::Proposed),
            EdgeActorClass::Agent,
            2000,
        )?;
        Ok(edge_provenance_flags(v, &source, EdgeKind::Mentions, &target)? == confirmed)
    })
}
