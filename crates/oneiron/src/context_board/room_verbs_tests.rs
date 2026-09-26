//! Room render reads: the caller's scoped read and every present peer's.
use super::{RoomBar, RoomMode, RoomPresence};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::pipeline::{PREDICATE_WORLD_ACCESS_ALLOWED_SET, WorldAuthoritySet};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use crate::{EdgeActorClass, EdgeKind, EntityId, Result, TimeRange, Vault};
use rmpv::Value;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// A room rule; `reader` names the only actor allowed to read it.
fn put_rule(
    vault: &Vault,
    room: EntityId,
    predicate: &str,
    value: &str,
    reader: Option<EntityId>,
) -> Result<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(room),
        Value::from(value),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    body.scope = reader.map(|reader| {
        Value::Map(vec![(
            Value::from("typed_question_principal"),
            Value::from(reader.to_hex()),
        )])
    });
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_CLAIM,
            at(2),
            2,
            &crate::claim::encode_claim_body(&body)?,
        )
        .edge(&id, EdgeKind::ClaimOf, &room, 1.0)
        .commit()?;
    Ok(id)
}

fn present(actor: EntityId) -> Result<RoomPresence> {
    Ok(RoomPresence {
        actor,
        actor_class: Some(EdgeActorClass::Human),
        label: actor.to_hex(),
        present: true,
        active_worlds: WorldAuthoritySet::new(true, [])?,
    })
}

#[test]
fn room_render_reads_return_their_receipt() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let (alice, bob) = (EntityId::now(), EntityId::now());
    for member in [alice, bob] {
        vault.put_entity(&member, ENTITY_TYPE_PERSON, at(1), 1, b"member")?;
        let access = crate::pipeline::world_access_claim_body(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            member,
            &WorldAuthoritySet::new(true, [])?,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            None,
            None,
        )?;
        vault.put_claim(&EntityId::now(), &access, at(1), 1)?;
    }
    let room = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![
            (Value::from("kind"), Value::from("channel")),
            (
                Value::from("memberIds"),
                Value::Array(vec![Value::from(alice.to_hex()), Value::from(bob.to_hex())]),
            ),
        ]),
    )
    .map_err(|_| crate::Error::InvalidClaimBody("room body"))?;
    vault
        .batch()
        .put_replicated(&room, ENTITY_TYPE_CONVERSATION, at(1), 1, &body)
        .commit()?;
    let shared = put_rule(&vault, room, "room.posture.mode", "silent", None)?;
    // Alice may read this rule, her peer may not: the room withholds it.
    put_rule(&vault, room, "room.posture.bar", "high", Some(alice))?;
    // Only Bob may read this one: Alice's own read withholds it.
    put_rule(&vault, room, "room.posture.bar", "low", Some(bob))?;
    crate::test_util::authorize_readers(&vault, &[&alice.to_hex(), &bob.to_hex()]);

    let section = vault
        .memory(alice, EdgeActorClass::Human)
        .rooms_render(room, &[present(alice)?, present(bob)?])
        .expect("both members render the room");
    assert_eq!(
        section
            .claims
            .iter()
            .map(|claim| claim.claim_ref.clone())
            .collect::<Vec<_>>(),
        vec![shared.to_hex()]
    );
    assert_eq!(section.posture.mode, RoomMode::Silent);
    assert_eq!(section.posture.bar, RoomBar::default());
    assert_eq!(section.receipt.suppressed_count, 2);
    assert!(
        section
            .receipt
            .narrowed_axes
            .contains(&"row_authority".to_owned())
    );
    Ok(())
}
