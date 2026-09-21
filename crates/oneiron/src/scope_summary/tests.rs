//! Exact covers, gated merge atomicity and revision-bound late results.

use super::*;
use crate::conversation_dag::fixtures as support;
use crate::conversation_dag::{ScopePath, ScopeSelector};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::{EdgeKind, EntityId, ErrorKind};
use support::*;

#[test]
fn retained_subsession_scope_covers_300_body_truth_edges_cap_and_one_header() {
    let (_dir, vault, conv, actor) = fixture();
    let asking = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let session = vault.spawn_dag_sub_session(&asking, actor).unwrap();
    assert_eq!(vault.sub_sessions(&asking).unwrap(), [session]);
    let mut parent = asking;
    let mut turns = Vec::new();
    for n in 0..300 {
        let mut next = input(conv, Some(parent), false, actor);
        next.session = Some(session);
        next.occurred = time(30 + n);
        parent = vault.append_dag_record(&next).unwrap().id;
        turns.push(parent);
    }
    let selector = scope(conv, ScopePath::SubSession(session), false);
    assert_eq!(vault.resolve_dag_scope(&selector).unwrap().records, turns);
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::Canonical, true))
            .unwrap()
            .records,
        [asking]
    );
    assert_eq!(vault.head(&conv).unwrap(), Some(asking));
    let before_claims = vault.entities_by_type(ENTITY_TYPE_CLAIM).unwrap().len();
    let summary = vault
        .mint_dag_scope_summary(&selector, "  handed text verbatim  ", actor)
        .unwrap();
    let body = vault.get(&summary).unwrap().unwrap();
    let decoded = decode_scope_summary_body(&body).unwrap();
    assert_eq!(decoded.text, "  handed text verbatim  ");
    assert_eq!(decoded.actor, actor.entity_ref().to_hex());
    assert_eq!(decoded.covers, turns);
    assert_eq!(
        vault
            .targets(&summary, EdgeKind::DerivedFrom, Some(ENTITY_TYPE_TURN))
            .unwrap()
            .len(),
        256
    );
    assert_eq!(vault.scope_summary_covers(&summary).unwrap(), turns);
    let landed = vault.land_header(&summary, &asking, actor, false).unwrap();
    assert_eq!(landed.record, None);
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_CLAIM).unwrap().len(),
        before_claims + 1
    );
    let claim = vault.get_claim(&landed.claim).unwrap().unwrap();
    assert_eq!(claim.predicate, "merge.summary");
    assert_eq!(claim.subject, crate::claim::ClaimSubject::Entity(asking));
    assert_eq!(claim.value.as_str(), Some(summary.to_hex().as_str()));
    assert_eq!(vault.drill(&landed.claim).unwrap(), turns);
    assert_eq!(vault.resolve_dag_scope(&selector).unwrap().records, turns);
    assert_eq!(vault.head(&conv).unwrap(), Some(asking));
    // The body is the truth even when an index edge is pruned.
    vault
        .delete_edge(&summary, EdgeKind::DerivedFrom, &turns[0])
        .unwrap();
    assert_eq!(vault.scope_summary_covers(&summary).unwrap().len(), 300);
}

#[test]
fn subsessions_are_isolated_and_second_spawned_by_is_refused_or_detected() {
    let (_dir, vault, conv, actor) = fixture();
    let asking = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let other = vault
        .append_dag_record(&input(conv, Some(asking), true, actor))
        .unwrap()
        .id;
    let session = vault.spawn_dag_sub_session(&asking, actor).unwrap();
    let sibling = vault.spawn_dag_sub_session(&other, actor).unwrap();
    let mut next = input(conv, Some(asking), false, actor);
    next.session = Some(session);
    let child = vault.append_dag_record(&next).unwrap().id;
    next.parent = Some(child);
    next.session = Some(sibling);
    assert_eq!(
        vault.append_dag_record(&next).unwrap_err().kind(),
        ErrorKind::InvalidConversationDag
    );
    assert_eq!(
        vault.move_head(&conv, &child).unwrap_err().kind(),
        ErrorKind::InvalidConversationDag
    );
    let contradictory = ScopeSelector {
        session: Some(sibling),
        ..scope(conv, ScopePath::SubSession(session), false)
    };
    assert_eq!(
        vault.resolve_dag_scope(&contradictory).unwrap_err().kind(),
        ErrorKind::InvalidConversationDag
    );
    assert_eq!(
        vault
            .put_edge(&session, EdgeKind::SpawnedBy, &other, 1.0)
            .unwrap_err()
            .kind(),
        ErrorKind::ReservedEdgeKind
    );
    vault
        .batch()
        .edge_with_value_fields(
            &session,
            EdgeKind::SpawnedBy,
            &other,
            crate::batch::EdgeValueFields {
                weight: 1.0,
                created_at: 1,
                vad: crate::affect::Vad::NEUTRAL,
                provenance: None,
            },
        )
        .commit()
        .unwrap();
    assert_eq!(
        vault.sub_sessions(&asking).unwrap_err().kind(),
        ErrorKind::InvalidScopeSummary
    );
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::SubSession(session), false))
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidConversationDag
    );
}

#[test]
fn denied_header_and_reply_roll_back_then_granted_late_result_advances_trunk() {
    let (_dir, vault, conv, actor) = fixture();
    let asking = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let session = vault.spawn_dag_sub_session(&asking, actor).unwrap();
    let mut next = input(conv, Some(asking), false, actor);
    next.session = Some(session);
    let worker = vault.append_dag_record(&next).unwrap().id;
    let current = vault
        .append_dag_record(&input(conv, Some(asking), true, actor))
        .unwrap()
        .id;
    let selector = scope(conv, ScopePath::SubSession(session), false);
    let summary = vault
        .mint_dag_scope_summary(&selector, "The result", actor)
        .unwrap();
    let claims_before = vault.entities_by_type(ENTITY_TYPE_CLAIM).unwrap().len();
    let turns_before = vault.entities_by_type(ENTITY_TYPE_TURN).unwrap().len();
    let summaries_before = vault.entities_by_type(ENTITY_TYPE_SUMMARY).unwrap().len();
    grant(&vault, actor, false);
    assert_eq!(
        vault
            .land_header(&summary, &asking, actor, true)
            .unwrap_err()
            .kind(),
        ErrorKind::GateWriteRejected
    );
    assert_eq!(
        vault
            .mint_and_land_scope_summary(&selector, "not committed", actor, Some(asking), true)
            .unwrap_err()
            .kind(),
        ErrorKind::GateWriteRejected
    );
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_CLAIM).unwrap().len(),
        claims_before
    );
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_TURN).unwrap().len(),
        turns_before
    );
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_SUMMARY).unwrap().len(),
        summaries_before
    );
    assert_eq!(vault.head(&conv).unwrap(), Some(current));
    grant(&vault, actor, true);
    let landed = vault.land_header(&summary, &asking, actor, true).unwrap();
    let reply = landed.record.unwrap();
    assert_eq!(vault.head(&conv).unwrap(), Some(reply));
    assert_eq!(
        vault.targets(&reply, EdgeKind::Parent, None).unwrap(),
        [current]
    );
    assert_eq!(
        vault.targets(&reply, EdgeKind::RepliesTo, None).unwrap(),
        [asking]
    );
    assert_eq!(vault.drill(&landed.claim).unwrap(), [worker]);
    let body: serde_json::Value =
        rmp_serde::from_slice(&vault.get(&reply).unwrap().unwrap()).unwrap();
    assert_eq!(body["addr"], "reply");
    assert_eq!(body["reply_to"]["record"], asking.to_hex());
    assert_eq!(body["summary"], summary.to_hex());
    let strip = vault.reply_strip(&reply).unwrap().unwrap();
    assert_eq!(strip.record, asking);
    assert_eq!(strip.text.as_deref(), Some("record"));
    assert!(!strip.stale);
    vault
        .put_entity(
            &asking,
            ENTITY_TYPE_TURN,
            time(21),
            21,
            &support::body("edited"),
        )
        .unwrap();
    let strip = vault.reply_strip(&reply).unwrap().unwrap();
    assert!(strip.stale);
    assert_eq!(strip.text, None);
    assert_eq!(
        vault.resolve_dag_scope(&selector).unwrap().records,
        [worker]
    );
}

#[test]
fn scope_summary_codec_is_distinct_strict_and_versioned() {
    let actor = EntityId::now();
    let mut summary = ScopeSummaryBody {
        v: 1,
        scope: scope(EntityId::now(), ScopePath::Canonical, false),
        text: "text".to_owned(),
        actor: actor.to_hex(),
        covers: vec![EntityId::now()],
        minted_at: 1,
    };
    let encoded = encode_scope_summary_body(&summary).unwrap();
    assert_eq!(decode_scope_summary_body(&encoded).unwrap(), summary);
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        decode_scope_summary_body(&trailing).unwrap_err().kind(),
        ErrorKind::InvalidScopeSummary
    );
    summary.v = 2;
    assert_eq!(
        encode_scope_summary_body(&summary).unwrap_err().kind(),
        ErrorKind::InvalidScopeSummary
    );
    let mut value: serde_json::Value = rmp_serde::from_slice(&encoded).unwrap();
    value["v"] = 2.into();
    assert_eq!(
        decode_scope_summary_body(&rmp_serde::to_vec_named(&value).unwrap())
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidScopeSummary
    );
    summary.v = 1;
    summary.covers.push(summary.covers[0]);
    assert_eq!(
        encode_scope_summary_body(&summary).unwrap_err().kind(),
        ErrorKind::InvalidScopeSummary
    );
    summary.covers.pop();
    summary.text = "  ".to_owned();
    assert_eq!(
        encode_scope_summary_body(&summary).unwrap_err().kind(),
        ErrorKind::InvalidScopeSummary
    );
}

#[test]
fn nested_subsession_continues_its_spawning_turn_without_leaking_scopes() {
    let (_dir, vault, conv, actor) = fixture();
    let asking = vault
        .append_dag_record(&input(conv, None, true, actor))
        .unwrap()
        .id;
    let outer = vault.spawn_dag_sub_session(&asking, actor).unwrap();
    let mut next = input(conv, Some(asking), false, actor);
    next.session = Some(outer);
    let outer_turn = vault.append_dag_record(&next).unwrap().id;
    let inner = vault.spawn_dag_sub_session(&outer_turn, actor).unwrap();
    next.parent = Some(outer_turn);
    next.session = Some(inner);
    let inner_turn = vault.append_dag_record(&next).unwrap().id;
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::SubSession(outer), true))
            .unwrap()
            .records,
        [outer_turn]
    );
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::SubSession(inner), true))
            .unwrap()
            .records,
        [inner_turn]
    );
    assert_eq!(
        vault
            .resolve_dag_scope(&scope(conv, ScopePath::Canonical, true))
            .unwrap()
            .records,
        [asking]
    );
    assert_eq!(vault.head(&conv).unwrap(), Some(asking));
}
