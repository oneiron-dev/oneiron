//! The role rung (ARCH-0024 signal 3): a mention that names a person by
//! their relationship to the speaker, `my manager`, is looked up through the
//! speaker's role edges.
//!
//! A role edge is an ordinary claim `relationship.<word>` whose subject is
//! the person the role is relative to and whose value is the related
//! person's id in canonical 32-hex form (Engine ruling 13 Nov 12:58, as
//! `actor.subject_ref` holds its anchor): "Owen is my manager", said by the
//! owner, is `relationship.manager` on the owner valued with Owen's id. The
//! `relationship` root is multi-valued, so a second edge of one word stands
//! beside the first. The words are the fixed relationship labels
//! ([`relationship_trust_class`]): no synonym is read, so `my boss` never
//! reads a `relationship.manager` edge. The possessor of `my` is the one
//! author of the mention's message, never the vault's owner by default; a
//! message of no single author has none.

use std::collections::{BTreeMap, BTreeSet};

use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::federation::{RelationshipTrustClass, relationship_trust_class};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::{EntityId, Vault};

/// The role edge predicate for `word`: `relationship.<word>`.
fn role_edge_predicate(word: &str) -> String {
    format!("relationship.{word}")
}

/// The role word of a person mention that names someone by their
/// relationship to the speaker: `my <word>`, any case, with `<word>` one of
/// the fixed relationship labels. Any other mention, and a mention of any
/// other kind, has none.
pub(super) fn role_word(kind: u8, mention: &str) -> Option<String> {
    if kind != ENTITY_TYPE_PERSON {
        return None;
    }
    let mut parts = mention.split_whitespace();
    let (Some(possessive), Some(word), None) = (parts.next(), parts.next(), parts.next()) else {
        return None;
    };
    if !possessive.eq_ignore_ascii_case("my") {
        return None;
    }
    let word = word.to_lowercase();
    (relationship_trust_class(&word) != RelationshipTrustClass::Unlabeled).then_some(word)
}

/// The one author of `message`, whom its `my` names; `None` when it has no
/// author or several.
pub(super) fn speaker_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
) -> Result<Option<EntityId>> {
    let mut authors = BTreeSet::new();
    for edge in vault.store.port_edges(
        txn,
        message,
        EdgeDirection::Out,
        Some(EdgeKind::AuthoredBy),
        None,
    )? {
        authors.insert(edge?.target);
    }
    let mut authors = authors.into_iter();
    Ok(match (authors.next(), authors.next()) {
        (Some(author), None) => Some(author),
        _ => None,
    })
}

/// The role edge a claim body is, when it is one of `possessor`'s for
/// `predicate` that stands at `now`: Active and not marked stale, valid at
/// `now`, about `possessor` itself, and valued with an entity id in
/// canonical 32-hex form. The answer pairs that id with whether the edge is Approved. Auto
/// and Proposed edges are unsure; a Rejected edge, which the owner refused,
/// names no one.
fn role_edge(
    body: &ClaimBody,
    possessor: &EntityId,
    predicate: &str,
    now: u64,
) -> Option<(EntityId, bool)> {
    if body.subject != ClaimSubject::Entity(*possessor)
        || body.predicate != predicate
        || body.lifecycle != ClaimLifecycleStatus::Active
        || body.stale
        || body.valid_from.is_some_and(|start| start > now)
        || body.valid_to.is_some_and(|end| end <= now)
    {
        return None;
    }
    let approved = match body.approval {
        ClaimApprovalStatus::Approved => true,
        ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed => false,
        ClaimApprovalStatus::Rejected => return None,
    };
    let hex = body.value.as_str()?;
    let person = EntityId::from_hex(hex)
        .ok()
        .filter(|id| id.to_hex() == hex)?;
    Some((person, approved))
}

/// The ids `possessor`'s role edges for `word` name at `now`
/// ([`role_edge`]), each with whether an Approved edge names it, as stored:
/// the caller resolves each to its head. `admits` keeps the claims the
/// reader may see. An Approved edge whose owner-answer obligation is open
/// (ARCH-0026 §G3, [`crate::gate::claim_critical_confirm_settled_in_txn`])
/// is held from every effect reader, so it names its person only as an
/// unsure edge does: a held edge never hard-links.
pub(super) fn role_edges_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    possessor: &EntityId,
    word: &str,
    now: u64,
    mut admits: impl FnMut(&EntityId) -> Result<bool>,
) -> Result<BTreeMap<EntityId, bool>> {
    let predicate = role_edge_predicate(word);
    let mut edges = Vec::new();
    vault.find_claim_for_subject_in_txn(txn, possessor, |claim, body| {
        if let Some(edge) = role_edge(body, possessor, &predicate, now) {
            edges.push((*claim, edge));
        }
        None::<()>
    })?;
    let mut found = BTreeMap::new();
    for (claim, (person, approved)) in edges {
        if admits(&claim)? {
            let settled = approved
                && crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, &claim)?;
            let sure: &mut bool = found.entry(person).or_default();
            *sure |= settled;
        }
    }
    Ok(found)
}
