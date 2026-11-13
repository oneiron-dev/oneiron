//! The role rung (ARCH-0024 signal 3): a mention that names a person by
//! their relationship to the speaker, `my manager`, is looked up through the
//! speaker's role edges.
//!
//! A role edge is an ordinary claim `relationship.<word>` whose subject is
//! the person the role is relative to and whose value is the related
//! person's id: "Owen is my manager", said by the owner, is
//! `relationship.manager` on the owner valued with Owen's id. The words are
//! the fixed relationship labels ([`relationship_trust_class`]): no synonym
//! is read, so `my boss` never reads a `relationship.manager` edge. The
//! possessor of `my` is the one author of the mention's message, never the
//! vault's owner by default; a message of no single author has none.

use std::collections::{BTreeMap, BTreeSet};

use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
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

/// The persons `possessor`'s role edges for `word` name, each with whether
/// an Approved edge names them. Only Active claims count, Auto or Approved,
/// whose value is an entity id; a Proposed or Rejected edge never does.
/// `admits` keeps the claims the reader may see.
pub(super) fn role_edges_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    possessor: &EntityId,
    word: &str,
    mut admits: impl FnMut(&EntityId) -> Result<bool>,
) -> Result<BTreeMap<EntityId, bool>> {
    let predicate = role_edge_predicate(word);
    let mut found = BTreeMap::new();
    for claim in vault.claims_for_subject_in_txn(txn, possessor)? {
        let Some(body) = vault.get_claim_in_txn(txn, &claim)? else {
            continue;
        };
        if body.predicate != predicate || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let approved = match body.approval {
            ClaimApprovalStatus::Approved => true,
            ClaimApprovalStatus::Auto => false,
            ClaimApprovalStatus::Proposed | ClaimApprovalStatus::Rejected => continue,
        };
        let Some(person) = body
            .value
            .as_str()
            .and_then(|hex| EntityId::from_hex(hex).ok())
        else {
            continue;
        };
        if !admits(&claim)? {
            continue;
        }
        let sure: &mut bool = found.entry(person).or_default();
        *sure |= approved;
    }
    Ok(found)
}
