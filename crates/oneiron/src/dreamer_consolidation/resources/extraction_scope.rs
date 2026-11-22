//! One child's attenuated extraction scope, shared by native slices and bound steps.
//!
//! Native extraction and a bound generation step narrow the same pinned base
//! scope in the same order: sibling TURNs, unrelated part conversations and
//! unshown prior heads leave first, then unkept membership versions, then
//! unkept MESSAGE versions, and an unbound scope finally binds to the
//! relationship every labelled word shares. This module holds that ordered
//! narrowing and the MESSAGE-label fold behind it, so both callers run one
//! implementation with their own retained sets.

use std::collections::{BTreeMap, BTreeSet};

use super::super::PriorHead;
use super::super::neighbourhood::Neighbourhood;
use super::super::turn_text::TurnText;
use super::SourcePin;
use crate::Vault;
use crate::claim::{RelationshipRead, relationship_read};
use crate::entity_id::EntityId;
use crate::error::Result;
use oneiron_model::llm::{Scope, ScopeResource};

/// The borrowed pins one extraction scope narrows from, with the retained sets.
/// Native supplies its branch pins with its sliced listing; a bound step
/// supplies its projection pins with no retained prior or membership.
pub(super) struct ExtractionScopeInputs<'a> {
    /// The pinned source rows the scope narrows over, by entity id.
    pub(super) sources: &'a BTreeMap<EntityId, SourcePin>,
    /// Each queued TURN's declared part conversation, by TURN id.
    pub(super) turns: &'a BTreeMap<EntityId, EntityId>,
    /// The admitted prior heads, by claim id.
    pub(super) priors: &'a BTreeMap<EntityId, PriorHead>,
    /// Each TURN's frozen text, by TURN id.
    pub(super) texts: &'a BTreeMap<EntityId, TurnText>,
    /// The cited TURNs this extraction reads.
    pub(super) cited: &'a BTreeSet<EntityId>,
    /// The cited TURNs' part conversations.
    pub(super) cited_parents: &'a BTreeSet<EntityId>,
    /// Whether an id is a declared part's conversation.
    pub(super) is_part_parent: &'a dyn Fn(&EntityId) -> bool,
    /// Whether the retained listing shows a prior head.
    pub(super) shows_prior: &'a dyn Fn(EntityId) -> bool,
    /// The retained listing whose memberships stay, or none when no membership stays.
    pub(super) kept_listing: Option<&'a Neighbourhood>,
    /// The whole listing whose unkept memberships leave.
    pub(super) whole_listing: &'a Neighbourhood,
}

/// Narrows `base` to exactly what the cited TURNs' extraction reads, in native
/// order: first every sibling TURN, unrelated part conversation and unshown
/// prior head leaves, then every unkept membership version, then every unkept
/// MESSAGE version, and an unbound scope finally takes `word_bound`, which runs
/// only when the scope has no relationship, exactly where native ran it.
pub(super) fn attenuate_extraction_scope(
    base: &Scope,
    inputs: &ExtractionScopeInputs<'_>,
    word_bound: impl FnOnce() -> Result<Option<BTreeSet<EntityId>>>,
) -> Result<Scope> {
    let mut scope = base.clone();
    // Keep its own conversations and the buckets, but remove every
    // sibling TURN, every other part's conversation, MESSAGE and
    // prior head from this child's capabilities.
    for (id, source) in inputs.sources {
        if (inputs.turns.contains_key(id) && !inputs.cited.contains(id))
            || ((inputs.is_part_parent)(id) && !inputs.cited_parents.contains(id))
            || (inputs.priors.contains_key(id) && !(inputs.shows_prior)(*id))
        {
            scope.readable.remove(&source.resource);
            scope.writable.remove(&source.resource);
        }
    }
    let kept_memberships: BTreeSet<ScopeResource> = inputs
        .kept_listing
        .into_iter()
        .flat_map(Neighbourhood::membership_versions)
        .map(|(_, version)| version.clone())
        .collect();
    for (_, version) in inputs.whole_listing.membership_versions() {
        if !kept_memberships.contains(version) {
            scope.readable.remove(version);
            scope.writable.remove(version);
        }
    }
    let kept_messages: BTreeSet<ScopeResource> = inputs
        .cited
        .iter()
        .filter_map(|id| inputs.texts.get(id))
        .flat_map(TurnText::versions)
        .map(|(_, version)| version.clone())
        .collect();
    for version in inputs
        .texts
        .values()
        .flat_map(TurnText::versions)
        .map(|(_, version)| version)
    {
        if !kept_messages.contains(version) {
            scope.readable.remove(version);
            scope.writable.remove(version);
        }
    }
    // An unbound branch's words still carry their MESSAGEs'
    // labels: the chunk binds to the relationships every labelled
    // word shares (the empty set when they share none), so a
    // candidate that names no relationship inherits the strictest
    // label and never `all`, and one that names a relationship
    // stays inside it (S63E-RULED, lead 9 Nov 19:0x).
    if scope.relationship.is_none() {
        scope.relationship = word_bound()?;
    }
    Ok(scope)
}

/// The relationships every labelled word of `turns` may be read within, read in
/// `txn`: each MESSAGE a TURN's text was projected from, at its stored scope,
/// meets the others. A private MESSAGE, or one whose label does not resolve,
/// admits no relationship. The result is `None` when no word carries a label, so
/// the caller stays unbound; a MESSAGE that is gone, or whose kind does not
/// gate, adds none.
pub(super) fn word_bound_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    texts: &BTreeMap<EntityId, TurnText>,
    turns: &BTreeSet<EntityId>,
) -> Result<Option<BTreeSet<EntityId>>> {
    let mut bound: Option<BTreeSet<EntityId>> = None;
    // The MESSAGEs whose words the transcript shows, not every pinned
    // child: a hidden or unfinished one is read by no call, so its label
    // binds nothing (review round 1 of #6903).
    let messages = turns
        .iter()
        .filter_map(|id| texts.get(id))
        .flat_map(TurnText::projection);
    for message in messages {
        let Some(raw) = vault.get_raw_in(txn, &message)? else {
            continue;
        };
        let label: BTreeSet<EntityId> = match relationship_read(&vault.store, txn, &message, &raw) {
            Ok(RelationshipRead::Gated { private: true, .. }) | Err(_) => BTreeSet::new(),
            Ok(RelationshipRead::Gated {
                space: Some(space), ..
            }) => space.into_iter().collect(),
            Ok(RelationshipRead::Gated { space: None, .. } | RelationshipRead::Decided(_)) => {
                continue;
            }
        };
        bound = Some(match bound {
            None => label,
            Some(held) => held.intersection(&label).copied().collect(),
        });
    }
    Ok(bound)
}
