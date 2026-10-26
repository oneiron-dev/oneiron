//! A probe's source family: the `DerivedFrom` component its document is in (FIX 9831).
//!
//! A document, the summaries written from it and what it was written from are one piece of
//! evidence to a move's check, so their probes share one family and the swap interval counts
//! them once. The family's id is the least source root of the whole component, a member that
//! derives from nothing; a component that is all cycle takes its least member.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead};

/// One document's source family.
pub(super) struct SourceFamily {
    /// The family's id.
    pub(super) id: EntityId,
    /// Every record of its component, the document among them.
    pub(super) members: BTreeSet<EntityId>,
}

/// `document`'s source family as `txn` reads it: its component walked to the end through
/// `DerivedFrom` edges either way, each record once, with no depth or member bound.
///
/// # Errors
/// A store failure.
pub(super) fn probe_source_family_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    document: EntityId,
) -> Result<SourceFamily> {
    let mut members = BTreeSet::from([document]);
    let mut roots = BTreeSet::new();
    let mut frontier = vec![document];
    while let Some(member) = frontier.pop() {
        let origins: Vec<EntityId> = vault
            .store
            .port_edge_peers(
                txn,
                &member,
                EdgeDirection::Out,
                crate::EdgeKind::DerivedFrom,
            )?
            .collect::<Result<_>>()?;
        if origins.is_empty() {
            roots.insert(member);
        }
        let derived: Vec<EntityId> = vault
            .store
            .port_edge_peers(
                txn,
                &member,
                EdgeDirection::In,
                crate::EdgeKind::DerivedFrom,
            )?
            .collect::<Result<_>>()?;
        for peer in origins.into_iter().chain(derived) {
            if members.insert(peer) {
                frontier.push(peer);
            }
        }
    }
    let id = *roots.first().or(members.first()).unwrap_or(&document);
    Ok(SourceFamily { id, members })
}

/// Source families read in one transaction, each component walked once.
#[derive(Default)]
pub(super) struct ProbeFamilies {
    resolved: BTreeMap<EntityId, EntityId>,
}

impl ProbeFamilies {
    /// `document`'s family id as `txn` reads it ([`probe_source_family_in_txn`]).
    ///
    /// # Errors
    /// A store failure.
    pub(super) fn family_of(
        &mut self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        document: EntityId,
    ) -> Result<EntityId> {
        if let Some(family) = self.resolved.get(&document) {
            return Ok(*family);
        }
        let family = probe_source_family_in_txn(vault, txn, document)?;
        for member in family.members {
            self.resolved.insert(member, family.id);
        }
        Ok(family.id)
    }
}
