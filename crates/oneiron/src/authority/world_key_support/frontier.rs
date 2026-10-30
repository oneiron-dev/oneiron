//! The frontier parents a world key record may name in place of the rows its
//! evidence rests on (FIX 5464, CALLS "FIX 5464 side parents"): this
//! install's main-log heads, and the valid side leaves of the record's own
//! world that its signer's previous row of the world is beneath. A resumed
//! fold and a fold past an adopted image keep the state at exactly such rows,
//! so a record on them continues past the base without the whole history.
//!
//! A main head a chosen side leaf already names beneath itself is left out:
//! the leaf's state holds it, and an image that kept the leaf as a frontier
//! row keeps no state at the head. Another world's side rows are never
//! named; neither is any row the record's world classification refuses.
//!
//! The candidate never replaces evidence it does not carry: the writer names
//! it only when every row it would name explicitly is beneath it
//! ([`KeyFrontier::carries_in_txn`]), and otherwise keeps those explicit rows
//! (CALLS "FIX 5464 partial evidence"). Rows are read from the store, and on a
//! vault that adopted a checkpoint image from the image's row summaries
//! ([`super::super::adopted_evidence::AdoptedEvidence::rows`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;
use crate::EntityId;
use crate::error::Result;
use crate::store::Store;

/// What the frontier reads of one row: its signer, its world when it is a
/// world's side row, and its parents.
struct RowFacts {
    signer: AuthorityKey,
    world: Option<EntityId>,
    parents: Vec<AuthorityEntryHash>,
}

/// The rows the frontier read, each once, and the adopted image's summaries
/// once the store first misses one.
#[derive(Default)]
struct Rows {
    evidence: Option<Option<Arc<super::super::adopted_evidence::AdoptedEvidence>>>,
    read: BTreeMap<AuthorityEntryHash, Option<RowFacts>>,
}

impl Rows {
    /// The row signed as `hash`, stored here or summarized by the adopted
    /// image; None when neither holds it.
    fn get(
        &mut self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        hash: &AuthorityEntryHash,
    ) -> Result<Option<&RowFacts>> {
        if !self.read.contains_key(hash) {
            let facts = match super::super::stored_authority_row(store, txn, hash)? {
                Some(entry) if authority_entry_hash(&entry)? == *hash => Some(RowFacts {
                    signer: entry.signer_key().clone(),
                    world: super::super::world_privacy::side_world(&entry.op),
                    parents: entry.parent_hashes,
                }),
                _ => {
                    if self.evidence.is_none() {
                        self.evidence = Some(
                            super::super::adopted_evidence::adopted_evidence_in_txn(store, txn)?,
                        );
                    }
                    self.evidence
                        .iter()
                        .flatten()
                        .find_map(|evidence| evidence.rows().get(hash))
                        .map(|row| RowFacts {
                            signer: row.signer.clone(),
                            world: row.world,
                            parents: row.parents.clone(),
                        })
                }
            };
            self.read.insert(*hash, facts);
        }
        Ok(self.read.get(hash).and_then(Option::as_ref))
    }

    /// The rows of `world`'s side branch beneath `start`, and every other
    /// row a side row among `start` and them names: the main-log rows the
    /// side rows rest on. A parent neither stored nor summarized ends its
    /// path; nothing beneath it is claimed.
    fn side_past(
        &mut self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        world: EntityId,
        start: AuthorityEntryHash,
    ) -> Result<Option<SidePast>> {
        let Some(row) = self.get(store, txn, &start)? else {
            return Ok(None);
        };
        let mut stack = row.parents.clone();
        let mut past = SidePast::default();
        let mut seen = BTreeSet::new();
        while let Some(at) = stack.pop() {
            if !seen.insert(at) {
                continue;
            }
            match self.get(store, txn, &at)? {
                Some(row) if row.world == Some(world) => {
                    past.side.insert(at);
                    stack.extend(row.parents.iter().copied());
                }
                _ => {
                    past.main.insert(at);
                }
            }
        }
        Ok(Some(past))
    }
}

/// One side row's past in its world: the side rows beneath it, and the
/// other rows they and it name.
#[derive(Default)]
struct SidePast {
    side: BTreeSet<AuthorityEntryHash>,
    main: BTreeSet<AuthorityEntryHash>,
}

/// A frontier candidate's two parts before any bound: the main-log heads no
/// chosen side leaf names beneath itself, and those side leaves, with the
/// rows read to find them.
struct Candidate {
    heads: BTreeSet<AuthorityEntryHash>,
    leaves: BTreeSet<AuthorityEntryHash>,
    rows: Rows,
}

/// What a key record's writer joins first when the record's frontier is
/// wider than one record names.
pub(crate) enum WideFrontier {
    /// The main-log heads past the record's bound, and how many of them it
    /// names beside its side leaves (FIX 8497, L04 09:40 (a)): joined so the
    /// record names the join tips and every head stays beneath it.
    Heads(BTreeSet<AuthorityEntryHash>, usize),
    /// The side leaves, when they alone fill the record beside its main
    /// heads (FIX 11868): joined in the world's own scope into one tip,
    /// which is then its signer's previous row of the world and the one
    /// leaf the record names, with every leaf beneath it.
    Leaves(BTreeSet<AuthorityEntryHash>),
}

/// The frontier parents of the next key record a machine signs in one world,
/// and the rows read to find them.
pub(crate) struct KeyFrontier {
    parents: BTreeSet<AuthorityEntryHash>,
    rows: Rows,
}

impl KeyFrontier {
    /// The parents the next record of `world` names on `fold` when its
    /// signer's previous row of the world is `chain`: each main-log head no
    /// chosen side leaf names beneath itself, and the side leaves of `world`
    /// that `chain` is, or is beneath. A side leaf is the latest valid row of
    /// some signer of the world that no other such row descends from. None
    /// when no candidate stands here: no main head, a `chain` row this vault
    /// cannot read, or more parents than one record names. A writer joins
    /// such a frontier first ([`Self::wide_in_txn`]): its main heads (FIX
    /// 8497), or its side leaves when they alone fill the record (FIX 11868).
    pub(crate) fn of_in_txn(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        world: EntityId,
        chain: Option<AuthorityEntryHash>,
    ) -> Result<Option<Self>> {
        let Some(candidate) = Self::candidate_in_txn(store, txn, fold, world, chain)? else {
            return Ok(None);
        };
        let mut parents = candidate.heads;
        parents.extend(candidate.leaves);
        if parents.len() > MAX_PARENTS {
            return Ok(None);
        }
        Ok(Some(Self {
            parents,
            rows: candidate.rows,
        }))
    }

    /// What the writer of the next record of `world` on `fold` joins first
    /// when the record's frontier is wider than one record names
    /// ([`WideFrontier`]). None when the candidate fits, or when none stands
    /// here ([`Self::of_in_txn`]).
    pub(crate) fn wide_in_txn(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        world: EntityId,
        chain: Option<AuthorityEntryHash>,
    ) -> Result<Option<WideFrontier>> {
        let Some(Candidate { heads, leaves, .. }) =
            Self::candidate_in_txn(store, txn, fold, world, chain)?
        else {
            return Ok(None);
        };
        if heads.len() + leaves.len() <= MAX_PARENTS {
            return Ok(None);
        }
        if leaves.len() >= MAX_PARENTS {
            return Ok(Some(WideFrontier::Leaves(leaves)));
        }
        let room = MAX_PARENTS - leaves.len();
        Ok(Some(WideFrontier::Heads(heads, room)))
    }

    /// The candidate on `fold` before any bound ([`Candidate`]).
    fn candidate_in_txn(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        world: EntityId,
        chain: Option<AuthorityEntryHash>,
    ) -> Result<Option<Candidate>> {
        if fold.append_heads.is_empty() {
            return Ok(None);
        }
        let mut rows = Rows::default();
        let mut parents = fold.append_heads.clone();
        let mut chosen = BTreeSet::new();
        if let Some(chain) = chain {
            let mut tips: BTreeSet<_> = fold
                .scope_heads
                .iter()
                .filter(|((_, of), _)| *of == world)
                .map(|(_, (_, hash))| *hash)
                .collect();
            tips.insert(chain);
            let mut pasts = BTreeMap::new();
            for tip in tips {
                match rows.side_past(store, txn, world, tip)? {
                    Some(past) => {
                        pasts.insert(tip, past);
                    }
                    None if tip == chain => return Ok(None),
                    None => {}
                }
            }
            // The tips `chain` is or is beneath, and of those the ones no
            // other descends from.
            let above: BTreeSet<_> = pasts
                .iter()
                .filter(|(tip, past)| **tip == chain || past.side.contains(&chain))
                .map(|(tip, _)| *tip)
                .collect();
            let leaves: BTreeSet<_> = above
                .iter()
                .filter(|tip| {
                    !above
                        .iter()
                        .any(|other| other != *tip && pasts[other].side.contains(*tip))
                })
                .copied()
                .collect();
            for leaf in &leaves {
                parents.retain(|head| !pasts[leaf].main.contains(head));
            }
            chosen = leaves;
        }
        Ok(Some(Candidate {
            heads: parents,
            leaves: chosen,
            rows,
        }))
    }

    /// The parents the first record names.
    pub(crate) fn parents(&self) -> &BTreeSet<AuthorityEntryHash> {
        &self.parents
    }

    /// Whether every row of `named` is beneath these parents: one of them, or
    /// a valid main-log row this install keeps on its main log, which is a
    /// main head or beneath one (a head left out is beneath the side leaf
    /// that names it). A row on an anchor branch this install does not pin, a
    /// side row, a row this fold holds invalid and one this vault cannot read
    /// are not shown beneath them: the writer keeps its explicit parents.
    pub(crate) fn carries_in_txn(
        &mut self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        named: &BTreeSet<AuthorityEntryHash>,
    ) -> Result<bool> {
        let pinned = fold.pinned_root.map(|pin| pin.anchor_key);
        for hash in named {
            if self.parents.contains(hash) {
                continue;
            }
            if !fold.valid_entries.contains(hash) {
                return Ok(false);
            }
            let Some(row) = self.rows.get(store, txn, hash)? else {
                return Ok(false);
            };
            let foreign = fold.anchor_entries.contains(hash)
                && matches!(&row.signer, AuthorityKey::Ed25519(anchor) if pinned != Some(*anchor));
            if row.world.is_some() || foreign {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
