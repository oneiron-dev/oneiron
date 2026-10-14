//! A world's key records, folded (world privacy P6b, contract §4).
//!
//! The first counted record for a key id is its mint: it fixes the key's
//! commitment and owner. A counted record that names other bytes or another
//! owner marks the key conflicted, and a conflicted key is never current.
//! Each recipient keeps at most four envelopes of one key, the first counted:
//! a later wrap never displaces one, and the opener tries each, so a bad wrap
//! never hides a good one. "First" is causal: slots rank by how many entries
//! a record descends from, then by hash, so a merge never lets a descendant
//! evict its ancestor's envelope; the hash breaks ties between concurrent
//! records only.
//!
//! A record counts under this install's pin, never under admission alone:
//! its signer is mine here with the key that signed it, the world is private
//! and readable on the signer, every machine recipient is mine and may read
//! it, and the record's settings revision is the world's at its parents. A
//! record from an admitted machine that is not mine here (a host-anchored
//! one, say) is a valid no-op: it never mints the current key and never
//! fills a recipient's slots. That only withholds; the pin doors wrap again.
//! Validity is pin-free: a record no chain of its machine admits under the
//! key that signed it is invalid on every install.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;

use super::machine_claims::folded_machine_in;
use super::machine_standing::{Standing, StandingView};
use super::world_privacy::policy_revision;
use super::world_strength::world_meet;
use super::*;

/// At most this many envelopes of one key for one recipient.
pub const WORLD_KEY_WRAPS_PER_RECIPIENT: usize = 4;

/// One world key as a history holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WorldKeyState {
    owner: EntityId,
    commitment: [u8; 32],
    conflicted: bool,
    /// Per recipient, the records whose wraps count, by causal rank, each
    /// with the settings revision it was wrapped under.
    wraps: BTreeMap<WrapRecipient, BTreeMap<SlotRank, PolicyRevision>>,
}

/// A wrap slot's place: how many entries its record descends from, then the
/// record's hash. An ancestor always ranks before its descendants.
type SlotRank = (usize, AuthorityEntryHash);

/// One world key as this install's fold holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedWorldKey {
    pub id: WorldKeyId,
    /// The vault owner PERSON its mint named.
    pub owner: EntityId,
    pub commitment: [u8; 32],
    /// Counted records named other bytes or another owner for this id.
    pub conflicted: bool,
    /// At most four counted envelopes per recipient.
    pub wraps: BTreeMap<WrapRecipient, Vec<WrappedKey>>,
}

/// One counted envelope of a key for one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    pub envelope: Vec<u8>,
    /// The world's settings revision the wrap was made under.
    pub policy: PolicyRevision,
    pub entry: AuthorityEntryHash,
}

impl AuthorityFold {
    /// Every key of `world` this fold holds, in `(generation, mint)` order.
    pub fn world_keys(&self, world: EntityId) -> impl Iterator<Item = &FoldedWorldKey> {
        let first = WorldKeyId {
            world,
            generation: 0,
            mint: [0; 16],
        };
        let last = WorldKeyId {
            world,
            generation: u64::MAX,
            mint: [u8::MAX; 16],
        };
        self.world_keys.range(first..=last).map(|(_, key)| key)
    }

    /// Every key this fold holds, world by world.
    pub fn all_world_keys(&self) -> impl Iterator<Item = &FoldedWorldKey> {
        self.world_keys.values()
    }

    /// One key by id.
    #[must_use]
    pub fn world_key(&self, id: &WorldKeyId) -> Option<&FoldedWorldKey> {
        self.world_keys.get(id)
    }

    /// The current key: the greatest `(generation, mint)` that is not
    /// conflicted.
    #[must_use]
    pub fn current_world_key(&self, world: EntityId) -> Option<&FoldedWorldKey> {
        self.world_keys(world).filter(|key| !key.conflicted).last()
    }
}

/// The `WorldKeyWraps` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster check:
/// its signer is a machine's install key.
pub(super) fn apply_world_key_wraps(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    record: &WorldKeyWrapsRecord,
    hash: AuthorityEntryHash,
    context: FoldContext<'_>,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let AuthorityKey::Ed25519(signer) = entry.signer_key() else {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    };
    if !folded_machine_in(state, record.machine).is_some_and(|machine| {
        machine
            .chains()
            .any(|(_, chain)| chain.says_yours() && chain.profile.machine_key == *signer)
    }) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if state
        .seqs
        .get(entry.signer_key())
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    if !counts(state, record, signer, context) {
        state.refused_world_keys.insert(hash);
        return Ok(());
    }
    let key = state.world_keys.entry(record.key).or_insert_with(|| {
        Arc::new(WorldKeyState {
            owner: record.owner,
            commitment: record.commitment,
            conflicted: false,
            wraps: BTreeMap::new(),
        })
    });
    let key = Arc::make_mut(key);
    if key.commitment != record.commitment || key.owner != record.owner {
        key.conflicted = true;
        return Ok(());
    }
    // Every slot the parent state holds is an ancestor of this record and
    // ranks before it, so with four slots full this record is the one left
    // out.
    let rank = (
        context
            .entry_ancestors
            .and_then(|ancestors| ancestors.get(&hash))
            .map_or(entry.parent_hashes.len(), BTreeSet::len),
        hash,
    );
    for (recipient, _) in &record.wraps {
        let slots = key.wraps.entry(*recipient).or_default();
        if slots.len() < WORLD_KEY_WRAPS_PER_RECIPIENT {
            slots.insert(rank, record.policy);
        }
    }
    Ok(())
}

/// Whether a well-signed record counts here, judged in its parent state as
/// this install counts machines: the signer and every machine recipient mine
/// under the pin with this install's holds, through the seam
/// ([`Standing::counted_key`]), and the world readable on each in the read
/// this install computes there.
fn counts(
    state: &FoldState,
    record: &WorldKeyWrapsRecord,
    signer: &[u8; 32],
    context: FoldContext<'_>,
) -> bool {
    let standing = Standing::new(state, context.pin, context.machine_standing);
    let read = world_meet(&standing, record.key.world, StandingView::Install)
        .effective()
        .read;
    let may_read = |id: EntityId| {
        let mine = || standing.counted_key(id).is_some();
        match &read {
            EffectiveRead::MyMachines => mine(),
            EffectiveRead::OneMachine(only) => *only == id && mine(),
            EffectiveRead::Everywhere | EffectiveRead::Conflicted { .. } => false,
        }
    };
    record.key.generation == FIRST_GENERATION
        && standing.counted_key(record.machine) == Some(*signer)
        && may_read(record.machine)
        && record.policy == policy_revision(state, record.key.world)
        && record.wraps.iter().all(|(recipient, _)| match recipient {
            WrapRecipient::Machine(id) => may_read(*id),
            WrapRecipient::RecoveryRoot(_) => true,
        })
}

/// Joins two histories' keys: a key both hold keeps what both counted, up to
/// four wraps per recipient, and conflicts when they disagree on its bytes
/// or its owner. Order-free.
pub(super) fn merge_world_keys(
    merged: &mut BTreeMap<WorldKeyId, Arc<WorldKeyState>>,
    right: &BTreeMap<WorldKeyId, Arc<WorldKeyState>>,
) {
    for (id, key) in right {
        match merged.entry(*id) {
            Entry::Vacant(slot) => {
                slot.insert(Arc::clone(key));
            }
            Entry::Occupied(mut slot) => {
                if Arc::ptr_eq(slot.get(), key) || **slot.get() == **key {
                    continue;
                }
                let held = Arc::make_mut(slot.get_mut());
                held.conflicted |=
                    key.conflicted || held.commitment != key.commitment || held.owner != key.owner;
                held.commitment = held.commitment.min(key.commitment);
                held.owner = held.owner.min(key.owner);
                for (recipient, wraps) in &key.wraps {
                    let slots = held.wraps.entry(*recipient).or_default();
                    slots.extend(wraps.iter().map(|(rank, policy)| (*rank, *policy)));
                    keep_first_slots(slots);
                }
            }
        }
    }
}

/// Keeps the four causally first slots.
fn keep_first_slots(slots: &mut BTreeMap<SlotRank, PolicyRevision>) {
    while slots.len() > WORLD_KEY_WRAPS_PER_RECIPIENT {
        slots.pop_last();
    }
}

/// The fold's public view of every key, with each counted envelope read
/// from the record that carries it.
pub(super) fn folded_world_keys(
    state: &FoldState,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
) -> BTreeMap<WorldKeyId, FoldedWorldKey> {
    let envelope = |hash: &AuthorityEntryHash, recipient: &WrapRecipient| {
        let AuthorityOp::WorldKeyWraps(record) = &by_hash.get(hash)?.op else {
            return None;
        };
        record
            .wraps
            .iter()
            .find(|(to, _)| to == recipient)
            .map(|(_, envelope)| envelope.clone())
    };
    state
        .world_keys
        .iter()
        .map(|(id, key)| {
            let wraps = key
                .wraps
                .iter()
                .map(|(recipient, records)| {
                    let wrapped = records
                        .iter()
                        .filter_map(|((_, hash), policy)| {
                            Some(WrappedKey {
                                envelope: envelope(hash, recipient)?,
                                policy: *policy,
                                entry: *hash,
                            })
                        })
                        .collect();
                    (*recipient, wrapped)
                })
                .collect();
            (
                *id,
                FoldedWorldKey {
                    id: *id,
                    owner: key.owner,
                    commitment: key.commitment,
                    conflicted: key.conflicted,
                    wraps,
                },
            )
        })
        .collect()
}
