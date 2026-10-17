//! A world's key records, folded (world privacy P6b, contract §4).
//!
//! A key's counted records name its commitment and owner. The fold keeps
//! each pair they name, with the machines that signed it, and judges at its
//! end, in this install's final trust set: the key is the pair its standing
//! signers name, and two such pairs conflict it. A conflicted key is never
//! current. A removed signer's records never conflict a key a standing one
//! signed (Astra #1422d F3); when no signer stands, every pair judges, and
//! such a key is never current either. This machine's own records judge
//! while it stands; when it does not, its doors refuse it as not mine.
//! Each signer keeps at most four envelopes of one key per recipient, its
//! first counted: a later wrap never displaces one, and the opener tries
//! each, standing signers' first, so neither a bad wrap nor a removed
//! signer's flood hides a good one. "First" is the signer's sequence, then
//! the hash: a machine's later row always has a greater sequence, so a merge
//! never lets a descendant evict its ancestor's envelope, and the hash
//! breaks ties between concurrent rows only.
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
//!
//! A key is current only while a machine whose chain is not removed in this
//! install's trust set signed one of its counted records. A removed
//! machine's install key can still sign a record above the floor this
//! install keeps of it, which lands as honest late arrival does; it never
//! chooses the world's key, and no honest row that descends from it lends it
//! that standing (Astra #1422c F2, the Engine's Q1). Such a key stays in the
//! map, for reading and for the kit, and the next ensure on a machine of the
//! owner's mints afresh.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;

use super::machine_claims::folded_machine_in;
use super::machine_standing::{Standing, StandingView};
use super::world_privacy::policy_revision;
use super::world_strength::world_meet;
use super::*;

/// At most this many envelopes of one key, from one signer, for one
/// recipient.
pub const WORLD_KEY_WRAPS_PER_RECIPIENT: usize = 4;

/// One world key as a history holds it: per commitment and owner its counted
/// records named, per signer, per recipient, the records whose wraps count,
/// by rank, each with the settings revision it was wrapped under.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct WorldKeyState {
    named: BTreeMap<KeyBytes, BTreeMap<EntityId, BTreeMap<WrapRecipient, Slots>>>,
}

/// A record's commitment and owner.
type KeyBytes = ([u8; 32], EntityId);

type Slots = BTreeMap<SlotRank, PolicyRevision>;

/// A wrap slot's place among its signer's: the record's sequence, then its
/// hash. An ancestor always ranks before its descendants.
type SlotRank = (u64, AuthorityEntryHash);

/// One world key as this install's fold holds it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FoldedWorldKey {
    pub id: WorldKeyId,
    /// The vault owner PERSON its mint named.
    pub owner: EntityId,
    pub commitment: [u8; 32],
    /// Counted records named other bytes or another owner for this id.
    pub conflicted: bool,
    /// Per recipient, at most four counted envelopes from each signer of
    /// these bytes, standing signers' first.
    pub wraps: BTreeMap<WrapRecipient, Vec<WrappedKey>>,
    /// The machines that signed its counted records of these bytes, or of
    /// any bytes when it is conflicted.
    pub signers: BTreeSet<EntityId>,
}

/// One counted envelope of a key for one recipient.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// conflicted and that a machine not removed here stands behind.
    #[must_use]
    pub fn current_world_key(&self, world: EntityId) -> Option<&FoldedWorldKey> {
        self.world_keys(world)
            .filter(|key| !key.conflicted && self.world_key_stands(key))
            .last()
    }

    /// A machine whose chain is not removed in this install's trust set
    /// signed one of `key`'s counted records.
    #[must_use]
    pub fn world_key_stands(&self, key: &FoldedWorldKey) -> bool {
        key.signers
            .iter()
            .any(|machine| self.signer_stands(*machine))
    }

    /// No chain of `machine` in this install's trust set is removed, so a
    /// key record it signed may stand behind its key. A machine left out of
    /// a pin move is not removed.
    #[must_use]
    pub fn signer_stands(&self, machine: EntityId) -> bool {
        let local = self.local_admitter();
        self.machine(machine).is_some_and(|folded| {
            folded
                .trust_chains(&local)
                .iter()
                .all(|(_, chain)| !chain.removed)
        })
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
    let key = Arc::make_mut(state.world_keys.entry(record.key).or_default());
    let signed = key
        .named
        .entry((record.commitment, record.owner))
        .or_default()
        .entry(record.machine)
        .or_default();
    // Every slot of this signer the parent state holds is an ancestor of this
    // record and ranks before it, so with four slots full this record is the
    // one left out.
    for (recipient, _) in &record.wraps {
        let slots = signed.entry(*recipient).or_default();
        if slots.len() < WORLD_KEY_WRAPS_PER_RECIPIENT {
            slots.insert((entry.seq, hash), record.policy);
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
/// four wraps per signer and recipient. Order-free.
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
                for (bytes, signers) in &key.named {
                    let named = held.named.entry(*bytes).or_default();
                    for (machine, recipients) in signers {
                        let signed = named.entry(*machine).or_default();
                        for (recipient, wraps) in recipients {
                            let slots = signed.entry(*recipient).or_default();
                            slots.extend(wraps.iter().map(|(rank, policy)| (*rank, *policy)));
                            keep_first_slots(slots);
                        }
                    }
                }
            }
        }
    }
}

/// Keeps a signer's four first slots.
fn keep_first_slots(slots: &mut Slots) {
    while slots.len() > WORLD_KEY_WRAPS_PER_RECIPIENT {
        slots.pop_last();
    }
}

/// The fold's public view of every key, judged with `stands`, whether a
/// machine's chains in this install's final trust set are not removed, and
/// with each counted envelope read from the record that carries it.
pub(super) fn folded_world_keys(
    state: &FoldState,
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    stands: &dyn Fn(EntityId) -> bool,
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
        .filter_map(|(id, key)| {
            let standing = |signers: &BTreeMap<EntityId, _>| signers.keys().any(|m| stands(*m));
            let judged: Vec<_> = if key.named.values().any(standing) {
                key.named
                    .iter()
                    .filter(|(_, signers)| standing(signers))
                    .collect()
            } else {
                key.named.iter().collect()
            };
            let conflicted = judged.len() > 1;
            let (&(commitment, owner), signed) = *judged.first()?;
            let signers = if conflicted {
                key.named
                    .values()
                    .flat_map(BTreeMap::keys)
                    .copied()
                    .collect()
            } else {
                signed.keys().copied().collect()
            };
            // Standing signers' envelopes first, each signer's in rank order.
            let mut by_signer: Vec<_> = signed.iter().collect();
            by_signer.sort_by_key(|(machine, _)| !stands(**machine));
            let mut wraps: BTreeMap<WrapRecipient, Vec<WrappedKey>> = BTreeMap::new();
            for (_, recipients) in by_signer {
                for (recipient, slots) in recipients {
                    let wrapped = wraps.entry(*recipient).or_default();
                    wrapped.extend(slots.iter().filter_map(|((_, hash), policy)| {
                        Some(WrappedKey {
                            envelope: envelope(hash, recipient)?,
                            policy: *policy,
                            entry: *hash,
                        })
                    }));
                }
            }
            Some((
                *id,
                FoldedWorldKey {
                    id: *id,
                    owner,
                    commitment,
                    conflicted,
                    wraps,
                    signers,
                },
            ))
        })
        .collect()
}
