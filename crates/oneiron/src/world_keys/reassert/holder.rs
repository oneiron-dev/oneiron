//! A holder's re-assertion of one world's keys (contract §4): the step the
//! re-assert door runs on a holder, and an owner work executor runs for a
//! request in Reassert mode.
//!
//! The holder opens each key it wrapped itself from its own valid records (a
//! checkpoint image's among them), checked against the commitment the fold
//! holds for that id, or from a counted wrap to it, and wraps it again under
//! the current settings and pin to every recipient that lacks a counted
//! wrap, so the key id survives. Only once every such key is wrapped again
//! is the world's coverage ensured (CALLS WORLD_KEY_REASSERT_MODE): an ensure
//! before that could mint over a key the holder never re-wrapped. A key
//! whose pad or opening record is missing here, or a world whose edits
//! outgrow one record, leaves the work waiting (CALLS
//! WORLD_KEY_REASSERT_INCOMPLETE), its progress committed.
//!
//! The holder's read checks (the key ids its own records name, the pad, the
//! opening record or counted wrap, the recipients that lack a wrap) are one
//! read ([`HolderRead`]) that its writer and its owner's executor diagnostics
//! share (FIX 4686); so is the plan of each key's records, which says
//! whether one record names their frontier (FIX 5552). Only the writer
//! appends.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use oneiron_crypto::HybridPublicKey;

use super::super::doors::{ChainHead, Parents, RootRecipient, WrapPlanInput, require_mine_reader};
use super::super::pads::pad_in_txn;
use super::super::{
    MachineSecret, SequenceCounter, WorldKey, WorldKeyBinding, WorldKeyId, WrapRecipient,
    open_counted, open_world_key, recipients,
};
use crate::authority::{
    AuthorityEntryHash, AuthorityKey, AuthorityView, EffectiveRead, KeyFrontier,
    WorldKeyWrapsRecord, invalid_authority, own_world_key_records_in_txn,
};
use crate::error::Result;
use crate::store::Store;
use crate::{EntityId, Vault};

/// How a re-assertion's key work runs (CALLS WORLD_KEY_REASSERT_MODE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReassertMode {
    /// The holder wraps its own keys again first, keeping each id, and the
    /// world's coverage is ensured only after. An install that holds none
    /// records the work for a holder and never mints in its place.
    ExplicitReassertBeforeEnsure,
}

const WORLD_KEY_REASSERT_MODE: ReassertMode = ReassertMode::ExplicitReassertBeforeEnsure;

/// What an incomplete re-assertion leaves its owner work (CALLS
/// WORLD_KEY_REASSERT_INCOMPLETE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReassertIncomplete {
    /// Recorded, awaiting a holder: no result, never "enacted", the progress
    /// committed. No second election names another holder; only a new owner
    /// act does.
    Pending,
}

pub(crate) const WORLD_KEY_REASSERT_INCOMPLETE: ReassertIncomplete = ReassertIncomplete::Pending;

/// What one holder's re-assertion of a world left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reasserted {
    /// Every key of the world this holder wrapped itself is wrapped again to
    /// every recipient the settings allow, or the world reads everywhere.
    Done,
    /// A key's pad, or a record of this holder's or a counted wrap that opens
    /// it here, is missing, or the world's edits outgrow one record.
    Incomplete,
}

impl Reasserted {
    /// Whether the world's coverage may be ensured now (CALLS
    /// WORLD_KEY_REASSERT_MODE).
    pub(crate) fn ensures(self) -> bool {
        match WORLD_KEY_REASSERT_MODE {
            ReassertMode::ExplicitReassertBeforeEnsure => self == Self::Done,
        }
    }
}

/// What a holder's read checks find for one key of a world that its own
/// records name: the checks its re-assertion and its owner's diagnostics
/// share (FIX 4686).
pub(crate) enum HeldKey {
    /// Counted records named other bytes or another owner for it: the holder
    /// leaves it as it is.
    Conflicted,
    /// No pad of it is here.
    MissingPad,
    /// No valid record of this holder's own, checked against the commitment
    /// the fold holds, and no counted wrap to it, opens it here.
    NoOpening,
    /// Opened, with the owner it binds and every recipient the settings
    /// allow that holds no counted wrap of it.
    Opened {
        key: WorldKey,
        owner: EntityId,
        missing: Vec<(WrapRecipient, HybridPublicKey)>,
    },
}

/// One holder's read of a world it re-asserts, in one transaction: its
/// snapshot, its install key, its own valid records and its pinned root.
pub(crate) struct HolderRead {
    pub(crate) fold: AuthorityView,
    pub(crate) signing: SigningKey,
    vault_id: [u8; 32],
    world: EntityId,
    own: Vec<(AuthorityEntryHash, WorldKeyWrapsRecord)>,
    root: Option<RootRecipient>,
    /// The key ids of the world this holder's own records name, ascending:
    /// the census comes from its own records alone.
    pub(crate) ids: BTreeSet<WorldKeyId>,
}

impl HolderRead {
    /// The read checks for the key `id`, as this holder (`secret`) finds it
    /// in `txn`. Reads only: nothing is wrapped or written.
    pub(crate) fn check(
        &self,
        store: &Store,
        txn: &heed::RoTxn<'_>,
        id: WorldKeyId,
        secret: &MachineSecret,
    ) -> Result<HeldKey> {
        let me = WrapRecipient::Machine(secret.machine);
        let held = self.fold.world_key(&id);
        if held.is_some_and(|held| held.conflicted) {
            return Ok(HeldKey::Conflicted);
        }
        let Some(pad) = pad_in_txn(store, txn, &id)? else {
            return Ok(HeldKey::MissingPad);
        };
        let opened = self
            .own
            .iter()
            .map(|(_, record)| record)
            .filter(|record| {
                record.key == id && held.is_none_or(|held| held.commitment == record.commitment)
            })
            .find_map(|record| {
                let (_, bytes) = record.wraps.iter().find(|(to, _)| *to == me)?;
                let envelope = oneiron_crypto::Envelope::parse(bytes).ok()?;
                let binding = WorldKeyBinding {
                    vault_id: self.vault_id,
                    key: id,
                    owner: record.owner,
                    policy: record.policy,
                    commitment: record.commitment,
                };
                open_world_key(&binding, me, &secret.secret, &envelope, &pad)
                    .ok()
                    .map(|key| (key, record.owner))
            })
            .or_else(|| {
                let held = held?;
                open_counted(&self.fold, held, me, &secret.secret, &pad)
                    .map(|key| (key, held.owner))
            });
        let Some((key, owner)) = opened else {
            return Ok(HeldKey::NoOpening);
        };
        let missing = recipients(&self.fold, self.world, self.root.clone())
            .into_iter()
            .filter(|(to, _)| !held.is_some_and(|held| held.wraps.contains_key(to)))
            .collect();
        Ok(HeldKey::Opened {
            key,
            owner,
            missing,
        })
    }

    /// Every recipient the world's settings allow, with this holder's pinned
    /// root: what an ensure wraps the world's key to.
    pub(crate) fn allowed(&self) -> Vec<(WrapRecipient, HybridPublicKey)> {
        recipients(&self.fold, self.world, self.root.clone())
    }

    /// The row this holder's first record of the world names beside its
    /// parents, before any append.
    pub(crate) fn chain_head(&self) -> ChainHead {
        let signer = AuthorityKey::Ed25519(self.signing.verifying_key().to_bytes());
        ChainHead::of(&self.fold, &signer, self.world)
    }

    /// Whether `machine`'s wraps of one key to `missing`, for `request`, would
    /// name more rows than one record may, its first record naming `chain`:
    /// the writer's own plan in `txn`'s snapshot (FIX 5552), with the join
    /// the writer runs first (FIX 8497, FIX 11865). Reads only: nothing is
    /// sealed, signed or raised.
    pub(crate) fn wraps_wide(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        (machine, request): (EntityId, Option<AuthorityEntryHash>),
        missing: &[(WrapRecipient, HybridPublicKey)],
        chain: ChainHead,
    ) -> Result<bool> {
        if missing.is_empty() {
            return Ok(false);
        }
        let to: Vec<WrapRecipient> = missing.iter().map(|(recipient, _)| *recipient).collect();
        let input = WrapPlanInput {
            fold: &self.fold,
            machine,
            world: self.world,
            recipients: &to,
            chain,
            request,
            parents: Parents::Frontier,
        };
        if vault.plan_world_key_wraps_in_txn(txn, &input)?.is_ok() {
            return Ok(false);
        }
        // FIX 11865: the writer joins a wide frontier first and wraps on
        // the fold read back (FIX 8497), its world's side leaves too when
        // they alone fill the record (FIX 11868), so a plan too wide here
        // is wide only where the writer still cannot proceed: where its own
        // join predicate names no join (its room included, never recomputed
        // here). A row the door writes first is unwritten, so its join asks
        // with this snapshot's head, which it descends from.
        let row = match chain {
            ChainHead::Row(row) => row,
            ChainHead::Planned => match self.chain_head() {
                ChainHead::Row(row) => row,
                // `chain_head` names a row of this snapshot, never a
                // planned one: no chain, the main heads alone ask.
                ChainHead::Planned => None,
            },
        };
        let join = KeyFrontier::wide_in_txn(&vault.store, txn, &self.fold, self.world, row)?;
        Ok(join.is_none())
    }
}

impl Vault {
    /// This install's holder read of `world` in `txn`, as `secret`'s
    /// machine: `None` when the world reads everywhere and counts no key.
    /// Only an eligible reader mine here under its install key reads it;
    /// any other is refused.
    pub(crate) fn holder_read_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        world: EntityId,
        secret: &MachineSecret,
    ) -> Result<Option<HolderRead>> {
        let signing = self.door_signing_key_in_txn(txn, secret.machine)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        // A world read everywhere counts no key.
        if fold.world_privacy(world).read == EffectiveRead::Everywhere {
            return Ok(None);
        }
        require_mine_reader(&fold, world, secret.machine, &signing)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let own = own_world_key_records_in_txn(
            &self.store,
            txn,
            &fold,
            secret.machine,
            signing.verifying_key().to_bytes(),
        )?;
        let root = self.pinned_root_recipient_in_txn(txn, &fold)?;
        let ids = own
            .iter()
            .map(|(_, record)| record.key)
            .filter(|id| id.world == world)
            .collect();
        Ok(Some(HolderRead {
            fold,
            signing,
            vault_id,
            world,
            own,
            root,
            ids,
        }))
    }

    /// Wraps again, in the caller's write transaction, each key of `world`
    /// this install wrapped itself, under the current settings and pin, to
    /// every recipient the settings allow that holds no counted wrap of it.
    /// Each record names `request`, the owner work request this holder does,
    /// or none when the owner's re-assertion runs on this holder. Only an
    /// eligible reader runs it: the owner's recipient choice, never a rule
    /// on who decided. A conflicted key is left as it is. The fold is the
    /// judge: every record written must count here.
    pub(crate) fn reassert_held_world_keys_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        world: EntityId,
        secret: &MachineSecret,
        request: Option<AuthorityEntryHash>,
    ) -> Result<Reasserted> {
        let Some(read) = self.holder_read_in_txn(txn, world, secret)? else {
            return Ok(Reasserted::Done);
        };
        let mut seq = SequenceCounter::new();
        let mut appended = Vec::new();
        let mut done = Reasserted::Done;
        for id in read.ids.iter().copied() {
            let (key, key_owner, missing) = match read.check(&self.store, txn, id, secret)? {
                HeldKey::Conflicted => continue,
                HeldKey::MissingPad | HeldKey::NoOpening => {
                    done = Reasserted::Incomplete;
                    continue;
                }
                HeldKey::Opened {
                    key,
                    owner,
                    missing,
                } => (key, owner, missing),
            };
            match self.append_world_key_wraps_in_txn(
                txn,
                &read.fold,
                &read.signing,
                secret.machine,
                &key,
                key_owner,
                &missing,
                &mut seq,
                request,
            )? {
                Ok(records) => appended.extend(records),
                Err(_wide) => done = Reasserted::Incomplete,
            }
        }
        self.require_counted_in_txn(txn, &appended)?;
        Ok(done)
    }
}
