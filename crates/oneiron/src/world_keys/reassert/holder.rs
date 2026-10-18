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

use std::collections::BTreeSet;

use super::super::doors::require_mine_reader;
use super::super::pads::pad_in_txn;
use super::super::{
    MachineSecret, SequenceCounter, WorldKeyBinding, WorldKeyId, WrapRecipient, open_counted,
    open_world_key, recipients,
};
use crate::authority::{
    AuthorityEntryHash, EffectiveRead, invalid_authority, own_world_key_records_in_txn,
};
use crate::error::Result;
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

impl Vault {
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
        let signing = self.door_signing_key_in_txn(txn, secret.machine)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        // A world read everywhere counts no key.
        if fold.world_privacy(world).read == EffectiveRead::Everywhere {
            return Ok(Reasserted::Done);
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
        let me = WrapRecipient::Machine(secret.machine);
        let ids: BTreeSet<WorldKeyId> = own
            .iter()
            .map(|(_, record)| record.key)
            .filter(|id| id.world == world)
            .collect();
        let mut seq = SequenceCounter::new();
        let mut appended = Vec::new();
        let mut done = Reasserted::Done;
        for id in ids {
            let held = fold.world_key(&id);
            if held.is_some_and(|held| held.conflicted) {
                continue;
            }
            let Some(pad) = pad_in_txn(&self.store, txn, &id)? else {
                done = Reasserted::Incomplete;
                continue;
            };
            let opened = own
                .iter()
                .map(|(_, record)| record)
                .filter(|record| {
                    record.key == id && held.is_none_or(|held| held.commitment == record.commitment)
                })
                .find_map(|record| {
                    let (_, bytes) = record.wraps.iter().find(|(to, _)| *to == me)?;
                    let envelope = oneiron_crypto::Envelope::parse(bytes).ok()?;
                    let binding = WorldKeyBinding {
                        vault_id,
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
                    open_counted(&fold, held, me, &secret.secret, &pad).map(|key| (key, held.owner))
                });
            let Some((key, key_owner)) = opened else {
                done = Reasserted::Incomplete;
                continue;
            };
            let missing: Vec<_> = recipients(&fold, world, root.clone())
                .into_iter()
                .filter(|(to, _)| !held.is_some_and(|held| held.wraps.contains_key(to)))
                .collect();
            match self.append_world_key_wraps_in_txn(
                txn,
                &fold,
                &signing,
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
