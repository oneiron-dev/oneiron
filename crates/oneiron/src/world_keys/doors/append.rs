//! A key record's appends: one machine's wraps of one key, as side entries
//! of the key's world, split across records within the codec's bounds as
//! their read-only plan says (`frontier`, FIX 5552), and the sequence and
//! chain each record of one door transaction takes.
//!
//! A record names this install's main heads and its world's side leaves in
//! place of the rows its evidence rests on whenever those carry every such
//! row ([`KeyFrontier`], FIX 5464), so a resumed fold and a fold past an
//! adopted image fold it without the whole history; otherwise it names the
//! rows themselves, as before. The bridge record keeps its own parents.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use oneiron_crypto::HybridPublicKey;

use super::super::pads::require_pad_in_txn;
use super::super::{PolicyRevision, WorldKey, WorldKeyBinding, WrapRecipient, seal_world_key};
use super::frontier::{ChainHead, Parents, WrapPlanInput};
use super::{FrontierWide, RootRecipient, provenance};
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, AuthorityLogEntry, AuthorityOp, MAX_PARENTS,
    invalid_authority, next_sequence, scope_head, sign_side_entry, standing_rows,
};
use crate::error::Result;
use crate::{EntityId, TimeRange, Vault};

/// One key record's parents and the recipients it wraps to.
type WrapChunk<'a> = (
    BTreeSet<AuthorityEntryHash>,
    Vec<(WrapRecipient, &'a HybridPublicKey)>,
);

/// The parents one key record names beside its signer's previous row of the
/// world.
const RECORD_PARENTS: usize = MAX_PARENTS - 1;

/// One machine's next sequences inside one door transaction, and the last
/// row it wrote there for each world.
pub(crate) struct SequenceCounter {
    last: Option<u64>,
    chained: BTreeMap<EntityId, AuthorityEntryHash>,
}

impl SequenceCounter {
    pub(crate) fn new() -> Self {
        Self {
            last: None,
            chained: BTreeMap::new(),
        }
    }

    fn next(&mut self, fold: &AuthorityFold, signing: &SigningKey) -> Result<u64> {
        let signer = crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
        let next = match self.last {
            None => next_sequence(fold, &signer)?,
            Some(last) => last.checked_add(1).ok_or_else(invalid_authority)?,
        };
        self.last = Some(next);
        Ok(next)
    }

    /// The machine's previous key record of `world`, which its next key
    /// record names. Settings edits are main-log rows (mesh contract §6), so
    /// the scope head holds key records only. A machine's key records of a
    /// world thus form one chain in one sequence scope, and a receiver that
    /// stores a later one first still admits the earlier ones under its floor
    /// (Astra #1422b F1, #1422c).
    fn chain(
        &self,
        fold: &AuthorityFold,
        signing: &SigningKey,
        world: EntityId,
    ) -> Option<AuthorityEntryHash> {
        let signer = crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
        self.chained
            .get(&world)
            .copied()
            .or_else(|| scope_head(fold, &signer, world))
    }
}

impl Vault {
    /// Appends `machine`'s wraps of `key` to `recipients` in the caller's
    /// write transaction, as side entries of the key's world. The settings
    /// revision comes from `fold`, and the rows the records' evidence rests on:
    /// the world's live edits, the rows each named machine's standing rests
    /// on, the root's record, and `request`, the owner work request the
    /// records do (`None` for an eligible reader's own wraps), counted before
    /// any split. Recipients are split across records so each stays within
    /// the codec's bounds. When this install's main heads and the world's side
    /// leaves carry every one of those rows, the first record names them and
    /// each later one the record before it ([`KeyFrontier`], FIX 5464);
    /// otherwise each names the rows themselves and its signer's previous row
    /// of the world. Returns the records' hashes; the caller judges the
    /// refold. On the frontier a record's width is the parents it names
    /// alone (FIX 5680): a world whose rows outgrow one record raises its
    /// OF-520 question and writes nothing ([`FrontierWide`]) only when its
    /// records stay on those rows.
    #[expect(
        clippy::too_many_arguments,
        reason = "one append: the snapshot, the signer, the key, its recipients and its request"
    )]
    pub(crate) fn append_world_key_wraps_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        signing: &SigningKey,
        machine: EntityId,
        key: &WorldKey,
        owner: EntityId,
        recipients: &[(WrapRecipient, HybridPublicKey)],
        seq: &mut SequenceCounter,
        request: Option<AuthorityEntryHash>,
    ) -> Result<std::result::Result<Vec<AuthorityEntryHash>, FrontierWide>> {
        self.append_wraps_in_txn(
            txn,
            fold,
            signing,
            (machine, key, owner),
            recipients,
            seq,
            request,
            Parents::Frontier,
        )
    }

    /// [`Self::append_world_key_wraps_in_txn`] on the rows the records'
    /// evidence rests on alone, never the frontier: for `fold`, a view the
    /// store has moved past since (repin's pre-wrap on the old pin's rows,
    /// after the new marks and pin are stored).
    #[expect(
        clippy::too_many_arguments,
        reason = "one append: the snapshot, the signer, the key, its recipients and its request"
    )]
    pub(crate) fn append_world_key_wraps_explicit_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        signing: &SigningKey,
        machine: EntityId,
        key: &WorldKey,
        owner: EntityId,
        recipients: &[(WrapRecipient, HybridPublicKey)],
        seq: &mut SequenceCounter,
        request: Option<AuthorityEntryHash>,
    ) -> Result<std::result::Result<Vec<AuthorityEntryHash>, FrontierWide>> {
        self.append_wraps_in_txn(
            txn,
            fold,
            signing,
            (machine, key, owner),
            recipients,
            seq,
            request,
            Parents::Explicit,
        )
    }

    /// One append of `key`'s wraps, its records' parents as `mode` allows.
    #[expect(
        clippy::too_many_arguments,
        reason = "one append: the snapshot, the signer, the key, its recipients and its parents"
    )]
    fn append_wraps_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        signing: &SigningKey,
        (machine, key, owner): (EntityId, &WorldKey, EntityId),
        recipients: &[(WrapRecipient, HybridPublicKey)],
        seq: &mut SequenceCounter,
        request: Option<AuthorityEntryHash>,
        mode: Parents,
    ) -> Result<std::result::Result<Vec<AuthorityEntryHash>, FrontierWide>> {
        if recipients.is_empty() {
            return Ok(Ok(Vec::new()));
        }
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let world = key.id().world;
        let policy = PolicyRevision::of(
            fold.worlds
                .get(&world)
                .into_iter()
                .flat_map(|folded| folded.live.keys().copied()),
        );
        let binding = WorldKeyBinding {
            vault_id,
            key: *key.id(),
            owner,
            policy,
            commitment: key.commitment(),
        };
        let to: Vec<WrapRecipient> = recipients.iter().map(|(recipient, _)| *recipient).collect();
        let input = WrapPlanInput {
            fold,
            machine,
            world,
            recipients: &to,
            chain: ChainHead::Row(seq.chain(fold, signing, world)),
            request,
            parents: mode,
        };
        let plan = match self.plan_world_key_wraps_in_txn(txn, &input)? {
            Ok(plan) => plan,
            Err(wide) => {
                self.world_keys.frontier_wide(world, wide.rows);
                return Ok(Err(FrontierWide(if wide.base {
                    "the world's key rests on more rows than one record names: merge this world's \
                     settings from one machine that sees every edit, then retry"
                } else {
                    "a recipient's standing and the world's edits are more rows than one record \
                     names: merge this world's settings from one machine that sees every edit, \
                     then retry"
                })));
            }
        };
        let chunks: Vec<WrapChunk<'_>> = plan
            .records
            .into_iter()
            .map(|record| {
                let wraps = record
                    .recipients
                    .into_iter()
                    .map(|index| (recipients[index].0, &recipients[index].1))
                    .collect();
                (record.parents, wraps)
            })
            .collect();
        self.put_wrap_records_in_txn(
            txn,
            fold,
            signing,
            machine,
            key,
            &binding,
            chunks,
            seq,
            request,
            plan.on_frontier,
        )
        .map(Ok)
    }

    /// This machine's own record of `key` when no record names the world's
    /// whole frontier ([`FrontierWide`]). It wraps the key to `root`, when
    /// there is one, and to this machine only, whatever the frontier, so a flood can make it wrap
    /// to no one else. Its parents are the rows this machine's standing rests
    /// on, the root records, and as many of the world's live edits as one
    /// record still names; its policy is the revision at those parents. A
    /// later door here opens the key from it whether or not it counts, so a
    /// merge and a re-run reach the same key (Engine, 2026-10-15, on Sol
    /// S2-R2 S2-F3 and Astra A2-F2). It names `request` as the other
    /// records do, before the live edits fill the room left.
    #[expect(
        clippy::too_many_arguments,
        reason = "one append: the snapshot, the signer, the key, its two recipients and its request"
    )]
    pub(crate) fn append_bridge_wrap_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        signing: &SigningKey,
        machine: EntityId,
        key: &WorldKey,
        owner: EntityId,
        root: Option<&RootRecipient>,
        own: &HybridPublicKey,
        seq: &mut SequenceCounter,
        request: Option<AuthorityEntryHash>,
    ) -> Result<AuthorityEntryHash> {
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let mut parents = standing_rows(fold, machine);
        parents.extend(root.map(|root| root.entry));
        if let Some(pinned) = self.pinned_root_recipient_in_txn(txn, fold)? {
            parents.insert(pinned.entry);
        }
        parents.extend(request);
        let room = RECORD_PARENTS
            .checked_sub(parents.len())
            .ok_or_else(invalid_authority)?;
        let live: BTreeSet<AuthorityEntryHash> = fold
            .worlds
            .get(&key.id().world)
            .into_iter()
            .flat_map(|folded| folded.live.keys().copied())
            .take(room)
            .collect();
        let binding = WorldKeyBinding {
            vault_id,
            key: *key.id(),
            owner,
            policy: PolicyRevision::of(live.iter().copied()),
            commitment: key.commitment(),
        };
        parents.extend(live);
        let wraps = root
            .map(|root| (WrapRecipient::RecoveryRoot(root.id), &root.key))
            .into_iter()
            .chain([(WrapRecipient::Machine(machine), own)])
            .collect();
        self.put_wrap_records_in_txn(
            txn,
            fold,
            signing,
            machine,
            key,
            &binding,
            vec![(parents, wraps)],
            seq,
            request,
            false,
        )?
        .pop()
        .ok_or_else(invalid_authority)
    }

    /// Seals `key` to each chunk's recipients under `binding` and appends one
    /// signed record per chunk, naming that chunk's parents, which hold
    /// `request` when the records do an owner work request, or hold it
    /// beneath them (`frontier`: the first chunk's parents hold its signer's
    /// previous row of the world beneath them, and each later chunk names the
    /// record before it alone).
    #[expect(
        clippy::too_many_arguments,
        reason = "one append: the snapshot, the signer, the key, its records and their request"
    )]
    fn put_wrap_records_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        signing: &SigningKey,
        machine: EntityId,
        key: &WorldKey,
        binding: &WorldKeyBinding,
        chunks: Vec<WrapChunk<'_>>,
        seq: &mut SequenceCounter,
        request: Option<AuthorityEntryHash>,
        frontier: bool,
    ) -> Result<Vec<AuthorityEntryHash>> {
        let now = self.instant_in_txn(txn)?.secs();
        let pad = require_pad_in_txn(&self.store, txn, key.id())?;
        let mut rows: Vec<(AuthorityLogEntry, TimeRange, u64)> = Vec::new();
        let mut hashes = Vec::new();
        let world = key.id().world;
        for (index, (mut parents, wraps)) in chunks.into_iter().enumerate() {
            if !frontier || index > 0 {
                parents.extend(seq.chain(fold, signing, world));
            }
            let wraps = wraps
                .into_iter()
                .map(|(recipient, public)| {
                    seal_world_key(binding, recipient, public, key, &pad)
                        .map(|envelope| (recipient, envelope.to_bytes()))
                })
                .collect::<Result<Vec<_>>>()?;
            let record = provenance::wraps_record(binding, machine, wraps, request);
            let entry = sign_side_entry(
                fold,
                signing,
                seq.next(fold, signing)?,
                parents,
                AuthorityOp::WorldKeyWraps(record),
                now,
            )?;
            let hash = crate::authority::authority_entry_hash(&entry)?;
            seq.chained.insert(world, hash);
            hashes.push(hash);
            rows.push((
                entry,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            ));
        }
        self.put_authority_log_entries_in_txn(txn, &rows)?;
        Ok(hashes)
    }
}
