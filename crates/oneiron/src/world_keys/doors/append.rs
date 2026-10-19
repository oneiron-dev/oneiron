//! A key record's appends: one machine's wraps of one key, as side entries
//! of the key's world, split across records within the codec's bounds, and
//! the sequence and chain each record of one door transaction takes.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use oneiron_crypto::HybridPublicKey;

use super::super::pads::require_pad_in_txn;
use super::super::{PolicyRevision, WorldKey, WorldKeyBinding, WrapRecipient, seal_world_key};
use super::{FrontierWide, RootRecipient, provenance};
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, AuthorityLogEntry, AuthorityOp, MAX_PARENTS,
    WORLD_KEY_WRAPS_MAX, invalid_authority, next_sequence, scope_head, sign_side_entry,
    standing_rows,
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
    /// write transaction, as side entries of the key's world. Parents and
    /// the settings revision come from `fold`: the world's live edits, the
    /// rows each named machine's standing rests on, the root's record, and
    /// `request`, the owner work request the records do (`None` for an
    /// eligible reader's own wraps), counted before any split. Recipients are
    /// split across records so each stays within the codec's bounds. Returns
    /// the records' hashes; the caller judges the refold. A world whose rows
    /// outgrow one record raises its OF-520 question and writes nothing
    /// ([`FrontierWide`]).
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
        if recipients.is_empty() {
            return Ok(Ok(Vec::new()));
        }
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let world = key.id().world;
        let frontier = fold.worlds.get(&world);
        let live: BTreeSet<AuthorityEntryHash> = frontier
            .into_iter()
            .flat_map(|folded| folded.live.keys().copied())
            .collect();
        let policy = PolicyRevision::of(live.iter().copied());
        let binding = WorldKeyBinding {
            vault_id,
            key: *key.id(),
            owner,
            policy,
            commitment: key.commitment(),
        };
        let mut base = live;
        base.extend(standing_rows(fold, machine));
        if let Some(root) = self.pinned_root_recipient_in_txn(txn, fold)? {
            base.insert(root.entry);
        }
        base.extend(request);
        // Whether a live edit counts may rest on a later revision of its
        // machine, so name those too while they stay few (as the settings
        // door does).
        let authors: BTreeSet<_> = frontier
            .into_iter()
            .flat_map(|folded| folded.live.values())
            .flat_map(|author| standing_rows(fold, *author))
            .collect();
        if base.union(&authors).count() <= MAX_PARENTS / 2 {
            base.extend(authors);
        }
        // Each record names its signer's previous row of the world beside
        // these: the first names the scope head, which counts once when it is
        // already a live edit here, and each later one the record before it
        // (Astra #1422d F1).
        let chain = seq.chain(fold, signing, world);
        let named = |parents: &BTreeSet<AuthorityEntryHash>,
                     rows: &BTreeSet<AuthorityEntryHash>,
                     first: bool| {
            let chained = !first
                || chain.is_some_and(|chain| !parents.contains(&chain) && !rows.contains(&chain));
            parents.union(rows).count() + usize::from(chained)
        };
        let base_named = named(&base, &BTreeSet::new(), true);
        if base_named > MAX_PARENTS {
            self.world_keys.frontier_wide(world, base_named);
            return Ok(Err(FrontierWide(
                "the world's key rests on more rows than one record names: merge this world's \
                 settings from one machine that sees every edit, then retry",
            )));
        }
        let mut chunks: Vec<(BTreeSet<AuthorityEntryHash>, Vec<_>)> = Vec::new();
        let mut parents = base.clone();
        let mut wraps = Vec::new();
        for (recipient, public) in recipients {
            let rows = match recipient {
                WrapRecipient::Machine(id) => standing_rows(fold, *id),
                WrapRecipient::RecoveryRoot(_) => BTreeSet::new(),
            };
            let full = |parents: &BTreeSet<_>, wraps: &Vec<_>, first: bool| {
                named(parents, &rows, first) > MAX_PARENTS || wraps.len() == WORLD_KEY_WRAPS_MAX
            };
            if full(&parents, &wraps, chunks.is_empty()) && !wraps.is_empty() {
                chunks.push((
                    std::mem::replace(&mut parents, base.clone()),
                    std::mem::take(&mut wraps),
                ));
            }
            if full(&parents, &wraps, chunks.is_empty()) {
                self.world_keys
                    .frontier_wide(world, named(&parents, &rows, chunks.is_empty()));
                return Ok(Err(FrontierWide(
                    "a recipient's standing and the world's edits are more rows than one record \
                     names: merge this world's settings from one machine that sees every edit, \
                     then retry",
                )));
            }
            parents.extend(rows);
            wraps.push((*recipient, public));
        }
        chunks.push((parents, wraps));
        self.put_wrap_records_in_txn(
            txn, fold, signing, machine, key, &binding, chunks, seq, request,
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
        )?
        .pop()
        .ok_or_else(invalid_authority)
    }

    /// Seals `key` to each chunk's recipients under `binding` and appends one
    /// signed record per chunk, naming that chunk's parents, which hold
    /// `request` when the records do an owner work request.
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
    ) -> Result<Vec<AuthorityEntryHash>> {
        let now = self.instant_in_txn(txn)?.secs();
        let pad = require_pad_in_txn(&self.store, txn, key.id())?;
        let mut rows: Vec<(AuthorityLogEntry, TimeRange, u64)> = Vec::new();
        let mut hashes = Vec::new();
        let world = key.id().world;
        for (mut parents, wraps) in chunks {
            parents.extend(seq.chain(fold, signing, world));
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
