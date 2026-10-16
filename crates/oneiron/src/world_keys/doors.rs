//! The doors that mint, wrap and open a world's key (contract §5), and what
//! every world-key door shares: this install's machine and secret, a world's
//! liveness, opening a key, and appending one machine's wraps of one key as
//! side entries of the key's world.
//!
//! The machine secret is read from the keystore before a door's transaction,
//! and the transaction refuses when the machine id changed in between. No
//! key, seed or secret is ever written; only the signed records are.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use oneiron_crypto::{Envelope, HybridPublicKey, HybridSecretKey};

use super::pads::{WorldKeyPad, require_pad_in_txn};
use super::{
    FIRST_GENERATION, PolicyRevision, WorldKey, WorldKeyBinding, WorldKeyId, WorldRecoveryState,
    WrapRecipient, machine_secret, open_world_key, recovery_state, refused, seal_world_key,
};
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, AuthorityLogEntry, AuthorityOp, Destination, EffectiveRead,
    FoldedWorldKey, MAX_PARENTS, RecoveryRootId, WORLD_KEY_WRAPS_MAX, WorldKeyWrapsRecord,
    invalid_authority, next_sequence, owner_root_record_in_txn, scope_head, sign_side_entry,
    standing_rows,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::ports::TombstoneStoreRead;
use crate::registry::ENTITY_TYPE_WORLD;
use crate::{EntityId, TimeRange, Vault};

/// One key record's parents and the recipients it wraps to.
type WrapChunk<'a> = (
    BTreeSet<AuthorityEntryHash>,
    Vec<(WrapRecipient, &'a HybridPublicKey)>,
);

/// What [`Vault::ensure_world_key`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorldKeyStatus {
    /// The world reads everywhere: no key counts for it.
    NotPrivate,
    /// It had no current key; this machine minted one and wrapped it.
    Minted(WorldKeyId),
    /// This machine wrapped the current key to `added` recipients it lacked.
    Wrapped { key: WorldKeyId, added: usize },
    /// Every recipient already holds a wrap of the current key.
    UpToDate(WorldKeyId),
}

/// This install's machine secret, read outside any transaction, with the
/// machine id its slot is named by.
pub(crate) struct MachineSecret {
    pub(crate) machine: EntityId,
    pub(crate) secret: HybridSecretKey,
}

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

    /// The machine's previous row of `world`, a settings edit or a key
    /// record, which its next key record names. A machine's rows of a world
    /// thus form one chain in one sequence scope, and a receiver that stores
    /// a later one first still admits the earlier ones under its floor
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
    /// This install's machine secret, read before a door's transaction. A
    /// machine with no identity yet has no secret: no door mints one here.
    pub(crate) fn machine_secret_outside_txn(&self) -> Result<MachineSecret> {
        let keystore = self.device_keystore()?;
        // The door signs its record with the machine key in its txn: load it here.
        self.load_install_signing_if_minted()?;
        let (machine, vault_id) = {
            let txn = self.store.env.read_txn()?;
            let machine = crate::identity::read_machine_id_in_txn(self, &txn)?
                .ok_or_else(|| refused("this install has no machine identity"))?;
            let vault_id = self
                .authority_view_readonly_in_txn(&txn)?
                .vault_id
                .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
            (machine, vault_id)
        };
        let secret = machine_secret(keystore.as_ref(), vault_id, *machine.as_bytes())?;
        Ok(MachineSecret { machine, secret })
    }

    /// This install's install key in the door's snapshot, refused when the
    /// machine id is not the one the secret was read under.
    pub(crate) fn door_signing_key_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        expected: EntityId,
    ) -> Result<SigningKey> {
        if crate::identity::read_machine_id_in_txn(self, txn)? != Some(expected) {
            return Err(refused(
                "the machine identity changed after its secret was read",
            ));
        }
        crate::identity::read_machine_signing_key_in_txn(self, txn)?
            .ok_or_else(|| refused("this install has no machine key"))
    }

    /// Whether `world` is a stored WORLD row other than base reality, not
    /// deleted, archived or stale here (the erasure guard, contract §5).
    pub(crate) fn world_row_live_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        world: EntityId,
    ) -> Result<bool> {
        if world == crate::claim::base_world_id()
            || self.get_entity_type_in_txn(txn, &world)? != Some(ENTITY_TYPE_WORLD)
        {
            return Ok(false);
        }
        let visibility = TombstoneStoreRead::port_deletion_state(&self.store, txn, &world)?;
        Ok(!(visibility.deleted || visibility.archived || visibility.stale))
    }

    /// Mints the world's key if it has no current one, and wraps the current
    /// key to every machine mine here that may read the world and to this
    /// install's pinned root. This machine must be mine, may read the world,
    /// and holds the world's live WORLD row.
    pub fn ensure_world_key(
        &self,
        owner: &AuthenticatedOwner,
        world: EntityId,
    ) -> Result<WorldKeyStatus> {
        let secret = self.machine_secret_outside_txn()?;
        self.with_write_txn(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            self.ensure_world_key_in_txn(txn, actor, world, &secret)
        })
    }

    /// [`Vault::ensure_world_key`] for every private world this machine may
    /// read, in one transaction: what a machine that holds keys runs once a
    /// sync brings a newly joined machine of the owner's. A world whose
    /// current key this machine holds no wrap of is left to a machine that
    /// does.
    pub fn ensure_world_keys(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Vec<(EntityId, WorldKeyStatus)>> {
        let secret = self.machine_secret_outside_txn()?;
        self.with_write_txn(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let worlds: Vec<EntityId> = fold
                .worlds
                .keys()
                .copied()
                .filter(|world| {
                    fold.world_privacy(*world).read != EffectiveRead::Everywhere
                        && fold.world_readable_on(*world, Destination::Machine(secret.machine))
                })
                .collect();
            let mut out = Vec::new();
            for world in worlds {
                if let Some(status) =
                    self.ensure_world_key_after_edit_in_txn(txn, actor, world, &secret)?
                {
                    out.push((world, status));
                }
            }
            Ok(out)
        })
    }

    /// [`Vault::ensure_world_key`] in the caller's write transaction.
    pub(crate) fn ensure_world_key_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        world: EntityId,
        secret: &MachineSecret,
    ) -> Result<WorldKeyStatus> {
        self.ensure_world_key_or_wide_in_txn(txn, owner, world, secret)?
            .map_err(FrontierWide::refused)
    }

    /// The key a settings edit leaves `world` with, in the edit's transaction.
    /// - When this machine may read the world after the edit and the world has no
    ///   key yet, the key is minted in this commit, and any refusal (no keystore, a
    ///   keystore failure, no machine identity) refuses the edit: a private world
    ///   never commits keyless on a machine that could mint its key.
    /// - A world whose live edits outgrow one key record still mints its first
    ///   key, on this machine's own record (Docs Q06), with OF-520's question
    ///   raised: the rate law refuses no edit for a count.
    /// - Otherwise a refusal leaves the edit standing, as before: another reader
    ///   mints, or the new recipients are wrapped on that reader's next ensure.
    pub(crate) fn world_key_for_edit_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        world: EntityId,
        secret: Result<&MachineSecret>,
    ) -> Result<Option<WorldKeyStatus>> {
        let needs_key = {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let machine = crate::identity::read_machine_id_in_txn(self, txn)?;
            fold.world_privacy(world).read != EffectiveRead::Everywhere
                && fold.current_world_key(world).is_none()
                && machine.is_some_and(|machine| {
                    fold.trusted_machine(machine).is_some()
                        && fold.world_readable_on(world, Destination::Machine(machine))
                })
        };
        let attempt = match secret {
            Ok(secret) => self.ensure_world_key_or_wide_in_txn(txn, owner, world, secret),
            Err(error) if needs_key => return Err(error),
            Err(_) => return Ok(None),
        };
        match attempt {
            Ok(Ok(status)) => Ok(Some(status)),
            Ok(Err(_wide)) => Ok(None),
            // Refusals all come before the first write.
            Err(error @ crate::error::Error::Secret(_)) if needs_key => Err(error),
            Err(crate::error::Error::Secret(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// [`Vault::ensure_world_key_in_txn`], with a world whose live edits outgrow one
    /// key record told apart from every other refusal.
    fn ensure_world_key_or_wide_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        world: EntityId,
        secret: &MachineSecret,
    ) -> Result<std::result::Result<WorldKeyStatus, FrontierWide>> {
        let signing = self.door_signing_key_in_txn(txn, secret.machine)?;
        if !self.world_row_live_in_txn(txn, world)? {
            return Err(refused("the world has no live WORLD row here"));
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if fold.world_privacy(world).read == EffectiveRead::Everywhere {
            return Ok(Ok(WorldKeyStatus::NotPrivate));
        }
        require_mine_reader(&fold, world, secret.machine, &signing)?;
        let root = self.pinned_root_recipient_in_txn(txn, &fold)?;
        let allowed = recipients(&fold, world, root.clone());
        let mut seq = SequenceCounter::new();
        let Some(current) = fold.current_world_key(world) else {
            let key = WorldKey::mint(world, FIRST_GENERATION)?;
            let id = *key.id();
            // The pad lands with the key's first wraps, which are sealed against it.
            let now = self.instant_in_txn(txn)?.secs();
            self.put_pad_in_txn(txn, &id, &WorldKeyPad::mint()?, now)?;
            let records = match self.append_world_key_wraps_in_txn(
                txn,
                &fold,
                &signing,
                secret.machine,
                &key,
                owner,
                &allowed,
                &mut seq,
            )? {
                Ok(records) => records,
                // A first key never leaves the world keyless for a count (Docs
                // Q06): this machine's own record, and the root's, on bounded
                // parents. The question stays raised; the other readers are
                // wrapped once the settings merge.
                Err(wide) => {
                    let mine = WrapRecipient::Machine(secret.machine);
                    let Some((_, own)) = allowed.iter().find(|(to, _)| *to == mine) else {
                        return Ok(Err(wide));
                    };
                    vec![self.append_bridge_wrap_in_txn(
                        txn,
                        &fold,
                        &signing,
                        secret.machine,
                        &key,
                        owner,
                        root.as_ref(),
                        own,
                        &mut seq,
                    )?]
                }
            };
            self.require_counted_in_txn(txn, &records)?;
            return Ok(Ok(WorldKeyStatus::Minted(id)));
        };
        let id = current.id;
        let missing: Vec<_> = allowed
            .into_iter()
            .filter(|(recipient, _)| !current.wraps.contains_key(recipient))
            .collect();
        if missing.is_empty() {
            return Ok(Ok(WorldKeyStatus::UpToDate(id)));
        }
        let pad = require_pad_in_txn(&self.store, txn, &id)?;
        let key = open_counted(
            &fold,
            current,
            WrapRecipient::Machine(secret.machine),
            &secret.secret,
            &pad,
        )
        .ok_or_else(|| refused("this machine holds no wrap of the world's current key"))?;
        let records = match self.append_world_key_wraps_in_txn(
            txn,
            &fold,
            &signing,
            secret.machine,
            &key,
            current.owner,
            &missing,
            &mut seq,
        )? {
            Ok(records) => records,
            Err(wide) => return Ok(Err(wide)),
        };
        self.require_counted_in_txn(txn, &records)?;
        Ok(Ok(WorldKeyStatus::Wrapped {
            key: id,
            added: missing.len(),
        }))
    }

    /// The settings door's step after an edit: the world's key follows its
    /// settings when this machine may still read the world. A world this
    /// machine no longer reads, or whose current key it holds no wrap of,
    /// keeps the edit; a machine that holds the key wraps it on its own
    /// ensure.
    pub(crate) fn ensure_world_key_after_edit_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        world: EntityId,
        secret: &MachineSecret,
    ) -> Result<Option<WorldKeyStatus>> {
        match self.ensure_world_key_in_txn(txn, owner, world, secret) {
            Ok(status) => Ok(Some(status)),
            // Refusals all come before the first write.
            Err(crate::error::Error::Secret(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Opens the world's current key on this machine into the session ring.
    /// Refused unless this machine is mine with its own keys, may read the
    /// world now, and holds its live WORLD row. Every call judges that
    /// again, and drops from the ring each key this machine may no longer
    /// read.
    pub fn world_key(&self, world: EntityId) -> Result<Arc<WorldKey>> {
        let secret = self.machine_secret_outside_txn()?;
        let txn = self.store.env.read_txn()?;
        let signing = self.door_signing_key_in_txn(&txn, secret.machine)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let readable = |world: EntityId| {
            fold.world_privacy(world).read != EffectiveRead::Everywhere
                && fold.world_readable_on(world, Destination::Machine(secret.machine))
        };
        self.sweep_world_key_ring(&readable);
        if !self.world_row_live_in_txn(&txn, world)? || !readable(world) {
            return Err(refused("this machine may not read the world"));
        }
        require_mine_reader(&fold, world, secret.machine, &signing)?;
        let current = fold
            .current_world_key(world)
            .ok_or_else(|| refused("the world has no key yet"))?;
        let mut ring = self.world_key_ring();
        // A ring entry counts only while it is the bytes the fold commits to.
        match ring.get(&current.id) {
            Some(key) if key.commitment() == current.commitment => return Ok(Arc::clone(key)),
            Some(_) => {
                ring.remove(&current.id);
            }
            None => {}
        }
        let pad = require_pad_in_txn(&self.store, &txn, &current.id)?;
        let key = open_counted(
            &fold,
            current,
            WrapRecipient::Machine(secret.machine),
            &secret.secret,
            &pad,
        )
        .ok_or_else(|| refused("this machine holds no wrap of the world's current key"))?;
        let key = Arc::new(key);
        ring.insert(current.id, Arc::clone(&key));
        Ok(key)
    }

    /// The no-kit warning for `world` on this install.
    pub fn world_recovery_state(&self, world: EntityId) -> Result<WorldRecoveryState> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let private = fold.world_privacy(world).read != EffectiveRead::Everywhere;
        let roots: Vec<RecoveryRootId> = fold
            .current_world_key(world)
            .into_iter()
            .flat_map(|key| key.wraps.keys())
            .filter_map(|recipient| match recipient {
                WrapRecipient::RecoveryRoot(root) => Some(*root),
                WrapRecipient::Machine(_) => None,
            })
            .collect();
        Ok(recovery_state(
            private,
            fold.pinned_root.map(|pin| pin.id),
            &roots,
        ))
    }

    /// This install's pinned root as a wrap recipient, read from its stored
    /// record. `None` with no pin.
    pub(crate) fn pinned_root_recipient_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
    ) -> Result<Option<RootRecipient>> {
        let Some(pin) = fold.pinned_root else {
            return Ok(None);
        };
        self.root_recipient_in_txn(txn, fold, pin.id)
    }

    /// A stored root as a wrap recipient: its id, the entry that records it,
    /// and its recovery key.
    pub(crate) fn root_recipient_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        root: RecoveryRootId,
    ) -> Result<Option<RootRecipient>> {
        let Some((entry, record)) = owner_root_record_in_txn(&self.store, txn, fold, root)? else {
            return Ok(None);
        };
        Ok(Some(RootRecipient {
            id: root,
            entry,
            key: record.recovery_public_key()?,
        }))
    }

    /// Appends `machine`'s wraps of `key` to `recipients` in the caller's
    /// write transaction, as side entries of the key's world. Parents and
    /// the settings revision come from `fold`: the world's live edits, the
    /// rows each named machine's standing rests on, and the root's record.
    /// Recipients are split across records so each stays within the codec's
    /// bounds. Returns the records' hashes; the caller judges the refold. A
    /// world whose rows outgrow one record raises its OF-520 question and
    /// writes nothing ([`FrontierWide`]).
    #[expect(
        clippy::too_many_arguments,
        reason = "one append: the snapshot, the signer, the key and its recipients"
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
        self.put_wrap_records_in_txn(txn, fold, signing, machine, key, &binding, chunks, seq)
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
    /// S2-R2 S2-F3 and Astra A2-F2).
    #[expect(
        clippy::too_many_arguments,
        reason = "one append: the snapshot, the signer, the key and its two recipients"
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
    ) -> Result<AuthorityEntryHash> {
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let mut parents = standing_rows(fold, machine);
        parents.extend(root.map(|root| root.entry));
        if let Some(pinned) = self.pinned_root_recipient_in_txn(txn, fold)? {
            parents.insert(pinned.entry);
        }
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
        )?
        .pop()
        .ok_or_else(invalid_authority)
    }

    /// Seals `key` to each chunk's recipients under `binding` and appends one
    /// signed record per chunk, naming that chunk's parents.
    #[expect(
        clippy::too_many_arguments,
        reason = "one append: the snapshot, the signer, the key and its records"
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
            let record = WorldKeyWrapsRecord {
                key: *key.id(),
                commitment: binding.commitment,
                owner: binding.owner,
                policy: binding.policy,
                machine,
                wraps,
            };
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

    /// The fold is the judge: every record must count here.
    pub(crate) fn require_counted_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        records: &[AuthorityEntryHash],
    ) -> Result<()> {
        let after = self.authority_view_readonly_in_txn(txn)?;
        if records.iter().all(|hash| {
            after.valid_entries.contains(hash) && !after.refused_world_keys.contains(hash)
        }) {
            Ok(())
        } else {
            Err(invalid_authority())
        }
    }

    pub(super) fn world_key_ring(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<WorldKeyId, Arc<WorldKey>>> {
        self.world_keys
            .ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drops from the ring every key of a world this machine may no longer
    /// read.
    pub(crate) fn sweep_world_key_ring(&self, readable: &dyn Fn(EntityId) -> bool) {
        self.world_key_ring().retain(|id, _| readable(id.world));
    }

    /// Puts an opened key in the ring.
    pub(crate) fn ring_world_key(&self, key: WorldKey) {
        self.world_key_ring().insert(*key.id(), Arc::new(key));
    }
}

/// A world whose live edits, with the standing rows named beside them, are
/// more parents than one key record names. Its question is raised; the
/// reason names the way out.
pub(crate) struct FrontierWide(&'static str);

impl FrontierWide {
    pub(crate) fn refused(self) -> crate::error::Error {
        refused(self.0)
    }
}

/// A root a key is wrapped to.
#[derive(Clone)]
pub(crate) struct RootRecipient {
    pub(crate) id: RecoveryRootId,
    /// The entry that records the root.
    pub(crate) entry: AuthorityEntryHash,
    pub(crate) key: HybridPublicKey,
}

/// This machine is mine here under the key it signs with, and may read
/// `world`.
fn require_mine_reader(
    fold: &AuthorityFold,
    world: EntityId,
    machine: EntityId,
    signing: &SigningKey,
) -> Result<()> {
    let mine = fold
        .trusted_machine(machine)
        .is_some_and(|trusted| trusted.profile.machine_key == signing.verifying_key().to_bytes());
    if !mine {
        return Err(refused("this machine is not one of the owner's here"));
    }
    if !fold.world_readable_on(world, Destination::Machine(machine)) {
        return Err(refused("this machine may not read the world"));
    }
    Ok(())
}

/// Every machine mine here that may read `world`, with the encryption key of
/// its trusted identity (never another chain's), and `root`.
pub(crate) fn recipients(
    fold: &AuthorityFold,
    world: EntityId,
    root: Option<RootRecipient>,
) -> Vec<(WrapRecipient, HybridPublicKey)> {
    let mut out = Vec::new();
    for id in fold.machines.keys() {
        let Some(trusted) = fold.trusted_machine(*id) else {
            continue;
        };
        if !fold.world_readable_on(world, Destination::Machine(*id)) {
            continue;
        }
        // A profile whose key does not import gets no wrap: it could open none.
        let Ok(public) = HybridPublicKey::from_bytes(&trusted.profile.encryption_key.key) else {
            continue;
        };
        out.push((WrapRecipient::Machine(*id), public));
    }
    if let Some(root) = root {
        out.push((WrapRecipient::RecoveryRoot(root.id), root.key));
    }
    out
}

/// Opens `key` from a counted wrap to `recipient` with its `pad`, trying each
/// envelope.
pub(crate) fn open_counted(
    fold: &AuthorityFold,
    key: &FoldedWorldKey,
    recipient: WrapRecipient,
    secret: &HybridSecretKey,
    pad: &WorldKeyPad,
) -> Option<WorldKey> {
    let vault_id = fold.vault_id?;
    key.wraps.get(&recipient)?.iter().find_map(|wrap| {
        let envelope = Envelope::parse(&wrap.envelope).ok()?;
        let binding = WorldKeyBinding {
            vault_id,
            key: key.id,
            owner: key.owner,
            policy: wrap.policy,
            commitment: key.commitment,
        };
        open_world_key(&binding, recipient, secret, &envelope, pad).ok()
    })
}
