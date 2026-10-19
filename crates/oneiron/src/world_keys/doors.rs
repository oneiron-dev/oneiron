//! The doors that mint, wrap and open a world's key (contract §5), and what
//! every world-key door shares: this install's machine and secret, a world's
//! liveness, opening a key, and appending one machine's wraps of one key as
//! side entries of the key's world.
//!
//! The machine secret is read from the keystore before a door's transaction,
//! and the transaction refuses when the machine id changed in between. No
//! key, seed or secret is ever written; only the signed records are. Each
//! record names the owner work request it does, if any ([`provenance`]).

mod append;
mod provenance;

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use oneiron_crypto::{Envelope, HybridPublicKey, HybridSecretKey};

pub(crate) use self::append::SequenceCounter;
use super::pads::{WorldKeyPad, require_pad_in_txn};
use super::{
    FIRST_GENERATION, WorldKey, WorldKeyBinding, WorldKeyId, WorldRecoveryState, WrapRecipient,
    machine_secret, open_world_key, recovery_state, refused,
};
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, Destination, EffectiveRead, FoldedWorldKey, RecoveryRootId,
    invalid_authority, owner_root_record_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::ports::TombstoneStoreRead;
use crate::registry::ENTITY_TYPE_WORLD;
use crate::{EntityId, Vault};

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
        self.ensure_world_key_or_wide_in_txn(txn, owner, world, secret, None)?
            .map_err(FrontierWide::refused)
    }

    /// The key a settings edit leaves `world` with, in the edit's transaction.
    /// - When this install may not read the world after the edit, it opens and
    ///   mints nothing: the signed decision commits, and a holder does the key
    ///   work (`None`, "awaiting a holder" on the receipt).
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
        let (private, reads, needs_key) = {
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let machine = crate::identity::read_machine_id_in_txn(self, txn)?;
            let private = fold.world_privacy(world).read != EffectiveRead::Everywhere;
            let reads = machine.is_some_and(|machine| {
                fold.trusted_machine(machine).is_some()
                    && fold.world_readable_on(world, Destination::Machine(machine))
            });
            (
                private,
                reads,
                private && reads && fold.current_world_key(world).is_none(),
            )
        };
        // Key possession and the owner's recipient choice, never who decides
        // (mesh contract §5): only an allowed reader opens or mints the
        // world's key, so a carrier that may not read the world skips the
        // helper before it reaches `require_mine_reader`.
        if private && !reads {
            return Ok(None);
        }
        let attempt = match secret {
            Ok(secret) => self.ensure_world_key_or_wide_in_txn(txn, owner, world, secret, None),
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
    /// key record told apart from every other refusal. Each record names
    /// `request` when an owner work request names this machine to do it.
    pub(super) fn ensure_world_key_or_wide_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        world: EntityId,
        secret: &MachineSecret,
        request: Option<AuthorityEntryHash>,
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
                request,
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
                        request,
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
            request,
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
        Ok(world_recovery_state_in(&fold, world))
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

/// The no-kit warning for `world`, read from `fold`.
pub(super) fn world_recovery_state_in(fold: &AuthorityFold, world: EntityId) -> WorldRecoveryState {
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
    recovery_state(private, fold.pinned_root.map(|pin| pin.id), &roots)
}

/// This machine is mine here under the key it signs with, and may read
/// `world`: a recipient limit, the owner's own read choice (mesh contract
/// §5), never a rule on who decides.
pub(super) fn require_mine_reader(
    fold: &AuthorityFold,
    world: EntityId,
    machine: EntityId,
    signing: &SigningKey,
) -> Result<()> {
    let mine = fold
        .trusted_machine(machine)
        .is_some_and(|trusted| trusted.profile.machine_key == signing.verifying_key().to_bytes());
    if !mine || !fold.world_readable_on(world, Destination::Machine(machine)) {
        return Err(refused(
            "the owner-selected world read policy excludes this destination; use an allowed \
             holder",
        ));
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
