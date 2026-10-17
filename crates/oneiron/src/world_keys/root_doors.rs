//! The root doors (contract §4-§5): activating a kit's root, anchoring a
//! machine with the kit's seed, restoring a world's keys from the kit, and
//! pinning a root from a fingerprint the owner carried.
//!
//! Each runs only on this machine (`EditOrigin::ThisMachine`): a remote
//! request never pins, anchors or restores. Every check runs before the
//! first write, and each door's writes, its pin and its re-wraps commit in
//! one transaction or not at all. A door that may mint this install's
//! machine identity first runs every refusal the stored state decides in a
//! read snapshot, so a refused kit, fingerprint, owner or root leaves no
//! identity behind; its transaction runs them again.

use std::collections::{BTreeMap, BTreeSet};

use super::repin::{RepinDoor, RepinReport, Withheld};
use super::{
    MachineSecret, NarrowedWorld, PreparedRoot, RecoveryRoot, RecoveryRootId, RecoveryRootSeed,
    SeedOrigin, WorldKeyId, refused,
};
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, EditOrigin, FoldedMachine,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineEncryptionKey, MachineEnrolmentRequest,
    OwnerRootRecord, PinnedRoot, RequestCode, anchor_mark_stands, invalid_authority,
    owner_root_records_in_txn, read_pin_row_in_txn, write_awaited_root_in_txn,
    write_pinned_root_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, KitRecord, Result, SecretError};
use crate::{EntityId, Vault};

/// What the owner confirmed for a kit seed this install cannot authenticate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KitConfirmation {
    /// The seed's root id equals a fingerprint the owner carried from one of
    /// their machines that pins it, typed or scanned.
    Fingerprint(RecoveryRootId),
    /// The owner's explicit go-ahead after the client showed that the kit was
    /// not verified.
    Owner,
}

/// A root activated on this install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivatedRoot {
    pub root: RecoveryRootId,
    pub keys: RepinReport,
}

/// A machine anchored with the kit's seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchoredMachine {
    pub machine: FoldedMachine,
    /// The re-wrap report of an own-request anchoring; `None` for another
    /// machine's request, which never moves the pin.
    pub repin: Option<RepinReport>,
}

/// What a kit restore did with each key wrapped to the kit's root.
#[derive(Debug, Default)]
pub struct RootRestore {
    /// Readable here: opened, wrapped to this machine, in the session. A key
    /// only machines removed here signed is opened and in the session but
    /// gets no wrap, and is never current (the Engine's Q2 on Astra #1422c).
    pub usable: Vec<WorldKeyId>,
    /// Kept on another machine: recoverable, not usable here (P11).
    pub needs_rehome: Vec<WorldKeyId>,
    pub withheld: Vec<(WorldKeyId, Withheld)>,
    pub narrowed: Vec<NarrowedWorld>,
}

pub(super) fn this_machine_only(origin: EditOrigin) -> Result<()> {
    match origin {
        EditOrigin::ThisMachine => Ok(()),
        EditOrigin::Peer(_) => Err(refused("a remote request never pins, anchors or restores")),
    }
}

/// The seed's root record, as the anchor publishes it.
fn root_record(root: &RecoveryRoot, owner: EntityId) -> OwnerRootRecord {
    OwnerRootRecord {
        owner,
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    }
}

/// The kit-restored seed rule (contract §4), before any write: whether a
/// door that pins from `seed` may proceed, and whether it publishes the
/// seed's root first.
fn kit_seed_gate(
    records: &BTreeMap<RecoveryRootId, (AuthorityEntryHash, OwnerRootRecord)>,
    root: &RecoveryRoot,
    seed: &RecoveryRootSeed,
    pinned: Option<RecoveryRootId>,
    confirm: Option<KitConfirmation>,
) -> Result<bool> {
    let stored = records
        .get(&root.id)
        .is_some_and(|(_, record)| root.matches(record));
    if seed.origin() == SeedOrigin::Drawn && !stored {
        return Err(refused(
            "a prepared root is published only by its activation",
        ));
    }
    if matches!(confirm, Some(KitConfirmation::Fingerprint(id)) if id != root.id) {
        return Err(refused("the fingerprint is not this seed's root"));
    }
    let authenticated =
        seed.authenticated() || (stored && pinned == Some(root.id)) || confirm.is_some();
    if !authenticated {
        let record = if stored {
            KitRecord::Stored
        } else if records.is_empty() {
            KitRecord::None
        } else {
            KitRecord::Mismatch
        };
        return Err(Error::Secret(SecretError::UnverifiedKitRestore {
            root: root.id.0,
            record,
        }));
    }
    Ok(!stored)
}

/// The activation's marks other than this machine's: each carried machine
/// with its trusted identity's keys, after the first-issue and prepared-root
/// checks. `me` is this install's machine, when it has one.
fn carried_marks(
    fold: &AuthorityFold,
    prepared: &PreparedRoot,
    carry: &BTreeSet<EntityId>,
    me: Option<EntityId>,
) -> Result<(RecoveryRoot, Vec<MachineEnrolmentRequest>)> {
    let vault_id = fold
        .vault_id
        .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
    let root = prepared.seed().public(&vault_id)?;
    let crate::authority::AuthorityOp::OwnerRoot(record) = &prepared.entry().op else {
        return Err(invalid_authority());
    };
    if !root.matches(record) {
        return Err(invalid_authority());
    }
    if fold.pinned_root.is_none() && !carry.is_empty() {
        return Err(refused("a first kit issue carries no machine"));
    }
    let mut marks = Vec::new();
    for machine in carry.iter().filter(|machine| Some(**machine) != me) {
        let trusted = fold
            .trusted_machine(*machine)
            .ok_or_else(|| refused("a carried machine is not mine under the old pin"))?;
        marks.push(MachineEnrolmentRequest {
            vault_id,
            machine: *machine,
            machine_key: trusted.profile.machine_key,
            encryption_key: trusted.profile.encryption_key.clone(),
            machine_proof: trusted.profile.machine_proof,
        });
    }
    Ok((root, marks))
}

impl Vault {
    /// Runs a root door's checks in a read snapshot, before this install's
    /// machine identity is minted.
    fn precheck_root_door<T>(
        &self,
        owner: &AuthenticatedOwner,
        check: impl FnOnce(&heed::RoTxn<'_>, &AuthorityFold) -> Result<T>,
    ) -> Result<T> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        check(&txn, &fold)
    }

    /// The kit-restored seed rule in `txn`: the seed's root, and whether the
    /// door publishes it first.
    fn kit_seed_gate_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
    ) -> Result<(RecoveryRoot, bool)> {
        let vault_id = fold
            .vault_id
            .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
        let root = seed.public(&vault_id)?;
        let records = owner_root_records_in_txn(&self.store, txn, fold)?;
        let publish = kit_seed_gate(
            &records,
            &root,
            seed,
            fold.pinned_root.map(|pin| pin.id),
            confirm,
        )?;
        Ok((root, publish))
    }

    /// This install's own enrolment request, its machine identity minted
    /// first when it has none, and its secret: all before any door's
    /// transaction.
    fn own_request(&self) -> Result<(MachineSecret, MachineEnrolmentRequest)> {
        let vault_id = self
            .authority_fold()?
            .vault_id
            .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
        let encryption_key = self.machine_encryption_key(vault_id)?;
        let request = self.machine_enrolment_request(vault_id, encryption_key)?;
        let secret = self.machine_secret_outside_txn()?;
        if secret.machine != request.machine {
            return Err(refused(
                "the machine identity changed after its secret was read",
            ));
        }
        Ok((secret, request))
    }

    /// The pin, written before a seed door stores its root's record and
    /// marks, so the store gate takes them as this install's own anchor's
    /// however many strangers' rows wait (Astra #1422e F1, r23).
    /// [`Self::move_pin_in_txn`] still runs after them.
    fn pin_first_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        before: Option<PinnedRoot>,
        pin: PinnedRoot,
        earlier: Option<crate::authority::MachineAdmitter>,
    ) -> Result<()> {
        if before == Some(pin) {
            return Ok(());
        }
        write_pinned_root_in_txn(&self.store, txn, pin, earlier)
    }

    /// Leaves `awaiting` as the root a pin door awaits, after a door that
    /// pinned `root`: a wait for another root stays.
    fn end_wait_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        root: RecoveryRootId,
        awaiting: Option<RecoveryRootId>,
    ) -> Result<()> {
        let row = read_pin_row_in_txn(&self.store, txn)?;
        if awaiting.is_none() && row.awaiting != Some(root) {
            return Ok(());
        }
        write_awaited_root_in_txn(&self.store, txn, awaiting)
    }

    /// The pin, written only when it moves. Whose seals count follows the
    /// pin (H161), so the stored shell edges are decided again here, in the
    /// pin's transaction, whether or not the door appends a row after it
    /// (Astra code-S2-R1 A1-F2).
    fn move_pin_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        before: Option<PinnedRoot>,
        pin: PinnedRoot,
        earlier: Option<crate::authority::MachineAdmitter>,
    ) -> Result<()> {
        if before == Some(pin) {
            return Ok(());
        }
        write_pinned_root_in_txn(&self.store, txn, pin, earlier)?;
        self.reconcile_identity_topology_if_seals_moved_in_txn(txn)
    }

    /// Kit issue, phase 2: called after the kit issuer reports the pieces
    /// saved. One write transaction: the root's record, the new anchor's
    /// `Owned(Yours)` mark of this machine and of each carried machine, the
    /// pin, and the re-wraps. It succeeds only if each appended mark heads
    /// the new anchor's chain and is the machine's trusted identity there,
    /// with the same keys; otherwise nothing is published. On a first issue
    /// `carry` is empty; on a re-issue each carried machine is mine under the
    /// old pin, and this machine is marked whenever it is.
    pub fn activate_owner_root(
        &self,
        owner: &AuthenticatedOwner,
        origin: EditOrigin,
        prepared: PreparedRoot,
        carry: &BTreeSet<EntityId>,
    ) -> Result<ActivatedRoot> {
        self.activate_owner_root_with(owner, origin, prepared, carry, |_| Ok(()))
            .map(|(activated, ())| activated)
    }

    /// [`Self::activate_owner_root`], with `also` run in its transaction once
    /// the new root stands: a kit's inventory and its vault-key wrap commit
    /// with the root or not at all.
    pub(crate) fn activate_owner_root_with<T>(
        &self,
        owner: &AuthenticatedOwner,
        origin: EditOrigin,
        prepared: PreparedRoot,
        carry: &BTreeSet<EntityId>,
        also: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<T>,
    ) -> Result<(ActivatedRoot, T)> {
        this_machine_only(origin)?;
        self.precheck_root_door(owner, |txn, fold| {
            let me = crate::identity::read_machine_id_in_txn(self, txn)?;
            carried_marks(fold, &prepared, carry, me).map(drop)
        })?;
        let (secret, request) = self.own_request()?;
        let seed = prepared.seed();
        let anchor = seed.anchor();
        let (root, report, extra) = self.with_write_txn(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let signing = self.door_signing_key_in_txn(txn, secret.machine)?;
            let old = self.authority_view_readonly_in_txn(txn)?;
            let (root, mut marks) = carried_marks(&old, &prepared, carry, Some(secret.machine))?;
            let pin = PinnedRoot {
                id: root.id,
                anchor_key: root.anchor_key,
            };
            let door = RepinDoor {
                secret: &secret,
                signing: &signing,
                new_root: root.id,
                seed: Some(seed),
                restore: false,
            };
            let start = self.repin_start_in_txn(txn, &door)?;
            self.pin_first_in_txn(txn, old.pinned_root, pin, start.earlier_admitter)?;
            marks.push(request.clone());
            self.put_anchor_entry_in_txn(txn, prepared.entry().clone())?;
            let mut appended = Vec::new();
            for mark in &marks {
                appended.push(self.append_anchor_mark_in_txn(txn, &anchor, actor, mark)?);
            }
            self.move_pin_in_txn(txn, old.pinned_root, pin, start.earlier_admitter)?;
            self.end_wait_in_txn(txn, root.id, None)?;
            let mid = self.authority_view_readonly_in_txn(txn)?;
            let stands = marks
                .iter()
                .zip(&appended)
                .all(|(mark, hash)| anchor_mark_stands(&mid, root.anchor_key, *hash, mark));
            if !stands || mid.pinned_root != Some(pin) {
                return Err(refused("the new root's marks do not stand"));
            }
            let report = self.repin_finish_in_txn(txn, &door, start)?.report;
            Ok((root, report, also(txn)?))
        })?;
        Ok((
            ActivatedRoot {
                root: root.id,
                keys: report,
            },
            extra,
        ))
    }

    /// Kit use: marks a machine `Owned(Yours)` under the seed's anchor.
    /// `request` is this install's own (then the door pins the seed's root
    /// and runs the re-wrap sequence, also when the pin stays), or a new
    /// machine's request shown here (then `code` must be the code the new
    /// machine displays, the seed's root must be this install's pin, and the
    /// pin never moves). The appended mark must head the anchor's chain and
    /// be the machine's trusted identity there with the request's keys.
    pub fn anchor_machine(
        &self,
        owner: &AuthenticatedOwner,
        origin: EditOrigin,
        seed: &RecoveryRootSeed,
        request: &MachineEnrolmentRequest,
        code: Option<RequestCode>,
        confirm: Option<KitConfirmation>,
    ) -> Result<AnchoredMachine> {
        this_machine_only(origin)?;
        self.load_install_signing_if_minted()?;
        let own = {
            let txn = self.store.env.read_txn()?;
            let machine = crate::identity::read_machine_id_in_txn(self, &txn)?;
            let key = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
                .map(|key| key.verifying_key().to_bytes());
            machine == Some(request.machine) && key == Some(request.machine_key)
        };
        if own {
            return self.anchor_own_machine(owner, seed, request, confirm);
        }
        if code != Some(request.code()) {
            return Err(refused(
                "the request code is not the one the new machine shows",
            ));
        }
        let root = seed.public(&request.vault_id)?;
        let anchor = seed.anchor();
        self.with_write_txn(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            if fold.vault_id != Some(request.vault_id) {
                return Err(invalid_authority());
            }
            if fold.pinned_root.map(|pin| pin.id) != Some(root.id) {
                return Err(refused(
                    "anchoring another machine needs the seed's root to be this install's pin",
                ));
            }
            let mark = self.append_anchor_mark_in_txn(txn, &anchor, actor, request)?;
            let after = self.authority_view_readonly_in_txn(txn)?;
            if !anchor_mark_stands(&after, root.anchor_key, mark, request) {
                return Err(refused("the anchor's mark does not stand"));
            }
            Ok(AnchoredMachine {
                machine: after
                    .machine(request.machine)
                    .cloned()
                    .ok_or_else(invalid_authority)?,
                repin: None,
            })
        })
    }

    fn anchor_own_machine(
        &self,
        owner: &AuthenticatedOwner,
        seed: &RecoveryRootSeed,
        request: &MachineEnrolmentRequest,
        confirm: Option<KitConfirmation>,
    ) -> Result<AnchoredMachine> {
        self.precheck_root_door(owner, |txn, fold| {
            self.kit_seed_gate_in_txn(txn, fold, seed, confirm)
                .map(drop)
        })?;
        let (secret, own) = self.own_request()?;
        if own.machine != request.machine
            || own.machine_key != request.machine_key
            || own.encryption_key != request.encryption_key
        {
            return Err(refused("the request names this machine with other keys"));
        }
        let anchor = seed.anchor();
        self.with_write_txn(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let signing = self.door_signing_key_in_txn(txn, secret.machine)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let (root, publish) = self.kit_seed_gate_in_txn(txn, &fold, seed, confirm)?;
            let pin = PinnedRoot {
                id: root.id,
                anchor_key: root.anchor_key,
            };
            let door = RepinDoor {
                secret: &secret,
                signing: &signing,
                new_root: root.id,
                seed: Some(seed),
                restore: false,
            };
            let start = self.repin_start_in_txn(txn, &door)?;
            self.pin_first_in_txn(txn, fold.pinned_root, pin, start.earlier_admitter)?;
            if publish {
                self.publish_owner_root_in_txn(txn, &anchor, root_record(&root, actor))?;
            }
            let mark = self.append_anchor_mark_in_txn(txn, &anchor, actor, request)?;
            self.move_pin_in_txn(txn, fold.pinned_root, pin, start.earlier_admitter)?;
            self.end_wait_in_txn(txn, root.id, None)?;
            let mid = self.authority_view_readonly_in_txn(txn)?;
            if !anchor_mark_stands(&mid, root.anchor_key, mark, request)
                || mid.pinned_root != Some(pin)
            {
                return Err(refused("the anchor's mark does not stand"));
            }
            let finish = self.repin_finish_in_txn(txn, &door, start)?;
            let after = self.authority_view_readonly_in_txn(txn)?;
            Ok(AnchoredMachine {
                machine: after
                    .machine(request.machine)
                    .cloned()
                    .ok_or_else(invalid_authority)?,
                repin: Some(finish.report),
            })
        })
    }

    /// Kit restore: finds the stored root that matches the seed's id and both
    /// its keys, or publishes it when the kit-restored seed rule allows;
    /// anchors this install's own request under it unless this machine is
    /// already mine there with its own keys; pins it; and opens each key
    /// wrapped to it whose world is live here. Every root-wrapped key lands in
    /// exactly one list.
    pub fn restore_world_keys(
        &self,
        owner: &AuthenticatedOwner,
        origin: EditOrigin,
        seed: &RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
    ) -> Result<RootRestore> {
        this_machine_only(origin)?;
        self.precheck_root_door(owner, |txn, fold| {
            self.kit_seed_gate_in_txn(txn, fold, seed, confirm)
                .map(drop)
        })?;
        let (secret, request) = self.own_request()?;
        let anchor = seed.anchor();
        let (restore, usable) = self.with_write_txn(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let signing = self.door_signing_key_in_txn(txn, secret.machine)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let (root, publish) = self.kit_seed_gate_in_txn(txn, &fold, seed, confirm)?;
            let pin = PinnedRoot {
                id: root.id,
                anchor_key: root.anchor_key,
            };
            let door = RepinDoor {
                secret: &secret,
                signing: &signing,
                new_root: root.id,
                seed: Some(seed),
                restore: true,
            };
            let start = self.repin_start_in_txn(txn, &door)?;
            self.pin_first_in_txn(txn, fold.pinned_root, pin, start.earlier_admitter)?;
            if publish {
                self.publish_owner_root_in_txn(txn, &anchor, root_record(&root, actor))?;
            }
            let now = self.authority_view_readonly_in_txn(txn)?;
            let already = now
                .machine(request.machine)
                .and_then(|folded| {
                    folded
                        .trusted_under(&crate::authority::MachineAdmitter::Anchor(root.anchor_key))
                })
                .is_some_and(|trusted| {
                    trusted.profile.machine_key == request.machine_key
                        && trusted.profile.encryption_key == request.encryption_key
                });
            let mark = if already {
                None
            } else {
                Some(self.append_anchor_mark_in_txn(txn, &anchor, actor, &request)?)
            };
            self.move_pin_in_txn(txn, fold.pinned_root, pin, start.earlier_admitter)?;
            self.end_wait_in_txn(txn, root.id, None)?;
            let mid = self.authority_view_readonly_in_txn(txn)?;
            let stands =
                mark.is_none_or(|mark| anchor_mark_stands(&mid, root.anchor_key, mark, &request));
            if !stands || mid.pinned_root != Some(pin) {
                return Err(refused("the kit's root does not stand on this install"));
            }
            let finish = self.repin_finish_in_txn(txn, &door, start)?;
            Ok((
                RootRestore {
                    usable: finish.usable.iter().map(|key| *key.id()).collect(),
                    needs_rehome: finish.needs_rehome,
                    withheld: finish.report.withheld,
                    narrowed: finish.report.narrowed,
                },
                finish.usable,
            ))
        })?;
        for key in usable {
            self.ring_world_key(key);
        }
        Ok(restore)
    }

    /// Pins `root` on this install from a fingerprint the owner carried out
    /// of band, the full 32-byte id that binds the vault and both keys. In
    /// the same transaction it re-wraps the keys this machine may still read
    /// under the new pin and reports the rest; the pin commits. A root not in
    /// this vault's log yet, held behind strangers' rows say, is awaited
    /// instead: the pin stays, nothing is wrapped, and the store gate takes
    /// that root's own row and its anchor's marks on the next drain. So is a
    /// root this machine is not mine under yet, its marks still held. Either
    /// way the report names it, `owner_root_view` says when it has arrived,
    /// and pinning again then finishes (Astra #1422e F1; the Engine, r23).
    pub fn pin_owner_root(
        &self,
        owner: &AuthenticatedOwner,
        origin: EditOrigin,
        root: RecoveryRootId,
    ) -> Result<RepinReport> {
        this_machine_only(origin)?;
        let stored = self.precheck_root_door(owner, |txn, fold| {
            Ok(owner_root_records_in_txn(&self.store, txn, fold)?.contains_key(&root))
        })?;
        if !stored {
            self.with_write_txn(|txn| {
                owner.revalidate_as_vault_owner_in_txn(self, txn)?;
                write_awaited_root_in_txn(&self.store, txn, Some(root))
            })?;
            return Ok(RepinReport {
                awaiting: Some(root),
                ..RepinReport::default()
            });
        }
        let (secret, _) = self.own_request()?;
        self.with_write_txn(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let fold = self.authority_view_readonly_in_txn(txn)?;
            let (_, record) = owner_root_records_in_txn(&self.store, txn, &fold)?
                .remove(&root)
                .ok_or_else(|| refused("the root is not in this vault's log yet"))?;
            let signing = self.door_signing_key_in_txn(txn, secret.machine)?;
            let pin = PinnedRoot {
                id: root,
                anchor_key: record.anchor_key,
            };
            let door = RepinDoor {
                secret: &secret,
                signing: &signing,
                new_root: root,
                seed: None,
                restore: false,
            };
            let start = self.repin_start_in_txn(txn, &door)?;
            self.move_pin_in_txn(txn, fold.pinned_root, pin, start.earlier_admitter)?;
            let mut report = self.repin_finish_in_txn(txn, &door, start)?.report;
            let after = self.authority_view_readonly_in_txn(txn)?;
            report.awaiting = after
                .trusted_machine(secret.machine)
                .is_none()
                .then_some(root);
            self.end_wait_in_txn(txn, root, report.awaiting)?;
            Ok(report)
        })
    }
}
