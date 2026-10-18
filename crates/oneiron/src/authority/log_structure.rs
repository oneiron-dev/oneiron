//! The authority log's consent structure, read from its signed rows alone,
//! so the fold's bounds and the store doors judge a row the same way (H72),
//! and the roots whose anchors this install's store gate takes as its own
//! (world privacy P6b; Astra #1422e F1, r23).

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::store::Store;

pub(super) fn admits_device(op: &AuthorityOp) -> Option<&DeviceAuthority> {
    match op {
        AuthorityOp::EnrollDevice { device }
        | AuthorityOp::RotateKey {
            new_device: device, ..
        }
        | AuthorityOp::ReRoot { new_device: device } => Some(device),
        _ => None,
    }
}

/// The log's consent structure, read from its signed rows alone, so the
/// fold's bounds and the store doors judge a row the same way.
#[derive(Debug, Default)]
pub(crate) struct AuthorityStructure {
    /// The verified genesis rows. A log with more than one, even from one
    /// key, has no admitters: the fold reads each as its own vault root.
    roots: Vec<AuthorityLogEntry>,
    /// The keys whose signature vouches for a row: the genesis key, and
    /// each owner or admin key named by a signed re-root, rotation or
    /// enrollment that an admitter signed or cosigned, the fold's own
    /// consent rule.
    admitters: BTreeSet<AuthorityKey>,
    /// The slip issuers: the admitters that hold the owner role.
    pub(super) issuers: BTreeSet<AuthorityKey>,
    /// Each machine and the install keys a slip issuer's or one of this
    /// install's own anchors' revisions of it named. Such a key signs that
    /// machine's world edits and key records.
    machine_keys: BTreeSet<(crate::EntityId, AuthorityKey)>,
    /// The install keys only other anchors' revisions named. Such a key
    /// signs as a machine key does, but as a stranger ([`Self::is_stranger`]).
    stranger_keys: BTreeSet<(crate::EntityId, AuthorityKey)>,
    /// The owner anchors a root record named, each signed by its own anchor
    /// alone (world privacy P6b). An anchor signs only what the fold's anchor
    /// rules let it: its own root records and its machine marks. It never
    /// becomes an admitter or a slip issuer.
    anchors: BTreeSet<[u8; 32]>,
    /// The anchors this install takes rows from as its own: [`LocalRoots`]'
    /// anchors.
    own_anchors: BTreeSet<[u8; 32]>,
    /// The anchor of a stored root record whose id a pin door awaits. Its
    /// marks are no stranger's, but the install keys they name sign as
    /// strangers until this install pins the root: awaiting widens only what
    /// the gate stores, never what counts.
    awaited_anchors: BTreeSet<[u8; 32]>,
    local: LocalRoots,
}

/// The roots whose anchors this install's store gate takes as its own: the
/// pin's and the earlier admitter's anchors, and the ids of the pin and of a
/// root a pin door awaits. They come from the pin singleton, which never
/// syncs. Every other anchor is a stranger until this install pins its root:
/// its root records, its marks and the world rows of the install keys only
/// such marks name share one bound (Astra #1422e F1; the Engine, r23).
#[derive(Debug, Clone, Default)]
pub(super) struct LocalRoots {
    anchors: BTreeSet<[u8; 32]>,
    roots: BTreeSet<RecoveryRootId>,
}

impl LocalRoots {
    pub(super) fn read_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> crate::error::Result<Self> {
        let row = super::pinned_root::read_pin_row_in_txn(store, txn)?;
        let mut local = Self::default();
        if let Some(pin) = row.pin {
            local.anchors.insert(pin.anchor_key);
            local.roots.insert(pin.id);
        }
        if let Some(MachineAdmitter::Anchor(anchor)) = row.earlier {
            local.anchors.insert(anchor);
        }
        local.roots.extend(row.awaiting);
        Ok(local)
    }
}

/// A root record its own anchor signed, alone and verifiably: it names its
/// anchor, as a genesis names its root.
pub(super) fn self_signed_root(entry: &AuthorityLogEntry) -> Option<[u8; 32]> {
    let AuthorityOp::OwnerRoot(record) = &entry.op else {
        return None;
    };
    (*entry.signer_key() == AuthorityKey::Ed25519(record.anchor_key)
        && entry.cosigns.is_empty()
        && verify_entry_signatures(entry).is_ok())
    .then_some(record.anchor_key)
}

pub(super) fn signed_by(entry: &AuthorityLogEntry, keys: &BTreeSet<AuthorityKey>) -> bool {
    std::iter::once(&entry.signer)
        .chain(&entry.cosigns)
        .any(|signature| keys.contains(&signature.public_key))
}

pub(super) fn is_consent_device(device: &DeviceAuthority) -> bool {
    device.roles & (ROLE_OWNER | ROLE_ADMIN) != 0
}

/// Every key the fold holds as a live owner is a slip issuer. Nothing
/// leaves the set, so a revocation the fold refuses never drops the
/// issuer, and slip rows a door stored uncounted never come to count
/// against the fold's bounds. An owner key leaves the host-rooted roster
/// only by a handoff, and a key a handoff retired signs nothing new at the
/// replicated door. A machine, agent or peer key, a stranger, and every
/// signer of a log without exactly one genesis row count as any other
/// signer.
pub(super) fn authority_structure<'a>(
    entries: impl Iterator<Item = &'a AuthorityLogEntry>,
) -> AuthorityStructure {
    let mut builder: StructureBuilder<'a> = StructureBuilder::default();
    for entry in entries {
        builder.push(entry);
    }
    builder.settle();
    builder.structure
}

/// [`authority_structure`] as this install's store gate reads it, taking
/// `local`'s anchors as its own.
pub(super) fn authority_structure_under<'a>(
    entries: impl IntoIterator<Item = &'a AuthorityLogEntry>,
    local: LocalRoots,
) -> AuthorityStructure {
    let mut builder: StructureBuilder<'a> = StructureBuilder::under(local);
    for entry in entries {
        builder.push(entry);
    }
    builder.settle();
    builder.structure
}

/// [`authority_structure`] grown a row at a time, as an import stages its
/// rows: the same structure for the same rows, in any order. A row that
/// waits for a grant is filed under each key that could give it, so a
/// settle visits only the rows its new grants wake.
#[derive(Debug, Default)]
pub(super) struct StructureBuilder<'a> {
    pub(super) structure: AuthorityStructure,
    root_roles: u16,
    /// Admissions and machine revisions pushed since the last settle.
    fresh: Vec<&'a AuthorityLogEntry>,
    /// Owner and admin admissions no admitter has signed yet, under each
    /// key that signed them.
    admissions: BTreeMap<AuthorityKey, Vec<&'a AuthorityLogEntry>>,
    /// Machine revisions whose primary signer is no slip issuer yet, under
    /// that signer.
    profiles: BTreeMap<AuthorityKey, Vec<&'a AuthorityLogEntry>>,
    /// The grants [`Self::settle`] made since the caller last took them.
    pub(super) grown: Vec<Grant>,
}

/// What [`StructureBuilder::settle`] granted a key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Grant {
    Admitter(AuthorityKey),
    Issuer(AuthorityKey),
    InstallKey(crate::EntityId, AuthorityKey),
    Anchor(AuthorityKey),
}

impl<'a> StructureBuilder<'a> {
    /// A builder that takes `local`'s anchors as this install's own.
    pub(super) fn under(local: LocalRoots) -> Self {
        let mut builder = Self::default();
        builder.structure.own_anchors.clone_from(&local.anchors);
        builder.structure.local = local;
        builder
    }

    /// Adds `entry` unsettled.
    pub(super) fn push(&mut self, entry: &'a AuthorityLogEntry) {
        match &entry.op {
            AuthorityOp::Genesis { device, .. } => {
                if device.key == *entry.signer_key()
                    && is_consent_device(device)
                    && !self.structure.roots.contains(entry)
                    && verify_entry_signatures(entry).is_ok()
                {
                    self.structure.roots.push(entry.clone());
                    self.root_roles |= device.roles;
                }
            }
            AuthorityOp::MachineProfile(_) | AuthorityOp::OwnerRoot(_) => self.fresh.push(entry),
            op => {
                if admits_device(op).is_some_and(is_consent_device) {
                    self.fresh.push(entry);
                }
            }
        }
    }

    /// Admits what the rows pushed so far admit. A log with more than one
    /// root admits nothing.
    pub(super) fn settle(&mut self) {
        let Some(root) = self
            .structure
            .roots
            .first()
            .filter(|_| self.structure.roots.len() == 1)
            .map(|genesis| genesis.signer_key().clone())
        else {
            self.structure.admitters.clear();
            self.structure.issuers.clear();
            self.structure.machine_keys.clear();
            self.structure.stranger_keys.clear();
            self.structure.anchors.clear();
            self.structure.own_anchors.clear();
            self.structure.awaited_anchors.clear();
            return;
        };
        let (mut admitted, mut issued, mut anchored) = (Vec::new(), Vec::new(), Vec::new());
        if self.root_roles & ROLE_OWNER != 0 && self.structure.issuers.insert(root.clone()) {
            issued.push(root.clone());
        }
        if self.structure.admitters.insert(root.clone()) {
            admitted.push(root);
        }
        for entry in std::mem::take(&mut self.fresh) {
            if let AuthorityOp::OwnerRoot(record) = &entry.op {
                let Some(anchor) = self_signed_root(entry) else {
                    continue;
                };
                if self.structure.local.roots.contains(&record.root)
                    && !self.structure.own_anchors.contains(&anchor)
                {
                    self.structure.awaited_anchors.insert(anchor);
                }
                if self.structure.anchors.insert(anchor) {
                    anchored.push(AuthorityKey::Ed25519(anchor));
                }
            } else if matches!(entry.op, AuthorityOp::MachineProfile(_)) {
                self.file_profile(entry);
            } else if signed_by(entry, &self.structure.admitters) {
                self.admit(entry, &mut admitted, &mut issued);
            } else {
                for signature in std::iter::once(&entry.signer).chain(&entry.cosigns) {
                    self.admissions
                        .entry(signature.public_key.clone())
                        .or_default()
                        .push(entry);
                }
            }
        }
        loop {
            if let Some(key) = admitted.pop() {
                for entry in self.admissions.remove(&key).unwrap_or_default() {
                    self.admit(entry, &mut admitted, &mut issued);
                }
                self.grown.push(Grant::Admitter(key));
            } else if let Some(key) = issued.pop() {
                for entry in self.profiles.remove(&key).unwrap_or_default() {
                    self.file_profile(entry);
                }
                self.grown.push(Grant::Issuer(key));
            } else if let Some(key) = anchored.pop() {
                for entry in self.profiles.remove(&key).unwrap_or_default() {
                    self.file_profile(entry);
                }
                self.grown.push(Grant::Anchor(key));
            } else {
                break;
            }
        }
    }

    /// Admits the key an admission an admitter signed names.
    fn admit(
        &mut self,
        entry: &AuthorityLogEntry,
        admitted: &mut Vec<AuthorityKey>,
        issued: &mut Vec<AuthorityKey>,
    ) {
        let Some(device) = admits_device(&entry.op) else {
            return;
        };
        if verify_entry_signatures(entry).is_err() {
            return;
        }
        if device.roles & ROLE_OWNER != 0 && self.structure.issuers.insert(device.key.clone()) {
            issued.push(device.key.clone());
        }
        if self.structure.admitters.insert(device.key.clone()) {
            admitted.push(device.key.clone());
        }
    }

    /// Takes a machine revision's install key when a slip issuer or an
    /// owner anchor signed it, as a stranger's when that anchor is not this
    /// install's own, or files it under its signer.
    fn file_profile(&mut self, entry: &'a AuthorityLogEntry) {
        let signer = entry.signer_key();
        let own = self.structure.issuers.contains(signer) || self.structure.is_own_anchor(signer);
        if !own && !self.structure.is_anchor(signer) {
            self.profiles.entry(signer.clone()).or_default().push(entry);
            return;
        }
        let AuthorityOp::MachineProfile(profile) = &entry.op else {
            return;
        };
        if verify_entry_signatures(entry).is_err() {
            return;
        }
        let key = (profile.machine, AuthorityKey::Ed25519(profile.machine_key));
        let vouched = self.structure.vouching_key(&key);
        if own {
            self.structure.stranger_keys.remove(&key);
            self.structure.machine_keys.insert(key.clone());
        } else if !self.structure.machine_keys.contains(&key) {
            self.structure.stranger_keys.insert(key.clone());
        }
        if !vouched {
            self.grown.push(Grant::InstallKey(key.0, key.1));
        }
    }
}

impl AuthorityStructure {
    /// Whether a key that may vouch for `entry` signed or cosigned it: an
    /// admitter, or, for a world edit, a world key record or a residence
    /// result, the install key of the machine it names, as its primary signer. A root record vouches
    /// for itself when its own anchor signed it alone, and an anchor signs
    /// machine marks alone; as the fold's anchor rules have it, an anchor
    /// vouches for nothing else. A genesis vouches for itself only in a log
    /// that holds none, or as the one it holds: any other, even from the
    /// root key with a new nonce, would fork the root. The caller verifies
    /// the signatures.
    pub(super) fn vouches_for(&self, entry: &AuthorityLogEntry) -> bool {
        let install_key =
            |machine: crate::EntityId| self.vouching_key(&(machine, entry.signer_key().clone()));
        match &entry.op {
            AuthorityOp::Genesis { device, .. } => {
                device.key == *entry.signer_key()
                    && is_consent_device(device)
                    && self.roots.iter().all(|root| root == entry)
            }
            AuthorityOp::WorldPrivacy(edit) => install_key(edit.machine),
            AuthorityOp::WorldKeyWraps(record) => install_key(record.machine),
            AuthorityOp::ResidenceResult(result) => install_key(result.machine),
            AuthorityOp::OwnerRoot(_) => self_signed_root(entry).is_some(),
            AuthorityOp::MachineProfile(_)
                if self.is_anchor(entry.signer_key()) && entry.cosigns.is_empty() =>
            {
                true
            }
            _ => signed_by(entry, &self.admitters),
        }
    }

    /// Whether `entry`, which a key may vouch for, vouches only as a
    /// stranger's: a root record of an anchor this install does not take as
    /// its own, unless its id is the pin's or an awaited root's; such an
    /// anchor's mark, unless a pin door awaits its root; or a world row or a
    /// residence result of an install key only such marks name. Every such
    /// row counts toward one shared bound (r23).
    pub(super) fn is_stranger(&self, entry: &AuthorityLogEntry) -> bool {
        let signer = entry.signer_key();
        if signed_by(entry, &self.admitters) {
            return false;
        }
        let machine_key =
            |machine: crate::EntityId| !self.machine_keys.contains(&(machine, signer.clone()));
        match &entry.op {
            AuthorityOp::OwnerRoot(record) => self_signed_root(entry).is_some_and(|anchor| {
                !self.own_anchors.contains(&anchor) && !self.local.roots.contains(&record.root)
            }),
            AuthorityOp::MachineProfile(_) => {
                !self.is_own_anchor(signer)
                    && !matches!(signer, AuthorityKey::Ed25519(anchor)
                        if self.awaited_anchors.contains(anchor))
            }
            AuthorityOp::WorldPrivacy(edit) => machine_key(edit.machine),
            AuthorityOp::WorldKeyWraps(record) => machine_key(record.machine),
            AuthorityOp::ResidenceResult(result) => machine_key(result.machine),
            _ => false,
        }
    }

    /// An install key some owner or anchor revision named.
    fn vouching_key(&self, key: &(crate::EntityId, AuthorityKey)) -> bool {
        self.machine_keys.contains(key) || self.stranger_keys.contains(key)
    }

    /// An owner anchor a stored root record named, or one of this install's
    /// own.
    fn is_anchor(&self, key: &AuthorityKey) -> bool {
        matches!(key, AuthorityKey::Ed25519(anchor)
            if self.anchors.contains(anchor) || self.own_anchors.contains(anchor))
    }

    fn is_own_anchor(&self, key: &AuthorityKey) -> bool {
        matches!(key, AuthorityKey::Ed25519(anchor) if self.own_anchors.contains(anchor))
    }

    /// Whether `key` signs rows the fold may come to admit: an admitter, an
    /// install key or an owner anchor, though the local fold may not hold it
    /// yet.
    pub(super) fn stands(&self, key: &AuthorityKey) -> bool {
        self.admitters.contains(key)
            || self.is_anchor(key)
            || self
                .machine_keys
                .iter()
                .chain(&self.stranger_keys)
                .any(|(_, machine_key)| machine_key == key)
    }
}
