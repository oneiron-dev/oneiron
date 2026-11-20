//! The owner's list of owner key changes (the owner's ruling AUTH-5, pass 27
//! section 4.4): every enrolment, every confirmation and every removal of an
//! enrolled owner key, in either shape (a device's or the recovery root's
//! Ed25519 key, or a passkey), that this vault's log holds and its fold
//! counts, newest first (row KEY-CHANGE-RECEIPT-EMPTY-NO-NOTICE).
//!
//! This list is the notice of a key change. It writes no row of its own:
//! each change is its authority entry, every owner device holds the log, and
//! so each device reads the same list and shows what it has not shown yet
//! ("[device] was removed. Not you?"). An install-local notification row
//! would reach only the install that wrote it.
//!
//! One removal ends its key although the fold counts no entry for it: two
//! removals that cross. When key A removes key B on one branch and B removes
//! A on a branch that never saw it, each revocation retires the other's
//! signer, so the fold refuses both entries and both keys end
//! (`retired_signers`). The list shows such an entry as
//! [`OwnerKeyChangeKind::RemovedByEndedKey`], so the owner still reads that
//! the key ended and which key signed its removal. Only a removal that a key
//! of the owner's signed lists so: a managed host's root may sign a second
//! revoke of a key that had already ended, and that entry is no act of the
//! owner's. And only one that no settled fence from a branch it never saw
//! holds a signer of: a removal whose signer a sibling handoff, appointment
//! or counted revocation ended yields to it and ends nothing, so when its
//! key ended all the same (a sibling `ReRoot` that fenced both keys, say),
//! the removal is not why, and it lists nothing. And only one that crossed:
//! the key it removes signed a removal of its signer on a branch that never
//! saw it, which the fold refused the same way. A removal whose signer
//! another crossing ended yielded to that crossing: when C and A remove each
//! other and A also removes B, A's removal of B ends nothing, so if B ended
//! by a crossing of its own with D, the list names D's removal of B alone.
//! The fold names no closed fence of a refused row, so a ring of three or
//! more removals, each of the next one's signer, lists none of them.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, Vault};

/// What happened to an enrolled owner key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKeyChangeKind {
    /// The key was enrolled.
    Enrolled,
    /// A key only a passkey vouched for was confirmed: a key of the owner's
    /// that is no passkey (on a hosted vault, outside the host's custody)
    /// vouched for it again, so it now signs for the owner in full (lead
    /// ruling WEBPASSKEY-BLIND-SIGNATURE = B). The list names it because it
    /// changes what the key may sign (Engine ANSWER 20 Nov 19:03,
    /// ROW-HANDOVER-KEY-CHANGE-RECEIPT-EMPTY-NO-NOTICE Q2 = A).
    Confirmed,
    /// The key was removed: a counted `RevokeDevice` of it.
    Removed,
    /// The key ended, and no counted removal names it: this `RevokeDevice`
    /// of it is one the fold refused only because its own signer's key ended
    /// too, by a removal that this key signed on a branch that never saw this
    /// entry (two removals that cross end both keys and count neither entry).
    RemovedByEndedKey,
}

/// One change of an enrolled owner key, as its authority entry says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyChange {
    /// The change's authority entry.
    pub entry: AuthorityEntryHash,
    /// What happened.
    pub change: OwnerKeyChangeKind,
    /// The key: a device's or the recovery root's Ed25519 key, or a
    /// passkey's P-256 key (compressed SEC1).
    pub public_key: AuthorityKey,
    /// The machine the key's enrolment names; for a passkey, the carrier
    /// that served its ceremony.
    pub machine: EntityId,
    /// What the key is, as its enrolment says; `None` for a passkey, which
    /// is neither kind.
    pub kind: Option<EnrolledOwnerKeyKind>,
    /// The key that signed the entry: an enrolment's predecessor, a
    /// confirmation's confirming key, a removal's proof.
    pub signed_by: AuthorityKey,
    /// When it was signed, advisory unix seconds.
    pub at: u64,
}

impl Vault {
    /// Every change of an enrolled owner key, newest first: each counted
    /// enrolment, confirmation and removal of a key an enrolment names, a
    /// passkey's included, from the rows this vault keeps (stored, or
    /// carried by an adopted checkpoint image). A key enrolled on two
    /// branches lists its smallest enrolment entry, as
    /// [`Self::enrolled_owner_keys`] and [`Self::enrolled_owner_passkeys`]
    /// do; each other counted enrolment of a key a passkey vouched for, by a
    /// key that may confirm it, lists as its confirmation
    /// ([`OwnerKeyChangeKind::Confirmed`]); a key that two counted entries
    /// removed lists both removals. A key that ended
    /// with no counted removal lists each removal of it that a key of the
    /// owner's signed and the fold refused for its signer alone, where the
    /// removal it crossed, signed by the key it removes, ended that signer
    /// ([`OwnerKeyChangeKind::RemovedByEndedKey`]). Empty before any
    /// enrolment.
    ///
    /// # Errors
    /// A refusal when the proof is no longer the vault's live owner; the
    /// log's read errors.
    pub fn owner_key_changes(&self, owner: &AuthenticatedOwner) -> Result<Vec<OwnerKeyChange>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let hosted = self.is_hosted();
        let mut rows = Vec::new();
        let mut stored = BTreeSet::new();
        for (_, body) in super::readonly_fold::authority_log_rows_in_txn(&self.store, &txn)? {
            let entry = decode_authority_log_entry_body(&body)?;
            let hash = authority_entry_hash(&entry)?;
            stored.insert(hash);
            rows.push((hash, entry));
        }
        if let Some(evidence) = super::adopted_evidence::adopted_evidence_in_txn(&self.store, &txn)?
        {
            rows.extend(
                evidence
                    .carried_past(&stored)
                    .map(|(hash, entry)| (*hash, entry.clone())),
            );
        }
        let keys = ListedOwnerKeys::of(
            self.enrolled_owner_keys_in_txn(&txn)?,
            self.enrolled_owner_passkeys_in_txn(&txn)?,
            &fold,
            hosted,
            &rows,
        );
        let fences = SignerFences::of(&fold, &rows);
        let mut changes: Vec<OwnerKeyChange> = rows
            .iter()
            .filter_map(|(hash, entry)| {
                owner_key_change(&fold, hosted, &keys, &fences, *hash, entry)
            })
            .collect();
        // A counted removal of a key is the whole account of its end.
        let removed: BTreeSet<AuthorityKey> = changes
            .iter()
            .filter(|change| change.change == OwnerKeyChangeKind::Removed)
            .map(|change| change.public_key.clone())
            .collect();
        changes.retain(|change| {
            change.change != OwnerKeyChangeKind::RemovedByEndedKey
                || !removed.contains(&change.public_key)
        });
        changes.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.entry.cmp(&b.entry)));
        Ok(changes)
    }
}

/// The enrolled owner keys the list names, in either shape, and the keys a
/// passkey vouched for.
struct ListedOwnerKeys {
    /// Each enrolled key, by its roster key.
    keys: BTreeMap<AuthorityKey, ListedOwnerKey>,
    /// Each key that a counted enrolment signed by an enrolled passkey
    /// vouched for: the keys a later vouch confirms (the fold's
    /// `remember_passkey_vouch`, read from the rows the list walks).
    passkey_vouched: BTreeSet<AuthorityKey>,
}

/// One enrolled owner key, as the list names it.
struct ListedOwnerKey {
    /// Its listed enrolment: the smallest counted entry that enrols it and
    /// confirms no passkey's vouch for it.
    entry: AuthorityEntryHash,
    /// The machine its enrolment names.
    machine: EntityId,
    /// What it is; `None` for a passkey.
    kind: Option<EnrolledOwnerKeyKind>,
    /// On the roster and not revoked.
    live: bool,
}

impl ListedOwnerKeys {
    /// The device and recovery root keys of `enrolled`, the passkeys of
    /// `passkeys`, and the keys a counted enrolment among `rows` on `fold`
    /// vouched for with an enrolled passkey as its predecessor. Each key's
    /// listed enrolment is its smallest counted enrolment among `rows` that
    /// confirms no such vouch ([`Self::confirms`]; `hosted` as it takes
    /// it): the enrolled-key rows take a confirmation's entry as an
    /// enrolment of its key too, and the list names that entry as the
    /// confirmation it is.
    fn of(
        enrolled: Vec<EnrolledOwnerKey>,
        passkeys: Vec<EnrolledOwnerPasskey>,
        fold: &AuthorityFold,
        hosted: bool,
        rows: &[(AuthorityEntryHash, AuthorityLogEntry)],
    ) -> Self {
        let mut keys: BTreeMap<AuthorityKey, ListedOwnerKey> = enrolled
            .into_iter()
            .map(|key| {
                let listed = ListedOwnerKey {
                    entry: key.entry,
                    machine: key.machine,
                    kind: Some(key.kind),
                    live: key.live,
                };
                (AuthorityKey::Ed25519(key.public_key), listed)
            })
            .collect();
        keys.extend(passkeys.into_iter().map(|passkey| {
            let listed = ListedOwnerKey {
                entry: passkey.entry,
                machine: passkey.machine,
                kind: None,
                live: passkey.live,
            };
            (AuthorityKey::P256(passkey.public_key), listed)
        }));
        let mut listed = Self {
            keys,
            passkey_vouched: BTreeSet::new(),
        };
        let passkey_vouched = rows
            .iter()
            .filter(|(hash, _)| fold.valid_entries.contains(hash))
            .filter_map(|(_, entry)| match &entry.op {
                AuthorityOp::OwnerKeyEnroll(enroll)
                    if listed.is_passkey(&entry.signer.public_key) =>
                {
                    Some(enroll.device.key.clone())
                }
                _ => None,
            })
            .collect();
        listed.passkey_vouched = passkey_vouched;
        let mut enrolments: BTreeMap<AuthorityKey, AuthorityEntryHash> = BTreeMap::new();
        for (hash, entry) in rows {
            let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op else {
                continue;
            };
            if fold.valid_entries.contains(hash)
                && !listed.confirms(fold, hosted, &enroll.device.key, entry)
            {
                let first = enrolments.entry(enroll.device.key.clone()).or_insert(*hash);
                *first = (*first).min(*hash);
            }
        }
        for (public_key, entry) in enrolments {
            if let Some(key) = listed.keys.get_mut(&public_key) {
                key.entry = entry;
            }
        }
        listed
    }

    /// Whether `key` is an enrolled passkey.
    fn is_passkey(&self, key: &AuthorityKey) -> bool {
        self.keys
            .get(key)
            .is_some_and(|listed| listed.kind.is_none())
    }

    /// Whether the counted enrolment `entry` of `key` confirms a passkey's
    /// vouch for it (lead ruling WEBPASSKEY-BLIND-SIGNATURE = B): a passkey
    /// vouched for `key`, and `entry`'s signer is no passkey and, on a
    /// `hosted` vault, outside the host's custody on `fold`, as the fold's
    /// `may_confirm_passkey_vouch` asks. Such an entry is a confirmation, or
    /// a fresh enrolment of the key on a branch that never saw the passkey's
    /// vouch, which the fold merges as its confirmation too.
    fn confirms(
        &self,
        fold: &AuthorityFold,
        hosted: bool,
        key: &AuthorityKey,
        entry: &AuthorityLogEntry,
    ) -> bool {
        let signer = &entry.signer.public_key;
        self.passkey_vouched.contains(key)
            && !self.is_passkey(signer)
            && !(hosted && fold.in_host_custody(signer))
    }
}

/// The settled fences that can make a refused removal yield, the refused
/// removals it can cross, and the authority DAG of the rows this vault
/// keeps, to place them against it.
struct SignerFences<'a> {
    /// Each key's counted `RevokeDevice` rows.
    revocations: BTreeMap<&'a AuthorityKey, Vec<AuthorityEntryHash>>,
    /// The `RevokeDevice` rows the fold refused for their signer alone
    /// (`RetiredSigner`).
    refused_revocations: Vec<(AuthorityEntryHash, &'a AuthorityLogEntry)>,
    /// The closed handoffs, settled or in conflict, and the counted root
    /// appointments.
    handoffs: Vec<AuthorityEntryHash>,
    /// Each kept row's parents.
    parents: BTreeMap<AuthorityEntryHash, &'a [AuthorityEntryHash]>,
}

impl<'a> SignerFences<'a> {
    /// The fences among `rows` on `fold`.
    fn of(fold: &AuthorityFold, rows: &'a [(AuthorityEntryHash, AuthorityLogEntry)]) -> Self {
        let mut fences = Self {
            revocations: BTreeMap::new(),
            refused_revocations: Vec::new(),
            handoffs: fold.closed_handoffs.iter().copied().collect(),
            parents: BTreeMap::new(),
        };
        for (hash, entry) in rows {
            fences.parents.insert(*hash, &entry.parent_hashes);
            if !fold.valid_entries.contains(hash) {
                if matches!(entry.op, AuthorityOp::RevokeDevice { .. })
                    && fold
                        .issues
                        .contains(&AuthorityFoldIssue::RetiredSigner(*hash))
                {
                    fences.refused_revocations.push((*hash, entry));
                }
                continue;
            }
            match &entry.op {
                AuthorityOp::RevokeDevice { revoked_key } => {
                    fences
                        .revocations
                        .entry(revoked_key)
                        .or_default()
                        .push(*hash);
                }
                AuthorityOp::RootAppointment(_) => fences.handoffs.push(*hash),
                _ => {}
            }
        }
        fences
    }

    /// Whether a settled fence on a branch that never saw the refused
    /// removal `entry`, at `hash`, holds a signer of it, so the removal
    /// yielded to it and ended nothing: a counted revocation of the signer,
    /// or a closed handoff or a counted appointment while such a fence holds
    /// the signer. The fold keeps no handoff's keys apart, so a signer some
    /// handoff holds counts as held by each handoff on a sibling branch. A
    /// fence below the removal, or one that saw it (a recovery after two
    /// removals that crossed, say), does not fence it.
    fn fence_a_signer_of(
        &self,
        fold: &AuthorityFold,
        hash: AuthorityEntryHash,
        entry: &AuthorityLogEntry,
    ) -> bool {
        super::retired_signers::entry_signer_keys(entry).any(|key| {
            let revoked = self
                .revocations
                .get(key)
                .is_some_and(|rows| rows.iter().any(|row| self.concurrent(*row, hash)));
            let handed_off = fold.handoff_or_appointment_retired_keys.contains(key)
                && self.handoffs.iter().any(|row| self.concurrent(*row, hash));
            revoked || handed_off
        })
    }

    /// Whether the refused removal `entry`, at `hash`, crossed: a removal
    /// the fold refused the same way (`RetiredSigner`), on a branch that
    /// never saw it, revokes a signer of `entry`, and the key `entry`
    /// revokes signed it. The two hold each other's signers, so their fences
    /// close together and each ends its key, unless a settled fence makes
    /// either yield ([`Self::fence_a_signer_of`]). A removal whose signer
    /// another crossing ended yielded to that crossing and ended nothing
    /// (REVIEW-9584 round 2).
    fn crossed(
        &self,
        fold: &AuthorityFold,
        hash: AuthorityEntryHash,
        entry: &AuthorityLogEntry,
    ) -> bool {
        let AuthorityOp::RevokeDevice { revoked_key } = &entry.op else {
            return false;
        };
        self.refused_revocations.iter().any(|(other, crossing)| {
            let AuthorityOp::RevokeDevice {
                revoked_key: crossing_revoked,
            } = &crossing.op
            else {
                return false;
            };
            self.concurrent(*other, hash)
                && super::retired_signers::entry_signer_keys(crossing).any(|key| key == revoked_key)
                && super::retired_signers::entry_signer_keys(entry)
                    .any(|key| key == crossing_revoked)
                && !self.fence_a_signer_of(fold, *other, crossing)
        })
    }

    /// Whether `a` and `b` are on branches that never saw each other.
    fn concurrent(&self, a: AuthorityEntryHash, b: AuthorityEntryHash) -> bool {
        a != b && !self.descends(a, b) && !self.descends(b, a)
    }

    /// Whether `ancestor` is in the ancestry of `row`, as the kept rows name
    /// it.
    fn descends(&self, row: AuthorityEntryHash, ancestor: AuthorityEntryHash) -> bool {
        let mut seen = BTreeSet::new();
        let mut next = vec![row];
        while let Some(current) = next.pop() {
            for parent in self.parents.get(&current).copied().unwrap_or_default() {
                if *parent == ancestor {
                    return true;
                }
                if seen.insert(*parent) {
                    next.push(*parent);
                }
            }
        }
        false
    }
}

/// The owner key change `entry`, at `hash`, is on `fold`: a counted
/// enrolment that stands for its key among `keys`, a counted enrolment of
/// such a key that confirms a passkey's vouch for it
/// ([`ListedOwnerKeys::confirms`]), a counted `RevokeDevice` of a key an
/// enrolment names, or a `RevokeDevice` of such a key that ended it
/// uncounted ([`ended_by_a_refused_removal`], no fence of `fences` made it
/// yield, and it crossed a removal of its signer, [`SignerFences::crossed`];
/// `hosted` is as [`AuthorityFold::proves_owner_acts`] takes it). Keys of
/// either shape alike. None for any other entry.
fn owner_key_change(
    fold: &AuthorityFold,
    hosted: bool,
    keys: &ListedOwnerKeys,
    fences: &SignerFences<'_>,
    hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
) -> Option<OwnerKeyChange> {
    let counted = fold.valid_entries.contains(&hash);
    let (change, public_key, key) = match &entry.op {
        AuthorityOp::OwnerKeyEnroll(enroll) if counted => {
            let public_key = &enroll.device.key;
            let key = keys.keys.get(public_key)?;
            if key.entry == hash {
                (OwnerKeyChangeKind::Enrolled, public_key, key)
            } else if keys.confirms(fold, hosted, public_key, entry) {
                (OwnerKeyChangeKind::Confirmed, public_key, key)
            } else {
                return None;
            }
        }
        AuthorityOp::RevokeDevice { revoked_key } => {
            let key = keys.keys.get(revoked_key)?;
            if counted {
                (OwnerKeyChangeKind::Removed, revoked_key, key)
            } else if ended_by_a_refused_removal(fold, hash, revoked_key, key)
                && signed_by_a_key_of_the_owners(fold, hosted, entry)
                && !fences.fence_a_signer_of(fold, hash, entry)
                && fences.crossed(fold, hash, entry)
            {
                (OwnerKeyChangeKind::RemovedByEndedKey, revoked_key, key)
            } else {
                return None;
            }
        }
        _ => return None,
    };
    Some(OwnerKeyChange {
        entry: hash,
        change,
        public_key: public_key.clone(),
        machine: key.machine,
        kind: key.kind,
        signed_by: entry.signer.public_key.clone(),
        at: entry.ts,
    })
}

/// Whether the uncounted `RevokeDevice` of `public_key` (listed as `key`) at
/// `hash` is a removal that ended it all the same: the key is retired, and
/// the fold refused the entry for its signer alone (`RetiredSigner`), so the
/// entry counted on its own branch and only a removal of its signer, on a
/// branch that never saw it, refused it. A refused entry of any other kind
/// (a bad signature, a signer the roster never held) is no removal and
/// lists nothing. The caller also asks who signed it
/// ([`signed_by_a_key_of_the_owners`]), whether a settled fence made it
/// yield ([`SignerFences::fence_a_signer_of`]) and whether it crossed the
/// removal that ended its signer ([`SignerFences::crossed`]).
fn ended_by_a_refused_removal(
    fold: &AuthorityFold,
    hash: AuthorityEntryHash,
    public_key: &AuthorityKey,
    key: &ListedOwnerKey,
) -> bool {
    !key.live
        && fold.retired_keys.contains(public_key)
        && fold
            .issues
            .contains(&AuthorityFoldIssue::RetiredSigner(hash))
}

/// Whether a key of the owner's signed `entry`, as its primary signer or as
/// a cosign: a roster key with `ROLE_OWNER`, live or ended, outside the
/// host's custody when the vault is `hosted`
/// ([`AuthorityFold::proves_owner_acts`], without its liveness: the list
/// reads an entry whose signer has ended since). A managed host's custodial
/// root and an admin-only key are no key of the owner's.
fn signed_by_a_key_of_the_owners(
    fold: &AuthorityFold,
    hosted: bool,
    entry: &AuthorityLogEntry,
) -> bool {
    std::iter::once(&entry.signer.public_key)
        .chain(entry.cosigns.iter().map(|cosign| &cosign.public_key))
        .any(|key| {
            fold.roster
                .get(key)
                .is_some_and(|device| device.roles & ROLE_OWNER != 0)
                && !(hosted && fold.in_host_custody(key))
        })
}
