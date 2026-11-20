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
//! One removal ends its key although the fold counts no entry for it: removals
//! that cross. When key A removes key B on one branch and B removes A on a
//! branch that never saw it, each revocation's fence holds the other's signer,
//! so their fences close together: the fold refuses both entries and both keys
//! end (`retired_signers`). A ring does the same: A removes B, B removes C and
//! C removes A. The list shows such an entry as
//! [`OwnerKeyChangeKind::RemovedByEndedKey`], so the owner still reads that the
//! key ended and which key signed its removal. The fold names these removals
//! ([`AuthorityFold::crossed_revocations`]), so the list judges no fence of its
//! own: a removal whose signer a closed fence from outside holds (a sibling
//! handoff, appointment or counted revocation, or another crossing) yielded to
//! it and ended nothing, and lists nothing. When C and A remove each other and
//! A also removes B, A's removal of B yields to C's removal of A, so if B ended
//! by a crossing of its own with D, the list names D's removal of B alone.
//! Only a removal that a key of the owner's signed lists so: a managed host's
//! root may sign a second revoke of a key that had already ended, and that
//! entry is no act of the owner's. A crossing removal the fold refused for a
//! row below it, not for its own signer, names no ended signer: when C
//! removes A on top of a row B signed and A removes B, A's fence refuses C's
//! removal of A and B's fence refuses A's, and C stands. The list shows it as
//! [`OwnerKeyChangeKind::RemovedInConflict`], so A's end has its line too.

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
    /// of it crossed other removals, each on a branch that never saw the
    /// others, whose fences hold one another's signers round a cycle. Their
    /// fences closed together, so the fold counts none of them, and this
    /// entry's own signer ended too ([`AuthorityFold::crossed_revocations`]).
    RemovedByEndedKey,
    /// The key ended, and no counted removal names it: this `RevokeDevice`
    /// of it conflicted with another removal, whose fence holds the signer
    /// of a row below it, while its own signer stands. Their fences closed
    /// together, so the vault counted neither removal, and the key ended
    /// ([`AuthorityFold::crossed_revocations`]; Engine ANSWER 20 Nov 20:44,
    /// row OWNER-KEY-CHANGES-CROSSED-REMOVAL-BELOW-REFUSED-ROW = A).
    RemovedInConflict,
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
    /// The machine the change's own row names for the key: an enrolment's
    /// or a confirmation's machine (a confirmation may name another machine
    /// than the enrolment it confirms); for a removal, the machine of the
    /// key's listed enrolment. For a passkey, the carrier that served its
    /// ceremony.
    pub machine: EntityId,
    /// What the key is, as the same row says (a removal: as the key's listed
    /// enrolment says); `None` for a passkey, which is neither kind.
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
    /// owner's signed and whose fence closed with the removals it crossed:
    /// one the fold refused for its signer as
    /// [`OwnerKeyChangeKind::RemovedByEndedKey`], any other as
    /// [`OwnerKeyChangeKind::RemovedInConflict`]. Empty before any
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
        let mut changes: Vec<OwnerKeyChange> = rows
            .iter()
            .filter_map(|(hash, entry)| owner_key_change(&fold, hosted, &keys, *hash, entry))
            .collect();
        // A counted removal of a key is the whole account of its end.
        let removed: BTreeSet<AuthorityKey> = changes
            .iter()
            .filter(|change| change.change == OwnerKeyChangeKind::Removed)
            .map(|change| change.public_key.clone())
            .collect();
        changes.retain(|change| {
            !matches!(
                change.change,
                OwnerKeyChangeKind::RemovedByEndedKey | OwnerKeyChangeKind::RemovedInConflict
            ) || !removed.contains(&change.public_key)
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
    /// The machine its listed enrolment names.
    machine: EntityId,
    /// What its listed enrolment names it as; `None` for a passkey.
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
    /// confirmation it is. The listed machine and kind are that enrolment's
    /// too, never a smaller confirmation's (REVIEW-9790 P1).
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
        let mut enrolments: BTreeMap<AuthorityKey, (AuthorityEntryHash, &OwnerKeyEnroll)> =
            BTreeMap::new();
        for (hash, entry) in rows {
            let AuthorityOp::OwnerKeyEnroll(enroll) = &entry.op else {
                continue;
            };
            if fold.valid_entries.contains(hash)
                && !listed.confirms(fold, hosted, &enroll.device.key, entry)
            {
                let first = enrolments
                    .entry(enroll.device.key.clone())
                    .or_insert((*hash, enroll));
                if *hash < first.0 {
                    *first = (*hash, enroll);
                }
            }
        }
        for (public_key, (entry, enroll)) in enrolments {
            if let Some(key) = listed.keys.get_mut(&public_key) {
                key.entry = entry;
                key.machine = enroll.machine;
                key.kind = enrolment_kind(enroll);
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

/// The owner key change `entry`, at `hash`, is on `fold`: a counted
/// enrolment that stands for its key among `keys`, a counted enrolment of
/// such a key that confirms a passkey's vouch for it
/// ([`ListedOwnerKeys::confirms`]), a counted `RevokeDevice` of a key an
/// enrolment names, or a `RevokeDevice` of such a key that ended it
/// uncounted ([`ended_by_an_uncounted_removal`], signed by a key of the
/// owner's; `hosted` is as [`AuthorityFold::proves_owner_acts`] takes it).
/// Keys of either shape alike. None for any other entry.
fn owner_key_change(
    fold: &AuthorityFold,
    hosted: bool,
    keys: &ListedOwnerKeys,
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
            } else {
                let change = ended_by_an_uncounted_removal(fold, hash, revoked_key, key)?;
                if !signed_by_a_key_of_the_owners(fold, hosted, entry) {
                    return None;
                }
                (change, revoked_key, key)
            }
        }
        _ => return None,
    };
    // An enrolment or a confirmation names its own row's machine and kind; a
    // removal names those of the key's listed enrolment.
    let (machine, kind) = match &entry.op {
        AuthorityOp::OwnerKeyEnroll(enroll) => (enroll.machine, enrolment_kind(enroll)),
        _ => (key.machine, key.kind),
    };
    Some(OwnerKeyChange {
        entry: hash,
        change,
        public_key: public_key.clone(),
        machine,
        kind,
        signed_by: entry.signer.public_key.clone(),
        at: entry.ts,
    })
}

/// What the enrolment `enroll` names its key as: its attestation kind for a
/// device's Ed25519 key, `None` for a passkey.
fn enrolment_kind(enroll: &OwnerKeyEnroll) -> Option<EnrolledOwnerKeyKind> {
    enroll
        .public_key()
        .map(|_| EnrolledOwnerKeyKind::of(enroll))
}

/// How the uncounted `RevokeDevice` of `public_key` (listed as `key`) at
/// `hash` ended it all the same, if it did: the key is retired, and the fold
/// names the entry as crossed ([`AuthorityFold::crossed_revocations`]), so
/// its own fence closed with the removals it crossed and it yielded to no
/// fence that holds its signer. The fold refused it for its signer
/// (`RetiredSigner`): a removal of its signer, on a branch that never saw
/// it, refused it ([`OwnerKeyChangeKind::RemovedByEndedKey`]); or for a row
/// below it, a crossing removal's fence refusing that row while its own
/// signer stands ([`OwnerKeyChangeKind::RemovedInConflict`]). An entry the
/// fold refused before any fence closed (a bad signature, a signer the
/// roster never held) has no fence, so no crossed entry is one, and it
/// lists nothing. The caller also asks who signed it
/// ([`signed_by_a_key_of_the_owners`]).
fn ended_by_an_uncounted_removal(
    fold: &AuthorityFold,
    hash: AuthorityEntryHash,
    public_key: &AuthorityKey,
    key: &ListedOwnerKey,
) -> Option<OwnerKeyChangeKind> {
    if key.live
        || !fold.retired_keys.contains(public_key)
        || !fold.crossed_revocations.contains(&hash)
    {
        return None;
    }
    if fold
        .issues
        .contains(&AuthorityFoldIssue::RetiredSigner(hash))
    {
        Some(OwnerKeyChangeKind::RemovedByEndedKey)
    } else {
        Some(OwnerKeyChangeKind::RemovedInConflict)
    }
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
