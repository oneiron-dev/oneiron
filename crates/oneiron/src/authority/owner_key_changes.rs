//! The owner's list of owner key changes (the owner's ruling AUTH-5, pass 27
//! section 4.4): every enrolment and every removal of an enrolled owner key,
//! and every switch back to web sign-in, that this vault's log holds and its
//! fold counts, newest first.
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
//! owner's.
//!
//! A switch back to web sign-in ([`Vault::switch_to_web_sign_in`]) names no
//! key: it is the act by which the vault stopped asking for one. It lists
//! every act the fold landed as the switch, in force or since ended by a
//! later enrolment or a later act of the setting, so the history keeps it.
//! Whether the vault runs on web sign-in now is the read's to say
//! ([`Vault::owner_key_requirement`]).

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::{EntityId, Vault};

/// The enrolled owner key a change names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangedOwnerKey {
    /// The key.
    pub public_key: [u8; 32],
    /// What the key is, as its enrolment says.
    pub kind: EnrolledOwnerKeyKind,
}

/// What happened to the vault's owner keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKeyChangeKind {
    /// The key was enrolled.
    Enrolled(ChangedOwnerKey),
    /// The key was removed: a counted `RevokeDevice` of it.
    Removed(ChangedOwnerKey),
    /// The key ended, and no counted removal names it: this `RevokeDevice`
    /// of it is one the fold refused only because its own signer's key ended
    /// too, on a branch that never saw this entry (two removals that cross
    /// end both keys and count neither entry).
    RemovedByEndedKey(ChangedOwnerKey),
    /// The owner switched the vault back to web sign-in: a web sign-in act
    /// the fold landed as the switch ([`WebSignInAct::SwitchedBack`]). It
    /// names no key.
    SwitchedToWebSignIn,
}

impl OwnerKeyChangeKind {
    /// The enrolled owner key the change names; None for the switch back to
    /// web sign-in.
    #[must_use]
    pub fn key(&self) -> Option<ChangedOwnerKey> {
        match self {
            Self::Enrolled(key) | Self::Removed(key) | Self::RemovedByEndedKey(key) => Some(*key),
            Self::SwitchedToWebSignIn => None,
        }
    }
}

/// One change of the vault's owner keys, as its authority entry says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyChange {
    /// The change's authority entry.
    pub entry: AuthorityEntryHash,
    /// What happened, and to which key.
    pub change: OwnerKeyChangeKind,
    /// The machine: the one the key's enrolment names, and for the switch
    /// back to web sign-in the one whose install key carried the act.
    pub machine: EntityId,
    /// The key that vouched for the change: the entry's signer for a key's
    /// enrolment (its predecessor) or removal (its proof), and for the
    /// switch back to web sign-in the owner key whose proof the act carries.
    pub signed_by: AuthorityKey,
    /// When it was signed, advisory unix seconds.
    pub at: u64,
}

impl Vault {
    /// Every change of the vault's owner keys, newest first: each counted
    /// enrolment and each counted removal of a key an enrolment names, and
    /// each switch back to web sign-in the fold landed, from the rows this
    /// vault keeps (stored, or carried by an adopted checkpoint image). A
    /// key enrolled on two branches lists its smallest
    /// enrolment entry, as [`Self::enrolled_owner_keys`] does; a key that
    /// two counted entries removed lists both removals. A key that ended
    /// with no counted removal lists each removal of it that a key of the
    /// owner's signed and the fold refused for its signer alone
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
        let enrolled: BTreeMap<[u8; 32], EnrolledOwnerKey> = self
            .enrolled_owner_keys_in_txn(&txn)?
            .into_iter()
            .map(|key| (key.public_key, key))
            .collect();
        let mut changes = Vec::new();
        let mut stored = BTreeSet::new();
        for (_, body) in super::readonly_fold::authority_log_rows_in_txn(&self.store, &txn)? {
            let entry = decode_authority_log_entry_body(&body)?;
            let hash = authority_entry_hash(&entry)?;
            stored.insert(hash);
            changes.extend(owner_key_change(&fold, hosted, &enrolled, hash, &entry));
        }
        if let Some(evidence) = super::adopted_evidence::adopted_evidence_in_txn(&self.store, &txn)?
        {
            for (hash, entry) in evidence.carried_past(&stored) {
                changes.extend(owner_key_change(&fold, hosted, &enrolled, *hash, entry));
            }
        }
        // A counted removal of a key is the whole account of its end.
        let removed: BTreeSet<[u8; 32]> = changes
            .iter()
            .filter_map(|change| match change.change {
                OwnerKeyChangeKind::Removed(key) => Some(key.public_key),
                _ => None,
            })
            .collect();
        changes.retain(|change| {
            !matches!(
                change.change,
                OwnerKeyChangeKind::RemovedByEndedKey(key) if removed.contains(&key.public_key)
            )
        });
        changes.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.entry.cmp(&b.entry)));
        Ok(changes)
    }
}

/// The owner key change `entry`, at `hash`, is on `fold`: a counted
/// enrolment that stands for its key among `enrolled`, a counted
/// `RevokeDevice` of a key an enrolment names, a `RevokeDevice` of such a
/// key that ended it uncounted ([`ended_by_a_refused_removal`]; `hosted` is
/// as [`AuthorityFold::proves_owner_acts`] takes it), or a switch back to
/// web sign-in ([`web_sign_in_switch_change`]). None for any other entry.
fn owner_key_change(
    fold: &AuthorityFold,
    hosted: bool,
    enrolled: &BTreeMap<[u8; 32], EnrolledOwnerKey>,
    hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
) -> Option<OwnerKeyChange> {
    let counted = fold.valid_entries.contains(&hash);
    let (change, machine) = match &entry.op {
        AuthorityOp::OwnerKeyEnroll(enroll) if counted => {
            let key = enrolled.get(enroll.public_key()?)?;
            (key.entry == hash)
                .then_some((OwnerKeyChangeKind::Enrolled(changed(key)), key.machine))?
        }
        AuthorityOp::RevokeDevice {
            revoked_key: AuthorityKey::Ed25519(revoked),
        } => {
            let key = enrolled.get(revoked)?;
            if counted {
                (OwnerKeyChangeKind::Removed(changed(key)), key.machine)
            } else if ended_by_a_refused_removal(fold, hash, key)
                && signed_by_a_key_of_the_owners(fold, hosted, entry)
            {
                (
                    OwnerKeyChangeKind::RemovedByEndedKey(changed(key)),
                    key.machine,
                )
            } else {
                return None;
            }
        }
        AuthorityOp::PolicySettingSet(set) => {
            return web_sign_in_switch_change(fold, hash, entry, set);
        }
        _ => return None,
    };
    Some(OwnerKeyChange {
        entry: hash,
        change,
        machine,
        signed_by: entry.signer.public_key.clone(),
        at: entry.ts,
    })
}

/// `key` as a change names it.
fn changed(key: &EnrolledOwnerKey) -> ChangedOwnerKey {
    ChangedOwnerKey {
        public_key: key.public_key,
        kind: key.kind,
    }
}

/// The switch back to web sign-in that `entry`, at `hash`, is on `fold`: an
/// act of the web sign-in setting that the fold landed as the switch
/// ([`AuthorityFold::web_sign_in_acts`]), in force or since replaced. Its
/// line names the carrier and the owner key whose proof the act carries,
/// the entry's one cosign: the fold lands no switch without it. None for an
/// act that landed as "ask again", waits for the owner's proof or was
/// refused, whatever value it carries, and for every other setting's act.
fn web_sign_in_switch_change(
    fold: &AuthorityFold,
    hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
    set: &PolicySettingSet,
) -> Option<OwnerKeyChange> {
    if fold.web_sign_in_acts().get(&hash) != Some(&WebSignInAct::SwitchedBack) {
        return None;
    }
    let [proof] = entry.cosigns.as_slice() else {
        return None;
    };
    Some(OwnerKeyChange {
        entry: hash,
        change: OwnerKeyChangeKind::SwitchedToWebSignIn,
        machine: set.machine,
        signed_by: proof.public_key.clone(),
        at: entry.ts,
    })
}

/// Whether the uncounted `RevokeDevice` of `key` at `hash` is a removal that
/// ended it all the same: the key is retired, and the fold refused the entry
/// for its signer alone (`RetiredSigner`), so the entry counted on its own
/// branch and only a removal of its signer, on a branch that never saw it,
/// refused it. A refused entry of any other kind (a bad signature, a signer
/// the roster never held) is no removal and lists nothing. The caller also
/// asks who signed it ([`signed_by_a_key_of_the_owners`]).
fn ended_by_a_refused_removal(
    fold: &AuthorityFold,
    hash: AuthorityEntryHash,
    key: &EnrolledOwnerKey,
) -> bool {
    !key.live
        && fold
            .retired_keys
            .contains(&AuthorityKey::Ed25519(key.public_key))
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
