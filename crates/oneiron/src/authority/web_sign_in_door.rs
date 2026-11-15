//! The owner switches a hosted vault back to web sign-in (the owner's ruling
//! AUTH-5, pass 27 row R3), and reads what the vault asks of him.
//!
//! A vault that has held an owner key keeps asking for one (the ratchet,
//! [`OwnerKeyRequirement::Required`]). The switch is the one act that ends
//! it: a `PolicySettingSet` of the web sign-in setting whose value speaks for
//! exactly the owner keys the vault has held. This install carries it under
//! its own live machine profile, as every owner choice is carried, and the
//! owner key it holds signs beside the carrier. The fold counts the switch
//! only with that proof, whoever carries it, so a web session alone never
//! turns the ratchet off: an install that holds no owner key answers
//! [`RecordError::OwnerKeyRequired`] and writes nothing.
//!
//! The owner decides on what the surface showed him: `seen` is the switch
//! value of the read ([`OwnerKeyRequirement::Required`]). A key enrolled
//! since changes that value, so the door refuses and the owner reviews
//! again. The fold agrees: an act that carried the old value would not be
//! the switch there, it would land as "ask for an owner key again".
//!
//! The door answers only once this install's fold counts the entry as the
//! switch and the vault reads as running on web sign-in. It marks the rows
//! its write counted for the vault's loaded windows and announces them once
//! the write committed, as the owner key removal doors do.

use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, RecordError, Result};
use crate::{EntityId, TimeRange, Vault};

/// The vault has never held an owner key, so there is nothing to switch.
/// Nothing was written.
const NEVER_HELD: &str =
    "the vault has never held an owner key, so it asks for none; nothing was written";
/// The switch is in force already. Nothing was written.
const ALREADY_WEB_SIGN_IN: &str = "the vault already runs on web sign-in; nothing was written";
/// A vault that is not hosted has no account to fall back to. Nothing was
/// written.
const NOT_HOSTED: &str = "web sign-in is a hosted vault's choice, and this vault is not hosted; \
                          nothing was written";
/// This install cannot carry the owner's switch: it has no machine identity
/// or install key, or no live profile of it stands under that key.
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the owner's switch to web sign-in; nothing was written";
/// The act would name more rows than one authority entry may.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one web sign-in \
                              act may name; nothing was written";
/// The owner reviewed other owner keys than the vault has held by now.
const KEYS_CHANGED: &str = "the vault's owner keys changed since the review; nothing was written";
/// The fold did not count the signed act as the switch here: the door never
/// reports success for it.
const NOT_COUNTED: &str = "this install's fold does not count the switch; nothing was written";

/// The owner's switch back to web sign-in, as its authority entry says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSignInSwitch {
    /// The switch's authority entry.
    pub entry: AuthorityEntryHash,
    /// The machine whose install key carried the act.
    pub machine: EntityId,
    /// The owner key whose proof the act carries.
    pub signed_by: AuthorityKey,
    /// When it was signed, advisory unix seconds.
    pub at: u64,
}

impl Vault {
    /// What the vault asks of its owner now
    /// ([`AuthorityFold::owner_key_requirement`]): whether it asks for an
    /// owner key, and on a hosted vault the value that
    /// [`Self::switch_to_web_sign_in`] takes as `seen`.
    ///
    /// # Errors
    /// A refusal when the proof is no longer the vault's live owner; the
    /// log's read errors.
    pub fn owner_key_requirement(&self, owner: &AuthenticatedOwner) -> Result<OwnerKeyRequirement> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        Ok(self
            .authority_view_readonly_in_txn(&txn)?
            .owner_key_requirement())
    }

    /// The owner switches this hosted vault back to web sign-in, from
    /// `surface` (audit only): the vault stops asking for an owner key until
    /// one is enrolled again. `seen` is the switch value the deciding
    /// surface showed him ([`Self::owner_key_requirement`]). The owner key
    /// this install holds signs beside the carrier, and the door answers
    /// only once the fold counts the entry here.
    ///
    /// # Errors
    /// An authority refusal when the vault has never held an owner key,
    /// already runs on web sign-in or is not hosted, when this install
    /// cannot carry the act, or when the fold does not count it;
    /// [`RecordError::OwnerKeyRequired`] when this install holds no owner
    /// key; [`Error::ConcurrentWrite`] when the vault's owner keys changed
    /// since `seen` was read; a refusal when the proof is no longer the
    /// vault's live owner. Every refusal leaves the log as it was.
    pub fn switch_to_web_sign_in(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        seen: [u8; 32],
    ) -> Result<WebSignInSwitch> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let before = self.authority_view_readonly_in_txn(&txn)?;
        web_sign_in_switch_value(&before)?;
        if self.owner_proof_signer(&before).is_none() {
            return Err(Error::Record(RecordError::OwnerKeyRequired));
        }
        let machine = crate::identity::read_machine_id_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let public_key = key.verifying_key().to_bytes();
        if !super::owner_act_signer_admits(before.machine(machine), &before.roster, &public_key) {
            return Err(authority_refused(NO_CARRIER));
        }
        // Join a frontier wider than one entry names, as every owner choice
        // door does (FIX 7908).
        let joiner = FrontierSigner::Install(machine, &key);
        let joined =
            self.prepare_authority_frontier_in_txn(&mut txn, &before, joiner, MAX_PARENTS)?;
        let fold = joined.as_ref().unwrap_or(&before);
        // The owner chose on what the surface showed him: the value speaks
        // for exactly the owner keys the vault had held at his review.
        let value = web_sign_in_switch_value(fold)?;
        if seen != value {
            return Err(Error::ConcurrentWrite(KEYS_CHANGED));
        }
        let proof = self
            .owner_proof_signer(fold)
            .ok_or(Error::Record(RecordError::OwnerKeyRequired))?;
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(fold, &signer)?;
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(authority_refused(TOO_MANY_HEADS));
        }
        let Ok(Some(target)) = PolicySetting::WebSignIn.reserved_target() else {
            return Err(invalid_authority());
        };
        let act = OwnerAct::by_owner(
            actor,
            PolicySetting::WebSignIn.act_kind(),
            target,
            surface,
            fold.policy_settings.revision(target),
        );
        let now = self.instant_in_txn(&txn)?.secs();
        let entry = sign_side_entry_with_owner_proof(
            fold,
            &key,
            seq,
            parents,
            AuthorityOp::PolicySettingSet(PolicySettingSet {
                act,
                machine,
                setting: PolicySetting::WebSignIn,
                prior: [0; 32],
                value: Some(value),
            }),
            now,
            Some(&*proof),
        )?;
        let entry_hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(&mut txn, &[(entry, at, now)])?;
        // The fold judged the very entry, so the door and the fold cannot
        // disagree.
        let after = self.authority_view_readonly_in_txn(&txn)?;
        after.refuse_waiting_choice(&entry_hash)?;
        if after.web_sign_in_acts().get(&entry_hash) != Some(&WebSignInAct::SwitchedBack)
            || after.install.held_back.contains(&entry_hash)
            || after.owner_key_requirement() != OwnerKeyRequirement::WebSignIn
        {
            return Err(authority_refused(NOT_COUNTED));
        }
        let rows = self.mark_rows_counted_since_in_txn(&mut txn, &before)?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        Ok(WebSignInSwitch {
            entry: entry_hash,
            machine,
            signed_by: proof.root(),
            at: now,
        })
    }
}

/// The value a web sign-in act carries to switch the vault back on `fold`.
///
/// # Errors
/// An authority refusal where there is nothing to switch: a vault that has
/// never held an owner key, one that runs on web sign-in already, and one
/// that is not hosted.
fn web_sign_in_switch_value(fold: &AuthorityFold) -> Result<[u8; 32]> {
    match fold.owner_key_requirement() {
        OwnerKeyRequirement::NeverHeld => Err(authority_refused(NEVER_HELD)),
        OwnerKeyRequirement::WebSignIn => Err(authority_refused(ALREADY_WEB_SIGN_IN)),
        OwnerKeyRequirement::Required {
            web_sign_in_switch: None,
        } => Err(authority_refused(NOT_HOSTED)),
        OwnerKeyRequirement::Required {
            web_sign_in_switch: Some(value),
        } => Ok(value),
    }
}
