//! The owner's choice "Let my passkey remove devices and keys" (choice id
//! `passkey.full_owner`; Engine ruling WEBPASSKEY-OPTIN-HOME = A, 16 Nov,
//! after the owner's principle of 00:44: a limit that is no correctness fix
//! ships as a good default with the owner's opt-out).
//!
//! Off by default: a passkey and a key only a passkey vouched for act in
//! part ([`FoldState::passkey_limited`]). The owner turns it on through the
//! confirm sheet on a device whose owner key is not the passkey alone: the
//! act counts only with an owner key's proof by a key the passkey limits do
//! not reach, whoever carries it, and this door proves it with the owner
//! key this install holds ([`Vault::owner_proof_signer`]). Turning it off
//! is any owner act. It is a `PolicySettingSet` act of
//! [`PolicySetting::PasskeyFullOwner`], folded on the setting register
//! ([`super::policy_setting_choice`]); no install keeps a row of it. No
//! Grant action names it: an agent may propose it, and the owner says yes.

use std::collections::BTreeSet;

use crate::error::Result;
use crate::{TimeRange, Vault};

use super::*;

/// The choice is the owner's own: no Grant action names it, so an agent's
/// act never makes it. Authority; nothing was written.
const OWNER_ONLY: &str =
    "the passkey full owner choice is the owner's to make; no Grant action names it";
/// This install cannot carry the owner's act: it has no machine identity or
/// install key, or no live profile of it stands under that key (FIX 2222).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the owner's passkey full owner choice";
/// The act would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one passkey full \
                              owner choice may name";
/// The fold did not count the signed act here.
const NOT_COUNTED: &str = "the authority fold did not count the passkey full owner choice";

impl AuthorityFold {
    /// Whether the owner's choice "Let my passkey remove devices and keys" is
    /// on in this fold: the setting's act in force here turns it on. No act,
    /// two live acts that did not see each other, and an act that turned it
    /// off all read off.
    #[must_use]
    pub fn passkey_full_owner(&self) -> bool {
        let Ok(Some(target)) = PolicySetting::PasskeyFullOwner.reserved_target() else {
            return false;
        };
        self.policy_settings
            .targets
            .get(&target)
            .is_some_and(|folded| {
                folded.conflict.is_empty()
                    && folded.selected() == Some(&passkey_full_owner_value(true))
            })
    }

    /// Whether this fold counts `act`: valid, not held back, and not waiting
    /// for the owner's proof.
    fn counts_passkey_full_owner_act(&self, act: &AuthorityEntryHash) -> bool {
        self.valid_entries.contains(act)
            && !self.install.held_back.contains(act)
            && !self.waiting_owner_choices().contains(act)
    }
}

impl Vault {
    /// Turns the owner's choice "Let my passkey remove devices and keys" on
    /// or off (`on`), carried by this install and proved by the owner key it
    /// holds ([`Vault::owner_proof_signer`]). The act names the main-log
    /// heads and the setting's revision there, so it supersedes every live
    /// act of the setting, and it lands atomically or not at all.
    ///
    /// # Errors
    /// An agent's act; a proof that is no longer a live owner of this vault;
    /// [`crate::error::RecordError::OwnerKeyRequired`] when the act waits for
    /// an owner key's proof (turning it on here with no owner key, or with
    /// one the passkey limits reach); an install that cannot carry it; a
    /// frontier too wide for one entry; or a fold that does not count it.
    pub fn set_passkey_full_owner(
        &self,
        authority: &ActAuthority,
        on: bool,
    ) -> Result<AuthorityEntryHash> {
        let mut txn = self.store.env.write_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let proof = self.owner_proof_signer(&fold);
        let (act, after) =
            self.append_passkey_full_owner_in_txn(&mut txn, authority, on, proof.as_deref(), None)?;
        after.refuse_waiting_choice(&act)?;
        if !after.counts_passkey_full_owner_act(&act) {
            return Err(authority_refused(NOT_COUNTED));
        }
        txn.commit()?;
        Ok(act)
    }

    /// Signs and stores one act of the choice in `txn`, carried by this
    /// install, with `proof`'s key as the owner key's proof when named: at
    /// the main-log heads under the setting's revision there, or on `fork`,
    /// parents that carry no act of the setting. Returns the act and the
    /// fold after it; judges nothing of its own.
    fn append_passkey_full_owner_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        authority: &ActAuthority,
        on: bool,
        proof: Option<&dyn CheckpointRootSigner>,
        fork: Option<Vec<AuthorityEntryHash>>,
    ) -> Result<(AuthorityEntryHash, AuthorityFold)> {
        let (owner, surface) = match authority {
            ActAuthority::Owner(owner, surface) => (owner, *surface),
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let target = PolicySetting::PasskeyFullOwner
            .reserved_target()?
            .ok_or_else(invalid_authority)?;
        let (machine, key) = self
            .carrier_in_txn(txn, &fold)
            .map_err(authority_refusal_as(NO_CARRIER))?;
        let (fold, parents, seen) = match fork {
            Some(parents) => (
                fold,
                parents.into_iter().collect::<BTreeSet<_>>(),
                policy_setting_revision(std::iter::empty()),
            ),
            None => {
                // FIX 7908: join a frontier wider than one entry names, else
                // today's path.
                let joiner = FrontierSigner::Install(machine, &key);
                let fold = self
                    .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
                    .unwrap_or(fold);
                if fold.append_heads.len() > MAX_PARENTS {
                    return Err(authority_refused(TOO_MANY_HEADS));
                }
                let parents = fold.append_heads.clone();
                let seen = fold.policy_settings.revision(target);
                (fold, parents, seen)
            }
        };
        let signer = AuthorityKey::Ed25519(key.verifying_key().to_bytes());
        let seq = next_sequence(&fold, &signer)?;
        let act = OwnerAct::by_owner(actor, OwnerActKind::PolicySetting, target, surface, seen);
        let op = AuthorityOp::PolicySettingSet(PolicySettingSet {
            act,
            machine,
            setting: PolicySetting::PasskeyFullOwner,
            prior: passkey_full_owner_value(fold.passkey_full_owner()),
            value: Some(passkey_full_owner_value(on)),
        });
        let now = self.instant_in_txn(txn)?.secs();
        let entry = sign_side_entry_with_owner_proof(&fold, &key, seq, parents, op, now, proof)?;
        let hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        Ok((hash, after))
    }

    /// One act of the choice carried by this install, with `proof`'s key and
    /// signature (over the authority transcript) as the owner key's proof
    /// when named, at the main-log heads or on `fork`, parents that carry no
    /// act of the setting; true when the fold counted it, false when it
    /// waits for a proof or is invalid. The integration tests' door to the
    /// proof that turns the choice on (Engine ruling WEBPASSKEY-OPTIN-HOME =
    /// A).
    ///
    /// # Errors
    /// An agent's act, an install that cannot carry it, an owner proof that
    /// no longer holds, or the store's refusal of the row.
    #[cfg(oneiron_test_support)]
    pub(crate) fn set_passkey_full_owner_for_test<S>(
        &self,
        authority: &ActAuthority,
        on: bool,
        proof: Option<(AuthorityKey, S)>,
        fork: Option<Vec<AuthorityEntryHash>>,
    ) -> Result<bool>
    where
        S: Fn(&[u8]) -> Vec<u8> + Send + Sync,
    {
        let proof = proof.map(|(key, sign)| ProofForTest { key, sign });
        let mut txn = self.store.env.write_txn()?;
        let (act, after) = self.append_passkey_full_owner_in_txn(
            &mut txn,
            authority,
            on,
            proof
                .as_ref()
                .map(|proof| proof as &dyn CheckpointRootSigner),
            fork,
        )?;
        let counted = after.counts_passkey_full_owner_act(&act);
        txn.commit()?;
        Ok(counted)
    }
}

/// An owner key's proof a test holds: its key and its signer.
#[cfg(oneiron_test_support)]
struct ProofForTest<S> {
    key: AuthorityKey,
    sign: S,
}

#[cfg(oneiron_test_support)]
impl<S> CheckpointRootSigner for ProofForTest<S>
where
    S: Fn(&[u8]) -> Vec<u8> + Send + Sync,
{
    fn root(&self) -> AuthorityKey {
        self.key.clone()
    }

    fn sign_checkpoint_statement(&self, _statement: &[u8]) -> Result<Vec<u8>> {
        Err(invalid_authority())
    }

    fn sign_owner_proof(&self, transcript: &[u8]) -> Result<Vec<u8>> {
        Ok((self.sign)(transcript))
    }
}
