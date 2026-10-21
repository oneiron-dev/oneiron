//! The owner's checkpoint root policy door (mesh PR2c, §A 06, K06): he
//! selects which roots attest his authority checkpoint images, and how many
//! of them must, from any surface where he is authenticated, on any host,
//! Hosted included. His say-so is the gate (`ActAuthority::Owner`, revalidated
//! in the writing transaction); this install carries it under its own live
//! machine profile, in any role the one carrier rule admits
//! ([`super::owner_act_signer_admits`]), a hosted node included. The operator
//! root alone acts as nobody (FIX 2222): it is a roster key, which the
//! carrier rule never admits.
//!
//! The choice names the vault's policy revision the deciding surface showed
//! him (`seen`); a stale one is a typed conflict, never a silent overwrite.
//! Existing pins never move with it: a folding install follows the choice,
//! an adopting install keeps the pin its pairing gave it, and re-pinning is
//! the owner's own pairing step ("pair again with a link from the owner").

use crate::error::{Error, RecordError, Result};
use crate::{TimeRange, Vault};

use super::checkpoint_policy::{checkpoint_root_policy_of, policy_refused};
use super::*;

/// The checkpoint root policy is the owner's: no Grant action names it, so an
/// agent's act never selects it. Authority; nothing was written.
const OWNER_ONLY: &str = "the checkpoint root policy is the owner's; no Grant action names it";
/// This install cannot carry the owner's choice: it has no machine identity
/// or install key, or no live profile of it stands under that key. Key
/// possession: the choice is signed by the install that carries it, and no
/// roster key, the host root included, carries an owner act (FIX 2222).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the owner's checkpoint policy choice";
/// The choice would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one checkpoint \
                              policy choice may name; nothing was written";
/// The fold did not count the signed choice here: it never reports success.
const NOT_COUNTED: &str = "this install's fold does not count the checkpoint policy choice";

/// The vault's checkpoint root policy as the owner's surface shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointPolicyView {
    /// The revision to present back as `seen`: the digest of the live
    /// choices, zero when none.
    pub revision: [u8; 32],
    /// The policy in force; `None` when the roster cannot fix it.
    pub policy: Option<CheckpointRootPolicy>,
    /// Why the roster cannot fix the policy in force, when it cannot.
    pub refusal: Option<String>,
    /// The owner's choice in force; `None` while the hosting posture fixes
    /// the policy.
    pub selected: Option<CheckpointPolicyHead>,
    /// Every live choice.
    pub heads: Vec<CheckpointPolicyHead>,
    /// The live choices in conflict, empty when none: the choice in force
    /// stays the last one they agreed on until a choice that saw them all
    /// supersedes them.
    pub conflict: Vec<CheckpointPolicyHead>,
}

impl Vault {
    /// The vault's checkpoint root policy, its revision, the owner's choice
    /// in force, and any conflict among his live choices.
    pub fn checkpoint_policy_view(&self) -> Result<CheckpointPolicyView> {
        let txn = self.store.env.read_txn()?;
        self.checkpoint_policy_view_in_txn(&txn)
    }

    fn checkpoint_policy_view_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<CheckpointPolicyView> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let folded = &fold.checkpoint_policy;
        let (policy, refusal) = match checkpoint_root_policy_of(&fold, self.privacy_posture()) {
            Ok(policy) => (Some(policy), None),
            Err(Error::Record(RecordError::CheckpointPolicyRefused(reason))) => {
                (None, Some(reason.to_owned()))
            }
            Err(other) => return Err(other),
        };
        Ok(CheckpointPolicyView {
            revision: folded.revision(CHECKPOINT_POLICY_REVISION_CONTEXT),
            policy,
            refusal,
            selected: folded.in_force.clone().filter(|head| head.choice.is_some()),
            heads: folded.live.values().cloned().collect(),
            conflict: folded.conflict.clone(),
        })
    }

    /// The owner selects the vault's checkpoint root policy (`choice`), or
    /// clears his choice (`None`) so the hosting posture fixes it again, as
    /// `authority`, from any linked surface on any host. `seen` is the
    /// revision the deciding surface showed him
    /// ([`CheckpointPolicyView::revision`]); `None` takes the current one.
    ///
    /// The choice must stand now: every key a selectable root, the quorum
    /// between the multi-root floor and the roots named, a hardware
    /// requirement some named root meets. It names the main-log heads alone,
    /// whose fold carries this install's standing rows and every live choice,
    /// so it supersedes all of them, and lands atomically or not at all.
    ///
    /// # Errors
    /// [`RecordError::AuthorityRefused`] for an agent's act or an install
    /// that cannot carry it; [`RecordError::CheckpointPolicyRevisionStale`]
    /// when `seen` is not the current revision;
    /// [`RecordError::CheckpointPolicyRefused`] naming the rule a choice
    /// breaks; an owner refusal when the proof is no longer the vault's live
    /// owner.
    pub fn set_checkpoint_policy_as(
        &self,
        authority: &ActAuthority,
        choice: Option<CheckpointRootChoice>,
        seen: Option<[u8; 32]>,
    ) -> Result<CheckpointPolicyView> {
        let (owner, surface) = match authority {
            ActAuthority::Owner(owner, surface) => (owner, *surface),
            ActAuthority::Agent(_) => return Err(authority_refused(OWNER_ONLY)),
        };
        // Every root the owner names is kept (FIX 7909): the count is
        // measured, and paced only before the writer opens.
        let _turn = self.admit_authority_work(
            choice.as_ref().map_or(0, |choice| choice.roots.len()),
            None,
            || owner.actor_for_read(self),
        )?;
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        // Revision integrity (mesh contract §4): the owner chose on what the
        // surface showed him.
        let current = fold
            .checkpoint_policy
            .revision(CHECKPOINT_POLICY_REVISION_CONTEXT);
        if seen.is_some_and(|seen| seen != current) {
            return Err(Error::Record(RecordError::CheckpointPolicyRevisionStale {
                current,
            }));
        }
        if let Some(choice) = &choice {
            CheckpointRootPolicy::from_choice_exactly(
                &fold.roster,
                self.privacy_posture(),
                choice,
            )?;
        }
        let machine = crate::identity::read_machine_id_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let public_key = key.verifying_key().to_bytes();
        if !super::owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            return Err(authority_refused(NO_CARRIER));
        }
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(&fold, &signer)?;
        // The main-log heads alone: this install's standing rows and every
        // live choice are main-log rows among them or their ancestors, so the
        // fold at the heads carries them (FIX 4987).
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(policy_refused(TOO_MANY_HEADS));
        }
        let act = OwnerAct::by_owner(
            actor,
            OwnerActKind::CheckpointPolicy,
            checkpoint_policy_target(&vault_id)?,
            surface,
            current,
        );
        let now = self.instant_in_txn(&txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &key,
            seq,
            parents,
            AuthorityOp::CheckpointPolicySet(CheckpointPolicySet {
                act,
                machine,
                choice,
            }),
            now,
        )?;
        let entry_hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(&mut txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        if !after.checkpoint_policy.live.contains_key(&entry_hash)
            || after.install.held_back.contains(&entry_hash)
        {
            return Err(policy_refused(NOT_COUNTED));
        }
        let view = self.checkpoint_policy_view_in_txn(&txn)?;
        txn.commit()?;
        Ok(view)
    }
}
