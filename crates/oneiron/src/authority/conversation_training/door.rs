//! The person's own "Learn from my conversations" opt-out door (FIX 4489,
//! FIX 5502 owner rulings, OF-420): "leave my messages out", on or off, from
//! any surface where they are authenticated, on any host. Their say-so is
//! the gate, revalidated at the person tier in the writing transaction
//! (`AuthenticatedOwner::revalidate_person_in_txn`): a live person of this
//! vault, member or guest, acting for themselves. The act's person is the
//! proof's own, never a caller's id, and no Grant action names it, so an
//! agent never makes it. It is refused while the vault's setting does not
//! let people opt out; a choice already made then stays, ignored. This
//! install carries it under its own live machine profile, in any role the
//! one carrier rule admits ([`super::super::owner_act_signer_admits`]).

use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{TimeRange, Vault};

use super::*;

/// This install cannot carry the person's choice: it has no machine
/// identity or install key, or no live profile of it stands under that key.
/// No roster key, the host root included, carries an act (FIX 2222).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the conversation training choice";
/// The choice would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one conversation \
                              training choice may name; nothing was written";
/// The supplied `seen` is not the person's current choice revision.
const STALE: &str = "the conversation training choice changed since it was read";
/// The vault's setting does not let people opt out.
const OPT_OUTS_NOT_ALLOWED: &str = "this vault does not allow opt-outs";
/// The fold did not count the signed choice here: it never reports success.
const NOT_COUNTED: &str = "this install's fold does not count the conversation training choice";

/// A person's own opt-out, as their own surface shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConversationTrainingView {
    /// The PERSON whose choice this is: the proof's own.
    pub person: EntityId,
    /// Whether they asked to leave their own messages out. A conflict reads
    /// as left out.
    pub leave_out: bool,
    /// Whether the vault's setting lets people opt out now: while it does
    /// not, `leave_out` is kept and ignored.
    pub allowed: bool,
    /// The revision to present back as `seen`: the digest of the person's
    /// live choices, zero when none.
    pub revision: PolicyRevision,
    /// Whether the person's live choices conflict.
    pub conflicted: bool,
    /// The authority entry of the choice in force; `None` while no choice
    /// counts or the choices conflict.
    pub act: Option<AuthorityEntryHash>,
}

impl Vault {
    /// The authenticated person's own opt-out.
    ///
    /// # Errors
    /// A refusal when the proof is no longer a live person of this vault;
    /// storage faults, and history this vault lacks, as the fold reads them.
    pub fn conversation_training_view(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<ConversationTrainingView> {
        let txn = self.store.env.read_txn()?;
        let person = owner.revalidate_person_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(opt_out_view(&fold, person))
    }

    /// The authenticated person leaves their own messages out of training
    /// (`leave_out`), or lets them back in, from `surface` (audit only).
    /// `seen` is the revision their surface showed them
    /// ([`ConversationTrainingView::revision`]); `None` takes the current
    /// one. Refused while the vault's setting does not let people opt out.
    /// The choice names the main-log heads alone, whose fold carries this
    /// install's standing rows and every live choice of the person's (FIX
    /// 4987), so it supersedes all of them, and lands atomically or not at
    /// all. It stops new sharing of their messages; it withdraws nothing
    /// already shared.
    ///
    /// # Errors
    /// A refusal when the proof is no longer a live person of this vault;
    /// [`crate::error::RecordError::AuthorityRefused`] ("this vault does not
    /// allow opt-outs") while the vault does not let people opt out, and when
    /// this install cannot carry the choice or its fold does not count it; [`Error::ConcurrentWrite`] when `seen` is not the current
    /// revision; [`Error::InvalidConfig`] when the choice would name more
    /// parents than one entry may.
    pub fn set_conversation_training(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        leave_out: bool,
        seen: Option<PolicyRevision>,
    ) -> Result<ConversationTrainingView> {
        let mut txn = self.store.env.write_txn()?;
        let person = owner.revalidate_person_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if !fold.conversation_training_vault.allows_opt_out() {
            return Err(authority_refused(OPT_OUTS_NOT_ALLOWED));
        }
        // Revision integrity (mesh contract §4): the person chose on what
        // the surface showed them.
        let current = fold.conversation_training.revision(person);
        if seen.is_some_and(|seen| seen != current) {
            return Err(Error::ConcurrentWrite(STALE));
        }
        let machine = crate::identity::read_machine_id_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let public_key = key.verifying_key().to_bytes();
        if !owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            return Err(authority_refused(NO_CARRIER));
        }
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(&fold, &signer)?;
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(Error::InvalidConfig(TOO_MANY_HEADS.to_owned()));
        }
        // The person's own act: owner and target are both the proof's
        // person (the holder meaning of `by: Owner`).
        let act = OwnerAct::by_owner(
            person,
            OwnerActKind::ConversationTraining,
            person,
            surface,
            current.0,
        );
        let now = self.instant_in_txn(&txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &key,
            seq,
            parents,
            AuthorityOp::ConversationTrainingSet(ConversationTrainingSet {
                act,
                machine,
                leave_out,
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
        let landed = after
            .conversation_training
            .persons
            .get(&person)
            .is_some_and(|folded| folded.live.contains_key(&entry_hash));
        if !landed || after.install.held_back.contains(&entry_hash) {
            return Err(authority_refused(NOT_COUNTED));
        }
        let view = opt_out_view(&after, person);
        txn.commit()?;
        Ok(view)
    }
}

/// `person`'s opt-out as `fold` reads it.
fn opt_out_view(fold: &AuthorityFold, person: EntityId) -> ConversationTrainingView {
    let training = &fold.conversation_training;
    ConversationTrainingView {
        person,
        leave_out: training.leaves_out(person),
        allowed: fold.conversation_training_vault.allows_opt_out(),
        revision: training.revision(person),
        conflicted: training.conflicted(person),
        act: training.act(person),
    }
}
