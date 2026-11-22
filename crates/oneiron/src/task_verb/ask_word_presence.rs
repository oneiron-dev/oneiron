//! The owner presence check of an ask word (row OWNER-CONFIRM-SHEET, PR 4b-4).
//!
//! On a surface that answers as this install's owner device, the owner key
//! this install holds signs the proof of each word the person gives
//! ([`crate::Vault::authenticate_owner_device`]). That proof is an owner
//! proof, so the key signs it on a ground: the person at this device,
//! checked by [`crate::Vault::owner_presence`] at the word's importance. A
//! word is as important as the act it approves
//! (`ask_guard::approved_act_in`): an approving option of an ask that asks a
//! person is important, and the device asks for the person. Every other word
//! is ordinary and asks nobody: a denial, a judgment, a word with no approving
//! route. The key still signs an ordinary word, because an ask
//! that asks one party admits a denial, too, only under that party's proof.
//!
//! The door reads before it asks. The answerer's own reads run first
//! ([`crate::Vault::owner_device_answerer`]), authenticating the person as the
//! proof's mint authenticates them, with no key in the proof. Then one read
//! transaction runs every check the word's admission makes
//! (`ask_record::check_word`), so a word the admission refuses
//! raises no prompt. For an approving word the same read makes the checks
//! the approved act's own writer makes on the cut before its first write
//! (`ask_guard::approved_act_stands_in`: an attendee ask's named contact
//! still lives, a training offer's model switch still binds), so nobody is
//! asked to approve an act the settlement then refuses; it refuses such a
//! word also where the word would not have cut the ask, which the write
//! would have recorded. The read checks the latest human word on an approving
//! repeat, including its answer unit on a bound ask, and checks silent member
//! TASKs and pending waiter traps before asking. A `proceed` word releasing a
//! durable verb hook asks for the person; after an ask has its result, and on
//! an ask its settlement here cuts stale, which decides nothing, only a
//! code consent word can still ask, and only while its wait still takes its
//! first answer. The read never asks whether an owner key
//! proves now: a key that rests under a device PIN proves only inside the
//! window the ask's PIN step opens, so the mint answers that after the ask.
//! The write admits the word under the signed proof, derives the importance
//! again and refuses a rise ([`WordProof::refuse_risen_importance_in`]).
//!
//! The door holds no transaction, no device PIN step and no lock of the vault
//! while the prompt is up; the word keeps its task-work turn, one of the line's
//! bound. The presence gate serializes its own prompts.
//!
//! A proof a host bound, generated code, a room turn and every surface that
//! is no owner device sign nothing here, so they ask nobody.

use std::borrow::Cow;

use super::ask_record::{self, AskGroup, WordStanding};
use super::{TaskAskDecide, TaskAskHandle, TaskAskWord, ask_guard, ask_settlement};
use crate::authority::OwnerProofGround;
use crate::consent::AuthenticatedOwner;
use crate::error::Error;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::store::GateDecisionId;
use crate::world_keys::{OwnerActImportance, OwnerPresenceWitness};
use crate::{EntityId, Vault};

/// The proof one ask word is admitted and cut under, with the ground an
/// owner key signed it on.
pub(super) struct WordProof<'memory> {
    owner: Option<Cow<'memory, AuthenticatedOwner>>,
    /// The ground of a proof this install's owner key signed for the word;
    /// `None` for a proof the host bound and for a word with no proof.
    ground: Option<OwnerProofGround>,
}

impl WordProof<'_> {
    /// The live proof, when the word carries one.
    pub(super) fn owner(&self) -> Option<&AuthenticatedOwner> {
        self.owner.as_deref()
    }

    /// Refuses `word` where it approves an act and the person at this device
    /// was asked for an ordinary word: the write derives the importance the
    /// read derived, on its own view of the ask `id`, after the admission's
    /// refusals. A proof no owner key signed here has no ground and refuses
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`Error::ConcurrentWrite`] on a rise; storage errors.
    pub(super) fn refuse_risen_importance_in(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        group: &AskGroup,
        word: &TaskAskWord,
    ) -> crate::Result<()> {
        let Some(ground) = &self.ground else {
            return Ok(());
        };
        let (importance, _) = word_presence_in(vault, txn, id, group, word)?;
        ground.refuse_risen_importance(importance)
    }
}

/// How much `word` on the ask `id` moves, and the line the device's prompt
/// shows for it: important with its kind's line where it approves an act,
/// else ordinary, which shows no prompt.
fn word_presence_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    word: &TaskAskWord,
) -> crate::Result<(OwnerActImportance, &'static str)> {
    Ok(
        match ask_guard::approved_act_in(vault, txn, id, group, word)? {
            Some(reason) => (OwnerActImportance::Important, reason),
            None => (OwnerActImportance::Ordinary, ""),
        },
    )
}

impl Memory<'_> {
    /// The proof `word` on `handle`'s ask carries on this surface: the one
    /// the host bound for a direct request
    /// ([`Self::answer_owner_proof`]), else, on a surface that answers as
    /// this install's owner device, the one its owner key signs for this
    /// word (UC-05 PR 2b) after the word's read and the presence check this
    /// module's head describes. Generated code and a room turn carry none
    /// either way.
    ///
    /// # Errors
    ///
    /// On an owner-device surface: every refusal of the word's admission,
    /// before anyone is asked; the presence check's
    /// ([`crate::Vault::owner_presence`]); then the mint's
    /// ([`crate::Vault::authenticate_owner_device`]).
    pub(super) fn word_owner_proof(
        &self,
        handle: &TaskAskHandle,
        word: &TaskAskWord,
    ) -> MemoryResult<WordProof<'_>> {
        if !self.owner_device_key_proves_words() {
            return Ok(WordProof {
                owner: self.answer_owner_proof().map(Cow::Borrowed),
                ground: None,
            });
        }
        let (importance, reason) = self.owner_device_word_read(handle, word)?;
        let witness = self.vault().owner_presence(importance, reason)?;
        self.owner_device_word_proof_on(&witness)
    }

    /// The checks [`Self::tasks_answer`] meets on an owner-device surface
    /// before it asks for the person, then the key's: `Ok` when the word
    /// would be admitted now. A preview signs nothing and asks nobody
    /// (`can({verb})`, FIX [UI-GATE-PREVIEW]).
    ///
    /// # Errors
    ///
    /// The admission's, then
    /// [`crate::error::RecordError::OwnerKeyRequired`] where no owner key of
    /// this install proves now.
    pub(super) fn owner_device_word_admission(
        &self,
        handle: &TaskAskHandle,
        word: &TaskAskWord,
    ) -> MemoryResult<()> {
        self.owner_device_word_read(handle, word)?;
        self.vault().require_ask_word_proof_key()?;
        Ok(())
    }

    /// Whether this install's owner key signs the proof of a word this
    /// surface gives: an owner-device surface with no proof bound by a host,
    /// outside generated code and room turns.
    pub(super) fn owner_device_key_proves_words(&self) -> bool {
        self.answer_owner_proof().is_none()
            && !self.writes_generated()
            && self.room_turn().is_none()
            && self.is_owner_device_surface()
    }

    /// The read an owner-device word gets before anyone is asked: the
    /// person's own checks, the actor's, the ask's, and the word's whole
    /// admission, in the order the write meets them; then the word's
    /// importance with its prompt line. For an approving word it also reads
    /// the act, any selected repeat's bound answer unit, the silent member
    /// TASKs, and pending waiter traps. Nothing is recorded or signed.
    fn owner_device_word_read(
        &self,
        handle: &TaskAskHandle,
        word: &TaskAskWord,
    ) -> MemoryResult<(OwnerActImportance, &'static str)> {
        let answerer = self
            .vault()
            .owner_device_answerer(self.actor(), GateDecisionId::now())?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        self.verify_actor_write_in_txn(&txn)?;
        let group = self
            .ask_group_named_in(&txn, handle.group_ref)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
        let standing = ask_record::check_word(
            self.vault(),
            &txn,
            handle.group_ref,
            &group,
            self.write_actor(),
            word,
            Some(&answerer),
            self.vault().store.clock.now_recorded_at(),
        )
        .unwrap_or(WordStanding::New);
        let vault = self.vault();
        let id = handle.group_ref;
        let actor = self.actor();
        let (importance, reason) = word_presence_in(vault, &txn, id, &group, word)?;
        if importance == OwnerActImportance::Important {
            let selected = ask_settlement::word_a_cut_selects_in(
                vault, &txn, id, &group, actor, word, standing,
            )?;
            ask_guard::approved_act_stands_in(vault, &txn, id, &group, word, &selected)?;
            if matches!(standing, WordStanding::GivenBefore)
                && group.effective.what.outcome_binding.is_some()
            {
                // A First decision binds the selected word's unit; a quorum
                // decision binds the question unit. A collection binds neither.
                let unit = match &group.effective.decide {
                    Some(TaskAskDecide::First) => Some(selected.result_ref),
                    Some(TaskAskDecide::All { .. } | TaskAskDecide::AtLeast { .. }) => {
                        Some(group.effective.what.reference.entity_ref())
                    }
                    None => None,
                };
                if let Some(unit) = unit {
                    crate::llm::decision::questions::validate_task_answer_unit(
                        vault,
                        &txn,
                        ask_record::entity(&group.owner)?,
                        actor,
                        unit,
                    )?;
                }
            }
            ask_settlement::cut_reads_in(vault, &txn, id, &group, actor)?;
        }
        Ok((importance, reason))
    }

    /// The proof this install's owner key signs for one word on the ground
    /// of `witness`.
    fn owner_device_word_proof_on(
        &self,
        witness: &OwnerPresenceWitness,
    ) -> MemoryResult<WordProof<'_>> {
        let ground = OwnerProofGround::witnessed(witness);
        let owner =
            self.vault()
                .authenticate_owner_device(self.actor(), GateDecisionId::now(), &ground)?;
        Ok(WordProof {
            owner: Some(Cow::Owned(owner)),
            ground: Some(ground),
        })
    }

    /// [`Self::tasks_answer`] on an owner-device surface, with the word's
    /// proof signed on a presence check made at `importance` in place of
    /// the importance the word's read derives. Test door only
    /// (`test_doors::ask_word_presence`): it pins that the write refuses a
    /// word that approves an act under a proof signed for an ordinary word.
    /// No verb-hook session answers here.
    ///
    /// # Errors
    ///
    /// The presence check's, the mint's, then the write's, as
    /// `tasks_answer` answers them.
    #[cfg(oneiron_test_support)]
    pub(crate) fn tasks_answer_asked_as(
        &self,
        handle: &TaskAskHandle,
        word: &TaskAskWord,
        importance: OwnerActImportance,
    ) -> MemoryResult<super::TaskAskAnswer> {
        if !self.has_task_work_turn() {
            return self
                .task_work_memory()
                .tasks_answer_asked_as(handle, word, importance);
        }
        self.require_answers_in_own_name()?;
        let witness = self
            .vault()
            .owner_presence(importance, "answer an ask in a test")?;
        let proof = self.owner_device_word_proof_on(&witness)?;
        self.answer_under(handle, word, &proof)
    }
}
