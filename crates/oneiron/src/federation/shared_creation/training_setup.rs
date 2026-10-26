//! A shared vault's one training question, asked once at setup (OF-420 T3).
//!
//! The owner's canon (DEC-0005): the admin is asked once at vault setup, and
//! the "Learn from my conversations" setting stays off until turned on;
//! private worlds never count. Creation records the question on its own
//! record, in its own write, and never waits on, asks for or refuses without
//! the answer. A counted admin choice of the setting already in force then
//! (terminal init's yes, say) answers it at once and is kept as it is.
//!
//! The question is durable: every read returns the same one until it is
//! answered, and no read consumes it. The admin's first answer signs the
//! setting through its own writer (a yes on, people not allowed to opt out;
//! a no off) and records the question answered in that same commit. The
//! same answer again signs nothing; a different one is refused as already
//! answered, and the setting's own door changes it from then on. Setup never
//! reopens. A counted admin choice made through that door after the question
//! was asked answers it too, as a view derived on each read (Engine ruling
//! 10-21): a setup answer never signs over an admin's choice.

use super::SHARED_VAULT_CREATION;
use crate::authority::{ActSurface, AuthorityEntryHash, AuthorityFold, authority_refused};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::world_keys::PolicyRevision;
use crate::{EntityId, Vault};

/// The question identity's own domain.
const QUESTION_CONTEXT: &str = "oneiron shared vault setup training question v1";
/// A vault never shared has no setup question.
const NOT_SHARED: &str = "this vault was never shared, so it has no setup training question";
/// The answer names another question.
const WRONG_QUESTION: &str = "question_ref is not this vault's setup training question";
/// Setup never reopens: the setting's own door changes it.
const ALREADY_ANSWERED: &str = "the vault's setup training question is already answered; change \
                                the setting through PUT /v1/owner/conversation-learning";
/// The setting's counted admin choices conflict; a setup answer would sign
/// over them.
const CONFLICTED: &str = "the conversation learning setting's counted choices conflict; settle \
                          them through PUT /v1/owner/conversation-learning";

/// Where a shared vault's setup training question stands, kept on its
/// creation record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedTrainingSetup {
    /// Asked and not yet answered. Every read returns this same question.
    Pending {
        /// The question's identity, derived from the vault id and its
        /// creator: never a fresh draw per read.
        question_ref: [u8; 32],
        /// When it was asked, in seconds on the vault's clock; zero when that
        /// clock could not be read at creation. A record of the asking only:
        /// which choice answers it is the fold's to say.
        created_at: u64,
    },
    /// Answered, through this question or by a counted admin choice of the
    /// setting.
    Answered {
        /// Whether the answer turned the setting on.
        on: bool,
        /// The admin who answered; `None` when the answering choice's row is
        /// not stored here.
        answered_by: Option<EntityId>,
        /// The authority entry of the setting choice that answered it.
        setting_act: AuthorityEntryHash,
        /// The setting revision that choice left.
        setting_revision: PolicyRevision,
        /// When it was answered, in seconds on the vault's clock.
        answered_at: u64,
    },
}

/// The setup training question as the vault's admin reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedTrainingSetupQuestion {
    /// Where it stands; `None` while the vault was never shared.
    pub setup: Option<SharedTrainingSetup>,
    /// The setting's current revision, which an answer presents back as
    /// `seen`.
    pub seen: PolicyRevision,
}

/// The vault admin's answer to the setup training question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedTrainingSetupAnswer {
    /// The pending question's `question_ref`.
    pub question_ref: [u8; 32],
    /// Yes or no, stated: yes turns the setting on with people not allowed
    /// to opt out, no signs it off.
    pub on: bool,
    /// The setting revision the admin's surface showed them.
    pub seen: PolicyRevision,
}

/// The setup question's identity: the vault id and its creator, under the
/// question's own domain. The creation record is written once per vault, so
/// this names one question per setup, and the same one once it is answered.
fn question_ref(vault_id: u64, owner_ref: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(QUESTION_CONTEXT);
    hasher.update(&vault_id.to_be_bytes());
    hasher.update(owner_ref.as_bytes());
    *hasher.finalize().as_bytes()
}

impl Vault {
    /// The setup question a shared vault's creation records, read in its
    /// writing transaction `txn`: answered when a counted admin choice of the
    /// setting is already in force, which keeps the setting as it is, else
    /// pending. It writes nothing and never refuses: a fold it cannot read
    /// records the question pending (Engine ruling 10-21), and an answer then
    /// meets the same fault.
    pub(super) fn pending_shared_training_setup(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        owner_ref: &str,
    ) -> SharedTrainingSetup {
        let created_at = self.instant_in_txn(txn).map_or(0, |instant| instant.secs());
        let pending = SharedTrainingSetup::Pending {
            question_ref: question_ref(vault_id, owner_ref),
            created_at,
        };
        let answered = self
            .authority_view_readonly_in_txn(txn)
            .and_then(|fold| self.answering_choice_in_txn(txn, &fold));
        match answered {
            Ok(Some(answered)) => answered,
            Ok(None) => pending,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "shared vault setup: the setting's fold was not read; its training question \
                     is recorded pending"
                );
                pending
            }
        }
    }

    /// The vault's setup training question, for its admin: where it stands,
    /// and the setting revision an answer presents back as `seen`. A pending
    /// question reads the same until it is answered, and reading it consumes
    /// nothing; a counted admin choice of the setting in force now reads as
    /// its answer. The proof is revalidated, and the admin
    /// rule judged, in this read's own transaction.
    ///
    /// # Errors
    /// A refusal when the proof is no longer a live person of this vault, or
    /// is no admin of it; storage faults, and history this vault lacks, as
    /// the fold reads them.
    pub fn shared_training_setup_status(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<SharedTrainingSetupQuestion> {
        let txn = self.store.env.read_txn()?;
        let person = owner.revalidate_person_in_txn(self, &txn)?;
        self.require_learning_admin_in_txn(&txn, person)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let setup = self
            .shared_vault_creation_in_txn(&txn)?
            .map(|creation| self.standing_setup_in_txn(&txn, &fold, &creation.training_setup))
            .transpose()?;
        Ok(SharedTrainingSetupQuestion {
            setup,
            seen: fold.conversation_training_vault.revision(),
        })
    }

    /// The vault's admin answers its setup training question from `surface`
    /// (audit only), in one writing transaction: the proof revalidated and
    /// the admin rule judged in it, their first answer signs the setting
    /// through its writer (a yes on, people not allowed to opt out; a no
    /// off), and the question is recorded answered in the same commit, after
    /// which the setting's watchers are told. The same answer again (the
    /// question and its `on`), from any admin and whatever its `seen`,
    /// returns the recorded one and signs nothing; so does an answer agreeing
    /// with the counted admin choice of the setting in force now. Setup never
    /// reopens.
    ///
    /// # Errors
    /// A refusal when the proof is no longer a live person of this vault or
    /// is no admin of it, when the vault was never shared, when the question
    /// is answered otherwise (the setting's own door changes it), or when the
    /// setting's counted choices conflict;
    /// [`Error::InvalidConfig`] when `question_ref` names another question;
    /// and the setting writer's own: [`Error::ConcurrentWrite`] for a stale
    /// `seen`, and a choice this install cannot carry or does not count. Any
    /// of them leaves the question pending and the setting as it was.
    pub fn answer_shared_training_setup(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        answer: &SharedTrainingSetupAnswer,
    ) -> Result<SharedTrainingSetupQuestion> {
        let mut txn = self.store.env.write_txn()?;
        let person = owner.revalidate_person_in_txn(self, &txn)?;
        self.require_learning_admin_in_txn(&txn, person)?;
        let Some(mut creation) = self.shared_vault_creation_in_txn(&txn)? else {
            return Err(authority_refused(NOT_SHARED));
        };
        if answer.question_ref != question_ref(creation.vault_id, &creation.owner_ref) {
            return Err(Error::InvalidConfig(WRONG_QUESTION.to_owned()));
        }
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let setting = &fold.conversation_training_vault;
        match self.standing_setup_in_txn(&txn, &fold, &creation.training_setup)? {
            SharedTrainingSetup::Answered { on, .. } if on != answer.on => {
                return Err(authority_refused(ALREADY_ANSWERED));
            }
            answered @ SharedTrainingSetup::Answered { .. } => {
                // A replay: the transaction is dropped with nothing signed.
                return Ok(SharedTrainingSetupQuestion {
                    setup: Some(answered),
                    seen: setting.revision(),
                });
            }
            // Counted choices in conflict are never signed over, whatever
            // display time their entries carry (FIX 7710, FIX 7711).
            SharedTrainingSetup::Pending { .. } => {
                if !setting.choices.conflict.is_empty() {
                    return Err(authority_refused(CONFLICTED));
                }
            }
        }
        let (setting_act, view, answered_at) = self.set_conversation_learning_in_txn(
            &mut txn,
            owner,
            surface,
            answer.on,
            false,
            Some(answer.seen),
        )?;
        creation.training_setup = SharedTrainingSetup::Answered {
            on: answer.on,
            answered_by: Some(person),
            setting_act,
            setting_revision: view.revision,
            answered_at,
        };
        SHARED_VAULT_CREATION.put(&self.store, &mut txn, &(), &creation)?;
        txn.commit()?;
        // Its watchers re-read the setting now, as after its own door
        // (FIX 5575).
        self.store.notify_proactivity_changes();
        Ok(SharedTrainingSetupQuestion {
            setup: Some(creation.training_setup),
            seen: view.revision,
        })
    }

    /// `recorded` as it stands on `fold`: a pending question reads as the
    /// answer of the counted admin choice of the setting in force now, as
    /// the fold counts it, never by its entry's display time (FIX 7710, FIX
    /// 7711): creation answered at once from any choice counted then, so one
    /// in force now counted only after; anything else as recorded. It
    /// derives and writes nothing, so a read never consumes the question.
    fn standing_setup_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        recorded: &SharedTrainingSetup,
    ) -> Result<SharedTrainingSetup> {
        if let SharedTrainingSetup::Pending { .. } = recorded
            && let Some(answered) = self.answering_choice_in_txn(txn, fold)?
        {
            return Ok(answered);
        }
        Ok(recorded.clone())
    }

    /// The counted admin choice of the setting in force on `fold`, as the
    /// answer it gives the setup question: `None` while no choice counts or
    /// the counted ones conflict. Only a choice that counts at full strength
    /// on this install is in force (the rule its holds read), so a held one
    /// never answers it.
    fn answering_choice_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
    ) -> Result<Option<SharedTrainingSetup>> {
        let setting = &fold.conversation_training_vault;
        let (Some(act), Some(head)) = (setting.act(), setting.choices.in_force.as_ref()) else {
            return Ok(None);
        };
        Ok(Some(SharedTrainingSetup::Answered {
            on: setting.on(),
            answered_by: self.conversation_learning_set_by_in_txn(txn, fold)?,
            setting_act: act,
            setting_revision: setting.revision(),
            answered_at: head.at,
        }))
    }
}
