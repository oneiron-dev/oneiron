//! Folds the vault's signed "Learn from my conversations" setting (FIX
//! 5502 owner rulings, OF-420), and the doors that read and set it.
//!
//! The owner's rulings (10-19, "my casa my rules"): one setting per vault,
//! set by its admin and off until the admin turns it on. While it is on,
//! everything in the vault counts, people, agents and guests alike, and
//! private worlds never do. The admin may also let people opt out
//! (`allow_opt_out`, off unless turned on): then each person's own "leave my
//! messages out" ([`super::conversation_training`]) counts. Turning the
//! setting off stops new sharing; it withdraws nothing already shared.
//!
//! The setting keeps the shared owner-choice register
//! ([`super::owner_choice`]) under its own revision domain, on the vault's
//! one frontier: a choice supersedes exactly the live choices its parents
//! carry, and concurrent different choices conflict. No choice, and a
//! conflict, read as off, opt-outs not allowed. A choice this install does
//! not count at full strength counts as not made. Choices are main-log
//! entries, so every machine the owner admits folds them.
//!
//! The writer ([`Vault::set_conversation_learning`]) revalidates the proof's
//! person in its own transaction and requires an admin there: the vault's
//! live owner, or, in a shared vault, an Owner or Admin whose live,
//! activated vault grant holds the workspace-settings power (the
//! `work_companion` writer's rule). A room's admin, a bare write token and an
//! agent are none. The reader ([`Vault::conversation_learning_view`]) needs
//! a live member, delegate or guest of the vault, and shows them who set it;
//! a read grants no transcript and no one's receipt.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::federation::SharedVaultWrite;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::{TimeRange, Vault, WriteActor};

use super::machine_standing::InstallCounted;
use super::owner_choice::{
    FoldedOwnerChoice, OwnerChoiceOp, OwnerChoiceState, folded_owner_choice, live_choices_by,
    owner_choice_landing,
};
use super::*;

/// What one setting choice states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct VaultTrainingChoice {
    /// Whether the vault's conversations count for training.
    pub(crate) on: bool,
    /// Whether a person's own opt-out counts.
    pub(crate) allow_opt_out: bool,
}

/// The vault's setting choices in one fold state.
pub(super) type ConversationTrainingVaultState = OwnerChoiceState<VaultTrainingChoice>;

/// This install cannot carry the choice: it has no machine identity or
/// install key, or no live profile of it stands under that key. No roster
/// key, the host root included, carries an act (FIX 2222).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the conversation learning setting";
/// The choice would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one conversation \
                              learning setting may name; nothing was written";
/// The supplied `seen` is not the current revision.
const STALE: &str = "the conversation learning setting changed since it was read";
/// The fold did not count the signed choice here: it never reports success.
const NOT_COUNTED: &str = "this install's fold does not count the conversation learning setting";
/// The setting is the vault admin's.
const NOT_ADMIN: &str = "only the vault's owner, or a shared vault's owner or admin holding the \
                         workspace-settings power, sets conversation learning";
/// The setting is read by the vault's members, delegates and guests.
const NOT_READER: &str =
    "only a live member, delegate or guest of this vault reads conversation learning";
/// Who set it, when their PERSON row carries no name or cannot be read.
const UNNAMED_ADMIN: &str = "the vault's admin";

/// The line a member's surface shows while the setting is on (owner rulings
/// 10-19 21:0x and 21:1x): the words before and after the admin's name, by
/// whether people may opt out. The only place the wording lives.
const fn training_line_wording(allow_opt_out: bool) -> (&'static str, &'static str) {
    if allow_opt_out {
        (
            "Training is on. Set by ",
            ". You can leave your own messages out.",
        )
    } else {
        ("Training is on. Set by ", ".")
    }
}

/// The vault's folded setting, as this install counts it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FoldedConversationTrainingVault {
    /// The setting choices.
    pub(crate) choices: FoldedOwnerChoice<VaultTrainingChoice>,
}

impl FoldedConversationTrainingVault {
    /// The choice in force, unless the live choices conflict.
    fn in_force(&self) -> Option<&VaultTrainingChoice> {
        self.choices
            .selected()
            .filter(|_| self.choices.conflict.is_empty())
    }

    /// Whether the setting is on: an on in force with no conflict. No
    /// choice, an off and a conflict all read as off.
    pub(crate) fn on(&self) -> bool {
        self.in_force().is_some_and(|choice| choice.on)
    }

    /// Whether a person's own opt-out counts now: the setting is on and lets
    /// people opt out.
    pub(crate) fn allows_opt_out(&self) -> bool {
        self.in_force()
            .is_some_and(|choice| choice.on && choice.allow_opt_out)
    }

    /// The setting revision: what a surface shows and passes back as
    /// `seen`, zero while no choice is live.
    pub(crate) fn revision(&self) -> PolicyRevision {
        PolicyRevision(
            self.choices
                .revision(CONVERSATION_TRAINING_VAULT_REVISION_CONTEXT),
        )
    }

    /// Whether the live setting choices conflict.
    pub(crate) fn conflicted(&self) -> bool {
        !self.choices.conflict.is_empty()
    }

    /// The authority entry of the choice in force; `None` while none counts
    /// or the choices conflict.
    pub(crate) fn act(&self) -> Option<AuthorityEntryHash> {
        self.choices
            .in_force
            .as_ref()
            .filter(|_| self.choices.conflict.is_empty())
            .map(|head| head.act)
    }

    /// Whether a live choice rests on how this install counts machines.
    pub(super) fn rests_on_counting(&self) -> bool {
        !self.choices.live.is_empty()
    }

    /// The live choices `machine` carried, for its next profile revision's
    /// acknowledged set ([`super::world_privacy::live_edits_by`]).
    pub(super) fn live_choices_by(
        &self,
        machine: EntityId,
    ) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
        live_choices_by(&self.choices, machine)
    }
}

/// The `ConversationTrainingVaultSet` transition ([`owner_choice_landing`]),
/// under the setting's revision domain, on the vault's frontier.
pub(super) fn apply_conversation_training_vault(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    set: &ConversationTrainingVaultSet,
    hash: AuthorityEntryHash,
    counting: (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) -> std::result::Result<(), AuthorityFoldIssue> {
    let choice = VaultTrainingChoice {
        on: set.on,
        allow_opt_out: set.allow_opt_out,
    };
    let op = OwnerChoiceOp {
        act: &set.act,
        machine: set.machine,
        choice: Some(&choice),
        context: CONVERSATION_TRAINING_VAULT_REVISION_CONTEXT,
    };
    let landing = owner_choice_landing(
        state,
        &state.conversation_training_vault,
        entry,
        op,
        hash,
        counting,
        restriction_only,
    )?;
    state.conversation_training_vault.land(landing);
    Ok(())
}

/// The fold's view of the setting, under this install's pin and holds.
pub(super) fn folded_conversation_training_vault(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> FoldedConversationTrainingVault {
    FoldedConversationTrainingVault {
        choices: folded_owner_choice(state, &state.conversation_training_vault, pin, counted),
    }
}

/// The vault's setting, as a member's or guest's surface shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConversationLearningView {
    /// Whether the setting is on now. No choice, an off and a conflict read
    /// as off.
    pub on: bool,
    /// Whether people may leave their own messages out now.
    pub allow_opt_out: bool,
    /// The revision to present back as `seen`: the digest of the vault's
    /// live setting choices, zero when none.
    pub revision: PolicyRevision,
    /// Whether the live setting choices conflict. While they do, it reads
    /// as off until a choice that saw them all supersedes them.
    pub conflicted: bool,
    /// The authority entry of the choice in force; `None` while none counts
    /// or the choices conflict.
    pub act: Option<AuthorityEntryHash>,
    /// The admin's PERSON whose act the choice in force is; `None` while
    /// none counts, or its row is not stored here.
    pub set_by: Option<EntityId>,
    /// The one read-only line a member's surface shows while it is on;
    /// `None` while off.
    pub line: Option<String>,
}

impl Vault {
    /// The vault's setting, for a live member, delegate or guest.
    ///
    /// # Errors
    /// A refusal when the proof is no longer a live member, delegate or
    /// guest of this vault; storage faults, and history this vault lacks, as
    /// the fold reads them.
    pub fn conversation_learning_view(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<ConversationLearningView> {
        let txn = self.store.env.read_txn()?;
        let person = owner.revalidate_person_in_txn(self, &txn)?;
        if !self.conversation_learning_reader_in_txn(&txn, person)? {
            return Err(authority_refused(NOT_READER));
        }
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        self.setting_view_in_txn(&txn, &fold)
    }

    /// The vault's setting as the vault itself reads it, for the status its
    /// host reports to a supervisor (FIX 5575): one read transaction, no
    /// person, no act and no writer. It grants nothing, and the reader rule
    /// above still decides who reads it through a door.
    ///
    /// # Errors
    /// Storage faults, and history this vault lacks, as the fold reads them.
    pub fn conversation_learning_status(&self) -> Result<ConversationLearningView> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        self.setting_view_in_txn(&txn, &fold)
    }

    /// The vault's admin sets the vault's training setting from `surface`
    /// (audit only): `on`, and whether people may opt out
    /// (`allow_opt_out`). `seen` is the revision their surface showed them
    /// ([`ConversationLearningView::revision`]); `None` takes the current
    /// one. The choice names the main-log heads alone, whose fold carries
    /// this install's standing rows and every live setting choice (FIX
    /// 4987), so it supersedes all of them, and lands atomically or not at
    /// all. Turning it off stops new sharing; it withdraws nothing already
    /// shared.
    ///
    /// # Errors
    /// A refusal when the proof is no longer a live person of this vault, or
    /// is no admin of it; [`Error::ConcurrentWrite`] when `seen` is not the
    /// current revision; [`Error::InvalidConfig`] when the choice would name
    /// more parents than one entry may;
    /// [`crate::error::RecordError::AuthorityRefused`] when this install
    /// cannot carry the choice or its fold does not count it.
    pub fn set_conversation_learning(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        on: bool,
        allow_opt_out: bool,
        seen: Option<PolicyRevision>,
    ) -> Result<ConversationLearningView> {
        let mut txn = self.store.env.write_txn()?;
        let (_, view, _) = self.set_conversation_learning_in_txn(
            &mut txn,
            owner,
            surface,
            on,
            allow_opt_out,
            seen,
        )?;
        txn.commit()?;
        // Its watchers re-read it now: a managed host reports it to its
        // supervisor (FIX 5575).
        self.store.notify_proactivity_changes();
        Ok(view)
    }

    /// [`Vault::set_conversation_learning`] in the caller's writing
    /// transaction, with every one of its checks: the proof's person
    /// revalidated, the admin rule, `seen`, the carrier, the signature and
    /// the fold counting the choice. It returns the signed choice's authority
    /// entry, the setting's view after it and the vault seconds the entry was
    /// signed at (FIX 7712), and commits nothing: the caller commits, then
    /// tells the setting's watchers (`notify_proactivity_changes`).
    ///
    /// # Errors
    /// As [`Vault::set_conversation_learning`]; the caller drops the
    /// transaction on any of them.
    pub(crate) fn set_conversation_learning_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        on: bool,
        allow_opt_out: bool,
        seen: Option<PolicyRevision>,
    ) -> Result<(AuthorityEntryHash, ConversationLearningView, u64)> {
        let person = owner.revalidate_person_in_txn(self, txn)?;
        self.require_learning_admin_in_txn(txn, person)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        // Revision integrity (mesh contract §4): the admin chose on what the
        // surface showed them.
        let current = fold.conversation_training_vault.revision();
        if seen.is_some_and(|seen| seen != current) {
            return Err(Error::ConcurrentWrite(STALE));
        }
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let public_key = key.verifying_key().to_bytes();
        if !owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            return Err(authority_refused(NO_CARRIER));
        }
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let joiner = FrontierSigner::Install(machine, &key);
        let fold = self
            .prepare_authority_frontier_in_txn(txn, &fold, joiner, MAX_PARENTS)?
            .unwrap_or(fold);
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(&fold, &signer)?;
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(Error::InvalidConfig(TOO_MANY_HEADS.to_owned()));
        }
        let act = OwnerAct::by_owner(
            person,
            OwnerActKind::ConversationTraining,
            conversation_training_vault_target(&vault_id)?,
            surface,
            current.0,
        );
        let now = self.instant_in_txn(txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &key,
            seq,
            parents,
            AuthorityOp::ConversationTrainingVaultSet(ConversationTrainingVaultSet {
                act,
                machine,
                on,
                allow_opt_out,
            }),
            now,
        )?;
        let entry_hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !after
            .conversation_training_vault
            .choices
            .live
            .contains_key(&entry_hash)
            || after.install.held_back.contains(&entry_hash)
        {
            return Err(authority_refused(NOT_COUNTED));
        }
        let view = self.setting_view_in_txn(txn, &after)?;
        Ok((entry_hash, view, now))
    }

    /// The admin's PERSON whose act the setting choice in force on `fold` is,
    /// read from its stored row in `txn`; `None` while no choice counts, or
    /// when its row is not stored here (an adopted image covers it).
    ///
    /// # Errors
    /// Storage faults, and a stored row that does not decode.
    pub(crate) fn conversation_learning_set_by_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
    ) -> Result<Option<EntityId>> {
        let Some(act) = fold.conversation_training_vault.act() else {
            return Ok(None);
        };
        let id = authority_log_entity_id_from_hash(&act)?;
        let Some(raw) = self
            .store
            .port_entity_record(txn, &id)?
            .map(|row| row.encode())
        else {
            return Ok(None);
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_AUTHORITY_LOG)
        {
            return Ok(None);
        }
        let entry = decode_authority_log_entry_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        Ok(match &entry.op {
            AuthorityOp::ConversationTrainingVaultSet(set)
                if authority_entry_hash(&entry)? == act =>
            {
                Some(set.act.owner)
            }
            _ => None,
        })
    }

    /// Whether `person` reads the setting: a live PERSON who is the vault's
    /// live owner, holds a live member or guest standing in this shared vault
    /// (`Vault::membership_standing_in_txn`), or holds a live Delegate grant
    /// over it (`Vault::delegate_standing_in_txn`).
    ///
    /// # Errors
    /// Storage faults: never a reader.
    fn conversation_learning_reader_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
    ) -> Result<bool> {
        if !crate::consent::person_is_live_in_txn(self, txn, &person)? {
            return Ok(false);
        }
        if crate::policy_model::is_live_vault_owner_in_txn(self, txn, &person)? {
            return Ok(true);
        }
        let Some(creation) = self.shared_vault_creation_in_txn(txn)? else {
            return Ok(false);
        };
        if self
            .membership_standing_in_txn(txn, creation.vault_id, &person)?
            .is_some()
        {
            return Ok(true);
        }
        self.delegate_standing_in_txn(txn, creation.vault_id, &person)
    }

    /// The setting's view on `fold`, its line naming who set it.
    fn setting_view_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
    ) -> Result<ConversationLearningView> {
        let setting = &fold.conversation_training_vault;
        let set_by = self.conversation_learning_set_by_in_txn(txn, fold)?;
        let line = if setting.on() {
            let name = match set_by {
                Some(admin) => crate::reaction::person_name_in(self, txn, admin)?,
                None => None,
            };
            let (before, after) = training_line_wording(setting.allows_opt_out());
            let name = name.as_deref().unwrap_or(UNNAMED_ADMIN);
            Some(format!("{before}{name}{after}"))
        } else {
            None
        };
        Ok(ConversationLearningView {
            on: setting.on(),
            allow_opt_out: setting.allows_opt_out(),
            revision: setting.revision(),
            conflicted: setting.conflicted(),
            act: setting.act(),
            set_by,
            line,
        })
    }

    /// The setting's admin rule, in the writing transaction: `person` is the
    /// vault's live owner, or, in a shared vault, holds the
    /// workspace-settings power over it as an Owner or Admin.
    pub(crate) fn require_learning_admin_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
    ) -> Result<()> {
        if crate::policy_model::is_live_vault_owner_in_txn(self, txn, &person)? {
            return Ok(());
        }
        let Some(creation) = self.shared_vault_creation_in_txn(txn)? else {
            return Err(authority_refused(NOT_ADMIN));
        };
        self.authorize_shared_vault_write_in_txn(
            txn,
            creation.vault_id,
            &WriteActor::new(person, EdgeActorClass::Human),
            &SharedVaultWrite::WorkspaceSettings,
        )
        .map_err(|error| match error {
            Error::Claim(ClaimError::ActorLacksClaimAuthority { .. }) => {
                authority_refused(NOT_ADMIN)
            }
            other => other,
        })
    }
}
