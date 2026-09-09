//! Resumable onboarding runner, house-name rename, and roster read.

use super::*;

impl Vault {
    /// Onboards one member into a workspace, idempotently and resumably.
    ///
    /// The writer needs an admin federation grant over the target vault;
    /// `mailbox_owner` authenticates the member PERSON, independently of the writer.
    /// Requested/PendingFulfillment stay resumable. External fulfillment requires
    /// policy-gated Bind ([`Vault::apply_channel_identity_lifecycle_intent`]), then
    /// trusted manual/API completion ([`Vault::fulfill_channel_identity`]). Onboarding
    /// does neither. Exact replay verifies live grants without writes; different
    /// inputs under the same id fail with [`Error::InvalidClaimBody`].
    pub fn onboard_workspace_member(
        &self,
        intent: MemberOnboardingIntent,
        authenticated_writer: &WriteActor,
        mailbox_owner: Option<&AuthenticatedOwner>,
    ) -> Result<MemberOnboardingOutcome> {
        self.onboard_workspace_member_halting_after(
            intent,
            authenticated_writer,
            mailbox_owner,
            MemberOnboardingStep::Complete,
        )?
        .ok_or(Error::InvariantViolation(
            "workspace onboarding halted before Complete",
        ))
    }

    /// [`Vault::onboard_workspace_member`], stopping after `halt_after`.
    ///
    /// Crate-internal because "stop half way" is not a product verb — it is how
    /// the resume path is exercised without staging a real crash. `None` means
    /// the run halted before [`MemberOnboardingStep::Complete`], leaving a
    /// journal a later call resumes from.
    pub(super) fn onboard_workspace_member_halting_after(
        &self,
        intent: MemberOnboardingIntent,
        authenticated_writer: &WriteActor,
        mailbox_owner: Option<&AuthenticatedOwner>,
        halt_after: MemberOnboardingStep,
    ) -> Result<Option<MemberOnboardingOutcome>> {
        intent.validate()?;
        if intent.delegated_mailbox.is_some() {
            require_mailbox_owner(&intent, mailbox_owner)?;
        }
        require_workspace_authority(
            self,
            intent.workspace.workspace_vault_id,
            authenticated_writer,
        )?;

        let digest = intent_digest(&intent)?;
        let key = onboarding_key(&intent.onboarding_id);
        let mut done = match read_journal(self, &key)? {
            Some(record) => {
                if record.intent_digest != digest {
                    return Err(invalid(
                        "onboarding_id was already used with different inputs",
                    ));
                }
                if let Some(completed_at) = record.completed_at {
                    let revision = verify_mailbox_revision(self, &intent, mailbox_owner)?;
                    with_workspace_authority(
                        self,
                        intent.workspace.workspace_vault_id,
                        authenticated_writer,
                        |_| require_mailbox_revision(self, revision),
                    )?;
                    return Ok(Some(outcome_of(&intent, completed_at)));
                }
                record.step.rank()
            }
            None => {
                validate_workspace_references(self, &intent)?;
                if read_preset(self, &intent.workspace.workspace_ref)?
                    .is_some_and(|stored| stored != intent.workspace)
                {
                    return Err(invalid(
                        "workspace_ref is already bound to a different workspace preset",
                    ));
                }
                write_journal(
                    self,
                    &key,
                    &intent,
                    &OnboardingJournal {
                        intent_digest: digest,
                        step: MemberOnboardingStep::Started,
                        completed_at: None,
                    },
                    authenticated_writer,
                    mailbox_owner,
                )?;
                0
            }
        };

        for step in ONBOARDING_STEPS {
            if step.rank() <= done {
                continue;
            }
            require_workspace_authority(
                self,
                intent.workspace.workspace_vault_id,
                authenticated_writer,
            )?;
            self.run_onboarding_step(step, &intent, authenticated_writer, mailbox_owner)?;
            let completed_at =
                (step == MemberOnboardingStep::Complete).then_some(intent.occurred_at);
            write_journal(
                self,
                &key,
                &intent,
                &OnboardingJournal {
                    intent_digest: digest,
                    step,
                    completed_at,
                },
                authenticated_writer,
                mailbox_owner,
            )?;
            done = step.rank();
            if step == halt_after {
                break;
            }
        }

        if done < MemberOnboardingStep::Complete.rank() {
            return Ok(None);
        }
        Ok(Some(outcome_of(&intent, intent.occurred_at)))
    }

    /// Runs one pinned step. Each arm is individually idempotent, so a resumed
    /// run that re-executes a partially applied step adds nothing.
    pub(super) fn run_onboarding_step(
        &self,
        step: MemberOnboardingStep,
        intent: &MemberOnboardingIntent,
        writer: &WriteActor,
        mailbox_owner: Option<&AuthenticatedOwner>,
    ) -> Result<()> {
        match step {
            MemberOnboardingStep::Started => Ok(()),
            MemberOnboardingStep::Validated => establish_workspace(self, intent, writer),
            MemberOnboardingStep::ActorLinked => link_member_actor(self, intent, writer),
            MemberOnboardingStep::MemberGranted => grant_member_bundle(self, intent, writer),
            MemberOnboardingStep::CompanionBorn => {
                birth_companion(self, intent, intent.required_companion()?, writer)
            }
            MemberOnboardingStep::MailboxBound => match &intent.delegated_mailbox {
                Some(mailbox) => {
                    bind_delegated_mailbox(self, intent, mailbox, writer)?;
                    let owner = require_mailbox_owner(intent, mailbox_owner)?;
                    self.apply_channel_identity_autonomy(&mailbox.autonomy, owner)?;
                    self.verify_channel_identity_autonomy(&mailbox.autonomy, owner)?;
                    Ok(())
                }
                None => Ok(()),
            },
            MemberOnboardingStep::Complete => {
                record_roster_member(self, intent, writer, mailbox_owner)
            }
        }
    }

    /// Changes only the runtime house name. `None` restores the venture name.
    ///
    /// The seeded agent definition and completed onboarding outcomes are not
    /// rewritten. Authority and the preset compare-and-set share one write txn.
    pub fn set_workspace_house_display_name(
        &self,
        workspace_ref: &str,
        display_name: Option<String>,
        authenticated_writer: &WriteActor,
    ) -> Result<()> {
        validate_name(
            workspace_ref,
            "workspace_ref must be 1..=256 bytes and contain no NUL",
        )?;
        if let Some(name) = &display_name {
            validate_name(
                name,
                "house_display_name must be 1..=256 bytes and contain no NUL",
            )?;
        }
        let mut preset = read_preset(self, workspace_ref)?.ok_or(Error::EntityNotFound)?;
        let prior = encode_value(&preset_value(&preset))?;
        let vault_id = preset.workspace_vault_id;
        preset.house_display_name = display_name;
        let next = encode_value(&preset_value(&preset))?;
        let key = preset_key(workspace_ref);
        self.with_write_txn(|txn| {
            require_workspace_authority_in_txn(self, txn, vault_id, authenticated_writer)?;
            if self.store.vault_meta.get(txn, &key)?.as_deref() != Some(prior.as_slice()) {
                return Err(invalid(
                    "workspace preset changed during rename; retry from current state",
                ));
            }
            if prior != next {
                self.store.vault_meta.put(txn, &key, &next)?;
            }
            Ok(())
        })
    }

    /// The personas visible in `workspace_ref`: the house mind, then each
    /// principal's companion, as separate rows under one shared presence.
    ///
    /// An unknown `workspace_ref` is an empty roster, not an error — asking
    /// about a workspace nobody has onboarded into yet is a legal question.
    pub fn workspace_roster(
        &self,
        workspace_ref: &str,
        at: u64,
    ) -> Result<Vec<WorkspaceRosterEntry>> {
        let Some(preset) = read_preset(self, workspace_ref)? else {
            return Ok(Vec::new());
        };

        let mut entries = vec![house_mind_entry(self, &preset, at)?];
        let mut prefix = roster_member_prefix(workspace_ref);
        prefix.push(ROSTER_KEY_SEPARATOR);

        let rows = {
            let rtxn = self.store.env.read_txn()?;
            let mut rows = Vec::new();
            for entry in self.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
                let (_, raw) = entry?;
                rows.push(decode_roster_member_row(&raw)?);
            }
            rows
        };

        for row in rows {
            entries.push(companion_entry(self, &preset, &row, at)?);
        }
        Ok(entries)
    }
}
