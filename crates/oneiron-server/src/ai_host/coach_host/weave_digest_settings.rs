//! The host's digest settings drafter (FIX 5609, ARCH-0026): the Coach's
//! model, on its own seat or else the chat seat, runs the
//! `weave-digest-settings` hub skill the job loads on its attempt, over one
//! owner's own digest record, and answers with at most one step. The engine
//! builds the record, checks the answer and files it under the owner's Grant
//! or as his proposal. With no seat, a refused call or no hub skill, the
//! engine's closed-form rule decides. The Coach pays for the calls, each
//! owner's evaluation on a line of its own (FIX 6166).
use oneiron::claim::WeaveDigestSettingsDrafter;
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::{EntityId, Error, LlmMessageRole};

use super::super::code_fix::{HostModels, message};
use crate::server::SyncServer;

/// The purpose the drafts are metered and routed under.
const PURPOSE: &str = "coach_weave_digest_settings";
/// What one owner's evaluation's drafts may spend (FIX 6166): each owner a
/// job evaluates opens a line of its own, so an owner late in the job is
/// not left to the rule for what earlier owners spent. The server-wide and
/// payer ceilings still bind every line.
const OWNER_DRAFT_BUDGET_UNITS: u64 = 1 << 20;
/// The skill's file the Coach runs; the owner's record goes as data.
const SKILL_FILE: &str = "SKILL.md";

/// One `coach.weave_digest_settings` job: the skill loaded on the attempt,
/// then each due owner's draft.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let attempt = EntityId::from_bytes(*admitted.status.attempt.id.as_bytes())?;
    let drafter = HostDrafter {
        server,
        attempt,
        instruction: ready(server, attempt, admitted, now)?,
    };
    server
        .vault()
        .run_coach_weave_digest_settings(admitted, &drafter, now)
}

/// The line one owner's evaluation spends on: the job's attempt, the owner
/// and his settings generation (FIX 6166).
fn owner_run_id(attempt: EntityId, owner: EntityId, generation: u64) -> String {
    format!(
        "coach-weave-digest-settings:{}:{}:{generation}",
        attempt.to_hex(),
        owner.to_hex()
    )
}

/// The skill's instruction, the skill's revision and the Coach seat's model
/// stamped on the attempt, once per job. `None` when the model cannot be
/// opened, no seat serves the Coach, or no hub skill loads: every draft is
/// then unavailable.
fn ready(
    server: &SyncServer,
    attempt_ref: EntityId,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<Option<String>> {
    let vault = server.vault();
    // Whether the model opens at all, on the job's own line; each owner's
    // draft opens its own (FIX 6166).
    let models = match HostModels::open(
        server,
        format!("coach-weave-digest-settings:{}", attempt_ref.to_hex()),
        PURPOSE,
        OWNER_DRAFT_BUDGET_UNITS,
    ) {
        Ok(models) => models,
        // By kind only: an engine error can quote the vault.
        Err(error) => {
            tracing::debug!(kind = ?error.kind(), "the Coach's digest settings model did not open");
            return Ok(None);
        }
    };
    let Some(executor) = server
        .ai
        .model_runtime()
        .seat(models.coach())
        .map(|seat| seat.model.as_str().to_owned())
    else {
        return Ok(None);
    };
    let Some(skill) = vault.weave_digest_settings_skill()? else {
        return Ok(None);
    };
    let attempt = &admitted.status.attempt;
    let loaded = match vault.load_attempt_skill_pack(
        attempt.id,
        &skill,
        attempt.lease_owner.as_deref().unwrap_or_default(),
        attempt.attempt_count,
        &executor,
        now,
    ) {
        Ok(loaded) => loaded,
        // A retired, unapproved or deleted skill drafts nothing.
        Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(loaded
        .source_files
        .as_ref()
        .and_then(|files| files.iter().find(|file| file.path == SKILL_FILE))
        .and_then(|file| std::str::from_utf8(&file.content).ok())
        .map(str::to_owned))
}

/// The Coach's model on the skill, opened per owner's evaluation; nothing
/// ready drafts nothing.
struct HostDrafter<'a> {
    server: &'a SyncServer,
    attempt: EntityId,
    instruction: Option<String>,
}

impl WeaveDigestSettingsDrafter for HostDrafter<'_> {
    fn draft(
        &self,
        owner: EntityId,
        generation: u64,
        brief: &str,
    ) -> oneiron::Result<Option<String>> {
        let Some(instruction) = &self.instruction else {
            return Ok(None);
        };
        let models = match HostModels::open(
            self.server,
            owner_run_id(self.attempt, owner, generation),
            PURPOSE,
            OWNER_DRAFT_BUDGET_UNITS,
        ) {
            Ok(models) => models,
            // By kind only; this owner falls back to the rule.
            Err(error) => {
                tracing::debug!(kind = ?error.kind(), "the Coach's digest settings model did not open");
                return Ok(None);
            }
        };
        let answer = models.generate(
            models.coach(),
            vec![
                message(LlmMessageRole::System, instruction.clone()),
                message(LlmMessageRole::User, brief.to_owned()),
            ],
        );
        // A call the seat's ladder failed is a refused call: the rule decides.
        Ok(answer.unwrap_or_else(|error| {
            tracing::debug!(kind = ?error.kind(), "the Coach's digest settings call failed");
            None
        }))
    }
}
