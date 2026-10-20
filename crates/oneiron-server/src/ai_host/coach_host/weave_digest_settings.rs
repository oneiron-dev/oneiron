//! The host's digest settings drafter (FIX 5609, ARCH-0026): the Coach's
//! model, on its own seat or else the chat seat, runs the
//! `weave-digest-settings` hub skill the job loads on its attempt, over one
//! owner's own digest record, and answers with at most one step. The engine
//! builds the record, checks the answer and files it under the owner's Grant
//! or as his proposal. With no seat, a refused call or no hub skill, the
//! engine's closed-form rule decides. The Coach pays for the calls.
use oneiron::claim::WeaveDigestSettingsDrafter;
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::{EntityId, Error, LlmMessageRole};

use super::super::code_fix::{HostModels, message};
use crate::server::SyncServer;

/// The purpose the drafts are metered and routed under.
const PURPOSE: &str = "coach_weave_digest_settings";
/// What one job's drafts may spend.
const BUDGET_UNITS: u64 = 1 << 20;
/// The skill's file the Coach runs; the owner's record goes as data.
const SKILL_FILE: &str = "SKILL.md";

/// One `coach.weave_digest_settings` job: the skill loaded on the attempt,
/// then each due owner's draft.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let drafter = HostDrafter {
        ready: ready(server, admitted, now)?,
    };
    server
        .vault()
        .run_coach_weave_digest_settings(admitted, &drafter, now)
}

/// The Coach's seat and the skill's instruction, the skill's revision and
/// the seat's model stamped on the attempt. `None` when the model cannot be
/// opened, no seat serves the Coach, or no hub skill loads: every draft is
/// then unavailable.
fn ready<'a>(
    server: &'a SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<Option<(HostModels<'a>, String)>> {
    let vault = server.vault();
    let run_id = format!(
        "coach-weave-digest-settings:{}",
        EntityId::from_bytes(*admitted.status.attempt.id.as_bytes())?.to_hex()
    );
    let models = match HostModels::open(server, run_id, PURPOSE, BUDGET_UNITS) {
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
        .map(|instruction| (models, instruction.to_owned())))
}

/// The Coach's model on the skill; nothing ready drafts nothing.
struct HostDrafter<'a> {
    ready: Option<(HostModels<'a>, String)>,
}

impl WeaveDigestSettingsDrafter for HostDrafter<'_> {
    fn draft(&self, brief: &str) -> oneiron::Result<Option<String>> {
        let Some((models, instruction)) = &self.ready else {
            return Ok(None);
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
