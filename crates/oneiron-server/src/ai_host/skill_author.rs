//! The Coach's skill-edit author (OF-214). For each skill the engine's
//! optimizer selects, the Coach's seat drafts replacement instructions from
//! the skill's DEV-partition evidence, or declines. The held-out judge scores
//! what it drafts; nothing it writes reaches canon without the gate. The
//! Coach pays for the calls, on one budget per draft.
//!
//! On the optimizer's own attempt (`draft_on`) the Coach runs the shipped
//! `skill-optimize` workflow (ARCH-0079: each recipe is a workflow skill): it
//! loads the skill on that attempt, which pins its revision and the Coach's
//! model there, and its instructions are the recipe. A heal's repair, which
//! has no such attempt, drafts on the Coach's own instruction, and so does
//! the optimizer when the workflow does not load on its attempt. A heal's
//! repair also reads what the engine recorded of the failure's cause beside
//! its brief, as data (OF-418 L10). A model finding's issue whose recorded
//! links name a policy manifest or a config asks the Coach for a fix of it: a
//! delta against the exact base the engine bound, with why, filed for the
//! owner and never applied (OF-418 L3).
use std::sync::Weak;

use oneiron::attempt_queue::AttemptRecord;
use oneiron::dreamer_runner::maintenance::coach_diagnostic::{ProducerFixDraft, ProducerTarget};
use oneiron::dreamer_runner::maintenance::coach_heal::CoachHealAuthor;
use oneiron::dreamer_runner::maintenance::coach_learning::coach_improver_skill_id;
use oneiron::limit_ask::EngineLimit;
use oneiron::self_heal::HealEvidenceContext;
use oneiron::skill_optimize::{
    RejectedSkillEditReason, SKILL_OPTIMIZE_CALL_PURPOSE_NAME, SkillEditDraft, SkillOptimizeAuthor,
    SkillOptimizeBrief, union_source_rows,
};
use oneiron::{EntityId, Error, LlmMessageRole, Vault};
use serde::Deserialize;

use super::code_fix::{HostModels, message};
use crate::server::SyncServer;

/// The improver workflow's file the Coach runs as its recipe.
const SKILL_FILE: &str = "SKILL.md";
/// The Coach's author for one wake pass, on the server once it is bound.
pub(super) struct CoachSkillAuthor {
    server: Weak<SyncServer>,
    /// The server's runtime: the Dreamer's own cannot carry the call while
    /// its thread waits on the draft.
    handle: tokio::runtime::Handle,
    /// What one draft's calls may spend: the pass's ordinary allowance.
    budget_units: u64,
}

impl CoachSkillAuthor {
    pub(super) fn new(
        server: Weak<SyncServer>,
        handle: tokio::runtime::Handle,
        budget_units: u64,
    ) -> Self {
        Self {
            server,
            handle,
            budget_units,
        }
    }

    /// The Coach's models for one draft, on one budget.
    fn models<'a>(
        &self,
        server: &'a SyncServer,
        brief: &SkillOptimizeBrief,
    ) -> oneiron::Result<HostModels<'a>> {
        self.models_for(
            server,
            &format!("coach-skill-optimize:{}", brief.skill.to_hex()),
        )
    }

    /// The Coach's models for one draft about `about`, on one budget.
    fn models_for<'a>(
        &self,
        server: &'a SyncServer,
        about: &str,
    ) -> oneiron::Result<HostModels<'a>> {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis());
        HostModels::open_on(
            server,
            format!("{about}:{at}"),
            SKILL_OPTIMIZE_CALL_PURPOSE_NAME,
            self.budget_units,
            self.handle.clone(),
        )
    }
}

impl SkillOptimizeAuthor for CoachSkillAuthor {
    fn draft(&self, brief: &SkillOptimizeBrief) -> oneiron::Result<SkillEditDraft> {
        let server = self
            .server
            .upgrade()
            .ok_or_else(|| failed("the server stopped"))?;
        let models = self.models(&server, brief)?;
        let wording = server.ai.dreamer_wording();
        draft_with(
            server.vault(),
            &models,
            wording.coach_skill_draft().to_owned(),
            brief,
            brief.source_rows.clone(),
        )
    }

    fn draft_on(
        &self,
        attempt: &AttemptRecord,
        brief: &SkillOptimizeBrief,
    ) -> oneiron::Result<SkillEditDraft> {
        let server = self
            .server
            .upgrade()
            .ok_or_else(|| failed("the server stopped"))?;
        let models = self.models(&server, brief)?;
        let wording = server.ai.dreamer_wording();
        let Some(executor) = server
            .ai
            .model_runtime()
            .seat(models.coach())
            .map(|seat| seat.model.as_str().to_owned())
        else {
            // No seat to pin: the Coach's own path answers, as it always did.
            return draft_with(
                server.vault(),
                &models,
                wording.coach_skill_draft().to_owned(),
                brief,
                brief.source_rows.clone(),
            );
        };
        // The workflow is the Coach's recipe. Its load pins its revision and
        // the Coach's model on the optimization attempt, where the edit's
        // held-out outcome is credited.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let (loaded, pack_sources) = match server.vault().load_attempt_skill_pack_sourced(
            attempt.id,
            &coach_improver_skill_id()?,
            attempt.lease_owner.as_deref().unwrap_or_default(),
            attempt.attempt_count,
            &executor,
            now,
        ) {
            Ok(loaded) => loaded,
            // A retired, unapproved, superseded or missing workflow, or a
            // load the attempt refuses: the Coach drafts on its own
            // instruction as before, and the outcome stays the Coach's.
            Err(error) => {
                tracing::warn!(
                    %error,
                    "the improver workflow did not load; the Coach drafts on its own instruction"
                );
                return draft_with(
                    server.vault(),
                    &models,
                    wording.coach_skill_draft().to_owned(),
                    brief,
                    brief.source_rows.clone(),
                );
            }
        };
        let workflow = loaded
            .source_files
            .as_ref()
            .and_then(|files| files.iter().find(|file| file.path == SKILL_FILE))
            .and_then(|file| std::str::from_utf8(&file.content).ok())
            .unwrap_or(loaded.record.desc.as_str());
        let system = format!("{workflow}\n\n{}", wording.coach_skill_workflow_answer());
        let sources =
            union_source_rows([brief.source_rows.as_deref(), Some(pack_sources.as_slice())]);
        draft_with(server.vault(), &models, system, brief, sources)
    }
}

impl CoachHealAuthor for CoachSkillAuthor {
    fn draft_skill(
        &self,
        brief: &SkillOptimizeBrief,
        cause: &HealEvidenceContext,
    ) -> oneiron::Result<SkillEditDraft> {
        let server = self
            .server
            .upgrade()
            .ok_or_else(|| failed("the server stopped"))?;
        let models = self.models(&server, brief)?;
        let wording = server.ai.dreamer_wording();
        draft_with_cause(
            server.vault(),
            &models,
            format!(
                "{} {}",
                wording.coach_skill_draft(),
                wording.coach_skill_cause(),
            ),
            brief,
            cause,
        )
    }

    fn draft_producer_fix(
        &self,
        target: &ProducerTarget,
        cause: &HealEvidenceContext,
    ) -> oneiron::Result<ProducerFixDraft> {
        let server = self
            .server
            .upgrade()
            .ok_or_else(|| failed("the server stopped"))?;
        let base_revision = target
            .base_revision()
            .ok_or_else(|| failed("no producer is bound"))?;
        let models = self.models_for(&server, &format!("coach-producer-fix:{base_revision}"))?;
        let wording = server.ai.dreamer_wording();
        let data = serde_json::json!({
            "target": target.value(),
            "untrusted_cause_context": cause.value(),
        });
        let text = models
            .generate(
                models.coach(),
                vec![
                    message(
                        LlmMessageRole::System,
                        wording.coach_producer_fix().to_owned(),
                    ),
                    message(LlmMessageRole::User, data.to_string()),
                ],
            )?
            .ok_or_else(|| failed("no seat served the Coach"))?;
        let (delta, rationale) =
            parse_fix(&text).ok_or_else(|| failed("the answer is not a fix"))?;
        Ok(ProducerFixDraft {
            target: target.clone(),
            base_revision,
            delta,
            rationale,
        })
    }
}

fn failed(what: &str) -> Error {
    Error::InvalidConfig(format!("the Coach's skill draft: {what}"))
}

/// One draft call on the Coach's seat, under `system`.
fn draft_with(
    vault: &Vault,
    models: &HostModels<'_>,
    system: String,
    brief: &SkillOptimizeBrief,
    sources: Option<Vec<EntityId>>,
) -> oneiron::Result<SkillEditDraft> {
    let text = models
        .generate_sourced(
            models.coach(),
            vec![
                message(LlmMessageRole::System, system),
                message(LlmMessageRole::User, brief_data(vault, brief).to_string()),
            ],
            sources,
        )?
        .ok_or_else(|| failed("no seat served the Coach"))?;
    parse_draft(&text).ok_or_else(|| failed("the answer is not a draft"))
}

/// One heal-repair draft call on the Coach's seat (OF-418 L10): the brief as
/// [`draft_with`] sends it, and beside it what the engine recorded of the
/// failure's cause, whole, as data.
fn draft_with_cause(
    vault: &Vault,
    models: &HostModels<'_>,
    system: String,
    brief: &SkillOptimizeBrief,
    cause: &HealEvidenceContext,
) -> oneiron::Result<SkillEditDraft> {
    let data = serde_json::json!({
        "brief": brief_data(vault, brief),
        "untrusted_cause_context": cause.value(),
    });
    let text = models
        .generate_sourced(
            models.coach(),
            vec![
                message(LlmMessageRole::System, system),
                message(LlmMessageRole::User, data.to_string()),
            ],
            brief.source_rows.clone(),
        )?
        .ok_or_else(|| failed("no seat served the Coach"))?;
    parse_draft(&text).ok_or_else(|| failed("the answer is not a draft"))
}

/// The brief as the Coach reads it: DEV evidence only, and of a rejected
/// edit only its text, its reason and the gate's category. A heal's repair
/// also reads the failure it is aimed at (FIX 2495): its class and each of
/// its reports, the agent's own words as data. Every text and list goes
/// whole: the longest is measured, never cut.
fn brief_data(vault: &Vault, brief: &SkillOptimizeBrief) -> serde_json::Value {
    let mut longest = brief.desc.len();
    let failure = brief.failure.as_ref().map(|failure| {
        let _ = vault.measure_limit(
            EngineLimit::MaintenanceRowItems,
            failure.reports.len() as u64,
        );
        let reports: Vec<_> = failure
            .reports
            .iter()
            .map(|report| {
                longest = longest.max(report.untrusted_detail.len());
                serde_json::json!({
                    "receipt": report.receipt.to_hex(),
                    "category": report.category,
                    "untrusted_detail": report.untrusted_detail,
                })
            })
            .collect();
        serde_json::json!({
            "class": failure.failure_class,
            "category": failure.category,
            "reports": reports,
        })
    });
    let corrections: Vec<_> = brief
        .substitution_proposals
        .iter()
        .map(|proposal| {
            let text = proposal.from.len().max(proposal.to.len());
            longest = longest.max(text.max(proposal.rationale.len()));
            serde_json::json!({
                "scope": proposal.scope,
                "from": proposal.from,
                "to": proposal.to,
                "why": proposal.rationale,
            })
        })
        .collect();
    let rejected: Vec<_> = brief
        .rejected_edits
        .iter()
        .map(|edit| {
            let text = edit.desc.len().max(edit.author_rationale.len());
            longest = longest.max(text);
            serde_json::json!({
                "instructions": edit.desc,
                "rationale": edit.author_rationale,
                "rejected_as": match edit.rejection_reason {
                    RejectedSkillEditReason::Tie => "tie",
                    RejectedSkillEditReason::Regression => "regression",
                },
            })
        })
        .collect();
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
    let mut data = serde_json::json!({
        "skill_id": brief.skill_id,
        "version": brief.version,
        "instructions": brief.desc,
        "reliability": { "alpha": brief.posterior.alpha, "beta": brief.posterior.beta },
        "prior": { "alpha": brief.prior.alpha, "beta": brief.prior.beta },
        "attributed_outcomes": brief.attributed_outcomes,
        "content_found_wrong": brief.defect_receipts.len(),
        "content_found_missing": brief.discovery_proposals.len(),
        "repeated_corrections": corrections,
        "rejected_edits": rejected,
    });
    if let Some(failure) = failure {
        data["failure"] = failure;
    }
    // A policy-bearing skill's dials, so an edit can name the one to move
    // (FIX 12071).
    if let Some(dials) = &brief.policy_dials {
        let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, dials.len() as u64);
        data["policy_dials"] = serde_json::Value::Object(dials.clone());
    }
    data
}

/// The draft's answer as the Coach writes it.
#[derive(Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
enum DraftWire {
    Edit {
        instructions: String,
        rationale: String,
    },
    Decline {
        rationale: String,
    },
}

/// The one JSON object in the answer; `None` when there is none.
fn parse_draft(text: &str) -> Option<SkillEditDraft> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    Some(
        match serde_json::from_str::<DraftWire>(text.get(start..=end)?).ok()? {
            DraftWire::Edit {
                instructions,
                rationale,
            } => SkillEditDraft::Edit {
                desc: instructions,
                rationale,
            },
            DraftWire::Decline { rationale } => SkillEditDraft::Decline { rationale },
        },
    )
}

/// A producer fix's answer as the Coach writes it (OF-418 L3).
#[derive(Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
enum FixWire {
    Fix {
        delta: serde_json::Value,
        rationale: String,
    },
    Decline {
        rationale: String,
    },
}

/// The fix's delta, `None` for a decline, and its rationale, from the one JSON
/// object in the answer; `None` when there is none.
fn parse_fix(text: &str) -> Option<(Option<serde_json::Value>, String)> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    Some(
        match serde_json::from_str::<FixWire>(text.get(start..=end)?).ok()? {
            FixWire::Fix { delta, rationale } => (Some(delta), rationale),
            FixWire::Decline { rationale } => (None, rationale),
        },
    )
}
