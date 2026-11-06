//! Explicit Repair jobs use the original reader at every actual model rung.

use std::sync::{Mutex, PoisonError};

use oneiron::attempt_queue::{AttemptId, AttemptQueue, ReadSetProducer};
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::settings::{ReadDestination, ReleaseHold};
use oneiron::skill_optimize::{
    EvalAuthoringInventory, EvalRepairAuthoringPlan, EvalRepairAuthoringSource,
    eval_authoring_skill_id, union_source_rows,
};
use oneiron::{EntityId, Error, LlmMessageRole, LlmRequest, Vault};

use super::{BUDGET_UNITS, EVAL_AUTHORING, EVAL_AUTHORING_CALL_PURPOSE, SKILL_FILE};
use crate::ai_host::code_fix::{HostModels, message};
use crate::models::{SourceAdmission, SourceOffer};
use crate::server::SyncServer;

pub(in crate::ai_host) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    let vault = server.vault();
    let source = vault
        .coach_eval_repair_authoring_source(admitted)
        .map_err(source_error)?;
    let (inventory, rows) = source.inventory_sourced(now).map_err(source_error)?;
    if !inventory.has_work() && source.recipes().is_empty() {
        return Ok(());
    }
    let models = HostModels::open(
        server,
        format!(
            "coach-eval-repair-authoring:{}",
            EntityId::from_bytes(*admitted.status.attempt.id.as_bytes())?.to_hex()
        ),
        EVAL_AUTHORING_CALL_PURPOSE,
        BUDGET_UNITS,
    )?;
    if server.ai.model_runtime().seat(models.coach()).is_none() {
        return Ok(());
    }
    let attempt = &admitted.status.attempt;
    let declared = vault
        .declare_attempt_read_producers(attempt.id, &[EVAL_AUTHORING, ReadSetProducer::SKILL_PACK])
        .is_ok();
    if !declared {
        tracing::warn!(attempt = ?attempt.id, "Repair authoring read set could not be declared");
    }
    let (loaded, skill_rows) = match vault.load_attempt_call_skill_pack_sourced(
        attempt.id,
        &eval_authoring_skill_id()?,
        attempt.lease_owner.as_deref().unwrap_or_default(),
        attempt.attempt_count,
        now,
    ) {
        Ok(loaded) => loaded,
        Err(Error::EntityNotFound | Error::InvalidClaimBody(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let Some(instruction) = loaded
        .source_files
        .as_ref()
        .and_then(|files| files.iter().find(|file| file.path == SKILL_FILE))
        .and_then(|file| std::str::from_utf8(&file.content).ok())
        .map(str::to_owned)
    else {
        return Ok(());
    };
    let skill = (loaded.entity, loaded.record.version);
    let rows = union_source_rows([rows, Some(skill_rows.clone())]);
    if declared {
        record_sources(vault, attempt.id, rows.clone());
    }
    let sources = RepairSources {
        vault,
        source,
        now,
        skill_rows,
        attempt: attempt.id,
        declared,
        sent: Mutex::new(None),
    };
    let Some((text, binding)) = models.generate_admitted_recorded(
        models.coach(),
        vec![message(LlmMessageRole::System, instruction)],
        rows,
        &sources,
    )?
    else {
        return Ok(());
    };
    let Some(sent) = sources
        .sent
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
    else {
        return Err(Error::InvalidConfig(
            "Repair authoring has no sent source view".into(),
        ));
    };
    // The load did not invent an executor from the initially selected seat.
    AttemptQueue::new(vault).set_executor_model(
        attempt.id,
        attempt.lease_owner.as_deref().unwrap_or_default(),
        attempt.attempt_count,
        binding.rung.model.as_str(),
    )?;
    let start = text.find('{');
    let end = text.rfind('}');
    let plan: Option<EvalRepairAuthoringPlan> = start
        .zip(end)
        .and_then(|(start, end)| text.get(start..=end))
        .and_then(|text| serde_json::from_str(text).ok());
    let Some(plan) = plan else {
        tracing::debug!("the Coach's Repair authoring answer held no plan");
        return Ok(());
    };
    let (answer, audited) = sent
        .source
        .apply_plan_listing(plan, &sent.inventory, skill, now);
    if declared {
        record_sources(vault, attempt.id, Some(audited));
    }
    let report = answer.map_err(source_error)?;
    tracing::debug!(
        repairs = report.repairs.len(),
        cuts = report.authoring.cohorts_cut.len(),
        retired = report.authoring.cohorts_retired.len(),
        model = binding.rung.model.as_str(),
        "the Coach applied its source-bound Repair plan"
    );
    Ok(())
}

fn source_error(error: oneiron::memory::MemoryError) -> Error {
    // The public stable code only; source errors may quote vault content.
    Error::InvalidConfig(format!(
        "Repair authoring source read failed: {}",
        error.code
    ))
}

fn record_sources(vault: &Vault, attempt: AttemptId, rows: Option<Vec<EntityId>>) {
    if let Err(error) = vault.record_attempt_sources(attempt, EVAL_AUTHORING, rows) {
        tracing::warn!(attempt = ?attempt, kind = ?error.kind(), "Repair authoring read set was not recorded");
        let _ = vault.record_attempt_sources(attempt, EVAL_AUTHORING, None);
    }
}

#[derive(Clone)]
struct ServedRepair<'v> {
    destination: ReadDestination,
    source: EvalRepairAuthoringSource<'v>,
    inventory: EvalAuthoringInventory,
    rows: Option<Vec<EntityId>>,
}

struct RepairSources<'v> {
    vault: &'v Vault,
    source: EvalRepairAuthoringSource<'v>,
    now: u64,
    skill_rows: Vec<EntityId>,
    attempt: AttemptId,
    declared: bool,
    sent: Mutex<Option<ServedRepair<'v>>>,
}

impl SourceAdmission for RepairSources<'_> {
    fn offer(&self, request: &LlmRequest, destination: &ReadDestination) -> SourceOffer {
        let source = match self.source.for_destination(destination) {
            Ok(source) => source,
            Err(_) => return SourceOffer::Held(ReleaseHold::Placement.reason()),
        };
        // Ordinary Coach ledger metadata keeps its existing native reader.
        // Only Repair choices come from the original credential's read.
        let (inventory, rows) = match source.inventory_sourced(self.now) {
            Ok(read) => read,
            Err(_) => return SourceOffer::Held(ReleaseHold::Placement.reason()),
        };
        let repairs = source.recipes();
        if repairs.is_empty() && !inventory.has_work() {
            return SourceOffer::Held(ReleaseHold::Placement.reason());
        }
        let rows = union_source_rows([rows, Some(self.skill_rows.clone())]);
        let data = serde_json::json!({
            "kind": "repair", "inventory": inventory, "repairs": repairs,
        })
        .to_string();
        let mut offered = request.clone();
        offered.messages.push(message(LlmMessageRole::User, data));
        if self.declared {
            record_sources(self.vault, self.attempt, rows.clone());
        }
        *self.sent.lock().unwrap_or_else(PoisonError::into_inner) = Some(ServedRepair {
            destination: destination.clone(),
            source,
            inventory,
            rows,
        });
        SourceOffer::Send(offered)
    }

    fn source_rows(&self, destination: &ReadDestination) -> Option<Option<Vec<EntityId>>> {
        let sent = self.sent.lock().unwrap_or_else(PoisonError::into_inner);
        Some(
            sent.as_ref()
                .filter(|sent| sent.destination == *destination)
                .and_then(|sent| sent.rows.clone()),
        )
    }

    fn recheck(&self, destination: &ReadDestination) -> Option<&'static str> {
        let sent = self
            .sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(sent) = sent.filter(|sent| sent.destination == *destination) else {
            return Some(ReleaseHold::Placement.reason());
        };
        match sent.source.recheck_destination(destination) {
            Ok(true) => None,
            Ok(false) | Err(_) => Some(ReleaseHold::Placement.reason()),
        }
    }
}
