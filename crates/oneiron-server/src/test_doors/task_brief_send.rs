//! Census L8-07 door (review #7821 round 1, P1 x2): one composed brief's
//! model call, sent on a runtime's `[models.roles.local_reasoner]` seat as
//! the vault's task-brief model sends it, for the egress tests.

use oneiron::llm::manifest::ModelRole;
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, EntityId, Vault};

use crate::ai_host::task_brief::{draft_call, send_draft};
use crate::models::ModelRuntime;

/// The instruction the door's call carries.
const INSTRUCTION: &str = "Draft the task brief as one JSON object.";

/// Sends one draft call whose prompt is `input`, carrying the words of
/// `_lens_refs` (rows of `_vault`), on `runtime`'s local reasoner seat, as
/// `HostTaskBriefModel` sends it once the role is admitted. The reply's
/// text, or the refusal's message.
///
/// # Errors
///
/// No local reasoner seat; the call's refusal or failure, as its message.
pub async fn send_brief_call(
    runtime: &ModelRuntime,
    _vault: &Vault,
    input: &str,
    _lens_refs: &[EntityId],
) -> Result<String, String> {
    let seat = runtime
        .seat(ModelRole::LocalReasoner)
        .ok_or_else(|| "no [models.roles.local_reasoner] seat".to_owned())?;
    let schema = serde_json::json!({ "type": "object" });
    let call = draft_call(&seat.model, seat.locality, INSTRUCTION, input, &schema);
    let run = runtime.undeclared_run(
        "task-brief-door",
        BudgetGuard::new("task-brief-door", 100_000, BudgetExhaustionPolicy::Suspend),
    );
    send_draft(&seat.ladder, &run, call)
        .await
        .map_err(|error| error.message)
}
