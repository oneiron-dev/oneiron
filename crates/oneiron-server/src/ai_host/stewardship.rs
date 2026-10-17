//! Follow-up drafts for due stewardship reach-outs (ARCH-0026 Represent).
//!
//! The engine names each pending reach-out whose owner rule routes drafts.
//! This host reads the reach-out's sources through the representation seam,
//! asks the generative role once on the Dreamer's budget, and hands the
//! answer back pre-materialized. The owner's own instruction is the system
//! message; the sources go as data. What lands is a representation proposal
//! the owner reviews at `/v1/owner/representation` before any send.
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use oneiron::dreamer_runner::maintenance::representation::PrematerializedDraft;
use oneiron::dreamer_runner::maintenance::stewardship::StewardshipDraftRequest;
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, EntityId, Error,
    LlmMessage, LlmMessageRole, LlmRequest, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};

use super::CHAT_ROLE;
use crate::models::ModelRuntime;

/// The purpose a draft's call is metered and routed under.
const DRAFT_PURPOSE: &str = "stewardship_follow_up";
/// Reach-outs one round drafts.
const ROUND: usize = 8;
/// The least time between two rounds: a burst of vault writes wakes one.
const SETTLE: Duration = Duration::from_secs(60);

/// Drafts each due follow-up, then waits for the vault to change. Runs on
/// the Dreamer's thread and stops with it. A reach-out whose draft failed
/// after its call is not asked again in this process: one failure costs one
/// call, not one call per vault write.
pub(super) async fn draft_loop(
    vault: Arc<Vault>,
    runtime: Arc<ModelRuntime>,
    budget_units: u64,
    admission: super::dreamer::PassAdmission,
) {
    let mut changes = vault.subscribe_proactivity_changes();
    let mut failed = HashSet::new();
    loop {
        // A round the host's gate refuses waits for the next change.
        if let Some(_pass) = super::dreamer::admit(&admission)
            && let Err(error) = draft_round(&vault, &runtime, budget_units, &mut failed).await
        {
            // By kind only: an engine error can quote the vault.
            tracing::warn!(kind = ?error.kind(), "stewardship drafts could not be listed");
        }
        tokio::time::sleep(SETTLE).await;
        if changes.changed().await.is_err() {
            return;
        }
    }
}

async fn draft_round(
    vault: &Vault,
    runtime: &ModelRuntime,
    budget_units: u64,
    failed: &mut HashSet<EntityId>,
) -> oneiron::Result<()> {
    let mut drafted = 0;
    for draft in vault.stewardship_draft_requests(ROUND.saturating_add(failed.len()))? {
        if drafted == ROUND {
            break;
        }
        if failed.contains(&draft.proposal) {
            continue;
        }
        drafted += 1;
        if let Err(error) = draft_one(vault, runtime, budget_units, &draft).await {
            failed.insert(draft.proposal);
            tracing::warn!(kind = ?error.kind(), "a stewardship follow-up was not drafted");
        }
    }
    Ok(())
}

fn message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    }
}

async fn draft_one(
    vault: &Vault,
    runtime: &ModelRuntime,
    budget_units: u64,
    draft: &StewardshipDraftRequest,
) -> oneiron::Result<()> {
    let context = vault.representation_context(&draft.request)?;
    let seat = runtime
        .seat(CHAT_ROLE)
        .ok_or_else(|| Error::InvalidConfig("no [models] rung drafts follow-ups".into()))?;
    // Each evidence source carries the marker its citation checks for; the
    // voice samples are the owner's own words.
    let sources = serde_json::json!({
        "kind": "follow_up",
        "channel": draft.request.channel,
        "target": draft.request.target,
        "evidence": context
            .evidence
            .iter()
            .map(|source| serde_json::json!({
                "cite": source.cite(String::new()).marker(),
                "text": source.text,
            }))
            .collect::<Vec<_>>(),
        "voice": context
            .voice
            .iter()
            .map(|source| source.text.as_str())
            .collect::<Vec<_>>(),
    });
    let purpose = CallPurpose::Other {
        name: DRAFT_PURPOSE.to_owned(),
    };
    let request = LlmRequest {
        model: seat.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(DRAFT_PURPOSE.to_owned())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: seat.locality,
        },
        messages: vec![
            message(LlmMessageRole::System, draft.instruction.clone()),
            message(LlmMessageRole::User, sources.to_string()),
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    };
    let call = runtime
        .admit_role(vault, CHAT_ROLE, request)
        .map_err(|refusal| Error::InvalidConfig(format!("stewardship draft refused: {refusal}")))?;
    // The Dreamer pays, on its own live budget policy rows.
    let run_id = format!("stewardship-draft:{}", draft.proposal.to_hex());
    let guard = vault.policy_budget_guard(
        run_id.clone(),
        budget_units,
        oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS,
        BudgetExhaustionPolicy::Suspend,
        vault.dreamer_authority()?,
    )?;
    let run = runtime.undeclared_run(run_id, guard);
    let response = call
        .ladder
        .generate(&run, call.request, None)
        .await
        .map_err(|error| Error::InvalidConfig(format!("stewardship draft call failed: {error}")))?;
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    vault.schedule_stewardship_draft(draft.proposal, &mut PrematerializedDraft { text }, now)?;
    Ok(())
}
