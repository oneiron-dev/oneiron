//! Follow-up drafts for due stewardship reach-outs (ARCH-0026 Represent).
//!
//! The engine names each pending reach-out whose owner rule routes drafts.
//! This host reads the reach-out's sources through the representation seam,
//! asks the generative role once on the Dreamer's budget (once more, over
//! the newest sources, when that call fails), and hands the answer back
//! pre-materialized. The owner's own instruction is the system
//! message; the sources go as data, each model the call reaches sent only
//! the sources its own destination may receive (FIX 8714, `sources`), and
//! the draft scheduled with the evidence the one that answered was sent.
//! What lands is a representation proposal
//! the owner reviews at `/v1/owner/representation` before any send. A draft
//! the owner's rule moved under while it was written is drafted again at
//! once against the current rule (FIX 6079). The host's pause (a managed
//! reap freeze, FIX 6909) starts no next draft; what it leaves stays pending.
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use oneiron::dreamer_runner::maintenance::representation::PrematerializedDraft;
use oneiron::dreamer_runner::maintenance::stewardship::{
    StewardshipDraftOutcome, StewardshipDraftRequest,
};
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, EntityId, Error,
    LlmRequest, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};
use tokio::sync::watch;

use self::sources::{DraftSources, draft_messages};
use super::CHAT_ROLE;
use super::dreamer::{PassAdmission, admit, pause, paused};
use crate::models::ModelRuntime;

mod sources;

/// The purpose a draft's call is metered and routed under.
const DRAFT_PURPOSE: &str = "stewardship_follow_up";
/// The newest sources a draft is written from again, once, after its call
/// over every eligible source failed: a model's window is its provider's
/// format bound. Used only after the full set failed; never a cap on a
/// first attempt.
const FALLBACK_DRAFT_EVIDENCE: usize = 8;
/// The least time between two rounds: a burst of vault writes wakes one.
const SETTLE: Duration = Duration::from_secs(60);

/// Drafts every due follow-up, then waits for the vault to change. Runs on
/// the Dreamer's thread and stops with it. A reach-out whose draft failed
/// after its call is not asked again in this process: one failure costs its
/// call and at most one fallback call, not one call per vault write.
pub(super) async fn draft_loop(
    vault: Arc<Vault>,
    runtime: Arc<ModelRuntime>,
    budget_units: u64,
    admission: PassAdmission,
) {
    let mut changes = vault.subscribe_proactivity_changes();
    let mut failed = HashSet::new();
    loop {
        // The pause epoch this round runs under, read before its gates, so a
        // freeze that races a gate reads as a pause.
        let epoch = pause(&admission);
        if let Err(error) = draft_round(
            &vault,
            &runtime,
            budget_units,
            &admission,
            epoch.as_ref(),
            &mut failed,
        )
        .await
        {
            // By kind only: an engine error can quote the vault.
            tracing::warn!(kind = ?error.kind(), "stewardship drafts could not be listed");
        }
        tokio::time::sleep(SETTLE).await;
        // A round the pause held or refused also looks again once it lifts.
        tokio::select! {
            changed = changes.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            () = pause_lifted(epoch) => {}
        }
    }
}

/// Resolves once the pause `epoch` held lifts: the epoch closed at a thaw,
/// or cleared. Pends while it holds none.
async fn pause_lifted(epoch: Option<watch::Receiver<bool>>) {
    match epoch {
        Some(mut epoch) if paused(Some(&epoch)) => {
            let _ = epoch.wait_for(|held| !*held).await;
        }
        _ => std::future::pending::<()>().await,
    }
}

/// Drafts every due follow-up: the reach-out index is read a page at a time,
/// each page a traversal unit, and its continuation followed to the end.
/// The host's gate is asked again before each page and each draft, and the
/// thread yields between drafts. A gate that refuses ends the round; the
/// rest stay pending, undrafted, for the next change. So does the host's
/// pause in `epoch` (FIX 6909), before each draft and each redraft.
async fn draft_round(
    vault: &Vault,
    runtime: &ModelRuntime,
    budget_units: u64,
    admission: &PassAdmission,
    epoch: Option<&watch::Receiver<bool>>,
    failed: &mut HashSet<EntityId>,
) -> oneiron::Result<()> {
    let mut after = None;
    loop {
        let page = {
            let Some(_pass) = admit(admission) else {
                return Ok(());
            };
            vault.stewardship_draft_page(after)?
        };
        for mut draft in page.drafts {
            if failed.contains(&draft.proposal) {
                continue;
            }
            tokio::task::yield_now().await;
            let Some(_pass) = admit(admission) else {
                return Ok(());
            };
            // A draft the owner's rule moved under is drafted again at once
            // against the current rule (FIX 6079): a fresh request and a
            // fresh call, each counted, with no cap. A request read again
            // that did not move is not drafted again.
            let mut redrafts: u64 = 0;
            loop {
                // The host's pause starts no next draft or redraft: this one
                // stays pending, not failed.
                if paused(epoch) {
                    return Ok(());
                }
                match draft_with_fallback(vault, runtime, budget_units, &draft).await {
                    Ok(StewardshipDraftOutcome::Scheduled(_)) => break,
                    Ok(StewardshipDraftOutcome::Stale) => {
                        redrafts += 1;
                        tracing::info!(
                            proposal = %draft.proposal.to_hex(),
                            redrafts,
                            "a stewardship draft went stale against the owner's current rule"
                        );
                        let Some(current) = vault.stewardship_draft_request(draft.proposal)? else {
                            break;
                        };
                        if !current.moved_from(&draft) {
                            failed.insert(draft.proposal);
                            tracing::warn!(
                                proposal = %draft.proposal.to_hex(),
                                "a stale stewardship draft's rule did not move; it is not drafted again"
                            );
                            break;
                        }
                        draft = current;
                    }
                    Err(error) => {
                        failed.insert(draft.proposal);
                        tracing::warn!(kind = ?error.kind(), "a stewardship follow-up was not drafted");
                        break;
                    }
                }
            }
        }
        let Some(next) = page.next else {
            return Ok(());
        };
        after = Some(next);
    }
}

/// [`draft_one`] over every eligible source and, when that fails and the
/// request cites more than [`FALLBACK_DRAFT_EVIDENCE`] sources, once more
/// over the newest of them, so a draft that was written before every source
/// was fed is still written.
async fn draft_with_fallback(
    vault: &Vault,
    runtime: &ModelRuntime,
    budget_units: u64,
    draft: &StewardshipDraftRequest,
) -> oneiron::Result<StewardshipDraftOutcome> {
    match draft_one(vault, runtime, budget_units, draft).await {
        Err(error) if draft.request.evidence.len() > FALLBACK_DRAFT_EVIDENCE => {
            // By kind only: an engine error can quote the vault.
            tracing::info!(
                proposal = %draft.proposal.to_hex(),
                kind = ?error.kind(),
                sources = draft.request.evidence.len(),
                "a stewardship draft over every source failed; drafting over the newest"
            );
            // The request's evidence is newest first.
            let mut newest = draft.clone();
            newest.request.evidence.truncate(FALLBACK_DRAFT_EVIDENCE);
            draft_one(vault, runtime, budget_units, &newest).await
        }
        outcome => outcome,
    }
}

/// One model draft of `draft`, scheduled as the request the model that
/// answered read: `Stale` when the owner's rule or the reach-out moved
/// meanwhile.
async fn draft_one(
    vault: &Vault,
    runtime: &ModelRuntime,
    budget_units: u64,
    draft: &StewardshipDraftRequest,
) -> oneiron::Result<StewardshipDraftOutcome> {
    // Read on this device, for the call's admission: no byte of it goes to
    // a model before its own destination's read (FIX 8714).
    let context = vault.representation_context(&draft.request)?;
    let seat = runtime
        .seat(CHAT_ROLE)
        .ok_or_else(|| Error::InvalidConfig("no [models] rung drafts follow-ups".into()))?;
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
        messages: draft_messages(draft, &context),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
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
    // Each offer the call reaches, the first included, is sent only what its
    // own destination may receive, read and kept before the send.
    let sources = DraftSources::new(vault, draft);
    let response = call
        .ladder
        .generate_admitted(&run, call.request, None, &sources)
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
    // Scheduled with the evidence the offer that answered was sent.
    let served = sources
        .served()
        .ok_or_else(|| Error::InvalidConfig("stewardship draft was sent no sources".into()))?;
    vault.schedule_stewardship_draft(&served, &mut PrematerializedDraft { text }, now)
}
