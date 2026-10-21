//! The host's half of the digest's urgent breakthrough (OF-194 L3;
//! ARCH-0026: "urgent breakthrough only when waiting would harm the user's
//! intent").
//!
//! One loop on the Dreamer's thread reads the engine's harm candidates each
//! time the vault's proactivity changes, and queues one harm question per
//! candidate on the Dreamer's maintenance lane: no poll, no scheduler of its
//! own and no top-N. A pass's executor answers each on the server's shared
//! decision ladder, up to its Big rung so no person is asked, off the pass's
//! runtime, and hands the answer with its full receipt to the engine's
//! witnessed request. The engine delivers a yes; a no or an abstain is kept
//! and delivers nothing early. The question's wording is shipped data beside
//! this host, which `[models.dreamer].urgent_digest_question` replaces.

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use oneiron::dreamer_runner::DreamerParkCause;
use oneiron::dreamer_runner::maintenance::digest::DIGEST_ASSESS_UNLENT_PARK_REASON;
use oneiron::llm::decision::{DecisionRung, Reversibility};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{DreamerAdmittedAttempt, DreamerAttemptExecution, Vault, WakeAttemptContext};
use tokio::sync::watch;

use super::{PassAdmission, admit, now_ms, pause, paused};
use crate::decision_host::DecisionHost;

/// The harm question's shipped wording: prompt data beside this host, never
/// engine prose.
const WORDING: &str = include_str!("urgent_digest_wording.json");

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Wording {
    question: String,
}

/// Queues a harm question for every urgent digest candidate, then waits for
/// the vault's proactivity to change; it subscribes before its first read,
/// so no commit between the two is missed. Runs on the Dreamer's thread and
/// stops with it. A candidate queued once in this process is not queued
/// again: a changed intent, result or cadence is a new candidate, and after
/// a restart each pending one is asked once more. The host's gate and pause
/// (FIX 6909) start no round; the next change, or the pause lifting, does.
pub(super) async fn candidate_loop(
    vault: Arc<Vault>,
    configured: Option<String>,
    admission: PassAdmission,
) {
    let mut changes = vault.subscribe_proactivity_changes();
    let question = match configured {
        Some(question) => question,
        None => match serde_json::from_str::<Wording>(WORDING) {
            Ok(wording) => wording.question,
            Err(_) => {
                tracing::warn!("the urgent digest's shipped wording does not read");
                return;
            }
        },
    };
    let mut queued = HashSet::new();
    loop {
        let epoch = pause(&admission);
        if !paused(epoch.as_ref())
            && let Some(_round) = admit(&admission)
            && let Err(error) = queue_round(&vault, &question, &mut queued)
        {
            // By kind only: an engine error can quote the vault.
            tracing::warn!(kind = ?error.kind(), "urgent digest questions were not queued");
        }
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

/// Queues each current candidate this process has not queued yet.
fn queue_round(
    vault: &Vault,
    question: &str,
    queued: &mut HashSet<[u8; 32]>,
) -> oneiron::Result<()> {
    let now = now_ms() / 1_000;
    for candidate in vault.digest_harm_candidates(now)? {
        let basis = candidate.basis(question)?;
        if queued.contains(&basis) {
            continue;
        }
        vault.request_digest_harm_assessment(&candidate, question, now)?;
        queued.insert(basis);
    }
    Ok(())
}

/// Resolves once the pause `epoch` held lifts; pends while it holds none.
async fn pause_lifted(epoch: Option<watch::Receiver<bool>>) {
    match epoch {
        Some(mut epoch) if paused(Some(&epoch)) => {
            let _ = epoch.wait_for(|held| !*held).await;
        }
        _ => std::future::pending::<()>().await,
    }
}

/// Answers one queued harm question on the server's shared ladder and hands
/// the answer, receipt and all, to the engine's witnessed request. The
/// ladder's model rungs block on the server's runtime, so the call runs on a
/// blocking thread, off this pass's, on the pass's remaining clock. An
/// unstaffed host parks the question for the runner's retry; a basis that
/// moved since it was queued ends with no answer, its new basis queued anew.
pub(super) async fn assess_waiting_harm(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    decisions: &Arc<OnceLock<DecisionHost>>,
) -> oneiron::Result<DreamerAttemptExecution> {
    let Some(host) = decisions.get().cloned() else {
        return Ok(DreamerAttemptExecution::Park {
            reason: DIGEST_ASSESS_UNLENT_PARK_REASON.to_owned(),
            cause: DreamerParkCause::Retry,
        });
    };
    let now = ctx.now_ms / 1_000;
    let Some(input) = ctx.vault.digest_harm_judge_input(attempt, now)? else {
        tracing::info!(
            code = "digest_harm_basis_moved",
            "an urgent digest question's basis moved; its new basis is asked anew"
        );
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    };
    let budget = Duration::from_millis(ctx.deadline.remaining_ms());
    let decision = tokio::task::spawn_blocking(move || {
        let deadline = RetrievalDeadline::hard(Instant::now(), budget);
        host.ladder().ladder().run(
            &input.question,
            input.principal,
            &input.evidence,
            &input.state,
            host.dial(DecisionRung::Big),
            &host.bands(),
            Reversibility::ReversibleRead,
            &deadline,
        )
    })
    .await
    .map_err(|_| oneiron::Error::InvalidConfig("the urgent digest judge panicked".into()))??;
    ctx.vault
        .request_urgent_proactivity_digest(attempt, decision, now)?;
    Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
}
