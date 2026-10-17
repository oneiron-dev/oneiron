//! The host's scheduled T2/T3 detector pass (ARCH-0066 #tiers, OF-418). For
//! each `[self_heal.detectors.<family>]` the owner wrote, it reads the recent
//! retrieval runs, cuts them into windows and asks the detector's question of
//! each window not graded yet: each completed window of time for `t2` and
//! `t3`, each conversation gone quiet for `session`. A raised window is a
//! proposed diagnostic; nothing is repaired here. A `t2` detector whose
//! family's `t3` findings the owner has labeled asks with those findings.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use oneiron::self_heal::detector_pass::detector_window_key;
use oneiron::self_heal::tiered::{
    DETECTOR_DIAL, DetectorDecisions, DetectorPolicy, ProposedDiagnostic,
};
use oneiron::store::RetrievalRunRecord;

use crate::config::{DetectorTier, SelfHealConfig};
use crate::server::SyncServer;

const TICK: Duration = Duration::from_secs(300);
/// Newest runs one pass reads.
const RECENT_RUNS: usize = 1_024;
/// Windows one pass grades at most, across every detector.
const ROUND: usize = 8;
/// One question's budget.
const DECIDE_BUDGET: Duration = Duration::from_secs(20);
/// Runs one window holds at most: the engine's bound. A longer window keeps
/// its newest runs.
const WINDOW_RUNS: usize = 64;
/// Bytes of run facts one window's state carries at most, under the ladder's
/// state bound.
const STATE_BYTES: usize = 60 * 1024;

struct Detector {
    policy: DetectorPolicy,
    tier: DetectorTier,
    window_secs: u64,
}

/// Starts the pass, or nothing when no detector is configured. Each pass
/// runs on a blocking thread: the ladder's model rungs block on the server's
/// runtime.
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    config: &SelfHealConfig,
) -> Option<tokio::task::JoinHandle<()>> {
    let detectors: Vec<Detector> = config
        .detectors
        .iter()
        .filter_map(|(family, detector)| match detector.policy(family) {
            Ok(policy) => Some(Detector {
                policy,
                tier: detector.tier,
                window_secs: detector.window_secs,
            }),
            Err(error) => {
                tracing::warn!(%error, "a self-heal detector is skipped");
                None
            }
        })
        .collect();
    if detectors.is_empty() {
        return None;
    }
    let detectors = Arc::new(detectors);
    let weak = Arc::downgrade(server);
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            let detectors = Arc::clone(&detectors);
            match tokio::task::spawn_blocking(move || round(&server, &detectors)).await {
                // By kind only: an engine error can quote the vault.
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "the self-heal detectors wait for the next pass");
                }
                Err(error) => tracing::warn!(%error, "the self-heal detector pass stopped"),
                Ok(Ok(())) => {}
            }
        }
    }))
}

fn round(server: &SyncServer, detectors: &[Detector]) -> oneiron::Result<()> {
    let vault = server.vault();
    let mut runs = vault.retrieval_runs(RECENT_RUNS)?;
    // A full read may have cut its oldest window short.
    let full = runs.len() >= RECENT_RUNS;
    runs.sort_by_key(|run| (run.started_at, run.run_id.as_bytes()));
    let now = vault.now_recorded_at();
    let principal = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| oneiron::Error::InvalidConfig(format!("no owner principal: {error}")))?;
    let host = server.decision_host();
    let mut graded = 0;
    for detector in detectors {
        let tier = detector.tier.proposed();
        for window in windows(&runs, detector, full, now) {
            if graded == ROUND {
                return Ok(());
            }
            let key = detector_window_key(&detector.policy, tier, window.iter().copied());
            if vault.detector_window_graded(&key)? {
                continue;
            }
            graded += 1;
            let window: Vec<RetrievalRunRecord> = window.into_iter().cloned().collect();
            let state = state_of(&window);
            let decisions = DetectorDecisions {
                ladder: host.ladder().ladder(),
                principal,
                dial: DETECTOR_DIAL,
                bands: host.bands(),
                state: &state,
                budget: DECIDE_BUDGET,
            };
            match grade(vault, detector, &decisions, &window) {
                Ok(raised) => {
                    vault.mark_detector_window_graded(&key, now)?;
                    tracing::debug!(
                        family = %detector.policy.family,
                        raised = raised.is_some(),
                        "a self-heal detector graded a window"
                    );
                }
                // By kind only; the next pass asks again.
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    family = %detector.policy.family,
                    "a self-heal detector could not grade a window"
                ),
            }
        }
    }
    Ok(())
}

fn grade(
    vault: &oneiron::Vault,
    detector: &Detector,
    decisions: &DetectorDecisions<'_>,
    runs: &[RetrievalRunRecord],
) -> oneiron::Result<Option<ProposedDiagnostic>> {
    match detector.tier {
        DetectorTier::T3 => vault.judge_retrieval_trace(&detector.policy, decisions, runs),
        DetectorTier::Session => vault.judge_session_quality(&detector.policy, decisions, runs),
        DetectorTier::T2 => match vault.mint_t2(detector.policy.clone())? {
            Some(minted) => vault.classify_minted_t2(&minted, decisions, runs),
            None => vault.classify_prompt(&detector.policy, decisions, runs),
        },
    }
}

/// The windows one detector grades, each oldest first: the runs of each
/// completed window of time for `t2` and `t3`, and the runs of each
/// conversation quiet for a window for `session`. A window with too few runs
/// is left out, and so is the one holding the oldest run of a full read,
/// which the read may have cut short.
fn windows<'a>(
    runs: &'a [RetrievalRunRecord],
    detector: &Detector,
    full: bool,
    now: u64,
) -> Vec<Vec<&'a RetrievalRunRecord>> {
    let span = detector.window_secs;
    let mut groups: BTreeMap<u128, Vec<&RetrievalRunRecord>> = BTreeMap::new();
    for run in runs {
        let group = match detector.tier {
            DetectorTier::Session => match run.turn {
                Some(turn) => u128::from_be_bytes(turn.episode_id),
                None => continue,
            },
            DetectorTier::T2 | DetectorTier::T3 => u128::from(run.started_at / span),
        };
        groups.entry(group).or_default().push(run);
    }
    let oldest = runs
        .first()
        .filter(|_| full)
        .map(|run| run.run_id.as_bytes());
    groups
        .into_iter()
        .filter_map(|(group, mut window)| {
            let done = match detector.tier {
                DetectorTier::Session => window
                    .last()
                    .is_some_and(|last| last.started_at.saturating_add(span) <= now),
                DetectorTier::T2 | DetectorTier::T3 => {
                    (group as u64).saturating_add(1).saturating_mul(span) <= now
                }
            };
            let cut = oldest.is_some_and(|oldest| window[0].run_id.as_bytes() == oldest);
            if !done || cut || window.len() < detector.policy.consecutive {
                return None;
            }
            let extra = window.len().saturating_sub(WINDOW_RUNS);
            window.drain(..extra);
            Some(window)
        })
        .collect()
}

/// The facts of a window's runs the detector's providers read, newest runs
/// dropped first past [`STATE_BYTES`]. Counts, signals and grades only: no
/// query or result text goes with them.
fn state_of(runs: &[RetrievalRunRecord]) -> serde_json::Value {
    let mut left = STATE_BYTES;
    let mut facts = Vec::with_capacity(runs.len());
    for run in runs {
        let fact = serde_json::json!({
            "run": run.run_id.to_hex(),
            "action": serde_json::to_value(&run.action).unwrap_or_default(),
            "started_at": run.started_at,
            "elapsed_us": run.elapsed_us,
            "results": run.result_ids.len(),
            "in_scope": run.total_in_scope,
            "claims_suppressed": run.claims_suppressed,
            "empty_reason": run.empty_reason,
            "signals": serde_json::to_value(&run.signals).unwrap_or_default(),
            "quality": serde_json::to_value(&run.quality).unwrap_or_default(),
            "degradation": serde_json::to_value(&run.degradation).unwrap_or_default(),
        });
        let size = fact.to_string().len();
        if size > left {
            break;
        }
        left -= size;
        facts.push(fact);
    }
    let cut = facts.len() < runs.len();
    serde_json::json!({ "runs": facts, "cut": cut })
}
