//! The host's scheduled T2/T3 detector pass (ARCH-0066 #tiers, OF-418). For
//! each `[self_heal.detectors.<family>]` the owner wrote, it reads the recent
//! retrieval runs, cuts them into windows and asks the detector's question of
//! each window not graded yet: each completed window of time for `t2` and
//! `t3`, each conversation gone quiet for `session`. A raised window is a
//! proposed diagnostic; nothing is repaired here. A `t2` detector whose
//! family's `t3` findings the owner has labeled asks with those findings.
//! Once a `t3` detector's reviewed findings mint a T2, the pass registers it
//! and grades its windows with it too, the reviewed examples' runs in the
//! state, until a shipped closed-form T1 reproduces every label and retires
//! it. The `t3` keeps running.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use oneiron::self_heal::detector_pass::{detector_window_key, minted_window_key};
use oneiron::self_heal::distillation::{MintedExample, MintedT2};
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
/// Of those, the bytes a minted T2's reviewed examples take at most, half
/// for the positives and half for the negatives.
const EXAMPLE_BYTES: usize = 16 * 1024;

struct Detector {
    policy: DetectorPolicy,
    tier: DetectorTier,
    window_secs: u64,
}

/// One detector a pass grades: one the owner configured, or the T2 registered
/// from a `t3` detector's reviewed findings, graded over that seed's windows.
enum Graded<'a> {
    Configured(&'a Detector),
    Minted {
        seed: &'a Detector,
        minted: MintedT2,
        revision: [u8; 32],
        examples: serde_json::Value,
    },
}

impl Graded<'_> {
    fn seed(&self) -> &Detector {
        match self {
            Self::Configured(seed) | Self::Minted { seed, .. } => seed,
        }
    }
}

/// Starts the pass, or nothing when no detector is configured. Each pass
/// runs on a blocking thread: the ladder's model rungs block on the server's
/// runtime.
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    config: &SelfHealConfig,
    admit: crate::server::HousekeepingAdmission,
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
            let Some(pass) = admit() else {
                continue;
            };
            let detectors = Arc::clone(&detectors);
            match tokio::task::spawn_blocking(move || {
                let _pass = pass;
                round(&server, &detectors)
            })
            .await
            {
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
    let mut pass: Vec<Graded<'_>> = detectors.iter().map(Graded::Configured).collect();
    pass.extend(
        detectors
            .iter()
            .filter_map(|seed| registered(vault, seed, now)),
    );
    let mut graded = 0;
    for detector in &pass {
        let seed = detector.seed();
        for window in windows(&runs, seed, full, now) {
            if graded == ROUND {
                return Ok(());
            }
            let key = match detector {
                Graded::Configured(seed) => {
                    detector_window_key(&seed.policy, seed.tier.proposed(), &window)
                }
                Graded::Minted { revision, .. } => {
                    minted_window_key(&seed.policy, revision, &window)
                }
            };
            if vault.detector_window_graded(&key)? {
                continue;
            }
            graded += 1;
            let window: Vec<RetrievalRunRecord> = window.into_iter().cloned().collect();
            let examples = match detector {
                Graded::Configured(_) => None,
                Graded::Minted { examples, .. } => Some(examples),
            };
            let state = state_of(&window, examples);
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
                        family = %seed.policy.family,
                        raised = raised.is_some(),
                        "a self-heal detector graded a window"
                    );
                }
                // By kind only; the next pass asks again.
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    family = %seed.policy.family,
                    "a self-heal detector could not grade a window"
                ),
            }
        }
    }
    Ok(())
}

/// The T2 registered for a `t3` detector's family, when its reviewed findings
/// mint one and no closed-form T1 has graduated it.
fn registered<'a>(vault: &oneiron::Vault, seed: &'a Detector, now: u64) -> Option<Graded<'a>> {
    if seed.tier != DetectorTier::T3 {
        return None;
    }
    let registered = vault
        .register_minted_t2(&seed.policy, now)
        .and_then(|registered| {
            let Some((minted, registration)) = registered else {
                return Ok(None);
            };
            if registration.graduated_to.is_some() {
                return Ok(None);
            }
            let examples = example_facts(&vault.minted_t2_examples(&minted)?);
            Ok(Some(Graded::Minted {
                seed,
                minted,
                revision: registration.revision,
                examples,
            }))
        });
    match registered {
        Ok(registered) => registered,
        // By kind only; the next pass registers again.
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                family = %seed.policy.family,
                "a minted T2 waits for the next pass"
            );
            None
        }
    }
}

fn grade(
    vault: &oneiron::Vault,
    detector: &Graded<'_>,
    decisions: &DetectorDecisions<'_>,
    runs: &[RetrievalRunRecord],
) -> oneiron::Result<Option<ProposedDiagnostic>> {
    let detector = match detector {
        Graded::Configured(detector) => detector,
        Graded::Minted { minted, .. } => {
            return vault.classify_minted_t2(minted, decisions, runs);
        }
    };
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
/// dropped first past [`STATE_BYTES`], with a minted T2's reviewed examples.
/// Counts, signals and grades only: no query or result text goes with them.
fn state_of(
    runs: &[RetrievalRunRecord],
    examples: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut left = STATE_BYTES.saturating_sub(examples.map_or(0, |e| e.to_string().len()));
    let (facts, cut) = facts_within(runs, &mut left);
    let mut state = serde_json::json!({ "runs": facts, "cut": cut });
    if let Some(examples) = examples {
        state["examples"] = examples.clone();
    }
    state
}

/// A minted T2's reviewed examples, each finding with its runs' facts, past
/// half of [`EXAMPLE_BYTES`] a side the later findings and runs left out.
fn example_facts(examples: &[MintedExample]) -> serde_json::Value {
    let mut shown = Vec::with_capacity(examples.len());
    for positive in [true, false] {
        let mut left = EXAMPLE_BYTES / 2;
        for example in examples.iter().filter(|e| e.positive == positive) {
            let mut room = left;
            let (runs, cut) = facts_within(&example.runs, &mut room);
            let finding = serde_json::json!({
                "finding": example.event_id.to_hex(),
                "positive": positive,
                "runs": runs,
                "cut": cut,
            });
            let size = finding.to_string().len();
            if runs.is_empty() || size > left {
                break;
            }
            left -= size;
            shown.push(finding);
        }
    }
    let cut = shown.len() < examples.len();
    serde_json::json!({ "findings": shown, "cut": cut })
}

/// The facts of `runs` that fit in `left` bytes, oldest first, and whether
/// any were left out.
fn facts_within(runs: &[RetrievalRunRecord], left: &mut usize) -> (Vec<serde_json::Value>, bool) {
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
        if size > *left {
            break;
        }
        *left -= size;
        facts.push(fact);
    }
    let cut = facts.len() < runs.len();
    (facts, cut)
}
