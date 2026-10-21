//! The host's scheduled T2/T3 detector pass (ARCH-0066 #tiers, OF-418). For
//! each `[self_heal.detectors.<family>]` the owner wrote, it reads every
//! retrieval run, cuts them into windows and asks the detector's question of
//! each window not graded yet: each completed window of time for `t2` and
//! `t3`, each conversation gone quiet for `session`. A long window is asked
//! in parts and graded whole: a `t2` streak runs on across parts, a `t3` or
//! `session` window raises when any part raised, and the window is marked
//! graded once every part is asked (OF-418 L6). Questions start at the host's
//! first staffed decision rung (OF-418 L9). A raised window is a
//! proposed diagnostic; nothing is repaired here. A `t2` detector whose
//! family's `t3` findings the owner has labeled asks with those findings.
//! Once a `t3` detector's reviewed findings mint a T2, the pass registers it
//! and grades its windows with it too, the reviewed examples' runs in the
//! state, until a shipped closed-form T1 reproduces every label and retires
//! it. The `t3` keeps running. A T2 asking with reviewed findings first tries
//! the T2a centroid rung over the entities its positive examples retrieved,
//! and asks its model only on a miss (FIX 2078). A `session` detector reads
//! the conversation's own words as the owner reads them off this device
//! (FIX 2079). A state goes whole: its size is measured, never cut.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use oneiron::EntityId;
use oneiron::limit_ask::EngineLimit;
use oneiron::llm::decision::DecisionDial;
use oneiron::self_heal::detector_pass::{
    centroid_window_key, detector_window_key, minted_window_key,
};
use oneiron::self_heal::distillation::{MintedExample, MintedT2};
use oneiron::self_heal::tiered::{
    DETECTOR_DIAL, DetectorDecisions, DetectorPolicy, ProposedDiagnostic, WindowGrade,
};
use oneiron::self_heal::{CentroidCorpus, SessionText};
use oneiron::store::RetrievalRunRecord;

use crate::config::{DetectorTier, SelfHealConfig};
use crate::decision_host::DecisionHost;
use crate::server::SyncServer;

const TICK: Duration = Duration::from_secs(300);
/// Window parts one pass asks, across every detector, before it starts no
/// further window: a window begun is asked to its last part, and the next
/// pass takes the rest.
const ROUND: usize = 8;
/// One question's budget.
const DECIDE_BUDGET: Duration = Duration::from_secs(20);
/// Runs one part of a window holds at most: each part's questions read its
/// own runs' facts. The window's streak, sufficiency and verdict stay the
/// whole window's ([`judge`]).
const WINDOW_RUNS: usize = 64;

struct Detector {
    policy: DetectorPolicy,
    tier: DetectorTier,
    window_secs: u64,
}

/// A minted T2's reviewed corpus as one pass grades with it: the T2, its
/// examples' facts for the state, and the T2a corpus they label.
struct Reviewed {
    minted: MintedT2,
    examples: serde_json::Value,
    corpus: CentroidCorpus,
}

/// One detector a pass grades: one the owner configured, a `t2` among them
/// with the T2 its family's reviewed findings mint, or the T2 registered
/// from a `t3` detector's reviewed findings, graded over that seed's windows.
enum Graded<'a> {
    Configured {
        seed: &'a Detector,
        reviewed: Option<Reviewed>,
    },
    Minted {
        seed: &'a Detector,
        revision: [u8; 32],
        reviewed: Reviewed,
    },
}

impl Graded<'_> {
    fn seed(&self) -> &Detector {
        match self {
            Self::Configured { seed, .. } | Self::Minted { seed, .. } => seed,
        }
    }

    /// The reviewed corpus it asks with, if any.
    fn reviewed(&self) -> Option<&Reviewed> {
        match self {
            Self::Configured { reviewed, .. } => reviewed.as_ref(),
            Self::Minted { reviewed, .. } => Some(reviewed),
        }
    }

    /// The key one window is graded under: the detector's wording at its
    /// tier, a minted T2's corpus revision, and its T2a corpus's revision,
    /// so a window graded before a label existed is graded afresh.
    fn key(&self, window: &[&RetrievalRunRecord]) -> [u8; 32] {
        let seed = self.seed();
        let key = match self {
            Self::Configured { reviewed: None, .. } => {
                detector_window_key(&seed.policy, seed.tier.proposed(), window)
            }
            Self::Configured {
                reviewed: Some(reviewed),
                ..
            } => minted_window_key(&seed.policy, &reviewed.minted.revision(), window),
            Self::Minted { revision, .. } => minted_window_key(&seed.policy, revision, window),
        };
        match self.reviewed() {
            Some(reviewed) => centroid_window_key(&key, &reviewed.corpus),
            None => key,
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
    // Every run is read: past `limits.maintenance_scan_rows` the pass asks
    // and reads on.
    let mut runs = vault.retrieval_runs(usize::MAX)?;
    let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, runs.len() as u64);
    runs.sort_by_key(|run| (run.started_at, run.run_id.as_bytes()));
    let now = vault.now_recorded_at();
    let principal = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| oneiron::Error::InvalidConfig(format!("no owner principal: {error}")))?;
    let host = server.decision_host();
    let mut pass: Vec<Graded<'_>> = detectors
        .iter()
        .filter_map(|seed| configured(vault, seed))
        .collect();
    pass.extend(
        detectors
            .iter()
            .filter_map(|seed| registered(vault, seed, now)),
    );
    let mut graded = 0;
    for detector in &pass {
        let seed = detector.seed();
        for window in windows(&runs, seed, now) {
            if graded >= ROUND {
                return Ok(());
            }
            let key = detector.key(&window);
            if vault.detector_window_graded(&key)? {
                continue;
            }
            graded += window.len().div_ceil(WINDOW_RUNS);
            let window: Vec<RetrievalRunRecord> = window.into_iter().cloned().collect();
            match judge(vault, host, principal, detector, &window) {
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

/// A detector the owner configured. A `t2` asks with the T2 its family's
/// reviewed findings mint, when they mint one: the same examples and T2a
/// corpus a registered T2 asks with. `None` while that read fails; the next
/// pass reads it again.
fn configured<'a>(vault: &oneiron::Vault, seed: &'a Detector) -> Option<Graded<'a>> {
    if seed.tier != DetectorTier::T2 {
        return Some(Graded::Configured {
            seed,
            reviewed: None,
        });
    }
    let reviewed = vault.mint_t2(seed.policy.clone()).and_then(|minted| {
        minted
            .map(|minted| review_corpus(vault, minted))
            .transpose()
    });
    match reviewed {
        Ok(reviewed) => Some(Graded::Configured { seed, reviewed }),
        // By kind only; the next pass reads it again.
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                family = %seed.policy.family,
                "a configured T2 waits for the next pass"
            );
            None
        }
    }
}

/// A minted T2's reviewed corpus for one pass: its examples' runs, read
/// once, as the state's facts and as the T2a corpus they label.
fn review_corpus(vault: &oneiron::Vault, minted: MintedT2) -> oneiron::Result<Reviewed> {
    let shown = vault.minted_t2_examples(&minted)?;
    Ok(Reviewed {
        corpus: vault.centroid_corpus(&shown)?,
        examples: example_facts(&shown),
        minted,
    })
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
            Ok(Some(Graded::Minted {
                seed,
                revision: registration.revision,
                reviewed: review_corpus(vault, minted)?,
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

/// Grades one whole window. A T2 with a reviewed corpus tries T2a over every
/// run first, and a match is its proposal; otherwise the detector asks its
/// model question part by part, each part of at most [`WINDOW_RUNS`] runs
/// over the state its runs make, with the reviewed examples and the
/// session's text whole beside them, and the window has one verdict once
/// every part is asked (OF-418 L6). Each question starts at the host's first
/// staffed rung, up to the detector's ceiling and in its band (OF-418 L9).
fn judge(
    vault: &oneiron::Vault,
    host: &DecisionHost,
    principal: EntityId,
    detector: &Graded<'_>,
    window: &[RetrievalRunRecord],
) -> oneiron::Result<Option<ProposedDiagnostic>> {
    let seed = detector.seed();
    let reviewed = detector.reviewed();
    if let Some(reviewed) = reviewed
        && let Some(found) =
            vault.classify_centroid_window(&seed.policy, &reviewed.corpus, window)?
    {
        return Ok(Some(found));
    }
    let session = match seed.tier {
        DetectorTier::Session => Some(vault.session_judge_context(principal, window)?),
        DetectorTier::T2 | DetectorTier::T3 => None,
    };
    let examples = reviewed.map(|reviewed| &reviewed.examples);
    let dial = DecisionDial {
        first: host.dial(DETECTOR_DIAL.ceiling).first,
        ..DETECTOR_DIAL
    };
    let mut grade = open_grade(vault, detector, window)?;
    for part in window.chunks(WINDOW_RUNS) {
        let state = state_of(vault, part, examples, session.as_ref())?;
        let decisions = DetectorDecisions {
            ladder: host.ladder().ladder(),
            principal,
            dial,
            bands: host.bands(),
            state: &state,
            budget: DECIDE_BUDGET,
        };
        vault.grade_window_part(&mut grade, &decisions, part.len())?;
    }
    vault.finish_window_grade(grade)
}

/// Opens a window for the detector's model question, validated whole. A
/// minted T2, and a configured `t2` its family's reviewed findings mint, ask
/// with their reviewed examples.
fn open_grade<'w>(
    vault: &oneiron::Vault,
    detector: &'w Graded<'_>,
    window: &'w [RetrievalRunRecord],
) -> oneiron::Result<WindowGrade<'w>> {
    let (seed, reviewed) = match detector {
        Graded::Configured { seed, reviewed } => (*seed, reviewed.as_ref()),
        Graded::Minted { reviewed, .. } => {
            return vault.open_minted_window_grade(&reviewed.minted, window);
        }
    };
    match (seed.tier, reviewed) {
        (DetectorTier::T2, Some(reviewed)) => {
            vault.open_minted_window_grade(&reviewed.minted, window)
        }
        (tier, _) => vault.open_window_grade(&seed.policy, tier.proposed(), window),
    }
}

/// The windows one detector grades, each oldest first: the runs of each
/// completed window of time for `t2` and `t3`, and the runs of each
/// conversation quiet for a window for `session`. A window with too few runs
/// is left out; every other one is graded whole, in parts ([`judge`]).
fn windows<'a>(
    runs: &'a [RetrievalRunRecord],
    detector: &Detector,
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
    groups
        .into_iter()
        .filter(|(group, window)| {
            let done = match detector.tier {
                DetectorTier::Session => window
                    .last()
                    .is_some_and(|last| last.started_at.saturating_add(span) <= now),
                DetectorTier::T2 | DetectorTier::T3 => {
                    (*group as u64).saturating_add(1).saturating_mul(span) <= now
                }
            };
            done && window.len() >= detector.policy.consecutive
        })
        .map(|(_, window)| window)
        .collect()
}

/// The whole state a window's providers read: the facts of every run, a
/// minted T2's reviewed examples, and a session's readable text. Of runs,
/// counts, signals and grades only, no query or result text; of a session,
/// its own words as its reader may read them off this device. Nothing is
/// cut: past `limits.maintenance_text_bytes` or `limits.maintenance_row_items`
/// the pass asks and reads on.
fn state_of(
    vault: &oneiron::Vault,
    runs: &[RetrievalRunRecord],
    examples: Option<&serde_json::Value>,
    session: Option<&SessionText>,
) -> oneiron::Result<serde_json::Value> {
    let facts = run_facts(runs);
    let mut items = facts.len();
    let mut state = serde_json::json!({ "runs": facts });
    if let Some(examples) = examples {
        items += examples["findings"].as_array().map_or(0, Vec::len);
        state["examples"] = examples.clone();
    }
    if let Some(session) = session {
        items += session.lines.len();
        state["session"] = serde_json::to_value(session)
            .map_err(|_| oneiron::Error::InvariantViolation("session text encode"))?;
    }
    let bytes = serde_json::to_vec(&state).map_or(0, |bytes| bytes.len());
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, items as u64);
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, bytes as u64);
    Ok(state)
}

/// A minted T2's reviewed examples, positives first, each finding with every
/// one of its runs' facts.
fn example_facts(examples: &[MintedExample]) -> serde_json::Value {
    let mut shown = Vec::with_capacity(examples.len());
    for positive in [true, false] {
        for example in examples.iter().filter(|e| e.positive == positive) {
            shown.push(serde_json::json!({
                "finding": example.event_id.to_hex(),
                "positive": positive,
                "runs": run_facts(&example.runs),
            }));
        }
    }
    serde_json::json!({ "findings": shown })
}

/// The facts of `runs`, oldest first: counts, signals and grades only.
fn run_facts(runs: &[RetrievalRunRecord]) -> Vec<serde_json::Value> {
    runs.iter()
        .map(|run| {
            serde_json::json!({
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
            })
        })
        .collect()
}
