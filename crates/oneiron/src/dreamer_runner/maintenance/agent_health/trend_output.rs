//! The daily trend pass and its output (OF-568 L3). One pass per Coach
//! nightly wake (`coach.health_trends`), beside the agent-health review,
//! which it neither replaces nor gates. It reads the comparison policy and
//! the rollups, reviews them, and writes one additive `agent_health`
//! DIAGNOSTIC per worsening comparison of an actor or a bound project whose
//! metric files under a T1 signal: a signal rate as itself, spend as
//! `cost_spike`, wait as `long_wait`. Attempts, calls and retries, and the
//! unbound project, stay in the review; the actor margin carries that work.
//!
//! No card, notification, Coach note, threshold or hold: a worsening is an
//! observation about the work, never a score of the agent, and it never
//! reaches reliability or payoff. A DIAGNOSTIC is written once: the same
//! comparison over the same evidence is the same body and the same id, its
//! replay hash binding the window, the policy and every typed ref. A failed
//! write is warned, kind only, and the pass goes on to the next comparison.

use std::collections::BTreeSet;

use rmpv::Value;

use super::rollups::{HealthTrendRollups, TrendMargin, TrendSource, health_trend_rollups};
use super::trend::{
    HealthTrendComparison, HealthTrendInput, TrendDirection, TrendSide, review_health_trends,
};
use super::trend_policy::{DetectionDialChanges, SECONDS_PER_DAY};
use crate::entity_id::bytes_to_hex_lower;
use crate::limit_ask::EngineLimit;
use crate::self_heal::{
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, diagnostic_event_id, encode_diagnostic_event_body,
};
use crate::{EntityId, Result, Vault};

/// Every trend DIAGNOSTIC's detector id starts so; the rollups never read
/// one back as a finding.
pub(super) const TREND_DETECTOR_PREFIX: &str = "coach.agent_health.trend.";
const TREND_DIGEST_DOMAIN: &[u8] = b"oneiron.coach.agent_health.trend.v1";

/// `result`'s value, or `None` with `source` named failed and a kind-only
/// warning: every read the pass makes goes through it.
pub(super) fn soft<T>(
    failed: &mut BTreeSet<TrendSource>,
    source: TrendSource,
    result: Result<T>,
) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(
                source = ?source,
                kind = ?error.kind(),
                "agent-health trend source not read"
            );
            failed.insert(source);
            None
        }
    }
}

/// One trend pass at `now`, unix seconds. Returns the DIAGNOSTICs it wrote.
/// It never fails: a source it cannot read leaves its comparisons unknown,
/// and a write that fails is skipped, each with a kind-only warning.
pub(crate) fn run_health_trends(vault: &Vault, now: u64) -> u64 {
    let today = now / SECONDS_PER_DAY;
    // The dial rows and the rollups read one snapshot, so a dial set between
    // two reads never passes as unchanged (FIX 8358).
    let mut unread = BTreeSet::new();
    let opened = vault.store.env.read_txn().map_err(crate::Error::from);
    let (dial_changes, rollups) = match soft(&mut unread, TrendSource::Attempts, opened) {
        Some(rtxn) => (
            soft(
                &mut BTreeSet::new(),
                TrendSource::DialRows,
                DetectionDialChanges::read_in(vault, &rtxn),
            ),
            health_trend_rollups(vault, &rtxn, today),
        ),
        None => (
            None,
            HealthTrendRollups {
                failed: unread,
                ..HealthTrendRollups::default()
            },
        ),
    };
    let review = review_health_trends(&HealthTrendInput {
        today,
        rollups,
        dial_changes,
    });
    let mut written = 0;
    for comparison in review
        .comparisons
        .iter()
        .filter(|comparison| comparison.direction == TrendDirection::Worsening)
    {
        match emit(vault, comparison) {
            Ok(true) => written += 1,
            Ok(false) => {}
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "agent-health trend DIAGNOSTIC not written"
            ),
        }
    }
    tracing::debug!(
        comparisons = review.comparisons.len(),
        written,
        failed = ?review.failed,
        unreadable_attempts = review.unreadable_attempts,
        withheld_diagnostics = review.withheld_diagnostics,
        unjoined_diagnostics = review.unjoined_diagnostics,
        "agent-health trend pass"
    );
    written
}

/// Writes one worsening comparison's DIAGNOSTIC, once. `false`: its metric
/// files under no signal, its margin is the unbound project, or the same
/// body is already stored.
fn emit(vault: &Vault, comparison: &HealthTrendComparison) -> Result<bool> {
    let Some(signal) = comparison.metric.signal() else {
        return Ok(false);
    };
    let (actor_class, actor_ref, run_ref, project) = match &comparison.margin {
        TrendMargin::Actor(actor) => ("agent", Some(*actor), None, None),
        TrendMargin::Project(Some(project)) => (
            "system",
            None,
            Some(format!(
                "project:{}",
                bytes_to_hex_lower(project.as_bytes())
            )),
            Some(*project),
        ),
        TrendMargin::Project(None) => return Ok(false),
    };
    let mut evidence: Vec<EntityId> = comparison
        .prior
        .refs
        .iter()
        .chain(&comparison.latest.refs)
        .copied()
        .chain(project)
        .collect();
    evidence.sort_unstable();
    evidence.dedup();
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, evidence.len() as u64);
    let (from, to) = comparison.latest.days;
    let event = DiagnosticEvent {
        detector_id: format!("{TREND_DETECTOR_PREFIX}{}.v1", signal.as_str()),
        event_class: DiagnosticEventClass::AgentHealth,
        signal: Some(signal),
        actor_class: actor_class.into(),
        actor_ref,
        source: DiagnosticSourceKind::Receipt,
        criticality: DiagnosticCriticality::Normal,
        expected: side_value(&comparison.prior),
        actual: side_value(&comparison.latest),
        delta: comparison.delta.map_or(Value::Nil, Value::F64),
        replay: DiagnosticReplayCoordinate {
            content_hash: content_hash(comparison),
            run_ref,
            checkpoint_ref: None,
        },
        evidence_refs: evidence,
        valid_from: from.saturating_mul(SECONDS_PER_DAY),
        valid_to: Some(to.saturating_mul(SECONDS_PER_DAY)),
    };
    let body = encode_diagnostic_event_body(&event)?;
    let id = diagnostic_event_id(&event.detector_id, &body);
    let stored = {
        let rtxn = vault.store.env.read_txn()?;
        vault.get_raw_in(&rtxn, &id)?.is_some()
    };
    if stored {
        return Ok(false);
    }
    vault.emit_diagnostic_event(&id, &event)?;
    Ok(true)
}

/// One side as the body carries it: its value (nil when unknown), its
/// numerator, denominator, known and eligible counts, and its bounds in
/// unix seconds.
fn side_value(side: &TrendSide) -> Value {
    Value::Array(vec![
        side.ratio.value().map_or(Value::Nil, Value::F64),
        Value::from(side.ratio.numerator),
        Value::from(side.ratio.denominator),
        Value::from(side.ratio.known),
        Value::from(side.ratio.eligible),
        Value::from(side.days.0.saturating_mul(SECONDS_PER_DAY)),
        Value::from(side.days.1.saturating_mul(SECONDS_PER_DAY)),
    ])
}

/// The replay hash: the margin, the stratum, the metric, and each side's
/// days (the policy's period), counts and every typed ref, spend scopes
/// included. The same evidence under the same policy is the same hash.
fn content_hash(comparison: &HealthTrendComparison) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(TREND_DIGEST_DOMAIN);
    match &comparison.margin {
        TrendMargin::Actor(actor) => {
            digest.update(b"actor");
            digest.update(actor.as_bytes());
        }
        TrendMargin::Project(project) => {
            digest.update(b"project");
            let bytes: [u8; 16] = project.as_ref().map_or([0_u8; 16], |id| *id.as_bytes());
            digest.update(&bytes);
        }
    }
    field(&mut digest, comparison.stratum.type_node.as_bytes());
    match &comparison.stratum.model {
        Some(model) => field(&mut digest, model.as_bytes()),
        None => {
            digest.update(&[0xff]);
        }
    }
    field(&mut digest, comparison.metric.token().as_bytes());
    for side in [&comparison.prior, &comparison.latest] {
        for number in [
            side.days.0,
            side.days.1,
            side.ratio.numerator,
            side.ratio.denominator,
            side.ratio.known,
            side.ratio.eligible,
        ] {
            digest.update(&number.to_le_bytes());
        }
        for ids in [&side.attempts, &side.refs] {
            digest.update(&(ids.len() as u64).to_le_bytes());
            for id in ids {
                digest.update(id.as_bytes());
            }
        }
        digest.update(&(side.scopes.len() as u64).to_le_bytes());
        for scope in &side.scopes {
            field(&mut digest, scope.as_bytes());
        }
    }
    *digest.finalize().as_bytes()
}

/// One length-prefixed field, so no two field lists hash alike.
fn field(digest: &mut blake3::Hasher, bytes: &[u8]) {
    digest.update(&(bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}
