//! The closed-form detectors over one review's working set, one per signal.
//! Entry: the `*_findings` functions; `said_blocked` and `covered` are shared.
//! Each returns `Finding`s; `pipeline` emits and merges them into cards.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    AgentHealthCounter, Attempts, DialBook, Dispatched, Dispatches, Finding, Traps, WAIT_PERSON,
    brief, dup_cost_unit, duplicate, entity, settled, task_of,
};
use crate::agent_dispatch::{AgentDispatcher, SpendScope, SpendState};
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState};
use crate::edge::EdgeKind;
use crate::learning::{
    DuplicateLabeller, DuplicateWorkKind, TeamEvent, project_run_coordination,
    team_events_from_attempts,
};
use crate::llm::DreamerTrapKind;
use crate::llm::run_admission::LeaseUnit;
use crate::ports::EdgeDirection;
use crate::self_heal::AgentHealthSignal;
use crate::{EntityId, Result, Vault};

/// `long_wait`: an attempt that spent more than the dial's share of its life
/// waiting, not on a person, over at least the dial's minutes. A settled
/// attempt's life is closed. A live one's runs to now, and its open trap
/// waits on a peer or on budget count to now; a wait for a person's answer
/// or consent does not.
pub(super) fn long_wait_findings(
    dispatched: &Dispatches,
    attempts: &Attempts,
    traps: &Traps,
    book: &DialBook,
    since: u64,
    now: u64,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for (id, dispatch) in dispatched {
        let Some(record) = attempts.get(id) else {
            continue;
        };
        let live = matches!(record.state, AttemptState::Leased | AttemptState::Paused);
        if !live && (!settled(record.state) || record.updated_at < since) {
            continue;
        }
        let dials = book.of(Some(dispatch));
        let end = if live { now } else { record.updated_at };
        let life = end.saturating_sub(record.created_at);
        if life == 0 || life < dials.wait_secs {
            continue;
        }
        let mut spans = Vec::new();
        let mut queue = 0_u64;
        for event in team_events_from_attempts(std::slice::from_ref(record)) {
            if let TeamEvent::Wait {
                reason, start, end, ..
            } = event
                && reason != WAIT_PERSON
            {
                if reason == crate::learning::coordination::WAIT_QUEUE {
                    queue += end.saturating_sub(start);
                }
                spans.push((start, end));
            }
        }
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        let mut evidence = vec![attempt];
        if live {
            for trap in traps.get(id).into_iter().flatten() {
                if matches!(
                    trap.kind,
                    DreamerTrapKind::PeerResult | DreamerTrapKind::Budget
                ) {
                    spans.push((trap.opened_at_ms / 1000, now));
                    evidence.push(trap.anchor);
                }
            }
        }
        let wait = covered(spans);
        let share = wait as f64 / life as f64;
        if share <= dials.wait_share {
            continue;
        }
        let permille = (share * 1000.0).round() as i64;
        let mut counter = Vec::new();
        if queue * 2 > wait {
            counter.push(AgentHealthCounter::QueueWait);
        }
        out.push(Finding {
            subject: dispatch.actor,
            signal: AgentHealthSignal::LongWait,
            task: task_of(record),
            attempt: Some(record.id),
            evidence,
            window: (record.created_at, end),
            // A live share moves on every review; the DIAGNOSTIC carries it in
            // tenths, so it is written again only when it crosses one.
            actual: if live { permille / 100 * 100 } else { permille },
            dial: (dials.wait_share * 1000.0).round() as i64,
            measured: permille,
            counter,
            confession: None,
            blocked: false,
            observed_brief: None,
            silence: None,
        });
    }
    out
}

/// Seconds covered by the union of `spans`.
pub(super) fn covered(mut spans: Vec<(u64, u64)>) -> u64 {
    spans.sort_unstable();
    let mut total = 0;
    let mut reach = 0;
    for (start, end) in spans {
        let start = start.max(reach);
        if end > start {
            total += end - start;
            reach = end;
        }
    }
    total
}

/// `cost_spike`: an attempt's own spend over the dial times the p90 of its
/// task type's settled runs in the same unit, every retained one read, from
/// at least its `health.cost.min_runs` of them. With fewer, it is held against
/// the plan's expected spend, at low confidence. Own spend is the launch scope's spend
/// less what its settled children spent. Retries share one scope, so a scope
/// counts once, on its newest attempt.
pub(super) fn cost_spike_findings(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    book: &DialBook,
    since: u64,
    now: u64,
) -> Result<Vec<Finding>> {
    let dispatcher = AgentDispatcher::new(vault);
    let mut scopes: BTreeMap<String, ([u8; 16], SpendScope)> = BTreeMap::new();
    for key in dispatched.keys() {
        let Some(record) = attempts.get(key) else {
            continue;
        };
        let Some(scope_id) = dispatcher.spend_scope_for_attempt(record.id)? else {
            continue;
        };
        let name = scope_id.to_string();
        let newer = scopes
            .get(&name)
            .and_then(|(held, _)| attempts.get(held))
            .is_none_or(|held| held.updated_at <= record.updated_at);
        if newer && let Some(scope) = dispatcher.read_spend_scope(&scope_id)? {
            scopes.insert(name, (*key, scope));
        }
    }
    let mut children: BTreeMap<String, u64> = BTreeMap::new();
    for (_, scope) in scopes.values() {
        if scope.state == SpendState::Closed
            && let Some(parent) = &scope.parent
        {
            *children.entry(parent.to_string()).or_default() += scope.spent_units;
        }
    }
    let own = |name: &str, scope: &SpendScope| {
        scope
            .spent_units
            .saturating_sub(children.get(name).copied().unwrap_or(0))
    };
    let mut history: BTreeMap<(&str, &LeaseUnit), Vec<(&str, u64)>> = BTreeMap::new();
    for (name, (key, scope)) in &scopes {
        if let (Some(record), Some(dispatch)) = (attempts.get(key), dispatched.get(key))
            && settled(record.state)
            && scope.state == SpendState::Closed
        {
            history
                .entry((dispatch.type_node.as_str(), &scope.unit))
                .or_default()
                .push((name.as_str(), own(name, scope)));
        }
    }
    let mut out = Vec::new();
    for (name, (key, scope)) in &scopes {
        let (Some(record), Some(dispatch)) = (attempts.get(key), dispatched.get(key)) else {
            continue;
        };
        let dials = book.of(Some(dispatch));
        let live = record.state == AttemptState::Leased;
        if !live && (!settled(record.state) || record.updated_at < since) {
            continue;
        }
        let spent = own(name, scope);
        let runs: Vec<u64> = history
            .get(&(dispatch.type_node.as_str(), &scope.unit))
            .into_iter()
            .flatten()
            .filter(|(run, _)| *run != name.as_str())
            .map(|(_, spent)| *spent)
            .collect();
        let (baseline, counter) = if runs.len() >= dials.cost_min_runs {
            (p90(runs), Vec::new())
        } else {
            match &dispatch.expected {
                Some((unit, units)) if *unit == scope.unit => {
                    (*units, vec![AgentHealthCounter::FewRuns])
                }
                _ => continue,
            }
        };
        if baseline == 0 || spent == 0 {
            continue;
        }
        let ratio = spent as f64 / baseline as f64;
        if ratio <= dials.cost_spike {
            continue;
        }
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        let permille = (ratio * 1000.0).round() as i64;
        out.push(Finding {
            subject: dispatch.actor,
            signal: AgentHealthSignal::CostSpike,
            task: task_of(record),
            attempt: Some(record.id),
            evidence: vec![attempt],
            window: (
                record.created_at,
                if live { now } else { record.updated_at },
            ),
            // A live ratio moves on every review; the DIAGNOSTIC carries it in
            // halves, so it is written again only when it crosses one.
            actual: if live { permille / 500 * 500 } else { permille },
            dial: (dials.cost_spike * 1000.0).round() as i64,
            measured: permille,
            counter,
            confession: None,
            blocked: false,
            observed_brief: None,
            silence: None,
        });
    }
    Ok(out)
}

/// The 90th percentile, by nearest rank, of `values` (not empty).
fn p90(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    let rank = (values.len() * 9).div_ceil(10).max(1);
    values[rank - 1]
}

/// Whether the agent said it was stuck: its TASK is Blocked, or it filed a
/// blocked report (`self.report_blocked`) at or after `since` that is
/// unbound or bound to `attempt`.
pub(super) fn said_blocked(
    vault: &Vault,
    actor: EntityId,
    task: Option<EntityId>,
    since: u64,
    attempt: Option<AttemptId>,
) -> Result<bool> {
    let recent = {
        let rtxn = vault.store.env.read_txn()?;
        if let Some(task) = task
            && crate::task_verb::task_is_blocked_in(vault, &rtxn, task)?
        {
            return Ok(true);
        }
        let mut recent = Vec::new();
        for id in vault.filtered_edge_peers(
            &rtxn,
            EdgeDirection::In,
            &actor,
            EdgeKind::AuthoredBy,
            Some(crate::registry::ENTITY_TYPE_MESSAGE),
        )? {
            let at = vault
                .get_raw_in(&rtxn, &id)?
                .as_deref()
                .and_then(crate::batch::EntityMetadataHeader::parse)
                .map_or(0, |header| unix_secs(header.occurred_start));
            if at >= since {
                recent.push(id);
            }
        }
        recent
    };
    // The report reader opens its own snapshot. A report the host bound to
    // another attempt of the same agent speaks for that one only.
    for id in recent {
        if crate::code_run::blocked::read_blocked_receipt(vault, &id)?
            .is_some_and(|receipt| receipt.speaks_for(attempt))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A stored time in seconds, whether it was written in seconds or in
/// milliseconds.
const fn unix_secs(at: u64) -> u64 {
    if at >= 100_000_000_000 { at / 1000 } else { at }
}

/// `duplicate_work`: each attempt that ran an action another attempt ran
/// first on the same inputs, unplanned (`duplicate`, OF-568), and its team's
/// audit-labelled redundant duplicates. The card goes on the agent that did
/// the second piece of work, once per attempt, unless that work cost less
/// than its `health.dup.min_cost` (its launch scope's spend, children
/// included). Every digest pair comes back too, for its label.
pub(super) fn duplicate_findings(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    book: &DialBook,
    since: u64,
    now: u64,
) -> Result<(Vec<Finding>, Vec<duplicate::DigestPair>)> {
    let dispatcher = AgentDispatcher::new(vault);
    let cheap = |record: &AttemptRecord, dispatch: &Dispatched| -> Result<bool> {
        let floor = book.of(Some(dispatch)).dup_min_cost;
        if floor > 0
            && let Some(scope_id) = dispatcher.spend_scope_for_attempt(record.id)?
            && let Some(scope) = dispatcher.read_spend_scope(&scope_id)?
        {
            return Ok(scope.unit == dup_cost_unit() && scope.spent_units < floor);
        }
        Ok(false)
    };
    let mut out = Vec::new();
    let mut found = BTreeSet::new();
    let pairs = duplicate::digest_duplicates(vault, dispatched, attempts, since)?;
    let mut repeats: BTreeMap<[u8; 16], BTreeSet<[u8; 16]>> = BTreeMap::new();
    for pair in pairs
        .iter()
        .filter(|pair| pair.kind == DuplicateWorkKind::Redundant)
    {
        repeats.entry(pair.second).or_default().insert(pair.first);
    }
    for (key, firsts) in repeats {
        let (Some(record), Some(dispatch)) = (attempts.get(&key), dispatched.get(&key)) else {
            continue;
        };
        if cheap(record, dispatch)? {
            continue;
        }
        let evidence = std::iter::once(record)
            .chain(firsts.iter().filter_map(|first| attempts.get(first)))
            .filter_map(|record| entity(record.id))
            .collect();
        found.insert(key);
        out.push(dup_finding(record, dispatch, evidence));
    }
    // Labels are kept per team, by its stamp's reference, not a queue run.
    let teams: BTreeSet<String> = dispatched
        .keys()
        .filter_map(|id| attempts.get(id))
        .filter(|record| record.updated_at >= since)
        .filter_map(team_of)
        .collect();
    for team in &teams {
        let cost = project_run_coordination(vault, team, now)?;
        for label in &cost.duplicate_work {
            // Only a redundant repeat is waste; a planned check is not. The
            // recipe's own labels restate its digest findings above.
            if label.kind != DuplicateWorkKind::Redundant
                || label.labelled_by == DuplicateLabeller::Health
            {
                continue;
            }
            // A work reference is the TASK the attempt did, or the attempt.
            let does = |reference: &str| {
                dispatched.iter().find_map(|(key, dispatch)| {
                    attempts
                        .get(key)
                        .filter(|record| {
                            team_of(record).as_ref() == Some(team)
                                && (record.task_ref.as_deref() == Some(reference)
                                    || crate::entity_id::bytes_to_hex_lower(key) == reference)
                        })
                        .map(|record| (record, dispatch))
                })
            };
            let Some((record, dispatch)) = does(&label.second) else {
                continue;
            };
            if found.contains(record.id.as_bytes()) || cheap(record, dispatch)? {
                continue;
            }
            let mut evidence: Vec<EntityId> =
                [Some(record), does(&label.first).map(|(first, _)| first)]
                    .into_iter()
                    .flatten()
                    .filter_map(|record| entity(record.id))
                    .collect();
            evidence.extend(EntityId::from_hex(&label.receipt).ok());
            out.push(dup_finding(record, dispatch, evidence));
        }
    }
    Ok((out, pairs))
}

/// The team an attempt's dispatch stamped it into.
fn team_of(record: &AttemptRecord) -> Option<String> {
    crate::agent_dispatch::attempt_team_stamp(record)
        .ok()
        .flatten()
        .map(|stamp| stamp.team_ref)
}

/// One `duplicate_work` finding on the attempt that did the second piece of
/// work.
fn dup_finding(record: &AttemptRecord, dispatch: &Dispatched, evidence: Vec<EntityId>) -> Finding {
    Finding {
        subject: dispatch.actor,
        signal: AgentHealthSignal::DuplicateWork,
        task: task_of(record),
        attempt: Some(record.id),
        evidence,
        window: (record.created_at, record.updated_at),
        actual: 1,
        dial: 0,
        measured: 1,
        counter: Vec::new(),
        confession: None,
        blocked: false,
        observed_brief: None,
        silence: None,
    }
}

/// `misalignment`: an audit found a flaw in an objective the agent's
/// confession called met with no flaw. A confession alone never flags.
pub(super) fn misalignment_findings(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    since: u64,
) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    for (id, dispatch) in dispatched {
        let Some(record) = attempts.get(id) else {
            continue;
        };
        if !settled(record.state) || record.updated_at < since {
            continue;
        }
        let Some(sealed) = vault.sealed_attempt_receipt(record.id)? else {
            continue;
        };
        let mut unreported = BTreeSet::new();
        let mut evidence = Vec::new();
        let mut checked_at = sealed.sealed_at;
        for check in &sealed.checks {
            let Some(outcome) = &check.outcome else {
                continue;
            };
            for finding in outcome
                .findings
                .iter()
                .filter(|finding| finding.flaw_present)
            {
                let reported = sealed
                    .confession
                    .objectives
                    .iter()
                    .any(|said| said.objective == finding.objective && said.confesses_flaw());
                if !reported && unreported.insert(finding.objective.as_str()) {
                    evidence.extend(EntityId::from_hex(&finding.evidence_ref).ok());
                    checked_at = checked_at.max(outcome.checked_at);
                }
            }
        }
        if unreported.is_empty() {
            continue;
        }
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        evidence.insert(0, attempt);
        let count = unreported.len() as i64;
        out.push(Finding {
            subject: dispatch.actor,
            signal: AgentHealthSignal::Misalignment,
            task: task_of(record),
            attempt: Some(record.id),
            evidence,
            window: (sealed.sealed_at, checked_at),
            actual: count,
            dial: 0,
            measured: count,
            counter: Vec::new(),
            confession: Some(attempt),
            blocked: false,
            observed_brief: None,
            silence: None,
        });
    }
    Ok(out)
}

/// `misalignment`: one attempt raised at least the dial's widen proposals in
/// the review window that the board has not approved, pending or declined
/// alike. A declined proposal stays the board's refusal on record.
pub(super) fn widen_denial_findings(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    book: &DialBook,
    since: u64,
) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    for (id, denials) in crate::agent_dispatch::unlanded_widens_by_parent_since(vault, since)? {
        let (Some(dispatch), Some(record)) = (dispatched.get(&id), attempts.get(&id)) else {
            continue;
        };
        let dials = book.of(Some(dispatch));
        if denials < dials.widen_denials {
            continue;
        }
        if settled(record.state) && record.updated_at < since {
            continue;
        }
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        let count = denials as i64;
        out.push(Finding {
            subject: dispatch.actor,
            signal: AgentHealthSignal::Misalignment,
            task: task_of(record),
            attempt: Some(record.id),
            evidence: vec![attempt],
            window: (
                record.claimed_at.unwrap_or(record.created_at),
                record.updated_at,
            ),
            actual: count,
            dial: dials.widen_denials as i64,
            measured: count,
            counter: Vec::new(),
            confession: None,
            blocked: false,
            observed_brief: None,
            silence: None,
        });
    }
    Ok(out)
}

/// `unsupported_done`: a Completed attempt whose TASK settled Done while an
/// evidence ref its done-means names does not resolve to a live entity.
/// Missing evidence, not deception: any one flags. The finding pins the
/// TASK's brief under the same read its done-means came from.
pub(super) fn unsupported_done_findings(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    since: u64,
    now: u64,
) -> Result<Vec<Finding>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for (id, dispatch) in dispatched {
        let Some(record) = attempts.get(id) else {
            continue;
        };
        if record.state != AttemptState::Completed || record.updated_at < since {
            continue;
        }
        let (Some(task), Some(attempt)) = (task_of(record), entity(record.id)) else {
            continue;
        };
        let Some(needed) = crate::task_verb::done_task_evidence_in(vault, &rtxn, task)? else {
            continue;
        };
        let mut missing = BTreeSet::new();
        for evidence in needed {
            if !crate::vault::live_entity_row_in_txn(&vault.store, &rtxn, &evidence)?.is_live() {
                missing.insert(evidence);
            }
        }
        if missing.is_empty() {
            continue;
        }
        let count = missing.len() as i64;
        let observed_brief = brief::pin_task_brief_in(vault, &rtxn, task, now)?;
        out.push(Finding {
            subject: dispatch.actor,
            signal: AgentHealthSignal::UnsupportedDone,
            task: Some(task),
            attempt: Some(record.id),
            evidence: vec![attempt, task],
            window: (
                record.claimed_at.unwrap_or(record.created_at),
                record.updated_at,
            ),
            actual: count,
            dial: 0,
            measured: count,
            counter: Vec::new(),
            confession: None,
            blocked: false,
            observed_brief,
            silence: None,
        });
    }
    Ok(out)
}
