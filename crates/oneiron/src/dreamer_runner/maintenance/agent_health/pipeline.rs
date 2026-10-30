//! One review: detect, emit each finding as a DIAGNOSTIC, route and merge.
//! Entry: `run` (the nightly review) and `land` (shared with `targeted`).
//! Owns `Route` and the card merge; the detectors are in `detectors`.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use rmpv::Value;

use super::erase::sync_card_membership;
use super::{
    AgentHealthCard, AgentHealthConfidence, AgentHealthMove, AgentHealthOutcome, AgentHealthTone,
    Attempts, CARDS, DialBook, Dispatched, Dispatches, Finding, HEALTH_DIGEST_DOMAIN,
    HealthCauseSource, SilenceCalls, SilenceRefresh, Traps, brief, call_evidence, call_loop,
    card_key, check_repeat, cost_spike_findings, duplicate, duplicate_findings, entity,
    environment, long_wait_findings, misalignment_findings, run_loop, said_blocked,
    silent_findings, unsupported_done_findings, widen_denial_findings,
};
use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::learning::{DuplicateLabeller, DuplicateWork, label_duplicate_work};
use crate::limit_ask::EngineLimit;
use crate::llm::open_trap_waits;
use crate::self_heal::{
    AgentHealthSignal, DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass,
    DiagnosticReplayCoordinate, DiagnosticSourceKind, diagnostic_event_id,
    encode_diagnostic_event_body,
};
use crate::{EntityId, Result, Vault};

/// One review: detect, emit, merge, escalate. Returns the cards it touched.
/// Each dial is read for the project and task type of the attempt it judges.
pub(in crate::dreamer_runner::maintenance) fn run(vault: &Vault, now: u64) -> Result<u64> {
    let attempts: Attempts = AttemptQueue::new(vault)
        .list()?
        .into_iter()
        .map(|record| (*record.id.as_bytes(), record))
        .collect();
    let dispatched: Dispatches = attempts
        .iter()
        .filter_map(|(key, record)| Dispatched::of(record).map(|dispatch| (*key, dispatch)))
        .collect();
    let book = DialBook::read(vault, &dispatched)?;
    if !book.any_review() {
        return Ok(0);
    }
    let mut traps = Traps::new();
    for wait in open_trap_waits(vault)? {
        traps
            .entry(*wait.attempt.as_bytes())
            .or_default()
            .push(wait);
    }

    // Each scope reads back over its own `health.review.window_hours`: one
    // pass per distinct window, each finding and digest pair kept from the
    // pass of its own scope's window. With every scope on one window, that
    // is a single pass.
    let mut findings = Vec::new();
    let mut digest_pairs = Vec::new();
    let mut refreshes = Vec::new();
    for window in book.windows() {
        let since = now.saturating_sub(window);
        let (found, pairs, refreshed) =
            detect(vault, &dispatched, &attempts, &traps, &book, since, now)?;
        refreshes.extend(refreshed.into_iter().filter(|refresh| {
            book.for_attempt(&dispatched, Some(refresh.attempt))
                .window_secs
                == window
        }));
        findings.extend(found.into_iter().filter(|finding| {
            book.for_attempt(&dispatched, finding.attempt).window_secs == window
        }));
        digest_pairs.extend(
            pairs
                .into_iter()
                .filter(|pair| book.of(dispatched.get(&pair.second)).window_secs == window),
        );
    }
    // A project or task type whose review is off keeps its findings unsaid,
    // and its cards as they stand.
    findings.retain(|finding| book.for_attempt(&dispatched, finding.attempt).review);
    refreshes.retain(|refresh| book.for_attempt(&dispatched, Some(refresh.attempt)).review);
    land(
        vault,
        findings,
        &digest_pairs,
        &refreshes,
        &dispatched,
        &attempts,
        &book,
        now,
        true,
    )
}

/// Lands one review's findings: what each agent said itself, each finding's
/// DIAGNOSTIC, the digest pairs' labels, then each card, and each open
/// `silent` card's refresh no finding of this review touched. With `escalate`, a
/// card its leader leaves open past the TTL also goes up to the owner: a
/// pass over every card, the nightly review's alone. Returns the cards it
/// touched.
#[allow(clippy::too_many_arguments)]
pub(super) fn land(
    vault: &Vault,
    mut findings: Vec<Finding>,
    digest_pairs: &[duplicate::DigestPair],
    refreshes: &[SilenceRefresh],
    dispatched: &Dispatches,
    attempts: &Attempts,
    book: &DialBook,
    now: u64,
    escalate: bool,
) -> Result<u64> {
    // What each agent said itself, for its card. A read that fails leaves
    // the card's mark as it stood, and the finding still lands.
    let mut blocked_unread = vec![false; findings.len()];
    for (finding, unread) in findings.iter_mut().zip(&mut blocked_unread) {
        let began = finding
            .attempt
            .and_then(|attempt| attempts.get(attempt.as_bytes()))
            .map_or(finding.window.0, |record| {
                record.claimed_at.unwrap_or(record.created_at)
            });
        match said_blocked(vault, finding.subject, finding.task, began, finding.attempt) {
            Ok(blocked) => finding.blocked = blocked,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "agent-health stuck mark not read for a finding; its card keeps its mark"
                );
                *unread = true;
            }
        }
    }

    // The attribution judge's labels on each finding's exact attempt
    // (OF-568 L10) and, at the nightly pass, on each open card's, so a label
    // that lands after its review still reaches its card. The Coach resolves
    // here: before the read snapshot, outside any writer.
    let causes = environment::attach(vault, &mut findings);
    let late = if escalate {
        environment::late(vault)
    } else {
        environment::Late::new()
    };
    let coach = environment::coach(vault, &causes, &late);

    // Each finding's DIAGNOSTIC, in its own write: the event door opens one.
    let mut emitted = Vec::with_capacity(findings.len());
    for (finding, causes) in findings.iter().zip(&causes) {
        emitted.push(emit(vault, finding, causes)?);
    }
    label_digest_pairs(vault, digest_pairs, &findings, &emitted, attempts)?;

    // Recipients from live authority: the project's effective leader, the
    // spawner by dispatch lineage, and the vault's live owners.
    let (owners, routes) = {
        let rtxn = vault.store.env.read_txn()?;
        // The brief each finding's TASK holds now: what this review observed.
        brief::pin_findings_in(vault, &rtxn, &mut findings, now);
        let owners = crate::policy_model::owners_in_txn(vault, &rtxn)?;
        let mut routes = Vec::with_capacity(findings.len());
        for finding in &findings {
            routes.push(route(vault, &rtxn, finding, dispatched, attempts, book)?);
        }
        (owners, routes)
    };

    vault.with_write_txn_grouped(|txn| {
        let mut touched = BTreeSet::new();
        for ((((finding, diagnostic), route), causes), unread) in findings
            .iter()
            .zip(&emitted)
            .zip(&routes)
            .zip(&causes)
            .zip(&blocked_unread)
        {
            let dials = book.for_attempt(dispatched, finding.attempt);
            if f64::from(AgentHealthTone::of(finding.signal).impact()) < dials.card_floor {
                continue;
            }
            let key = card_key(finding.subject, finding.signal, finding.task);
            let card = CARDS.get(&vault.store, txn, &key)?;
            // `merge` replaces the observed brief, whose TASK the draft names
            // (FIX 10434): the old row's membership is diffed below.
            let old_sources = card
                .as_ref()
                .map(|card| card.draft_source_rows())
                .unwrap_or_default();
            let kept = card.as_ref().is_some_and(|card| card.agent_blocked);
            let mut card = merge(
                card,
                finding,
                *diagnostic,
                route,
                &owners,
                dials.reviewer_revision(),
                now,
            );
            if *unread {
                card.agent_blocked = kept;
            }
            environment::fold_finding(vault, txn, &mut card, causes, coach);
            for items in [card.evidence.len(), card.diagnostics.len()] {
                let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, items as u64);
            }
            let new_sources = card.draft_source_rows();
            sync_card_membership(&vault.store, txn, &key, &old_sources, &new_sources)?;
            CARDS.put(&vault.store, txn, &key, &card)?;
            touched.insert(key);
        }
        // An open `silent` card whose attempt has spoken since shows what was
        // read now (FIX 8376); a finding this review merged holds its own.
        for refresh in refreshes {
            if touched.contains(&refresh.key) {
                continue;
            }
            let Some(mut card) = CARDS.get(&vault.store, txn, &refresh.key)? else {
                continue;
            };
            if card.outcome != AgentHealthOutcome::Open
                || card.attempt != entity(refresh.attempt)
                || card.silence == Some(refresh.silence)
            {
                continue;
            }
            card.silence = Some(refresh.silence);
            card.updated_at = now;
            CARDS.put(&vault.store, txn, &refresh.key, &card)?;
            touched.insert(refresh.key);
        }
        // A card its leader leaves open past the TTL goes up to the owner.
        let scan = if escalate {
            CARDS.scan(&vault.store, txn)?
        } else {
            Vec::new()
        };
        for (key, mut card) in scan {
            // A label that landed after its card's review (OF-568 L10).
            let mut changed = environment::fold_late(&mut card, &late, &key, coach, now);
            if card.outcome == AgentHealthOutcome::Open
                && !card.owner_copy
                && now
                    >= card.opened_at.saturating_add(
                        book.of(card
                            .attempt
                            .and_then(|attempt| dispatched.get(attempt.as_bytes())))
                            .ttl_secs,
                    )
            {
                card.owner_copy = true;
                add_recipients(&mut card.recipients, card.subject, &owners);
                changed = true;
            }
            if changed {
                CARDS.put(&vault.store, txn, &key, &card)?;
                touched.insert(key);
            }
        }
        // A touched card can arm the digest on its own (FIX 1979): its
        // deadline is read again once this write commits.
        if !touched.is_empty() {
            crate::batch::queue_proactivity_change(vault, txn);
        }
        Ok(touched.len() as u64)
    })
}

/// Every detector over the review window from `since`, the digest pairs
/// its duplicate findings came from, and the open `silent` cards to refresh.
fn detect(
    vault: &Vault,
    dispatched: &Dispatches,
    attempts: &Attempts,
    traps: &Traps,
    book: &DialBook,
    since: u64,
    now: u64,
) -> Result<(
    Vec<Finding>,
    Vec<duplicate::DigestPair>,
    Vec<SilenceRefresh>,
)> {
    // Each agent's calls, and their streams by the attempt each names
    // (OF-568 L4): `loop` and `failed_check_repeat` judge each stream as its
    // own; `silent` reads each leased attempt's own calls and its actor's
    // calls that name no attempt (OF-568 L5, `silence`).
    let (calls, unread_calls) = call_evidence::agent_calls(vault, since)?;
    let streams = call_evidence::call_streams(&calls);
    let mut findings = call_loop::loop_findings(&streams, dispatched, attempts, book);
    findings.extend(run_loop::run_loop_findings(
        vault, dispatched, attempts, book, since,
    )?);
    findings.extend(check_repeat::check_repeat_findings(
        vault, &streams, dispatched, attempts, book, since,
    )?);
    let (silent, refreshes) = silent_findings(
        vault,
        &SilenceCalls::Actors(&calls, unread_calls),
        dispatched,
        attempts,
        traps,
        book,
        now,
    );
    findings.extend(silent);
    findings.extend(long_wait_findings(
        dispatched, attempts, traps, book, since, now,
    ));
    let (duplicates, digest_pairs) =
        duplicate_findings(vault, dispatched, attempts, book, since, now)?;
    findings.extend(duplicates);
    findings.extend(misalignment_findings(vault, dispatched, attempts, since)?);
    findings.extend(widen_denial_findings(
        vault, dispatched, attempts, book, since,
    )?);
    findings.extend(unsupported_done_findings(
        vault, dispatched, attempts, since, now,
    )?);
    findings.extend(cost_spike_findings(
        vault, dispatched, attempts, book, since, now,
    )?);
    Ok((findings, digest_pairs, refreshes))
}

/// Writes each digest pair's `dup_of` label under its team (agent-mind §4.3:
/// "the health recipe or an audit writes it"), citing the DIAGNOSTIC its
/// finding emitted, else the second attempt's run record, which holds the
/// equal action digest. A pair with no team has no label key.
fn label_digest_pairs(
    vault: &Vault,
    pairs: &[duplicate::DigestPair],
    findings: &[Finding],
    emitted: &[EntityId],
    attempts: &Attempts,
) -> Result<()> {
    let diagnostics: BTreeMap<[u8; 16], EntityId> = findings
        .iter()
        .zip(emitted)
        .filter(|(finding, _)| matches!(finding.signal, AgentHealthSignal::DuplicateWork))
        .filter_map(|(finding, diagnostic)| Some((*finding.attempt?.as_bytes(), *diagnostic)))
        .collect();
    let hex = |record: &AttemptRecord| crate::entity_id::bytes_to_hex_lower(record.id.as_bytes());
    for pair in pairs {
        let (Some(team), Some(first), Some(second)) = (
            pair.team.as_deref(),
            attempts.get(&pair.first),
            attempts.get(&pair.second),
        ) else {
            continue;
        };
        // A work reference is the TASK the attempt did, or the attempt.
        let work = |record: &AttemptRecord| record.task_ref.clone().unwrap_or_else(|| hex(record));
        let (mut first_ref, mut second_ref) = (work(first), work(second));
        if first_ref == second_ref {
            (first_ref, second_ref) = (hex(first), hex(second));
        }
        label_duplicate_work(
            vault,
            team,
            &DuplicateWork {
                first: first_ref,
                second: second_ref,
                kind: pair.kind,
                labelled_by: DuplicateLabeller::Health,
                receipt: diagnostics
                    .get(&pair.second)
                    .map_or_else(|| hex(second), EntityId::to_hex),
            },
        )?;
    }
    Ok(())
}

/// The evaluator a finding's signal is judged by: its DIAGNOSTIC's detector
/// and the reviewer its card's outcomes score.
fn detector_id(signal: AgentHealthSignal) -> String {
    format!("coach.agent_health.{}.v1", signal.as_str())
}

/// Writes the finding's DIAGNOSTIC once: the same evidence is the same body
/// and the same id. It cites every evidence ref, and the source id of each
/// attribution label in `causes` (OF-568 L10); past
/// `limits.maintenance_row_items` it asks and cites them all.
fn emit(vault: &Vault, finding: &Finding, causes: &[HealthCauseSource]) -> Result<EntityId> {
    let mut evidence = finding.evidence.clone();
    // The labels ride on the DIAGNOSTIC alone: a card's evidence, and so its
    // watermark, never counts them.
    evidence.extend(causes.iter().map(|cause| cause.source));
    evidence.sort_unstable();
    evidence.dedup();
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, evidence.len() as u64);
    let mut digest = blake3::Hasher::new();
    digest.update(HEALTH_DIGEST_DOMAIN);
    digest.update(finding.signal.as_str().as_bytes());
    digest.update(finding.subject.as_bytes());
    for id in &evidence {
        digest.update(id.as_bytes());
    }
    let event = DiagnosticEvent {
        detector_id: detector_id(finding.signal),
        event_class: DiagnosticEventClass::AgentHealth,
        signal: Some(finding.signal),
        actor_class: "agent".into(),
        actor_ref: Some(finding.subject),
        source: DiagnosticSourceKind::Receipt,
        criticality: if AgentHealthTone::of(finding.signal) == AgentHealthTone::Concern {
            DiagnosticCriticality::Critical
        } else {
            DiagnosticCriticality::Normal
        },
        expected: Value::from(finding.dial),
        actual: Value::from(finding.actual),
        delta: Value::from(finding.actual - finding.dial),
        replay: DiagnosticReplayCoordinate {
            content_hash: *digest.finalize().as_bytes(),
            run_ref: finding.attempt.map(|attempt| {
                format!(
                    "attempt:{}",
                    crate::entity_id::bytes_to_hex_lower(attempt.as_bytes())
                )
            }),
            checkpoint_ref: None,
        },
        evidence_refs: evidence,
        valid_from: finding.window.0,
        valid_to: None,
    };
    let body = encode_diagnostic_event_body(&event)?;
    let id = diagnostic_event_id(&event.detector_id, &body);
    let stored = {
        let rtxn = vault.store.env.read_txn()?;
        vault.get_raw_in(&rtxn, &id)?.is_some()
    };
    if !stored {
        vault.emit_diagnostic_event(&id, &event)?;
    }
    Ok(id)
}

/// Who a finding's card goes to, and whether the owner gets a copy now.
struct Route {
    recipients: Vec<EntityId>,
    owner_copy: bool,
}

/// A concern, a card on the project's own leader and a card with no other
/// recipient always copy to the owner; `health.card.owner_copy` copies every
/// other card too, and never takes one of those away.
fn route(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    finding: &Finding,
    dispatched: &Dispatches,
    attempts: &Attempts,
    book: &DialBook,
) -> Result<Route> {
    let dispatch = finding
        .attempt
        .and_then(|attempt| dispatched.get(attempt.as_bytes()));
    // A helper's card goes to its spawner, which already controls it.
    let spawner = dispatch
        .and_then(|dispatch| dispatch.parent)
        .and_then(|parent| attempts.get(parent.as_bytes()))
        .and_then(Dispatched::of)
        .map(|parent| parent.actor);
    // The project's effective leader, never a stored claim of one.
    let leader = match dispatch.and_then(|dispatch| dispatch.project) {
        Some(project) => vault
            .effective_project_in_txn(txn, project)?
            .and_then(|(_, effective)| EntityId::from_hex(&effective.leader).ok()),
        None => None,
    };
    let mut recipients = Vec::new();
    add_recipients(
        &mut recipients,
        finding.subject,
        &[leader, spawner].into_iter().flatten().collect::<Vec<_>>(),
    );
    let owner_copy = AgentHealthTone::of(finding.signal) == AgentHealthTone::Concern
        || leader == Some(finding.subject)
        || recipients.is_empty()
        || book.of(dispatch).owner_copy;
    Ok(Route {
        recipients,
        owner_copy,
    })
}

/// Adds each of `ids` once, never the card's own subject.
pub(super) fn add_recipients(recipients: &mut Vec<EntityId>, subject: EntityId, ids: &[EntityId]) {
    for id in ids {
        if *id != subject && !recipients.contains(id) {
            recipients.push(*id);
        }
    }
}

/// Adds each of `more` once, after every id the card already holds. One set
/// built from the held ids makes each test constant time (FIX 6006).
fn add_ids(ids: &mut Vec<EntityId>, more: &[EntityId]) {
    let mut seen: HashSet<EntityId> = ids.iter().copied().collect();
    for id in more {
        if seen.insert(*id) {
            ids.push(*id);
        }
    }
}

fn moves(signal: AgentHealthSignal) -> Vec<AgentHealthMove> {
    use AgentHealthMove::{AskCoach, Budget, Hold, Note, Reassign, Steer};
    match signal {
        AgentHealthSignal::Loop | AgentHealthSignal::FailedCheckRepeat => {
            vec![Steer, Note, AskCoach, Hold]
        }
        AgentHealthSignal::Silent => vec![Note, Steer, Reassign, Hold],
        AgentHealthSignal::LongWait => vec![Note, Reassign, Budget],
        AgentHealthSignal::CostSpike => vec![Budget, Steer, Hold],
        AgentHealthSignal::DuplicateWork => vec![Note, Reassign, Hold],
        AgentHealthSignal::UnsupportedDone => vec![Note, Steer, AskCoach],
        AgentHealthSignal::Misalignment => vec![AskCoach, Hold, Reassign, Note],
    }
}

/// Merges a finding into its card. Repeats grow one card; a settled card stays
/// quiet until its evidence grows past its watermark. `revision` is the
/// reviewer revision that seeded the finding's dials, if one did.
fn merge(
    card: Option<AgentHealthCard>,
    finding: &Finding,
    diagnostic: EntityId,
    route: &Route,
    owners: &[EntityId],
    revision: Option<EntityId>,
    now: u64,
) -> AgentHealthCard {
    let mut card = card.unwrap_or_else(|| AgentHealthCard {
        subject: finding.subject,
        signal: finding.signal,
        task: finding.task,
        attempt: None,
        witnessed_attempts: Vec::new(),
        tone: AgentHealthTone::of(finding.signal),
        tier: 1,
        confidence: AgentHealthConfidence::High,
        diagnostics: Vec::new(),
        evidence: Vec::new(),
        window_from: finding.window.0,
        window_to: finding.window.1,
        measured: 0,
        dial: 0,
        counter_evidence: Vec::new(),
        agent_blocked: false,
        confession: None,
        moves: moves(finding.signal),
        recipients: Vec::new(),
        owner_copy: false,
        outcome: AgentHealthOutcome::Open,
        outcome_by: None,
        outcome_at: None,
        watermark: 0,
        opened_at: now,
        updated_at: now,
        coach: None,
        observed_brief: None,
        reviewer: detector_id(finding.signal),
        reviewer_revision: revision,
        review_outcomes: Vec::new(),
        causes: Vec::new(),
        silence: None,
        moves_taken: Vec::new(),
    });
    add_ids(&mut card.evidence, &finding.evidence);
    add_ids(&mut card.diagnostics, &[diagnostic]);
    let witnessed = finding.attempt.and_then(entity);
    card.attempt = witnessed.or(card.attempt);
    add_ids(&mut card.witnessed_attempts, witnessed.as_slice());
    card.window_from = card.window_from.min(finding.window.0);
    card.window_to = card.window_to.max(finding.window.1);
    card.measured = finding.measured;
    card.dial = finding.dial;
    card.counter_evidence = finding.counter.clone();
    card.confidence = if finding.counter.is_empty() {
        AgentHealthConfidence::High
    } else {
        AgentHealthConfidence::Low
    };
    card.confession = finding.confession.or(card.confession);
    card.agent_blocked = finding.blocked;
    // The newest finding's observation and evaluator: an ask or an outcome
    // already taken keeps its own copy.
    card.observed_brief = finding.observed_brief.clone();
    card.silence = finding.silence;
    card.reviewer = detector_id(finding.signal);
    card.reviewer_revision = revision;
    if card.outcome != AgentHealthOutcome::Open && card.evidence.len() > card.watermark {
        card.outcome = AgentHealthOutcome::Open;
        card.outcome_by = None;
        card.outcome_at = None;
        card.opened_at = now;
    }
    add_recipients(&mut card.recipients, card.subject, &route.recipients);
    if route.owner_copy {
        card.owner_copy = true;
    }
    if card.owner_copy {
        add_recipients(&mut card.recipients, card.subject, owners);
    }
    card.updated_at = now;
    card
}
