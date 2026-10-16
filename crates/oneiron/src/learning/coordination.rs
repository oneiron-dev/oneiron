//! Coordination cost of a team (ARCH-0079 #coordination-cost, DLM-005):
//! where its time went. Three optional fields: wait by reason, reuse delay
//! from a peer's publication to its first use, and duplicate work an audit
//! labelled.
//!
//! They are diagnostics, never a score, a payoff input or a limit. They are
//! gathered off the hot path: a projector derives them from event times the
//! attempt rows already carry, with no inline timer or counter. They stay in
//! the vault until the owner shows or publishes them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptState};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// Derived diagnostics per team. Key: team reference (the run id).
const COORDINATION: SideTable<String, CoordinationCost, Named> =
    SideTable::new(&side_table::LEARNING_COORDINATION);

/// Audit labels of duplicate work. Key: team reference NUL first NUL second.
const DUPLICATE_LABEL: SideTable<String, DuplicateWork, Named> =
    SideTable::new(&side_table::LEARNING_DUPLICATE_LABEL);

/// Longest team or work reference kept.
const MAX_REF_BYTES: usize = 256;

/// Why an agent waited.
pub const WAIT_QUEUE: &str = "queue";
/// A retry waiting out its backoff.
pub const WAIT_BACKOFF: &str = "backoff";
/// A paused attempt waiting to resume.
pub const WAIT_PAUSED: &str = "paused";

/// One timed event in a team's run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeamEvent {
    /// An agent waited from `start` to `end` for `reason`.
    Wait {
        agent: String,
        reason: String,
        start: u64,
        end: u64,
    },
    /// An agent published `reference` at `at`.
    Published {
        agent: String,
        reference: String,
        at: u64,
    },
    /// An agent first used `reference` at `at`.
    Used {
        agent: String,
        reference: String,
        at: u64,
    },
}

/// One peer output's reuse delay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReuseDelay {
    pub reference: String,
    pub publisher: String,
    pub user: String,
    pub published_at: u64,
    pub first_used_at: u64,
    pub delay: u64,
}

/// Work two agents did twice, as an audit labelled it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateWork {
    pub first: String,
    pub second: String,
    /// The audit receipt that labelled it.
    pub audit_receipt: String,
}

/// A team's coordination cost, shown beside elapsed time and calls.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationCost {
    pub team_ref: String,
    /// Agent-seconds spent waiting, by reason.
    pub wait_by_reason: BTreeMap<String, u64>,
    pub reuse_delays: Vec<ReuseDelay>,
    pub duplicate_work: Vec<DuplicateWork>,
    /// First event to last event, in seconds.
    pub elapsed: u64,
    /// Attempts the team made.
    pub calls: u64,
    pub derived_at: u64,
}

/// Derives the diagnostics from timed events: a pure function, so any event
/// source can feed it.
#[must_use]
pub fn derive_coordination_cost(
    team_ref: &str,
    events: &[TeamEvent],
    duplicates: Vec<DuplicateWork>,
    calls: u64,
    derived_at: u64,
) -> CoordinationCost {
    let mut wait_by_reason: BTreeMap<String, u64> = BTreeMap::new();
    let mut published: BTreeMap<&str, (&str, u64)> = BTreeMap::new();
    let mut first_use: BTreeMap<(&str, &str), u64> = BTreeMap::new();
    let mut first_at = u64::MAX;
    let mut last_at = 0;
    for event in events {
        match event {
            TeamEvent::Wait {
                reason, start, end, ..
            } => {
                *wait_by_reason.entry(reason.clone()).or_insert(0) += end.saturating_sub(*start);
                first_at = first_at.min(*start);
                last_at = last_at.max(*end);
            }
            TeamEvent::Published {
                agent,
                reference,
                at,
            } => {
                let slot = published
                    .entry(reference.as_str())
                    .or_insert((agent.as_str(), *at));
                if *at < slot.1 {
                    *slot = (agent.as_str(), *at);
                }
                first_at = first_at.min(*at);
                last_at = last_at.max(*at);
            }
            TeamEvent::Used {
                agent,
                reference,
                at,
            } => {
                let slot = first_use
                    .entry((reference.as_str(), agent.as_str()))
                    .or_insert(*at);
                *slot = (*slot).min(*at);
                first_at = first_at.min(*at);
                last_at = last_at.max(*at);
            }
        }
    }
    let mut reuse_delays = Vec::new();
    for ((reference, user), used_at) in first_use {
        let Some((publisher, published_at)) = published.get(reference) else {
            continue;
        };
        // Only a PEER's output, used after it was published.
        if *publisher == user || used_at < *published_at {
            continue;
        }
        reuse_delays.push(ReuseDelay {
            reference: reference.to_owned(),
            publisher: (*publisher).to_owned(),
            user: user.to_owned(),
            published_at: *published_at,
            first_used_at: used_at,
            delay: used_at - published_at,
        });
    }
    CoordinationCost {
        team_ref: team_ref.to_owned(),
        wait_by_reason,
        reuse_delays,
        duplicate_work: duplicates,
        elapsed: last_at.saturating_sub(if first_at == u64::MAX {
            last_at
        } else {
            first_at
        }),
        calls,
        derived_at,
    }
}

/// The timed events one run's attempt rows already carry: queue wait from
/// creation (or the scheduled instant) to claim, backoff from creation to the
/// scheduled instant, pause-to-resume spans, each completed attempt's task as
/// a publication, and each manifest load of a peer's published reference as a
/// use.
#[must_use]
pub fn team_events_from_attempts(records: &[AttemptRecord]) -> Vec<TeamEvent> {
    let mut events = Vec::new();
    for record in records {
        let agent = bytes_to_hex_lower(record.id.as_bytes());
        let ready = record
            .scheduled_at
            .unwrap_or(record.created_at)
            .max(record.created_at);
        if let Some(scheduled) = record.scheduled_at
            && scheduled > record.created_at
        {
            events.push(TeamEvent::Wait {
                agent: agent.clone(),
                reason: WAIT_BACKOFF.to_owned(),
                start: record.created_at,
                end: scheduled,
            });
        }
        if let Some(claimed) = record.claimed_at
            && claimed > ready
        {
            events.push(TeamEvent::Wait {
                agent: agent.clone(),
                reason: WAIT_QUEUE.to_owned(),
                start: ready,
                end: claimed,
            });
        }
        let mut paused_at = None;
        for event in &record.events {
            match event.kind {
                AttemptInterventionKind::Pause => paused_at = Some(event.at),
                AttemptInterventionKind::Resume => {
                    if let Some(start) = paused_at.take()
                        && event.at > start
                    {
                        events.push(TeamEvent::Wait {
                            agent: agent.clone(),
                            reason: WAIT_PAUSED.to_owned(),
                            start,
                            end: event.at,
                        });
                    }
                }
                _ => {}
            }
        }
        if record.state == AttemptState::Completed
            && let Some(task) = &record.task_ref
        {
            events.push(TeamEvent::Published {
                agent: agent.clone(),
                reference: task.clone(),
                at: record.updated_at,
            });
        }
        for entry in &record.manifest {
            events.push(TeamEvent::Used {
                agent: agent.clone(),
                reference: entry.reference.clone(),
                at: entry.at,
            });
        }
    }
    events
}

fn bounded(text: &str, what: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > MAX_REF_BYTES || text.contains('\0') {
        return Err(Error::InvalidClaimBody(what));
    }
    Ok(())
}

/// Re-derives one run's coordination cost from its attempt rows and the
/// audit labels, and stores it. Run it from a sweep, never inline in the work.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a malformed run id; storage errors.
pub fn project_run_coordination(vault: &Vault, run_id: &str, now: u64) -> Result<CoordinationCost> {
    bounded(run_id, "a team reference is 1..=256 bytes without NUL")?;
    let records = AttemptQueue::new(vault).list_run(run_id)?;
    let events = team_events_from_attempts(&records);
    let prefix = format!("{run_id}\0");
    let duplicates = {
        let rtxn = vault.store.env.read_txn()?;
        DUPLICATE_LABEL
            .scan_from(&vault.store, &rtxn, prefix.as_bytes())?
            .into_iter()
            .map(|(_, label)| label)
            .collect()
    };
    let cost = derive_coordination_cost(run_id, &events, duplicates, records.len() as u64, now);
    vault.with_write_txn_grouped(|wtxn| {
        COORDINATION.put(&vault.store, wtxn, &cost.team_ref, &cost)?;
        Ok(())
    })?;
    Ok(cost)
}

/// Records an audit's label that two pieces of a team's work duplicated each
/// other. Only an audit labels duplicate work; the next projection shows it.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for a malformed reference; storage errors.
pub fn label_duplicate_work(vault: &Vault, run_id: &str, label: &DuplicateWork) -> Result<()> {
    bounded(run_id, "a team reference is 1..=256 bytes without NUL")?;
    bounded(
        &label.first,
        "a work reference is 1..=256 bytes without NUL",
    )?;
    bounded(
        &label.second,
        "a work reference is 1..=256 bytes without NUL",
    )?;
    bounded(
        &label.audit_receipt,
        "an audit receipt is 1..=256 bytes without NUL",
    )?;
    if label.first == label.second {
        return Err(Error::InvalidClaimBody(
            "duplicate work names two distinct pieces of work",
        ));
    }
    let key = format!("{run_id}\0{}\0{}", label.first, label.second);
    vault.with_write_txn_grouped(|wtxn| {
        DUPLICATE_LABEL.put(&vault.store, wtxn, &key, label)?;
        Ok(())
    })
}

/// Every run with a derived cost or an audit label, in run order: the
/// coordination sweep's worklist.
///
/// # Errors
///
/// Storage errors.
pub fn coordination_runs(vault: &Vault) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut runs: std::collections::BTreeSet<String> = COORDINATION
        .scan_keys(&vault.store, &rtxn, &[])?
        .into_iter()
        .collect();
    for key in DUPLICATE_LABEL.scan_keys(&vault.store, &rtxn, &[])? {
        if let Some((run, _)) = key.split_once('\0') {
            runs.insert(run.to_owned());
        }
    }
    Ok(runs.into_iter().collect())
}

/// The last derived coordination cost of a team, if any.
///
/// # Errors
///
/// Storage errors.
pub fn coordination_cost(vault: &Vault, team_ref: &str) -> Result<Option<CoordinationCost>> {
    let rtxn = vault.store.env.read_txn()?;
    COORDINATION.get(&vault.store, &rtxn, &team_ref.to_owned())
}
