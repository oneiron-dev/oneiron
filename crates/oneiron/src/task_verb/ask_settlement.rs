//! Atomic ask cutoffs and the fixed human-word reducers.
use super::ask_record::{self, AskGroup};
use super::ask_types::*;
use crate::{EntityId, Result, Vault};
use std::collections::{BTreeMap, BTreeSet};

const SETTLEMENT: &str = "tasks.ask_settlement";

fn settlement_id(group: EntityId) -> Result<EntityId> {
    ask_record::derived_id(b"oneiron.tasks.ask.settlement", group, b"receipt")
}

pub(super) fn read_result(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group: EntityId,
) -> Result<Option<TaskAskResult>> {
    let id = settlement_id(group)?;
    let result: Option<TaskAskResult> = ask_record::read(vault, txn, id, SETTLEMENT)?;
    if result.as_ref().is_some_and(|r| {
        r.settlement.reference != id
            || r.settlement.group_ref != group
            || r.settlement.revision != r.settlement.effective.what.revision
    }) {
        return Err(ask_record::invalid());
    }
    if let Some(result) = &result {
        validate_result(id, result)?;
        if let Some(group) = ask_record::read_group(vault, txn, group)? {
            let who = group
                .members
                .iter()
                .map(|member| ask_record::entity(&member.actor))
                .collect::<Result<BTreeSet<_>>>()?;
            if result.settlement.requested != group.requested
                || result.settlement.effective != group.effective
                || result.settlement.electorate != who
                || result.settlement.question_digest != group.question_digest
            {
                return Err(ask_record::invalid());
            }
        }
    }
    Ok(result)
}

pub(crate) fn settle_ask_if_due(vault: &Vault, id: EntityId) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    if ask_record::read_group(vault, &txn, id)?.is_none() {
        return Ok(());
    }
    drop(txn);
    vault.with_write_txn(|txn| {
        settle_in(vault, txn, id, vault.store.clock.now_recorded_at()).map(|_| ())
    })
}

pub(super) fn settle_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    now: u64,
) -> Result<Option<TaskAskResult>> {
    if let Some(result) = read_result(vault, txn, id)? {
        return Ok(Some(result));
    }
    let Some(group) = ask_record::read_group(vault, txn, id)? else {
        return Ok(None);
    };
    // One admission node closes a revision; every replica reads the same fact.
    // Independent local first-observed cuts cannot promise one durable receipt.
    if !ask_record::owns_revision(vault, txn, id, &group)? {
        return Ok(None);
    }
    let who = group
        .members
        .iter()
        .map(|member| ask_record::entity(&member.actor))
        .collect::<Result<BTreeSet<_>>>()?;
    let mut evidence = ask_record::evidence_in(vault, txn, id, &group)?;
    let mut unmet_sources = BTreeSet::new();
    let (coverage, decision) = reduce(&group.effective, &who, &mut evidence, &mut unmet_sources)?;
    let stale = is_stale(vault, txn, &group)?;
    let deadline = group.effective.until.ok_or_else(ask_record::invalid)?;
    let mut all_responded = true;
    for member in &group.members {
        let task = ask_record::entity(&member.task)?;
        let person = ask_record::entity(&member.actor)?;
        if evidence
            .iter()
            .any(|entry| entry.person_ref == person && entry.source != TaskAskSource::Inform)
        {
            continue;
        }
        let body = super::create_validation::task_body_in_txn(vault, txn, task)
            .map_err(|_| ask_record::invalid())?;
        // A terminal answer whose separate fact has not arrived is not proof
        // of exhaustion. The origin's cutoff, not a sender's timestamp, admits it.
        all_responded &= body.terminal().is_some_and(|terminal| {
            !matches!(
                terminal.summary,
                Some(super::ConsultResultSummary::Answer { .. })
            )
        }) || body.settled_ladder_disposition().is_some()
            || vault
                .task_authority_state_in(txn, task)?
                .is_some_and(|state| state.cancelled);
    }
    let reason = if stale {
        TaskAskSettlementReason::Stale
    } else if now >= deadline {
        TaskAskSettlementReason::Deadline
    } else if matches!(decision, TaskAskDecision::First(_)) && coverage.met {
        TaskAskSettlementReason::FirstWord
    } else if all_responded {
        TaskAskSettlementReason::AllResponded
    } else {
        return Ok(None);
    };
    let decision = if stale {
        TaskAskDecision::Unknown
    } else {
        decision
    };
    let fallback = fallback(&group.effective, &coverage, &decision, stale, &evidence);
    let reference = settlement_id(id)?;
    let cutoff_order = evidence.iter().map(|entry| entry.order).max().unwrap_or(0);
    let mut result = TaskAskResult {
        coverage,
        decision,
        fallback,
        evidence,
        settlement: TaskAskSettlement {
            group_ref: id,
            reference,
            revision: group.effective.what.revision,
            at: now,
            cutoff_order,
            reason,
            requested: group.requested.clone(),
            effective: group.effective.clone(),
            base_policy_version: group.base_policy_version,
            electorate: who,
            question_digest: group.question_digest,
            unmet_sources,
            outcome_answer_ref: None,
        },
    };
    if result.coverage.met
        && result.fallback.is_none()
        && result.settlement.unmet_sources.is_empty()
        && let Some(binding) = &group.effective.what.outcome_binding
    {
        let selection = match &result.decision {
            TaskAskDecision::First(answer) => result
                .evidence
                .iter()
                .find(|entry| entry.answer == *answer)
                .map(|entry| {
                    (
                        entry,
                        entry.word.result_ref,
                        entry.word.option.as_ref().map_or_else(
                            || entry.word.result_ref.to_hex(),
                            |id| id.as_str().to_owned(),
                        ),
                    )
                }),
            TaskAskDecision::Answer(option) => result
                .evidence
                .iter()
                .find(|entry| {
                    entry.reason == TaskAskEvidenceReason::Counted
                        && entry.word.option.as_ref() == Some(option)
                })
                .map(|entry| {
                    (
                        entry,
                        group.effective.what.reference.entity_ref(),
                        option.as_str().to_owned(),
                    )
                }),
            _ => None,
        };
        if let Some((entry, unit, choice)) = selection {
            let bound = crate::llm::decision::questions::bind_task_answer_in_txn(
                vault,
                txn,
                crate::WriteActor::new(entry.answer.actor_ref, crate::EdgeActorClass::Human),
                crate::llm::decision::questions::TaskAnswerBinding {
                    task: id,
                    principal: ask_record::entity(&group.owner)?,
                    unit,
                    question: &group.effective.what.reference.short_ref(),
                    binding,
                    now,
                    choice: &choice,
                    revision: u32::try_from(group.effective.what.revision)
                        .map_err(|_| ask_record::invalid())?,
                },
            )?;
            result.settlement.outcome_answer_ref = Some(bound.claim);
        }
    }
    ask_record::put(vault, txn, reference, SETTLEMENT, &result, now)?;
    super::ask_facade::signal_waiters(vault, txn, id, now.saturating_mul(1000))
        .map_err(|_| ask_record::invalid())?;
    Ok(Some(result))
}

pub(super) fn question_digest(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    question: &TaskAskQuestion,
) -> Result<Option<[u8; 32]>> {
    let mut hash = blake3::Hasher::new();
    for reference in
        std::iter::once(question.reference).chain(question.context_refs.iter().copied())
    {
        let Some(raw) = vault.get_raw_in(txn, &reference.entity_ref())? else {
            return Ok(None);
        };
        let body = raw
            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .ok_or_else(ask_record::invalid)?;
        hash.update(reference.entity_ref().as_bytes());
        hash.update(&(body.len() as u64).to_be_bytes());
        hash.update(body);
    }
    Ok(Some(*hash.finalize().as_bytes()))
}

fn is_stale(vault: &Vault, txn: &heed::RoTxn<'_>, group: &AskGroup) -> Result<bool> {
    if question_digest(vault, txn, &group.effective.what)? != Some(group.question_digest) {
        return Ok(true);
    }
    let who = group
        .members
        .iter()
        .map(|member| ask_record::entity(&member.actor))
        .collect::<Result<BTreeSet<_>>>()?;
    for actor in &who {
        if vault.get_entity_type_in_txn(txn, actor)?.is_none() {
            return Ok(true);
        }
    }
    if let Some(TaskAskTarget::Authority(scope)) = &group.effective.who {
        let live: BTreeSet<_> = vault
            .ask_authority_holders_in_txn(txn, &scope.class, &scope.envelope)?
            .into_iter()
            .collect();
        if live != who {
            return Ok(true);
        }
    }
    if let Some(task) = group.effective.task_ref {
        let Some(body) = super::wire_decode::task_verb_body_in(vault, txn, task)? else {
            return Ok(true);
        };
        let Some(authority) = vault.task_authority_state_in(txn, task)? else {
            return Ok(true);
        };
        let owner = ask_record::entity(&group.owner)?;
        if authority.cancelled
            || authority.owner_ref.to_hex() != body.owner_ref
            || (authority.owner_ref != owner
                && body.assignee.and_then(super::TaskAssignee::entity_ref) != Some(owner))
        {
            return Ok(true);
        }
        let class = if let Some(fields) = body.spec.as_map() {
            let mut rows = fields
                .iter()
                .filter(|(key, _)| key.as_str() == Some("ask_class"));
            let row = rows.next().map(|(_, value)| value);
            if rows.next().is_some() {
                return Ok(true);
            }
            row.map(|value| {
                let bytes = rmp_serde::to_vec_named(value).map_err(|_| ask_record::invalid())?;
                rmp_serde::from_slice::<TaskAskClass>(&bytes).map_err(|_| ask_record::invalid())
            })
            .transpose()?
        } else {
            None
        };
        if class != group.context_class {
            return Ok(true);
        }
    }
    Ok(false)
}

fn reduce(
    spec: &TaskAskSpec,
    who: &BTreeSet<EntityId>,
    evidence: &mut [TaskAskEvidence],
    unmet_sources: &mut BTreeSet<super::ConsultPayloadRef>,
) -> Result<(TaskAskCoverage, TaskAskDecision)> {
    let need = spec.need.of.seats(who).map_err(|_| ask_record::invalid())?;
    let decision_seats = match &spec.decide {
        Some(TaskAskDecide::All { of, .. } | TaskAskDecide::AtLeast { of, .. }) => {
            of.seats(who).map_err(|_| ask_record::invalid())?
        }
        _ => who.clone(),
    };
    let required = spec
        .class
        .as_ref()
        .map(|class| class.required_people.clone())
        .unwrap_or_default();
    let sources = spec
        .class
        .as_ref()
        .map(|class| class.required_sources.clone())
        .unwrap_or_default();
    let mut latest = BTreeMap::new();
    for entry in evidence.iter() {
        if entry.source == TaskAskSource::Human {
            latest.insert(entry.person_ref, entry.answer.word_ref);
        }
    }
    let responded: BTreeSet<_> = latest.keys().copied().collect();
    let unknown = who.difference(&responded).copied().collect();
    let unmet_people: BTreeSet<_> = required.difference(&responded).copied().collect();
    let coverage = TaskAskCoverage {
        met: need.intersection(&responded).count() >= usize::from(spec.need.count)
            && unmet_people.is_empty(),
        required: spec.need.count,
        responded,
        unknown,
        unmet_people,
    };
    unmet_sources.clear();
    for entry in evidence.iter_mut() {
        entry.reason = match entry.source {
            TaskAskSource::Inform if latest.contains_key(&entry.person_ref) => {
                TaskAskEvidenceReason::HumanDominates
            }
            TaskAskSource::Inform => TaskAskEvidenceReason::Inform,
            TaskAskSource::Executor => TaskAskEvidenceReason::Executor,
            TaskAskSource::Human
                if latest.get(&entry.person_ref) != Some(&entry.answer.word_ref) =>
            {
                TaskAskEvidenceReason::Superseded
            }
            TaskAskSource::Human
                if !need.contains(&entry.person_ref)
                    && !decision_seats.contains(&entry.person_ref)
                    && !required.contains(&entry.person_ref) =>
            {
                TaskAskEvidenceReason::OutsideElectorate
            }
            TaskAskSource::Human if !sources.is_subset(&entry.word.provenance_refs) => {
                unmet_sources.extend(sources.difference(&entry.word.provenance_refs).copied());
                TaskAskEvidenceReason::MissingSource
            }
            TaskAskSource::Human => TaskAskEvidenceReason::Counted,
        };
    }
    let words: Vec<_> = evidence
        .iter()
        .filter(|entry| {
            entry.reason == TaskAskEvidenceReason::Counted
                && decision_seats.contains(&entry.person_ref)
        })
        .collect();
    let mut decision = match &spec.decide {
        None => TaskAskDecision::Collected,
        Some(TaskAskDecide::First) => words.first().map_or(TaskAskDecision::Unknown, |entry| {
            TaskAskDecision::First(entry.answer)
        }),
        // A tied opposing electorate is surfaced, never broken by arrival order.
        Some(TaskAskDecide::All { answer, .. }) => {
            let yes = words
                .iter()
                .filter(|entry| entry.word.option.as_ref() == Some(answer))
                .count();
            let no = words.len().saturating_sub(yes);
            if yes == decision_seats.len() {
                TaskAskDecision::Answer(answer.clone())
            } else if yes > 0 && yes == no {
                TaskAskDecision::Conflict
            } else if no > 0 {
                TaskAskDecision::No
            } else {
                TaskAskDecision::Unknown
            }
        }
        Some(TaskAskDecide::AtLeast { count, answer, .. }) => {
            let yes = words
                .iter()
                .filter(|entry| entry.word.option.as_ref() == Some(answer))
                .count();
            let mut alternatives = BTreeMap::new();
            for entry in &words {
                if let Some(option) = &entry.word.option
                    && option != answer
                {
                    *alternatives.entry(option).or_insert(0_usize) += 1;
                }
            }
            let threshold = usize::from(*count);
            if yes >= threshold && alternatives.values().any(|votes| *votes >= threshold) {
                TaskAskDecision::Conflict
            } else if yes >= threshold {
                TaskAskDecision::Answer(answer.clone())
            } else if yes + decision_seats.len().saturating_sub(words.len()) < threshold {
                TaskAskDecision::No
            } else {
                TaskAskDecision::Unknown
            }
        }
    };
    if !unmet_sources.is_empty() {
        decision = TaskAskDecision::Unknown;
    }
    Ok((coverage, decision))
}

fn fallback(
    spec: &TaskAskSpec,
    coverage: &TaskAskCoverage,
    decision: &TaskAskDecision,
    stale: bool,
    evidence: &[TaskAskEvidence],
) -> Option<TaskAskFallback> {
    if stale {
        return Some(TaskAskFallback {
            branch: TaskAskDefault::Hold,
            surface: TaskAskSurface::Card,
        });
    }
    let choices: BTreeSet<_> = evidence
        .iter()
        .filter(|entry| entry.reason == TaskAskEvidenceReason::Counted)
        .filter_map(|entry| entry.word.option.as_ref())
        .collect();
    if matches!(decision, TaskAskDecision::Conflict)
        || (matches!(decision, TaskAskDecision::No) && choices.len() > 1)
    {
        return Some(TaskAskFallback {
            branch: match spec.on_disagree.branch {
                TaskAskBranch::Hold => TaskAskDefault::Hold,
                TaskAskBranch::Proceed => TaskAskDefault::Proceed,
            },
            surface: spec.on_disagree.surface,
        });
    }
    if coverage.met
        && matches!(
            decision,
            TaskAskDecision::First(_) | TaskAskDecision::Answer(_) | TaskAskDecision::Collected
        )
    {
        return None;
    }
    Some(TaskAskFallback {
        branch: spec.default,
        surface: TaskAskSurface::Card,
    })
}

pub(super) fn evidence(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
) -> Result<Vec<TaskAskEvidence>> {
    let mut all = ask_record::evidence_in(vault, txn, id, group)?;
    if let Some(result) = read_result(vault, txn, id)? {
        return Ok(all
            .into_iter()
            .map(|mut entry| {
                if let Some(counted) = result
                    .evidence
                    .iter()
                    .find(|at_cut| at_cut.answer.word_ref == entry.answer.word_ref)
                {
                    entry.reason = counted.reason;
                } else {
                    entry.reason = TaskAskEvidenceReason::Late;
                }
                entry
            })
            .collect());
    }
    let who = group
        .members
        .iter()
        .map(|member| ask_record::entity(&member.actor))
        .collect::<Result<BTreeSet<_>>>()?;
    reduce(&group.effective, &who, &mut all, &mut BTreeSet::new())?;
    Ok(all)
}

pub(super) fn validate_result(id: EntityId, result: &TaskAskResult) -> Result<()> {
    let settlement = &result.settlement;
    if settlement.reference != id
        || settlement_id(settlement.group_ref)? != id
        || settlement.base_policy_version != 1
        || settlement.revision != settlement.effective.what.revision
        || result
            .evidence
            .iter()
            .any(|entry| entry.order == 0 || entry.order > settlement.cutoff_order)
        || result.evidence.windows(2).any(|pair| match pair {
            [a, b] => (a.order, a.answer.word_ref) >= (b.order, b.answer.word_ref),
            _ => true,
        })
    {
        return Err(ask_record::invalid());
    }
    let mut evidence = result.evidence.clone();
    let mut unmet_sources = BTreeSet::new();
    let (coverage, mut decision) = reduce(
        &settlement.effective,
        &settlement.electorate,
        &mut evidence,
        &mut unmet_sources,
    )?;
    let stale = settlement.reason == TaskAskSettlementReason::Stale;
    if stale {
        decision = TaskAskDecision::Unknown;
    }
    if coverage != result.coverage
        || decision != result.decision
        || evidence != result.evidence
        || unmet_sources != settlement.unmet_sources
        || fallback(
            &settlement.effective,
            &coverage,
            &decision,
            stale,
            &evidence,
        ) != result.fallback
    {
        return Err(ask_record::invalid());
    }
    Ok(())
}
