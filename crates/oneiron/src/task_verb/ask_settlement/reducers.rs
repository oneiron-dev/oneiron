//! Fixed ask evidence reducers and fallback choice.
//! Entry: `reduce`.
//! Ask result vocabulary belongs to `ask_types`.

use super::*;

pub(super) fn reduce(
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
    let mut human = BTreeMap::new();
    let mut delegated = BTreeMap::new();
    for entry in evidence.iter() {
        if matches!(
            entry.source,
            TaskAskSource::Human | TaskAskSource::ForeignStated
        ) {
            human.insert(entry.person_ref, entry.answer.word_ref);
        } else if entry.source == TaskAskSource::Companion && entry.delegation_grant_ref.is_some() {
            delegated.insert(entry.person_ref, entry.answer.word_ref);
        }
    }
    let mut latest = delegated;
    latest.extend(human.iter().map(|(person, word)| (*person, *word)));
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
            TaskAskSource::Inform if human.contains_key(&entry.person_ref) => {
                TaskAskEvidenceReason::HumanDominates
            }
            TaskAskSource::Inform => TaskAskEvidenceReason::Inform,
            TaskAskSource::Executor => TaskAskEvidenceReason::Executor,
            TaskAskSource::Companion if human.contains_key(&entry.person_ref) => {
                TaskAskEvidenceReason::HumanDominates
            }
            TaskAskSource::Companion if entry.delegation_grant_ref.is_none() => {
                TaskAskEvidenceReason::CompanionHint
            }
            TaskAskSource::Human | TaskAskSource::ForeignStated | TaskAskSource::Companion
                if latest.get(&entry.person_ref) != Some(&entry.answer.word_ref) =>
            {
                TaskAskEvidenceReason::Superseded
            }
            TaskAskSource::Human | TaskAskSource::ForeignStated | TaskAskSource::Companion
                if !need.contains(&entry.person_ref)
                    && !decision_seats.contains(&entry.person_ref)
                    && !required.contains(&entry.person_ref) =>
            {
                TaskAskEvidenceReason::OutsideElectorate
            }
            TaskAskSource::Human | TaskAskSource::ForeignStated | TaskAskSource::Companion
                if !sources.is_subset(&entry.word.provenance_refs) =>
            {
                unmet_sources.extend(sources.difference(&entry.word.provenance_refs).copied());
                TaskAskEvidenceReason::MissingSource
            }
            TaskAskSource::Human | TaskAskSource::ForeignStated | TaskAskSource::Companion => {
                TaskAskEvidenceReason::Counted
            }
        };
        entry.ladder_changed = if entry.reason == TaskAskEvidenceReason::Counted
            && entry.source == TaskAskSource::Human
        {
            spec.what
                .ladder_answer
                .as_ref()
                .zip(entry.word.option.as_ref())
                .map(|(ladder, person)| &ladder.option != person)
        } else {
            None
        };
    }
    let words: Vec<_> = evidence
        .iter()
        .filter(|entry| {
            entry.reason == TaskAskEvidenceReason::Counted
                && decision_seats.contains(&entry.person_ref)
        })
        .collect();
    // A collection completes on the words that count. Replies that lack a
    // required source stay as evidence but never complete it on their own.
    let counted: BTreeSet<_> = evidence
        .iter()
        .filter(|entry| entry.reason == TaskAskEvidenceReason::Counted)
        .map(|entry| entry.person_ref)
        .collect();
    let decision = match &spec.decide {
        None if need.intersection(&counted).count() >= usize::from(spec.need.count)
            && required.is_subset(&counted) =>
        {
            TaskAskDecision::Collected
        }
        None => TaskAskDecision::Unknown,
        Some(TaskAskDecide::First) => words.first().map_or(TaskAskDecision::Unknown, |entry| {
            if entry.word.confirmation.as_ref().is_some_and(|response| {
                response.decision == super::TaskAskConfirmationDecision::Reject
            }) {
                TaskAskDecision::No
            } else {
                TaskAskDecision::First(entry.answer.clone())
            }
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
            } else if yes + decision_seats.difference(&coverage.responded).count() < threshold {
                TaskAskDecision::No
            } else {
                TaskAskDecision::Unknown
            }
        }
    };
    Ok((coverage, decision))
}

pub(super) fn fallback(
    spec: &TaskAskSpec,
    coverage: &TaskAskCoverage,
    decision: &TaskAskDecision,
    stale: bool,
    evidence: &[TaskAskEvidence],
    policy_surface: TaskAskSurface,
) -> Option<TaskAskFallback> {
    if stale {
        return Some(TaskAskFallback {
            branch: TaskAskDefault::Hold,
            surface: spec.on_disagree.surface,
        });
    }
    // A companion commitment without the person's word takes the AskSpec
    // deadline branch even if delegated companions disagree.
    if spec.what.commitment
        && evidence.iter().any(|entry| {
            entry.source == TaskAskSource::Companion
                && !evidence.iter().any(|human| {
                    human.source == TaskAskSource::Human && human.person_ref == entry.person_ref
                })
        })
    {
        return Some(TaskAskFallback {
            branch: spec.default,
            surface: policy_surface,
        });
    }
    // An explicit human rejection is a veto, not silence. It never inherits
    // a permissive deadline/disagreement branch from the original question.
    if spec.what.commitment
        && evidence.iter().any(|entry| {
            entry.source == TaskAskSource::Human
                && entry.reason == TaskAskEvidenceReason::Counted
                && entry.word.confirmation.as_ref().is_some_and(|response| {
                    response.decision == super::TaskAskConfirmationDecision::Reject
                })
        })
    {
        return Some(TaskAskFallback {
            branch: TaskAskDefault::Hold,
            surface: policy_surface,
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
        surface: spec.on_disagree.surface,
    })
}
