//! Reads ordered verdict entries and maps canonical claims through served facts.

use super::questions::candidate;
use super::*;

/// Reads the typed extraction layout field from an inferred client error.
///
/// The bound client's error is the engine's MemoryError, which implements
/// Serialize but is not re-exported by oneiron-remote. Only the field's JSON
/// is decoded; neither message nor any other prose is inspected.
///
/// # Errors
///
/// Rejects an absent field or a field outside the closed layout mirror.
pub fn read_layout(error: &impl Serialize) -> Result<ExtractionLayout, Error> {
    let error = serde_json::to_value(error).map_err(|error| Error::Layout(error.to_string()))?;
    let field = error
        .get("extraction_layout")
        .filter(|field| !field.is_null())
        .ok_or_else(|| Error::Layout("the refusal carries no extraction layout".into()))?;
    serde_json::from_value(field.clone()).map_err(|error| Error::Layout(error.to_string()))
}

/// Reads a verdict result's pack entries with exact count, keys and order.
///
/// Identifier membership is checked against served claims by the step functions.
/// Actual Abstain entries remain unchanged in the returned history.
///
/// # Errors
///
/// Rejects a missing pack, undecodable entries, count differences or key differences.
pub fn read_answers(pack: &ExtractionPack, verdict: Value) -> Result<AnsweredPack, Error> {
    let entries = verdict
        .get("pack")
        .cloned()
        .ok_or_else(|| Error::Answers("the verdict carries no pack entries".into()))?;
    let entries: Vec<DecisionEntry> =
        serde_json::from_value(entries).map_err(|error| Error::Answers(error.to_string()))?;
    check_keys(pack, &entries)?;
    Ok(AnsweredPack {
        pack: pack.clone(),
        entries,
    })
}

fn check_keys(pack: &ExtractionPack, entries: &[DecisionEntry]) -> Result<(), Error> {
    if entries.len() != pack.questions.len() {
        return Err(Error::Answers(
            "answer count differs from pack questions".into(),
        ));
    }
    if entries
        .iter()
        .zip(&pack.questions)
        .any(|(entry, question)| entry.key != question.key)
    {
        return Err(Error::Answers("answer keys differ from pack order".into()));
    }
    Ok(())
}

pub(super) fn validate(
    input: Input<'_>,
    expected: &ExtractionPack,
    answered: &AnsweredPack,
) -> Result<(), Error> {
    if &answered.pack != expected {
        return Err(Error::History);
    }
    check_keys(expected, &answered.entries)?;
    for (entry, question) in answered.entries.iter().zip(&expected.questions) {
        let DecisionAnswer::Choice(answer) = &entry.answer else {
            continue;
        };
        let mut offered = false;
        for option in &question.options {
            if let Some(position) = option.strip_prefix("candidate:") {
                let position: usize = position.parse().map_err(|_| Error::History)?;
                offered |= candidate(input, position)?.claim == *answer;
            } else {
                offered |= option == answer;
            }
        }
        if !offered {
            return Err(Error::Answers(
                "chosen claim or resolution is outside canonical options".into(),
            ));
        }
    }
    Ok(())
}

pub(super) fn choice(entry: &DecisionEntry) -> Option<&str> {
    match &entry.answer {
        DecisionAnswer::Choice(answer) => Some(answer),
        DecisionAnswer::Abstain => None,
    }
}

#[derive(Clone, Copy)]
pub(super) enum IdentityKind {
    Listed,
    Candidate,
}

pub(super) fn position(input: Input<'_>, kind: IdentityKind, claim: &str) -> Result<usize, Error> {
    match kind {
        IdentityKind::Listed => input
            .observations
            .listed
            .iter()
            .position(|row| row.claim == claim),
        IdentityKind::Candidate => input
            .observations
            .candidates
            .iter()
            .find(|row| row.claim == claim && row.index < input.candidates.len())
            .map(|row| row.index),
    }
    .ok_or_else(|| {
        Error::Answers("chosen identifier was not served for this operand universe".into())
    })
}

pub(super) fn named(
    input: Input<'_>,
    kind: IdentityKind,
    entries: &[DecisionEntry],
) -> Result<Vec<usize>, Error> {
    let mut named = Vec::new();
    for entry in entries {
        if let Some(claim) = choice(entry).filter(|claim| *claim != "none") {
            let position = position(input, kind, claim)?;
            if !named.contains(&position) {
                named.push(position);
            }
        }
    }
    Ok(named)
}

pub(super) fn earlier(
    input: Input<'_>,
    kind: IdentityKind,
    groups: &[(PackQuestion, DecisionEntry)],
) -> Result<Vec<EarlierAnswer>, Error> {
    groups
        .iter()
        .map(|(question, entry)| {
            let answer = match choice(entry) {
                None if question.options.iter().any(|option| option == "none") => "none".into(),
                None => return Err(Error::EarlierAbsence),
                Some("none") => "none".into(),
                Some(claim) => match kind {
                    IdentityKind::Listed => claim.into(),
                    IdentityKind::Candidate => {
                        format!("candidate:{}", position(input, kind, claim)?)
                    }
                },
            };
            Ok(EarlierAnswer {
                key: entry.key.clone(),
                answer,
            })
        })
        .collect()
}

pub(super) fn most_probable(
    input: Input<'_>,
    kind: IdentityKind,
    groups: &[DecisionEntry],
) -> Result<Option<usize>, Error> {
    // Native max_by uses total_cmp and keeps the last entry on an exact tie.
    groups
        .iter()
        .filter_map(|entry| match (choice(entry), entry.p) {
            (Some(claim), Some(p)) if claim != "none" => Some((claim, p)),
            _ => None,
        })
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(claim, _)| position(input, kind, claim))
        .transpose()
}

pub(super) fn resolution_answer(entry: &DecisionEntry) -> Resolution {
    match choice(entry) {
        Some("merge") => Resolution::Merge,
        Some("supersede") => Resolution::Supersede,
        Some("accumulate") => Resolution::Accumulate,
        Some("escalate") => Resolution::Escalate,
        _ => Resolution::NoStandingAnswer,
    }
}
