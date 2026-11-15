//! Reduces a successful verdict history to the next pack or a typed result.
//!
//! This is a pure history fold, not a client call loop. A layout refusal
//! changes the initial parts; only successful answers enter the history.

use super::answers::{
    IdentityKind, choice, earlier, most_probable, named, resolution_answer, validate,
};
use super::*;

fn take<'a>(
    input: Input<'_>,
    expected: &ExtractionPack,
    history: &'a [AnsweredPack],
    cursor: &mut usize,
) -> Result<Option<&'a AnsweredPack>, Error> {
    let Some(answered) = history.get(*cursor) else {
        return Ok(None);
    };
    validate(input, expected, answered)?;
    *cursor += 1;
    Ok(Some(answered))
}

fn finished<T>(result: T, history: &[AnsweredPack], cursor: usize) -> Result<Step<T>, Error> {
    if cursor != history.len() {
        return Err(Error::History);
    }
    Ok(Step::Finished(result))
}

/// Returns the next correction pack or one completed correction per operand.
///
/// Starts Whole unless the engine supplied CorrectionPages. Every candidate's
/// initial answers precede its one-based finals; actual abstentions stay in
/// its decisions while canonical none replays an absent group where offered.
///
/// # Errors
///
/// Rejects wrong-kind layouts, unserved positions and histories that do not
/// match the exact next pack or its canonical answers.
pub fn correction_step(
    input: Input<'_>,
    layout: Option<&ExtractionLayout>,
    history: &[AnsweredPack],
) -> Result<Step<Vec<Correction>>, Error> {
    let packs = match layout {
        None => vec![correction(input, None)?],
        Some(layout) => correction_pages(layout)?
            .iter()
            .map(|page| correction(input, Some(page)))
            .collect::<Result<Vec<_>, _>>()?,
    };
    let mut cursor = 0;
    let mut groups: Vec<Vec<(PackQuestion, DecisionEntry)>> =
        vec![Vec::new(); input.candidates.len()];
    for pack in packs {
        if pack.questions.is_empty() {
            continue;
        }
        let Some(answered) = take(input, &pack, history, &mut cursor)? else {
            return Ok(Step::Ask(pack));
        };
        for (question, entry) in pack.questions.iter().zip(&answered.entries) {
            let position: usize = question.key[0].parse().map_err(|_| Error::History)?;
            groups[position].push((question.clone(), entry.clone()));
        }
    }
    let mut corrections = Vec::with_capacity(groups.len());
    for (position, groups) in groups.into_iter().enumerate() {
        let mut decisions: Vec<DecisionEntry> =
            groups.iter().map(|(_, entry)| entry.clone()).collect();
        match choose(
            FinalInput::Correction { input, position },
            groups,
            history,
            &mut cursor,
        )? {
            Step::Ask(pack) => return Ok(Step::Ask(pack)),
            Step::Finished(chosen) => {
                decisions.extend(chosen.decisions);
                corrections.push(Correction {
                    candidate: position,
                    corrects: chosen
                        .position
                        .map(|at| input.observations.listed[at].claim.clone()),
                    decisions,
                });
            }
        }
    }
    finished(corrections, history, cursor)
}

/// Returns the next resolution or final pack, or one judge set's typed decision.
///
/// A single page uses its answer. Multiple pages with any absence or escalate
/// have no standing answer; unanimous pages stand, and differing resolutions
/// get a round-zero final. Only merge or supersede chooses a kept identity.
///
/// # Errors
///
/// Rejects wrong-kind layouts, unserved pins and histories that differ from
/// the native next pack, including answer count, key or option differences.
pub fn resolution_step(
    input: ResolutionInput<'_>,
    layout: Option<&ExtractionLayout>,
    history: &[AnsweredPack],
) -> Result<Step<ConflictDecision>, Error> {
    let packs = match layout {
        None => vec![resolution(input, None)?],
        Some(layout) => resolution_pages(layout)?
            .iter()
            .map(|page| resolution(input, Some(page)))
            .collect::<Result<Vec<_>, _>>()?,
    };
    let mut cursor = 0;
    let mut resolutions = Vec::new();
    let mut page_answers = Vec::new();
    let mut groups = Vec::new();
    let mut decisions = Vec::new();
    for pack in packs {
        let Some(answered) = take(input.input, &pack, history, &mut cursor)? else {
            return Ok(Step::Ask(pack));
        };
        let entry = &answered.entries[0];
        resolutions.push(resolution_answer(entry));
        page_answers.push(entry.clone());
        groups.extend(
            pack.questions
                .iter()
                .zip(&answered.entries)
                .skip(1)
                .map(|(question, entry)| (question.clone(), entry.clone())),
        );
        decisions.extend_from_slice(&answered.entries);
    }
    let resolution = match resolutions.as_slice() {
        [only] => *only,
        paged
            if paged.iter().any(|answer| {
                matches!(answer, Resolution::NoStandingAnswer | Resolution::Escalate)
            }) =>
        {
            Resolution::NoStandingAnswer
        }
        [first, rest @ ..] if rest.iter().all(|answer| answer == first) => *first,
        _ => {
            let earlier: Vec<EarlierAnswer> = page_answers
                .iter()
                .map(|entry| EarlierAnswer {
                    key: entry.key.clone(),
                    answer: choice(entry).unwrap_or_default().to_owned(),
                })
                .collect();
            let pack = resolution_final(input, &earlier)?.ok_or(Error::History)?;
            let Some(answered) = take(input.input, &pack, history, &mut cursor)? else {
                return Ok(Step::Ask(pack));
            };
            decisions.extend_from_slice(&answered.entries);
            resolution_answer(&answered.entries[0])
        }
    };
    let mut identity = None;
    if matches!(resolution, Resolution::Merge | Resolution::Supersede) {
        match choose(FinalInput::Identity(input), groups, history, &mut cursor)? {
            Step::Ask(pack) => return Ok(Step::Ask(pack)),
            Step::Finished(chosen) => {
                identity = chosen.position;
                decisions.extend(chosen.decisions);
            }
        }
    }
    finished(
        ConflictDecision {
            resolution,
            identity,
            decisions,
        },
        history,
        cursor,
    )
}

#[derive(Clone, Copy)]
enum FinalInput<'a> {
    Correction { input: Input<'a>, position: usize },
    Identity(ResolutionInput<'a>),
}

impl<'a> FinalInput<'a> {
    fn input(self) -> Input<'a> {
        match self {
            Self::Correction { input, .. } => input,
            Self::Identity(input) => input.input,
        }
    }

    fn kind(self) -> IdentityKind {
        match self {
            Self::Correction { .. } => IdentityKind::Listed,
            Self::Identity(_) => IdentityKind::Candidate,
        }
    }

    fn pack(self, round: IdentityRound<'_>) -> Result<ExtractionPack, Error> {
        match self {
            Self::Correction { input, position } => correction_final(input, position, round),
            Self::Identity(input) => identity_final(input, round),
        }
    }
}

struct IdentityDecision {
    position: Option<usize>,
    decisions: Vec<DecisionEntry>,
}

fn choose(
    input: FinalInput<'_>,
    groups: Vec<(PackQuestion, DecisionEntry)>,
    history: &[AnsweredPack],
    cursor: &mut usize,
) -> Result<Step<IdentityDecision>, Error> {
    let original: Vec<DecisionEntry> = groups.iter().map(|(_, entry)| entry.clone()).collect();
    let mut shortlist = named(input.input(), input.kind(), &original)?;
    let mut replay = groups;
    let mut decisions = Vec::new();
    let mut round = 0;
    while shortlist.len() > 1 {
        round += 1;
        let earlier = earlier(input.input(), input.kind(), &replay)?;
        let pack = input.pack(IdentityRound {
            round,
            shortlist: &shortlist,
            earlier: &earlier,
        })?;
        let Some(answered) = take(input.input(), &pack, history, cursor)? else {
            return Ok(Step::Ask(pack));
        };
        let next: Vec<usize> = named(input.input(), input.kind(), &answered.entries)?
            .into_iter()
            .filter(|position| shortlist.contains(position))
            .collect();
        decisions.extend_from_slice(&answered.entries);
        if next.is_empty() {
            return Ok(Step::Finished(IdentityDecision {
                position: most_probable(input.input(), input.kind(), &original)?,
                decisions,
            }));
        }
        replay.extend(
            pack.questions
                .into_iter()
                .zip(answered.entries.iter().cloned()),
        );
        shortlist = next;
    }
    Ok(Step::Finished(IdentityDecision {
        position: shortlist.first().copied(),
        decisions,
    }))
}
