//! Builds canonical pack questions without wording, labels or byte measures.

use super::*;

const IDS_PER_QUESTION: usize = 63;
const RESOLUTIONS: [&str; 4] = ["merge", "supersede", "accumulate", "escalate"];

/// Returns the correction page parts and entries from a typed engine layout.
///
/// # Errors
///
/// Rejects the other layout kind or a layout without multiple pages.
pub fn correction_pages(
    layout: &ExtractionLayout,
) -> Result<Vec<Page<ExtractionCorrectionPair>>, Error> {
    match layout {
        ExtractionLayout::CorrectionPages { pages } => pages_from_entries(pages),
        ExtractionLayout::ResolutionPages { .. } => Err(Error::WrongLayout),
    }
}

/// Returns the resolution page parts and entries from a typed engine layout.
///
/// # Errors
///
/// Rejects the other layout kind or a layout without multiple pages.
pub fn resolution_pages(layout: &ExtractionLayout) -> Result<Vec<Page<usize>>, Error> {
    match layout {
        ExtractionLayout::ResolutionPages { pages } => pages_from_entries(pages),
        ExtractionLayout::CorrectionPages { .. } => Err(Error::WrongLayout),
    }
}

fn pages_from_entries<T: Clone>(pages: &[Vec<T>]) -> Result<Vec<Page<T>>, Error> {
    if pages.len() < 2 {
        return Err(Error::Part(
            "a paged read requires at least two pages".into(),
        ));
    }
    Ok(pages
        .iter()
        .enumerate()
        .map(|(page, entries)| Page {
            part: ExtractionPart::Page {
                page,
                pages: pages.len(),
            },
            entries: entries.clone(),
        })
        .collect())
}

pub(super) fn candidate<'a>(
    input: Input<'a>,
    position: usize,
) -> Result<&'a crate::extraction_observations::CandidateObservation, Error> {
    if position >= input.candidates.len() {
        return Err(Error::Observations(
            "candidate position is outside operands".into(),
        ));
    }
    input
        .observations
        .candidates
        .iter()
        .find(|row| row.index == position)
        .ok_or_else(|| Error::Observations("candidate position was not served".into()))
}

fn correction_entries(input: Input<'_>) -> Result<Vec<ExtractionCorrectionPair>, Error> {
    let mut entries = Vec::new();
    for position in 0..input.candidates.len() {
        for listed in &candidate(input, position)?.correctable {
            if *listed >= input.observations.listed.len() {
                return Err(Error::Observations(
                    "correctable listed position was not served".into(),
                ));
            }
            entries.push(ExtractionCorrectionPair {
                candidate: position,
                listed: *listed,
            });
        }
    }
    Ok(entries)
}

fn pack(input: Input<'_>, read: ExtractionRead, part: ExtractionPart) -> ExtractionPack {
    ExtractionPack {
        read,
        part,
        candidates: input.candidates.to_vec(),
        listed: Vec::new(),
        priors: Vec::new(),
        questions: Vec::new(),
        earlier: Vec::new(),
        set_members: None,
    }
}

fn listed_pins(input: Input<'_>) -> Vec<PinnedClaim> {
    input
        .observations
        .listed
        .iter()
        .map(|row| PinnedClaim {
            claim: row.claim.clone(),
            version: row.version.clone(),
        })
        .collect()
}

fn part_page(part: ExtractionPart) -> Result<Option<usize>, Error> {
    match part {
        ExtractionPart::Whole => Ok(None),
        ExtractionPart::Page { page, pages } if pages >= 2 && page < pages => Ok(Some(page)),
        _ => Err(Error::Part("invalid initial read part".into())),
    }
}

fn groups(ids: &[String], none: bool) -> Vec<Vec<String>> {
    ids.chunks(IDS_PER_QUESTION)
        .map(|chunk| {
            let mut options = Vec::new();
            if none || ids.len() > IDS_PER_QUESTION {
                options.push("none".into());
            }
            options.extend_from_slice(chunk);
            options
        })
        .collect()
}

fn page_key(mut key: Vec<String>, page: Option<usize>) -> Vec<String> {
    if let Some(page) = page {
        key.extend(["page".into(), page.to_string()]);
    }
    key
}

/// Builds the correction read over all operands or exactly one engine page.
///
/// # Errors
///
/// Rejects unserved positions, ineligible pairs and invalid page parts.
pub fn correction(
    input: Input<'_>,
    page: Option<&Page<ExtractionCorrectionPair>>,
) -> Result<ExtractionPack, Error> {
    let all = correction_entries(input)?;
    let (part, entries) = page.map_or((ExtractionPart::Whole, all.as_slice()), |page| {
        (page.part, page.entries.as_slice())
    });
    let page_index = part_page(part)?;
    let mut asked: Vec<(usize, Vec<String>)> = Vec::new();
    for entry in entries {
        if !all.contains(entry) {
            return Err(Error::Part(
                "page contains an ineligible correction pair".into(),
            ));
        }
        let id = input.observations.listed[entry.listed].claim.clone();
        if let Some((_, ids)) = asked
            .iter_mut()
            .find(|(position, _)| *position == entry.candidate)
        {
            ids.push(id);
        } else {
            asked.push((entry.candidate, vec![id]));
        }
    }
    let mut built = pack(input, ExtractionRead::Correction, part);
    built.listed = listed_pins(input);
    for (position, ids) in asked {
        for (group, options) in groups(&ids, true).into_iter().enumerate() {
            built.questions.push(PackQuestion {
                key: page_key(vec![position.to_string(), group.to_string()], page_index),
                options,
            });
        }
    }
    Ok(built)
}

fn across(input: ResolutionInput<'_>) -> Result<bool, Error> {
    let identity = input
        .input
        .observations
        .candidates
        .iter()
        .find(|row| row.identity_token == input.set.identity_token)
        .ok_or_else(|| Error::Observations("set identity was not served".into()))?;
    let mut across = false;
    for position in &input.set.candidate_indexes {
        across |= candidate(input.input, *position)?.predicate != identity.predicate;
    }
    Ok(across)
}

fn resolution_pack(
    input: ResolutionInput<'_>,
    read: ExtractionRead,
    part: ExtractionPart,
) -> Result<ExtractionPack, Error> {
    let mut built = pack(input.input, read, part);
    built.set_members = Some(input.set.candidate_indexes.clone());
    for position in &input.set.candidate_indexes {
        candidate(input.input, *position)?;
    }
    for claim in &input.set.prior_heads {
        let prior = input
            .input
            .observations
            .priors
            .iter()
            .find(|row| &row.claim == claim)
            .ok_or_else(|| Error::Observations("set prior pin was not served".into()))?;
        built.priors.push(PinnedClaim {
            claim: claim.clone(),
            version: prior.version.clone(),
        });
    }
    Ok(built)
}

/// Builds one judge set's resolution and initial identity groups.
///
/// # Errors
///
/// Rejects unserved members or priors and page entries outside the selected set.
pub fn resolution(
    input: ResolutionInput<'_>,
    page: Option<&Page<usize>>,
) -> Result<ExtractionPack, Error> {
    let (part, positions) = page.map_or(
        (
            ExtractionPart::Whole,
            input.set.candidate_indexes.as_slice(),
        ),
        |page| (page.part, page.entries.as_slice()),
    );
    let page_index = part_page(part)?;
    let mut built = resolution_pack(input, ExtractionRead::Resolution, part)?;
    let mut ids = Vec::new();
    for position in positions {
        if !input.set.candidate_indexes.contains(position) {
            return Err(Error::Part("page contains a nonmember candidate".into()));
        }
        ids.push(format!("candidate:{position}"));
    }
    built.questions.push(PackQuestion {
        key: page_key(vec!["resolution".into()], page_index),
        options: RESOLUTIONS.iter().map(|option| (*option).into()).collect(),
    });
    for (group, options) in groups(&ids, !across(input)? || page_index.is_some())
        .into_iter()
        .enumerate()
    {
        built.questions.push(PackQuestion {
            key: page_key(vec!["identity".into(), group.to_string()], page_index),
            options,
        });
    }
    Ok(built)
}

fn final_questions(
    base: &str,
    ids: &[String],
    none: bool,
    round: IdentityRound<'_>,
) -> Result<Vec<PackQuestion>, Error> {
    if round.round == 0 || ids.len() < 2 {
        return Err(Error::Part("final identity round has no shortlist".into()));
    }
    Ok(groups(ids, none)
        .into_iter()
        .enumerate()
        .map(|(group, options)| PackQuestion {
            key: vec![
                base.into(),
                "final".into(),
                round.round.to_string(),
                group.to_string(),
            ],
            options,
        })
        .collect())
}

/// Builds one candidate's one-based correction final over named listed positions.
///
/// # Errors
///
/// Rejects an unserved candidate, an ineligible shortlist or a nonexistent round.
pub fn correction_final(
    input: Input<'_>,
    position: usize,
    round: IdentityRound<'_>,
) -> Result<ExtractionPack, Error> {
    let observed = candidate(input, position)?;
    let mut ids = Vec::new();
    for at in round.shortlist {
        if !observed.correctable.contains(at) {
            return Err(Error::Part("correction shortlist is ineligible".into()));
        }
        let row = input
            .observations
            .listed
            .get(*at)
            .ok_or_else(|| Error::Observations("listed position was not served".into()))?;
        ids.push(row.claim.clone());
    }
    let mut built = pack(
        input,
        ExtractionRead::CorrectionFinal,
        ExtractionPart::Final { round: round.round },
    );
    built.listed = listed_pins(input);
    built.questions = final_questions(&position.to_string(), &ids, true, round)?;
    built.earlier = round.earlier.to_vec();
    Ok(built)
}

/// Builds the one-based identity final over named positions after merge or supersede.
///
/// The step function enforces the standing resolution before requesting this pack.
///
/// # Errors
///
/// Rejects a nonmember shortlist, unserved pins or a nonexistent round.
pub fn identity_final(
    input: ResolutionInput<'_>,
    round: IdentityRound<'_>,
) -> Result<ExtractionPack, Error> {
    let mut ids = Vec::new();
    for position in round.shortlist {
        if !input.set.candidate_indexes.contains(position) {
            return Err(Error::Part(
                "identity shortlist contains a nonmember".into(),
            ));
        }
        ids.push(format!("candidate:{position}"));
    }
    let mut built = resolution_pack(
        input,
        ExtractionRead::IdentityFinal,
        ExtractionPart::Final { round: round.round },
    )?;
    built.questions = final_questions("identity", &ids, !across(input)?, round)?;
    built.earlier = round.earlier.to_vec();
    Ok(built)
}

/// Builds the round-zero resolution final over first-seen distinct page answers.
///
/// Returns none when pages agree or any page escalates; an absent page is
/// handled by the step function before canonical earlier answers are built.
///
/// # Errors
///
/// Rejects non-page keys, noncanonical resolutions and unserved pins.
pub fn resolution_final(
    input: ResolutionInput<'_>,
    earlier: &[EarlierAnswer],
) -> Result<Option<ExtractionPack>, Error> {
    let mut options = Vec::new();
    for (page, answer) in earlier.iter().enumerate() {
        if answer.key != ["resolution".to_owned(), "page".into(), page.to_string()]
            || !RESOLUTIONS.contains(&answer.answer.as_str())
        {
            return Err(Error::Answers(
                "resolution earlier answer is not canonical".into(),
            ));
        }
        if answer.answer == "escalate" {
            return Ok(None);
        }
        if !options.contains(&answer.answer) {
            options.push(answer.answer.clone());
        }
    }
    if options.len() < 2 {
        return Ok(None);
    }
    let mut built = resolution_pack(
        input,
        ExtractionRead::ResolutionFinal,
        ExtractionPart::Final { round: 0 },
    )?;
    built.questions.push(PackQuestion {
        key: vec!["resolution".into(), "final".into()],
        options,
    });
    built.earlier = earlier.to_vec();
    Ok(Some(built))
}
