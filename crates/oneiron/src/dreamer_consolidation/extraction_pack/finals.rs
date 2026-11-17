//! The final-round rebuilds behind
//! [`rebuild_checked_pack`](super::rebuild_checked_pack): the correction and
//! conflict identity finals with their shared round replay, and the resolution
//! final over page answers.
//!
//! Every earlier answer below is mapped through the shared alias helper
//! before use, then checked against the canonical options of the question its
//! key names. Rounds replay from the shortlist the group answers name, so a
//! requested round exists exactly when native would ask it.

use super::super::call_labels::CallLabelMap;
use super::super::executor::extraction::corrections::{
    correction_choice_specs, group_correction_asks,
};
use super::super::executor::extraction::{
    DecisionKeyPart, ESCALATE, NONE, RESOLUTIONS, conflict_identity_specs, identity_round_specs,
    resolution_choice_spec, resolution_final_prep,
};
use super::super::support::invalid_consolidation;
use super::map_candidate_alias;
use super::reads::{BuiltConflict, CheckedPack, correction_page_entries, key_texts};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::verbs::{EarlierAnswer, ExtractionPart, PackQuestion};

/// The ids `answers` name, in order and each once: every choice answer that
/// is an id, never [`NONE`]. This mirrors the native shortlist rule over
/// already mapped answers.
fn identity_shortlist(answers: &[String]) -> Vec<EntityId> {
    let mut named = Vec::new();
    for answer in answers {
        if answer.as_str() != NONE
            && let Ok(id) = EntityId::from_hex(answer)
            && !named.contains(&id)
        {
            named.push(id);
        }
    }
    named
}

/// The questions of one final identity `round` over `shortlist`: the
/// round's shared choice specs as wire questions.
fn identity_round_questions(
    base: &[DecisionKeyPart],
    none: bool,
    round: usize,
    shortlist: &[EntityId],
) -> Vec<PackQuestion> {
    let mut labels = CallLabelMap::default();
    identity_round_specs(base, none, shortlist, round, &mut labels)
        .into_iter()
        .map(|spec| PackQuestion {
            key: key_texts(&spec.key),
            options: spec.options,
        })
        .collect()
}

/// The `target` one-based round over `shortlist` with `answers` as the rounds
/// before it: each earlier round validated against the round its shortlist
/// builds, each shortlist narrowed to the ids its round named. Returns the
/// target round's questions with the answers consumed and the target round's
/// shortlist for the lent execution.
fn replay_identity_final(
    base: &[DecisionKeyPart],
    none: bool,
    shortlist: Vec<EntityId>,
    answers: &[EarlierAnswer],
    target: usize,
    candidate_ids: &[EntityId],
) -> Result<(Vec<PackQuestion>, usize, Vec<EntityId>)> {
    if target == 0 {
        return Err(invalid_consolidation(
            "extraction final round does not exist",
        ));
    }
    let mut shortlist = shortlist;
    let mut consumed = 0_usize;
    for round in 1..target {
        let questions = identity_round_questions(base, none, round, &shortlist);
        let take: Vec<&EarlierAnswer> = answers
            .iter()
            .skip(consumed)
            .take(questions.len())
            .collect();
        if take.len() != questions.len() {
            return Err(invalid_consolidation(
                "extraction earlier answers do not cover their read",
            ));
        }
        let mut mapped: Vec<String> = Vec::with_capacity(take.len());
        for (offered, want) in take.iter().zip(&questions) {
            if offered.key != want.key {
                return Err(invalid_consolidation(
                    "an extraction earlier answer names no rebuilt question",
                ));
            }
            let answer = map_candidate_alias(&offered.answer, candidate_ids)?;
            if !want.options.contains(&answer) {
                return Err(invalid_consolidation(
                    "an extraction earlier answer lies outside its canonical options",
                ));
            }
            mapped.push(answer);
        }
        consumed += questions.len();
        shortlist = identity_shortlist(&mapped)
            .into_iter()
            .filter(|id| shortlist.contains(id))
            .collect();
        if shortlist.len() < 2 {
            return Err(invalid_consolidation(
                "extraction final round does not exist",
            ));
        }
    }
    let questions = identity_round_questions(base, none, target, &shortlist);
    Ok((questions, consumed, shortlist))
}

/// The questions of the correction final round over `checked` with `earlier`
/// as its group answers: the position read from the earlier keys, its groups
/// validated across the rebuilt pages, and the requested one-based round over
/// the shortlist they name. Returns the round questions with the candidate
/// position and the target round shortlist for the lent execution.
pub(super) fn correction_final_plan(
    checked: &CheckedPack,
    earlier: &[EarlierAnswer],
    part: ExtractionPart,
) -> Result<(Vec<PackQuestion>, usize, Vec<EntityId>)> {
    let ExtractionPart::Final { round } = part else {
        return Err(invalid_consolidation(
            "extraction pack part does not match its read",
        ));
    };
    if round == 0 {
        return Err(invalid_consolidation(
            "extraction final round does not exist",
        ));
    }
    let position = earlier
        .first()
        .ok_or_else(|| {
            invalid_consolidation("extraction correction final names no candidate position")
        })
        .and_then(|first| {
            first.key.first().ok_or_else(|| {
                invalid_consolidation("extraction correction final names no candidate position")
            })
        })?
        .parse::<usize>()
        .map_err(|_| {
            invalid_consolidation("extraction correction final names no candidate position")
        })?;
    let pages = correction_page_entries(&checked.rows, &checked.pairs, &checked.listed);
    let paged = pages.len() > 1;
    let candidate_ids = checked.candidate_ids();
    let listed_ids: Vec<EntityId> = checked.listed.iter().map(|row| row.claim).collect();
    let mut expected: Vec<PackQuestion> = Vec::new();
    for (page_index, entries) in pages.iter().enumerate() {
        let page = paged.then_some(page_index);
        let (asked, _) = group_correction_asks(entries.as_slice(), &listed_ids);
        let mut labels = CallLabelMap::default();
        for (position_at, specs) in correction_choice_specs(&asked, page, &mut labels) {
            if position_at != position {
                continue;
            }
            for spec in specs {
                expected.push(PackQuestion {
                    key: key_texts(&spec.key),
                    options: spec.options,
                });
            }
        }
    }
    let group_answers: Vec<&EarlierAnswer> = earlier.iter().take(expected.len()).collect();
    if group_answers.len() != expected.len() {
        return Err(invalid_consolidation(
            "extraction earlier answers do not cover their read",
        ));
    }
    let mut mapped: Vec<String> = Vec::with_capacity(group_answers.len());
    for (offered, want) in group_answers.iter().zip(&expected) {
        if offered.key != want.key {
            return Err(invalid_consolidation(
                "an extraction earlier answer names no rebuilt question",
            ));
        }
        let answer = map_candidate_alias(&offered.answer, &candidate_ids)?;
        if !want.options.contains(&answer) {
            return Err(invalid_consolidation(
                "an extraction earlier answer lies outside its canonical options",
            ));
        }
        mapped.push(answer);
    }
    let shortlist = identity_shortlist(&mapped);
    if shortlist.len() < 2 {
        return Err(invalid_consolidation(
            "extraction final choice has no shortlist",
        ));
    }
    let rest = earlier.get(expected.len()..).ok_or_else(|| {
        invalid_consolidation("extraction earlier answers do not cover their read")
    })?;
    let base = [DecisionKeyPart::Number(position)];
    let (questions, consumed, target) =
        replay_identity_final(&base, true, shortlist, rest, round, &candidate_ids)?;
    if consumed != rest.len() {
        return Err(invalid_consolidation(
            "extraction earlier answers do not cover their read",
        ));
    }
    Ok((questions, position, target))
}

/// The resolution final question over `built` with `earlier` as its page
/// answers: one answer per rebuilt page in page order, each inside the
/// canonical resolutions, with at least two pages reading different
/// non-standing resolutions, or native asks no final. The part carries the
/// resolution sentinel round zero. Returns the final question with the
/// checked page answers for the lent execution.
pub(super) fn resolution_final_plan(
    built: &BuiltConflict,
    earlier: &[EarlierAnswer],
    part: ExtractionPart,
) -> Result<(PackQuestion, Vec<Option<String>>)> {
    let ExtractionPart::Final { round } = part else {
        return Err(invalid_consolidation(
            "extraction pack part does not match its read",
        ));
    };
    if round != 0 {
        return Err(invalid_consolidation(
            "extraction final round does not exist",
        ));
    }
    let pages = built.rows.pages();
    if earlier.len() != pages.len() {
        return Err(invalid_consolidation(
            "extraction earlier answers do not cover their read",
        ));
    }
    if pages.len() < 2 {
        return Err(invalid_consolidation(
            "extraction pages read no final choice",
        ));
    }
    let mut answers: Vec<String> = Vec::with_capacity(earlier.len());
    for (index, offered) in earlier.iter().enumerate() {
        let want = key_texts(&resolution_choice_spec(Some(index)).key);
        if offered.key != want {
            return Err(invalid_consolidation(
                "an extraction earlier answer names no rebuilt question",
            ));
        }
        let mapped = map_candidate_alias(&offered.answer, &built.candidate_ids)?;
        let answer = mapped.as_str();
        if !RESOLUTIONS.contains(&answer) {
            return Err(invalid_consolidation(
                "an extraction earlier answer lies outside its canonical options",
            ));
        }
        answers.push(mapped);
    }
    if answers.iter().any(|answer| answer.as_str() == ESCALATE) {
        return Err(invalid_consolidation(
            "extraction pages read no final choice",
        ));
    }
    let first = answers
        .first()
        .ok_or_else(|| invalid_consolidation("extraction pages read no final choice"))?;
    if answers.iter().all(|answer| answer == first) {
        return Err(invalid_consolidation(
            "extraction pages read no final choice",
        ));
    }
    let read: Vec<Option<String>> = answers.into_iter().map(Some).collect();
    let spec = resolution_final_prep(&read);
    let question = PackQuestion {
        key: key_texts(&spec.key),
        options: spec.options,
    };
    Ok((question, read))
}

/// The questions of the conflict identity final `part` over `built` with
/// `earlier` as its group and round answers: the groups validated across the
/// rebuilt pages, then the requested one-based round replayed over the
/// shortlist they name. Returns the round questions with the target round
/// shortlist for the lent execution.
pub(super) fn identity_final_plan(
    built: &BuiltConflict,
    earlier: &[EarlierAnswer],
    part: ExtractionPart,
) -> Result<(Vec<PackQuestion>, Vec<EntityId>)> {
    let ExtractionPart::Final { round } = part else {
        return Err(invalid_consolidation(
            "extraction pack part does not match its read",
        ));
    };
    if round == 0 {
        return Err(invalid_consolidation(
            "extraction final round does not exist",
        ));
    }
    let pages = built.rows.pages();
    let paged = pages.len() > 1;
    let mut expected: Vec<PackQuestion> = Vec::new();
    for (page_index, shown) in pages.iter().enumerate() {
        let page = paged.then_some(page_index);
        let ids = built.rows.ids(shown);
        let mut labels = CallLabelMap::default();
        for spec in conflict_identity_specs(&ids, !built.across || paged, page, &mut labels) {
            expected.push(PackQuestion {
                key: key_texts(&spec.key),
                options: spec.options,
            });
        }
    }
    let group_answers: Vec<&EarlierAnswer> = earlier.iter().take(expected.len()).collect();
    if group_answers.len() != expected.len() {
        return Err(invalid_consolidation(
            "extraction earlier answers do not cover their read",
        ));
    }
    let mut mapped: Vec<String> = Vec::with_capacity(group_answers.len());
    for (offered, want) in group_answers.iter().zip(&expected) {
        if offered.key != want.key {
            return Err(invalid_consolidation(
                "an extraction earlier answer names no rebuilt question",
            ));
        }
        let answer = map_candidate_alias(&offered.answer, &built.candidate_ids)?;
        if !want.options.contains(&answer) {
            return Err(invalid_consolidation(
                "an extraction earlier answer lies outside its canonical options",
            ));
        }
        mapped.push(answer);
    }
    let shortlist = identity_shortlist(&mapped);
    if shortlist.len() < 2 {
        return Err(invalid_consolidation(
            "extraction final choice has no shortlist",
        ));
    }
    let rest = earlier.get(expected.len()..).ok_or_else(|| {
        invalid_consolidation("extraction earlier answers do not cover their read")
    })?;
    let base = [DecisionKeyPart::Text("identity")];
    let (questions, consumed, target) = replay_identity_final(
        &base,
        !built.across,
        shortlist,
        rest,
        round,
        &built.candidate_ids,
    )?;
    if consumed != rest.len() {
        return Err(invalid_consolidation(
            "extraction earlier answers do not cover their read",
        ));
    }
    Ok((questions, target))
}
