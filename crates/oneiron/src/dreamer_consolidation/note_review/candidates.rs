//! One NOTE review reply's candidates (OF-073), read through the review
//! call's own labels (FIX 7506): a subject is a listed entity's `P<n>` or a
//! person the reply declared, and each citation quotes the note's projected
//! markdown, which the engine binds to the one byte range it names. A
//! candidate whose label or quote binds nothing is skipped, as a bad range
//! was; the reply stands.

use std::ops::Range;

use rmpv::Value;

use super::Note;
use crate::claim::{ClaimSource, ClaimSubject};
use crate::dreamer_consolidation::call_labels::{CallLabelMap, CallSources, SourceShown};
use crate::dreamer_consolidation::evidence::EvidenceLocator;
use crate::dreamer_consolidation::executor::extraction::{decode_ref, resolve_subject};
use crate::dreamer_consolidation::extracted_people::PersonBindings;
use crate::dreamer_consolidation::provenance::PromotionCandidate;
use crate::dreamer_consolidation::support::{
    SCOPE_PROJECT_KEY, TURN_BODY_FACET_REF_KEY, invalid_consolidation,
};
use crate::dreamer_consolidation::value_projection::json_to_rmpv;
use crate::dreamer_promotion::DreamerRunContext;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::{EntityId, Result};

/// A NOTE review call's sources: its labels over the one NOTE it showed,
/// as the projected markdown it read.
pub(super) struct NoteSources<'n> {
    pub(super) labels: &'n CallLabelMap,
    pub(super) note: &'n Note,
}

impl CallSources for NoteSources<'_> {
    fn labels(&self) -> &CallLabelMap {
        self.labels
    }

    fn shown(&self, id: EntityId) -> Option<SourceShown<'_>> {
        (id == self.note.id).then(|| SourceShown {
            text: Some(self.note.markdown.as_str()),
            project: Some(self.note.project),
        })
    }
}

/// One reply candidate as a belief `note` grounds, with the byte ranges it
/// cites, or why it is not written. Every evidence ref must quote the
/// note's markdown, which binds to one byte range of it on character
/// boundaries. A candidate citing anything else, naming a subject its call
/// did not list or a person its reply did not bind, or naming a correction
/// or a relationship, is skipped: the review holds no prior head and a NOTE
/// carries no relationship.
pub(super) fn note_candidate(
    item: &serde_json::Value,
    note: &Note,
    run: &DreamerRunContext,
    sources: &NoteSources<'_>,
    people: &PersonBindings,
) -> Result<(PromotionCandidate, Vec<Range<usize>>)> {
    let named = |field: &str| item.get(field).is_some_and(|value| !value.is_null());
    if named("corrects") || named("rel") {
        return Err(invalid_consolidation(
            "a note review holds no prior head or relationship",
        ));
    }
    let subject = resolve_subject(item, sources.labels, people)?;
    let predicate = item
        .get("predicate")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_consolidation("note candidate names no predicate"))?;
    crate::claim::validate_predicate(predicate, false).map_err(|_| {
        invalid_consolidation("note candidate's predicate breaks the claim grammar")
    })?;
    let value = match item.get("value") {
        Some(value) if !value.is_null() => json_to_rmpv(value),
        _ => return Err(invalid_consolidation("note candidate names no value")),
    };
    let confidence = item
        .get("confidence")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.5) as f32;
    let refs = item
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array)
        .filter(|refs| !refs.is_empty())
        .ok_or_else(|| invalid_consolidation("note candidate cites no evidence"))?;
    let mut cited_ranges = Vec::with_capacity(refs.len());
    for cited in refs {
        let EvidenceLocator::TurnTextRange {
            source_id,
            start,
            end,
        } = decode_ref(cited, sources)?
            .locator
            .map_err(|binding| invalid_consolidation(binding.name()))?
        else {
            return Err(invalid_consolidation(
                "note candidate cites something other than the note",
            ));
        };
        // A blank range grounds nothing: a sealed pad's scratch lines read
        // as blanks.
        if source_id != note.id
            || start >= end
            || end > note.markdown.len()
            || !note.markdown.is_char_boundary(start)
            || !note.markdown.is_char_boundary(end)
            || note.markdown[start..end].trim().is_empty()
        {
            return Err(invalid_consolidation(
                "note candidate's evidence is not a range of the note",
            ));
        }
        cited_ranges.push(start..end);
    }
    let mut fields = vec![(
        Value::from(TURN_BODY_FACET_REF_KEY),
        Value::Binary(note.facet.as_bytes().to_vec()),
    )];
    if let Some(topic) = item.get("topic_key").filter(|topic| !topic.is_null()) {
        fields.push((Value::from("topic_key"), json_to_rmpv(topic)));
    }
    if note.project != crate::claim::default_project_id() {
        fields.push((
            Value::from(SCOPE_PROJECT_KEY),
            Value::Binary(note.project.as_bytes().to_vec()),
        ));
    }
    let candidate =
        ClaimCandidate::new(predicate, ClaimSubject::Entity(subject), value, confidence)
            .with_scope(Value::Map(fields));
    let facts = crate::dreamer_consolidation::conflict::candidate_facts(&candidate)?;
    let claim_id = crate::dreamer_consolidation::conflict::deterministic_claim_id(
        run.attempt_id,
        subject,
        predicate,
        &facts.value,
        facts.world,
        facts.facet,
        facts.rel.as_ref(),
        facts.project,
        facts.topic.as_deref(),
    )?;
    let promotion = PromotionCandidate {
        claim_id,
        candidate,
        evidence_turn_refs: vec![note.id],
        provenance_chain: Vec::new(),
        supersedes: None,
        // The Dreamer's reading of a NOTE is its own inference, whoever
        // wrote the NOTE.
        evidence_meet: ClaimSource::Generated,
        // A claim's times are Unix seconds (FIX 8695).
        occurred: TimeRange {
            start: run.now_ms / 1_000,
            end: run.now_ms / 1_000,
        },
        learned_at: run.now_ms / 1_000,
        decisions: Vec::new(),
    };
    Ok((promotion, cited_ranges))
}

/// Whether a belief citing `range` cites the `keep` line whose text is
/// `line`: the two share text that is not blank. Both are ranges of
/// `markdown` on character boundaries.
pub(super) fn cites(markdown: &str, range: &Range<usize>, line: &Range<usize>) -> bool {
    let (start, end) = (range.start.max(line.start), range.end.min(line.end));
    start < end && !markdown[start..end].trim().is_empty()
}
