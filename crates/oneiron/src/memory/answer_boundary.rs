//! The answer boundary (OF-063, Engine ruling 1231): an answer's citations
//! checked against the evidence it was composed from, and a composed answer
//! that stands read for its prose record links. [`Memory::chat`] crosses it
//! over its own pack, and a host's answer route crosses it over the evidence
//! that route already read, so no answer keeps a gate of its own. Surface
//! re-exported by [`super`].

use super::{MEMORY_CODE_INVENTED_REFERENCE, Memory, RecordRefusal, RefusalReason};

/// The field a composed answer's prose links are receipted at.
const ANSWER_FIELD: &str = "/answer";

/// What the answer boundary made of one answer's citations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerAdmission {
    /// The answer stands on these sources: every citation is one its
    /// evidence carries, as that evidence keeps it, deduped in first
    /// appearance order. Never empty.
    Admitted(Vec<String>),
    /// The answer may not be shown: it cites nothing, a blank, or a source
    /// its evidence does not carry.
    Refused {
        /// The typed refusal of a nonblank citation the evidence does not
        /// carry, the first one; none for an answer that failed only by
        /// citing nothing or a blank.
        refusal: Option<RecordRefusal>,
        /// That refusal's own receipt (`reference_refusal:<hex>`): none
        /// without a refusal, or when no record was kept, as in an anonymous
        /// off-record session.
        receipt_ref: Option<String>,
    },
}

impl Memory<'_> {
    /// Takes one answer the door `row` returns across the answer boundary,
    /// over evidence its caller already holds: no retrieval runs here and
    /// nothing is spent. `carried` maps a citation to the source the
    /// evidence keeps for it, `None` for one it does not carry; `composed`
    /// is a composed answer's text, none for one read out of the evidence
    /// itself.
    ///
    /// All or nothing: an answer citing nothing, a blank, or a source its
    /// evidence does not carry is refused, and only the last is a typed
    /// [`RecordRefusal`], receipted under `row` on its own write as this
    /// surface's writer's (none inside an anonymous off-record session). A
    /// composed answer that stands is read once for its prose record links
    /// (`oneiron://`, display only) under this surface's own read: each that
    /// does not resolve leaves an `unlinked` receipt, the text stands as
    /// written, and a link never refuses the answer.
    #[must_use]
    pub fn admit_answer(
        &self,
        row: &'static str,
        proposed: &[String],
        composed: Option<&str>,
        carried: impl Fn(&str) -> Option<String>,
    ) -> AnswerAdmission {
        let Some(sources) = cited_sources(proposed, &carried) else {
            let refusal = proposed
                .iter()
                .position(|candidate| !candidate.trim().is_empty() && carried(candidate).is_none())
                .map(answer_refusal);
            let receipt_ref = refusal
                .as_ref()
                .and_then(|refusal| refusal.receipt(self, row));
            return AnswerAdmission::Refused {
                refusal,
                receipt_ref,
            };
        };
        if let Some(text) = composed {
            crate::gate::record_references::admit_prose_text(self, row, ANSWER_FIELD, text, 0);
        }
        AnswerAdmission::Admitted(sources)
    }
}

/// Every citation's source, deduped in first appearance order, or `None`
/// when any is blank or not carried, or none remains. An unknown or blank
/// citation is not quietly dropped to salvage the rest: a composer citing
/// something its evidence never held has already shown that its sourcing
/// cannot be trusted for the citations that happen to match.
fn cited_sources(
    proposed: &[String],
    carried: &impl Fn(&str) -> Option<String>,
) -> Option<Vec<String>> {
    let mut sources: Vec<String> = Vec::new();
    for candidate in proposed {
        if candidate.trim().is_empty() {
            return None;
        }
        let source = carried(candidate)?;
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    (!sources.is_empty()).then_some(sources)
}

/// The typed refusal of an answer whose citation at `index` its evidence
/// does not carry: the citation's pointer, never the cited ref.
fn answer_refusal(index: usize) -> RecordRefusal {
    let field = format!("/source_short_ids/{index}");
    RecordRefusal {
        reason: RefusalReason::InventedReference,
        code: MEMORY_CODE_INVENTED_REFERENCE.to_owned(),
        message: format!(
            "the answer cites a source at `{field}` that the evidence it was composed from does not carry; the answer was refused"
        ),
        suggestions: vec![
            "Cite only the short ids of the evidence the answer was composed from.".to_owned(),
        ],
        field,
    }
}
