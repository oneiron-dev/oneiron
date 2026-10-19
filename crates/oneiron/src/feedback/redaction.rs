//! The engine text filter (OF-420): the seam every free text crosses before
//! it may leave the vault, and the feedback redactor over it.
//!
//! A [`TextFilter`] returns the text as filtered, or why it could not filter
//! it. No implementation here hands its input back, and there is no default
//! one: a host fills the seam with an in-vault recogniser (the server's
//! Oneironer tagger) and turns the spans it recognised into text with
//! [`apply_recognised_spans`], the one constructor of [`FilteredText`]. A
//! recogniser that found nothing proves nothing: its output is filtered text,
//! never a judgment about what the text holds or where it may go.
//!
//! [`FilteredFeedback`] is the [`FeedbackRedactor`] over any filter. It runs
//! the filter over every free text a bundle carries, and a filter that cannot
//! run, or answers out of shape, stops the whole bundle: nothing leaves half
//! filtered.

use crate::memory::extraction::NerSpan;

use super::bundle::{FeedbackBundle, FeedbackProposal};
use super::consent::{FeedbackRedactionError, FeedbackRedactor};

/// Whether the filter replaces every span the recogniser returns, whatever
/// its label (CALLS "FIX 4489 redaction label policy"). A label ruling
/// changes this line.
const TEXT_FILTER_REDACTS_EVERY_LABEL: bool = true;

/// The message a recognised span must name: a filter asks about exactly one
/// text, sent as the input's only message.
const TEXT_FILTER_MESSAGE: usize = 0;

/// Whether a recognised span labelled `label` is replaced by `[label]`.
const fn redacts_label(_label: &str) -> bool {
    TEXT_FILTER_REDACTS_EVERY_LABEL
}

/// Which filter made a [`FilteredText`], kept beside it for local
/// provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextFilterIdentity {
    /// The recogniser's model, as its host names it.
    pub model: String,
    /// The served stack that made the answer, when the recogniser names one.
    pub stack_sha16: Option<String>,
}

/// Text as an in-vault filter returned it, and the filter that made it.
///
/// Its only constructor is [`apply_recognised_spans`], so every value is the
/// exact input with each span the recogniser returned replaced as the label
/// policy says. It is filtered text and nothing more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilteredText {
    text: String,
    filter: TextFilterIdentity,
}

impl FilteredText {
    /// The filtered text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The filtered text, owned.
    #[must_use]
    pub fn into_text(self) -> String {
        self.text
    }

    /// The filter that made it.
    #[must_use]
    pub const fn filter(&self) -> &TextFilterIdentity {
        &self.filter
    }
}

/// Why a filter returned no text. Neither variant carries the text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TextFilterError {
    /// The filter could not run: no recogniser, one off the device, or a
    /// call that failed.
    #[error("the text filter is unavailable: {0}")]
    Unavailable(String),
    /// The recogniser answered out of shape for this text.
    #[error("the text filter rejected its recogniser's answer: {0}")]
    Rejected(String),
}

/// The in-vault filter free text runs through before it may leave.
///
/// An implementation returns the text only as [`apply_recognised_spans`]
/// made it from a recogniser's answer over exactly that text, or an error.
/// It never hands its input back because it could not run.
pub trait TextFilter: Send + Sync {
    /// Filters `text`, or explains why it could not.
    fn filter(&self, text: &str) -> Result<FilteredText, TextFilterError>;
}

/// Applies a recogniser's spans to the exact text it was asked about.
///
/// Every span must name message 0 (the filter's one message), cover a
/// nonempty half-open byte range inside `text` on character boundaries, and
/// carry a label with no whitespace, control character or bracket; once
/// sorted, no two spans may overlap. Any span out of shape rejects the whole
/// answer. Each span the label policy redacts becomes `[label]`; every byte
/// outside the spans stays as written. No spans is an answer like any other:
/// the text comes back filtered, and that says nothing about what it holds.
///
/// # Errors
/// [`TextFilterError::Rejected`] for any span out of shape.
pub fn apply_recognised_spans(
    text: &str,
    spans: &[NerSpan],
    filter: TextFilterIdentity,
) -> Result<FilteredText, TextFilterError> {
    for span in spans {
        check_span(text, span)?;
    }
    let mut ordered: Vec<&NerSpan> = spans.iter().collect();
    ordered.sort_by_key(|span| (span.start, span.end));
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for span in ordered {
        if span.start < cursor {
            return Err(TextFilterError::Rejected(format!(
                "two recognised spans overlap at byte {}",
                span.start
            )));
        }
        out.push_str(slice(text, cursor, span.start)?);
        if redacts_label(&span.label) {
            out.push('[');
            out.push_str(&span.label);
            out.push(']');
        } else {
            out.push_str(slice(text, span.start, span.end)?);
        }
        cursor = span.end;
    }
    out.push_str(slice(text, cursor, text.len())?);
    Ok(FilteredText { text: out, filter })
}

/// One span against the text it claims to cover. The refusal names offsets
/// and the rule, never the text or the label.
fn check_span(text: &str, span: &NerSpan) -> Result<(), TextFilterError> {
    if span.message != TEXT_FILTER_MESSAGE {
        return Err(TextFilterError::Rejected(format!(
            "a recognised span names message {}; the filter sent one",
            span.message
        )));
    }
    if span.start >= span.end || text.get(span.start..span.end).is_none() {
        return Err(TextFilterError::Rejected(format!(
            "the recognised span at bytes {}..{} is empty, runs past the text or splits a \
             character",
            span.start, span.end
        )));
    }
    let label_in_shape = !span.label.is_empty()
        && !span
            .label
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '[' || c == ']');
    if !label_in_shape {
        return Err(TextFilterError::Rejected(format!(
            "the recognised span at bytes {}..{} carries a blank label or one with whitespace, a \
             control character or a bracket",
            span.start, span.end
        )));
    }
    Ok(())
}

fn slice(text: &str, start: usize, end: usize) -> Result<&str, TextFilterError> {
    text.get(start..end).ok_or_else(|| {
        TextFilterError::Rejected(format!(
            "bytes {start}..{end} are not a character range of the text"
        ))
    })
}

/// The feedback redactor over an in-vault [`TextFilter`].
///
/// Every free text a bundle carries (the note, and a proposal's problem and
/// fix) leaves only as the filter returned it. The rest is closed vocabulary
/// nobody wrote as prose (the category, versions, the build platform, the
/// whitelisted config snapshot, diagnosis references and edge kinds) and
/// leaves as built. A filter that cannot run is
/// [`FeedbackRedactionError::Unavailable`], an answer out of shape is
/// [`FeedbackRedactionError::Rejected`], and either stops the whole bundle.
/// A bundle with no free text needs no filter and is returned as built.
#[derive(Debug, Clone)]
pub struct FilteredFeedback<F> {
    filter: F,
}

impl<F> FilteredFeedback<F> {
    /// The redactor over `filter`.
    #[must_use]
    pub const fn new(filter: F) -> Self {
        Self { filter }
    }
}

impl<F: TextFilter> FilteredFeedback<F> {
    fn filtered(&self, field: &str, text: &str) -> Result<String, FeedbackRedactionError> {
        self.filter
            .filter(text)
            .map(FilteredText::into_text)
            .map_err(|error| match error {
                TextFilterError::Unavailable(reason) => {
                    FeedbackRedactionError::Unavailable(format!("{field}: {reason}"))
                }
                TextFilterError::Rejected(reason) => {
                    FeedbackRedactionError::Rejected(format!("{field}: {reason}"))
                }
            })
    }
}

impl<F: TextFilter> FeedbackRedactor for FilteredFeedback<F> {
    fn redact(&self, bundle: FeedbackBundle) -> Result<FeedbackBundle, FeedbackRedactionError> {
        // Named field by field: a field added to the bundle stops this
        // compiling until someone decides whether it is free text.
        let FeedbackBundle {
            category,
            engine_version,
            platform,
            config,
            healer_diagnosis,
            user_note,
            proposal,
        } = bundle;
        let user_note = user_note
            .map(|note| self.filtered("user_note", &note))
            .transpose()?;
        let proposal = match proposal {
            None => None,
            Some(FeedbackProposal { problem, fix }) => Some(FeedbackProposal {
                problem: self.filtered("proposal problem", &problem)?,
                fix: self.filtered("proposal fix", &fix)?,
            }),
        };
        Ok(FeedbackBundle {
            category,
            engine_version,
            platform,
            config,
            healer_diagnosis,
            user_note,
            proposal,
        })
    }
}
