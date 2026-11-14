//! The inquiry and its answer (federation.md #inquiry, ruled 2026-11-11): the
//! records a company vault's `vault.inquire` sends to a member's vault, and
//! the answer that comes back.
//!
//! ```text
//! inquiry { id, from: vault + actor + role, task: id + one-line purpose,
//!           question, keep: task | copy, expires_at }
//! answer  { inquiry_id, outcome: answered | no_answer | pending | unavailable,
//!           statements: [text + source], valid_until, keep }
//! ```
//!
//! [`InquiryAnswer`] is the one wire projection of an answer. It carries
//! statement text and its source only: no hit, score, vector or record id of
//! the member's vault crosses, so ranking never spans vaults. `no_answer` has
//! one shape for "nothing there", "not allowed", "the member said no" and "no
//! reply in time": no reason, no statements, no `valid_until`.
//!
//! A statement's source is the member's word or the member's companion
//! (INQUIRY-COMPANION-SOURCE = A). The asking side names the member it asked
//! ("companion of <member>"), so no identifier of the member's vault crosses.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;

#[doc(hidden)]
pub(super) use oneiron_records::inquiry::record::refuse;
#[doc(hidden)]
pub use oneiron_records::inquiry::record::{
    Inquiry, InquiryAsker, InquiryKeep, InquiryOutcome, InquiryTask, StatementSource,
};

/// One statement of an answer: its text and who made it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InquiryStatement {
    text: String,
    source: StatementSource,
}

impl InquiryStatement {
    /// A statement of `text` by `source`.
    ///
    /// # Errors
    ///
    /// Empty text.
    pub fn new(text: impl Into<String>, source: StatementSource) -> Result<Self> {
        let statement = Self {
            text: text.into(),
            source,
        };
        statement.validate()?;
        Ok(statement)
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn source(&self) -> StatementSource {
        self.source
    }

    fn validate(&self) -> Result<()> {
        if self.text.trim().is_empty() {
            return Err(refuse("a statement has no text"));
        }
        Ok(())
    }
}

/// An answer to an inquiry, in the one shape that crosses between vaults.
/// Statements and `valid_until` are present only when the outcome is
/// `answered`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InquiryAnswer {
    inquiry_id: EntityId,
    outcome: InquiryOutcome,
    statements: Vec<InquiryStatement>,
    valid_until: Option<u64>,
    keep: InquiryKeep,
}

impl InquiryAnswer {
    /// `statements` for `inquiry`, good until `valid_until`.
    ///
    /// # Errors
    ///
    /// No statements; a statement with no text; a `valid_until` of zero.
    pub fn answered(
        inquiry: &Inquiry,
        statements: Vec<InquiryStatement>,
        valid_until: u64,
    ) -> Result<Self> {
        let answer = Self {
            inquiry_id: inquiry.id,
            outcome: InquiryOutcome::Answered,
            statements,
            valid_until: Some(valid_until),
            keep: inquiry.keep,
        };
        answer.validate()?;
        Ok(answer)
    }

    /// `no_answer` for `inquiry`: the same shape whatever the reason.
    #[must_use]
    pub fn no_answer(inquiry: &Inquiry) -> Self {
        Self::bare(inquiry, InquiryOutcome::NoAnswer)
    }

    /// `pending` for `inquiry`: the question went to the member.
    #[must_use]
    pub fn pending(inquiry: &Inquiry) -> Self {
        Self::bare(inquiry, InquiryOutcome::Pending)
    }

    /// `unavailable` for `inquiry`: the asking side found no route.
    #[must_use]
    pub fn unavailable(inquiry: &Inquiry) -> Self {
        Self::bare(inquiry, InquiryOutcome::Unavailable)
    }

    fn bare(inquiry: &Inquiry, outcome: InquiryOutcome) -> Self {
        Self {
            inquiry_id: inquiry.id,
            outcome,
            statements: Vec::new(),
            valid_until: None,
            keep: inquiry.keep,
        }
    }

    #[must_use]
    pub const fn inquiry_id(&self) -> EntityId {
        self.inquiry_id
    }

    #[must_use]
    pub const fn outcome(&self) -> InquiryOutcome {
        self.outcome
    }

    #[must_use]
    pub fn statements(&self) -> &[InquiryStatement] {
        &self.statements
    }

    #[must_use]
    pub const fn valid_until(&self) -> Option<u64> {
        self.valid_until
    }

    #[must_use]
    pub const fn keep(&self) -> InquiryKeep {
        self.keep
    }

    /// Whether this answers `inquiry`: its id and its keep.
    #[must_use]
    pub fn answers(&self, inquiry: &Inquiry) -> bool {
        self.inquiry_id == inquiry.id && self.keep == inquiry.keep
    }

    fn validate(&self) -> Result<()> {
        match self.outcome {
            InquiryOutcome::Answered => {
                if self.statements.is_empty() {
                    return Err(refuse("an answered inquiry has no statements"));
                }
                if self.valid_until.is_none_or(|until| until == 0) {
                    return Err(refuse("an answered inquiry has no valid_until"));
                }
                self.statements
                    .iter()
                    .try_for_each(InquiryStatement::validate)
            }
            InquiryOutcome::NoAnswer | InquiryOutcome::Pending | InquiryOutcome::Unavailable => {
                if !self.statements.is_empty() || self.valid_until.is_some() {
                    return Err(refuse(
                        "only an answered inquiry carries statements or valid_until",
                    ));
                }
                Ok(())
            }
        }
    }

    /// The answer as it crosses: JSON with exactly the five fields of the
    /// shape above.
    ///
    /// # Errors
    ///
    /// An encoding error.
    pub fn encode_wire(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|error| refuse(&format!("encode: {error}")))
    }

    /// An answer read from the wire. Its outcome, statements and
    /// `valid_until` must agree; fields this build does not know are
    /// ignored, so they never land.
    ///
    /// # Errors
    ///
    /// Bytes that are not an answer; an answer that breaks its outcome.
    pub fn decode_wire(bytes: &[u8]) -> Result<Self> {
        let answer: Self =
            serde_json::from_slice(bytes).map_err(|error| refuse(&format!("decode: {error}")))?;
        answer.validate()?;
        Ok(answer)
    }
}
