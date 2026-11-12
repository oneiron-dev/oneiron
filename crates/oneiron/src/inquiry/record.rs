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
use crate::error::{Error, Result};

/// What the company keeps of an answer: the company setting `inquiry_keep`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InquiryKeep {
    /// The default. The answer text is held with the task, bound to the
    /// asking actor, not indexed and not recallable, and dropped at task end
    /// or at `valid_until`.
    #[default]
    Task,
    /// The answer lands as a foreign, attributed, non-re-shareable record in
    /// the company vault.
    Copy,
}

impl InquiryKeep {
    /// The wire token: `task` or `copy`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Copy => "copy",
        }
    }

    /// The keep a wire token names.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "task" => Some(Self::Task),
            "copy" => Some(Self::Copy),
            _ => None,
        }
    }
}

/// How an inquiry stands.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InquiryOutcome {
    /// The member's vault answered with statements.
    Answered,
    /// One shape for nothing there, not allowed, the member said no and no
    /// reply in time.
    NoAnswer,
    /// The question went to the member; the asker sends the inquiry again.
    Pending,
    /// No route reached the member's vault. Only the asking side records it.
    Unavailable,
}

impl InquiryOutcome {
    /// The wire and receipt token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::NoAnswer => "no_answer",
            Self::Pending => "pending",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Who made a statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementSource {
    /// The member opened or answered it: the member's word.
    MemberWord,
    /// The member's companion answered it, or filed the note it came from:
    /// provisional, never the member's word.
    CompanionOfMember,
}

impl StatementSource {
    /// The wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemberWord => "member_word",
            Self::CompanionOfMember => "companion_of_member",
        }
    }

    /// Whether the statement is provisional: the companion's, not the
    /// member's.
    #[must_use]
    pub const fn is_provisional(self) -> bool {
        matches!(self, Self::CompanionOfMember)
    }

    /// The attribution the asking side shows, under `member`, the name it
    /// holds for the member it asked.
    #[must_use]
    pub fn label(self, member: &str) -> String {
        match self {
            Self::MemberWord => member.to_owned(),
            Self::CompanionOfMember => format!("companion of {member}"),
        }
    }
}

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

/// Who asks: the company vault, its actor and the actor's role there.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InquiryAsker {
    /// The asking vault's authority vault id, 64 lower-case hex.
    pub vault: String,
    /// The asking actor in that vault.
    pub actor: EntityId,
    /// The actor's role in that vault, as the member's log shows it.
    pub role: String,
}

/// The task the inquiry serves, in the asking vault.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InquiryTask {
    pub id: EntityId,
    /// One line: what the task needs the answer for.
    pub purpose: String,
}

/// An inquiry: one question from a company vault about one member, sent to
/// that member's vault.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Inquiry {
    /// The asking vault's id for the inquiry. A repeat with the same id is
    /// the same inquiry and returns its current answer.
    pub id: EntityId,
    pub from: InquiryAsker,
    pub task: InquiryTask,
    pub question: String,
    pub keep: InquiryKeep,
    /// The instant the asker stops waiting, in the vault clock's seconds.
    pub expires_at: u64,
}

impl Inquiry {
    /// Checks the inquiry's fields: a 64-hex asking vault, a role, a
    /// one-line purpose, a question and an expiry.
    ///
    /// # Errors
    ///
    /// The first field that breaks its rule.
    pub fn validate(&self) -> Result<()> {
        let vault = &self.from.vault;
        if vault.len() != 64
            || !vault
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(refuse("the asking vault is not 64 lower-case hex"));
        }
        if self.from.role.trim().is_empty() || self.from.role.contains('\n') {
            return Err(refuse("the asker's role is not one line"));
        }
        if self.task.purpose.trim().is_empty() || self.task.purpose.contains('\n') {
            return Err(refuse("the task's purpose is not one line"));
        }
        if self.question.trim().is_empty() {
            return Err(refuse("the inquiry has no question"));
        }
        if self.expires_at == 0 {
            return Err(refuse("the inquiry has no expiry"));
        }
        Ok(())
    }

    /// The inquiry as it crosses: JSON.
    ///
    /// # Errors
    ///
    /// An invalid inquiry; an encoding error.
    pub fn encode_wire(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| refuse(&format!("encode: {error}")))
    }

    /// An inquiry read from the wire, checked as [`Self::validate`] does.
    /// Fields this build does not know are ignored.
    ///
    /// # Errors
    ///
    /// Bytes that are not an inquiry; an invalid inquiry.
    pub fn decode_wire(bytes: &[u8]) -> Result<Self> {
        let inquiry: Self =
            serde_json::from_slice(bytes).map_err(|error| refuse(&format!("decode: {error}")))?;
        inquiry.validate()?;
        Ok(inquiry)
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

pub(super) fn refuse(rule: &str) -> Error {
    Error::InvalidConfig(format!("inquiry: {rule}"))
}
