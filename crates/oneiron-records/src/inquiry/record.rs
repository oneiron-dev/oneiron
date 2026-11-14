//! Moved from `crates/oneiron/src/inquiry/record.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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

pub fn refuse(rule: &str) -> Error {
    Error::InvalidConfig(format!("inquiry: {rule}"))
}
