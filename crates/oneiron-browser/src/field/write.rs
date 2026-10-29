//! The host's field writer (moved out of `field` whole): one model call
//! that writes a field's text, and the yes/no check of what it wrote.

use super::spec::TextReference;
use serde::Serialize;
use serde_json::Value;

/// One writer call's ask: the field as the page shows it, the page, and
/// what the step gave the writer to go on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldWrite {
    /// What the text is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
    /// The step's references, none of which the step typed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<TextReference>,
    /// The only texts the field takes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    /// The field's row: its role and accessible name, empty when the step's
    /// read did not find it.
    pub role: String,
    pub name: String,
    pub url: String,
    pub title: String,
    /// The subgoal's one clock, in Unix milliseconds (FIX 8903): the call
    /// ends at it, with no clock of its own. None where the caller set none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
}

/// What the writer wrote.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldWritten {
    pub text: String,
    /// The call's id, as the host names it: the text's `text_ref`.
    pub call: String,
    /// The call's record, kept among the batch's decisions under
    /// [`FIELD_WRITER`]: its role, model and usage.
    pub record: Value,
}

/// Why the writer wrote nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldWriteError {
    /// The host has no writer, or no model serves its role.
    Unavailable(String),
    /// The model's admission refused the call before it went out.
    Refused(String),
    /// The call failed, or answered no text.
    Failed(String),
    /// The subgoal's clock ran out before the call answered (FIX 8903):
    /// the host ended the call there.
    OutOfTime(String),
}

/// The host's field writer (CUA E6): one model call, admitted on the
/// host's browser planner role and spent on the caller's run, that writes
/// one field's text. The batch asks it once per Fill that reaches
/// generation, and never retries it.
pub trait FieldWriter: Send + Sync {
    /// Writes the text `ask` names.
    ///
    /// # Errors
    ///
    /// Why no text was written.
    fn write(&self, ask: &FieldWrite) -> Result<FieldWritten, FieldWriteError>;
}

/// No writer: a Fill that reaches generation stops `writer_unavailable`.
pub struct NoWriter;

impl FieldWriter for NoWriter {
    fn write(&self, _ask: &FieldWrite) -> Result<FieldWritten, FieldWriteError> {
        Err(FieldWriteError::Unavailable(
            "this browser host has no field writer".to_owned(),
        ))
    }
}

/// A yes/no check of a written text, asked of the host's decider: its
/// question, and the state it reads, which holds the text.
pub struct TextCheck<'a> {
    pub question: &'a str,
    pub state: Value,
    /// The subgoal's one clock, as the writer's (FIX 8903).
    pub until_ms: Option<u64>,
}

/// A text check's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextVerdict {
    Yes,
    No,
    /// No rung answered.
    Abstain,
}

/// The decider's answer to a text check, with the decision's record for
/// the batch's decisions.
#[derive(Clone, Debug)]
pub struct TextCheckReply {
    pub verdict: TextVerdict,
    pub decision: Value,
}

/// The key a batch's `decisions` entry holds a writer call's record under.
pub const FIELD_WRITER: &str = "field_writer";
