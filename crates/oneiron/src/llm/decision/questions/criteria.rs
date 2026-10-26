//! A question's criteria (ARCH-0076 §3), one type for every asker: a typed
//! question's lines and a task's done-means criteria share it (OF-506), each
//! line the asker's own kind, so a done-means criterion keeps its evidence
//! ref and a provider reads the same triple as text.

use super::super::types::invalid;
use super::super::{AnswerContract, DecisionCall};
use crate::Result;
use serde::{Deserialize, Serialize};

/// The most bytes one criteria line holds.
pub const MAX_CRITERION_BYTES: usize = 512;

/// A question's criteria (ARCH-0076 §3): every line a yes needs, any line
/// that makes a no, and the lines that are never a reason to say no. A
/// changed line is a new definition, so the question's version versions the
/// triple. Each provider maps it for its rung; it reads as `criteria` in the
/// call's state. A list holds every line its author wrote: their count is no
/// refusal (FIX 9915).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuestionCriteria<Line = String> {
    // `Vec::new`, not a bare default: serde would otherwise bound `Line:
    // Default`, which a done-means `Criterion` is not.
    #[serde(default = "Vec::new")]
    pub yes_if_all: Vec<Line>,
    #[serde(default = "Vec::new")]
    pub no_if_any: Vec<Line>,
    #[serde(default = "Vec::new")]
    pub not_a_reason_to_say_no: Vec<Line>,
}

impl<Line> Default for QuestionCriteria<Line> {
    fn default() -> Self {
        Self {
            yes_if_all: Vec::new(),
            no_if_any: Vec::new(),
            not_a_reason_to_say_no: Vec::new(),
        }
    }
}

impl<Line> QuestionCriteria<Line> {
    /// No line in any of the three lists.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.yes_if_all.is_empty()
            && self.no_if_any.is_empty()
            && self.not_a_reason_to_say_no.is_empty()
    }

    /// The same triple with each line mapped by `line`, in order.
    #[must_use]
    pub fn map_lines<Other>(&self, line: impl Fn(&Line) -> Other) -> QuestionCriteria<Other> {
        QuestionCriteria {
            yes_if_all: self.yes_if_all.iter().map(&line).collect(),
            no_if_any: self.no_if_any.iter().map(&line).collect(),
            not_a_reason_to_say_no: self.not_a_reason_to_say_no.iter().map(&line).collect(),
        }
    }

    /// Every line, yes lines first, then no lines, then the lines that are
    /// never a reason to say no.
    pub fn lines(&self) -> impl Iterator<Item = &Line> {
        self.yes_if_all
            .iter()
            .chain(&self.no_if_any)
            .chain(&self.not_a_reason_to_say_no)
    }
}

impl QuestionCriteria {
    /// The triple a call's state carries as `criteria`. A `criteria` that is
    /// not a valid nonempty triple is the caller's own state, no rubric.
    #[must_use]
    pub fn from_state(state: &serde_json::Value) -> Option<Self> {
        let criteria = Self::deserialize(state.get("criteria")?).ok()?;
        (criteria.validate().is_ok() && !criteria.is_empty()).then_some(criteria)
    }

    /// The criteria of `call`'s question when it is a yes/no: the triple
    /// says what a yes and a no mean, so another contract reads it as state.
    #[must_use]
    pub fn for_call(call: &DecisionCall<'_>) -> Option<Self> {
        matches!(call.question.contract, AnswerContract::Noul)
            .then(|| Self::from_state(call.state))
            .flatten()
    }

    /// What a yes means, for a rung that describes each answer: every line a
    /// yes needs holds and no line that makes a no does.
    #[must_use]
    pub fn yes_means(&self) -> String {
        self.describe(
            "Every one of these holds: ",
            &self.yes_if_all,
            "None of these holds: ",
        )
    }

    /// What a no means: a line a yes needs fails, or a line that makes a no
    /// holds.
    #[must_use]
    pub fn no_means(&self) -> String {
        self.describe(
            "One of these fails: ",
            &self.yes_if_all,
            "One of these holds: ",
        )
    }

    fn describe(&self, needs: &str, yes: &[String], vetoes: &str) -> String {
        let mut parts = Vec::with_capacity(3);
        if !yes.is_empty() {
            parts.push(format!("{needs}{}.", yes.join("; ")));
        }
        if !self.no_if_any.is_empty() {
            parts.push(format!("{vetoes}{}.", self.no_if_any.join("; ")));
        }
        if !self.not_a_reason_to_say_no.is_empty() {
            parts.push(format!(
                "Never a no on its own: {}.",
                self.not_a_reason_to_say_no.join("; ")
            ));
        }
        parts.join(" ")
    }

    /// The triple as a rubric for a rung that reads prose, every line in
    /// order.
    #[must_use]
    pub fn rubric(&self) -> String {
        let mut rubric = String::from("Criteria:");
        for (head, lines) in [
            ("Yes only if all of these hold:", &self.yes_if_all),
            ("No if any of these holds:", &self.no_if_any),
            ("Not a reason to say no:", &self.not_a_reason_to_say_no),
        ] {
            if lines.is_empty() {
                continue;
            }
            rubric.push('\n');
            rubric.push_str(head);
            for line in lines {
                rubric.push_str("\n- ");
                rubric.push_str(line);
            }
        }
        rubric
    }

    /// Each line nonempty, of at most [`MAX_CRITERION_BYTES`], with no NUL.
    pub fn validate(&self) -> Result<()> {
        if self.lines().any(|line| {
            line.trim().is_empty() || line.len() > MAX_CRITERION_BYTES || line.contains('\0')
        }) {
            return Err(invalid("invalid question criteria"));
        }
        Ok(())
    }
}
