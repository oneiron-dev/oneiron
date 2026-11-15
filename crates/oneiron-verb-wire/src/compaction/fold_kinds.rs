//! Moved from `crates/oneiron/src/compaction/fold_kinds.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::compaction::folds::FoldMarkInput;
use serde::Deserialize;
use serde::Serialize;

/// The kind of content one fold by kind folds in each step of its span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FoldKind {
    /// A step's REPL cell output: the console its sandbox returned. The
    /// program text and its say() messages stay.
    ReplOutput,
    /// A step's program text. Its speech calls stay in the stub, with
    /// their text; its console stays.
    Program,
}

impl FoldKind {
    /// The kind as the agent writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReplOutput => "repl_output",
            Self::Program => "program",
        }
    }
}

/// One step a fold by kind folded: what its stub keeps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldedOutput {
    pub step: u64,
    /// The folded content's own handle first, then each stored result it
    /// names: `describe(handle)` or `sandbox.fs.read_file` reads it back.
    pub handles: Vec<String>,
    /// Every id the folded content names.
    pub ids: Vec<String>,
    /// For a folded program, each speech call the step made, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub said: Vec<FoldedSpeech>,
}

/// One speech call a folded program made: its verb and the bridge call that
/// made it. The ledger keeps no words of it: the stub reads the call's text
/// from the run's record each time it renders, with custody values masked,
/// so a value custody learns after the fold lands is masked too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldedSpeech {
    /// `self.speak`, `self.think` or `self.express`.
    pub verb: String,
    /// The call's index in the run's bridge calls.
    pub call: u64,
}

/// The bound of a fold by kind that names none: past every step, and the
/// largest a JavaScript number names exactly, so a hook's rewrite of the
/// call keeps it.
pub const UNBOUNDED_THROUGH: u64 = (1 << 53) - 1;

/// `self.fold`'s object spelling, a fold by kind: `before` (exclusive) or
/// `through` (inclusive) bounds its span, `from` starts it (default the
/// first step), and with no bound it reaches the current step.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoldByKind {
    kind: FoldKind,
    #[serde(default)]
    from: Option<FoldStepRef>,
    #[serde(default)]
    through: Option<FoldStepRef>,
    #[serde(default)]
    before: Option<FoldStepRef>,
    #[serde(default)]
    note: Option<String>,
}

/// A step as the agent names it: `40`, or its label `"t40"`.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum FoldStepRef {
    Seq(u64),
    Label(String),
}

impl FoldStepRef {
    fn seq(&self) -> Result<u64, String> {
        match self {
            Self::Seq(seq) => Ok(*seq),
            Self::Label(label) => {
                let text = label.trim();
                text.strip_prefix('t')
                    .unwrap_or(text)
                    .parse::<u64>()
                    .map_err(|_| format!("`{label}` names no step; write 40 or \"t40\""))
            }
        }
    }
}

impl FoldByKind {
    pub fn normalize(self) -> Result<FoldMarkInput, String> {
        let from = self
            .from
            .as_ref()
            .map(FoldStepRef::seq)
            .transpose()?
            .unwrap_or(0);
        let through = match (&self.through, &self.before) {
            (Some(_), Some(_)) => {
                return Err("a fold by kind names `through` or `before`, not both".to_owned());
            }
            (Some(through), None) => through.seq()?,
            (None, Some(before)) => before
                .seq()?
                .checked_sub(1)
                .ok_or_else(|| "no step runs before t0".to_owned())?,
            // Every step that has run: the ledger cuts it to the current step.
            (None, None) => UNBOUNDED_THROUGH,
        };
        Ok(FoldMarkInput {
            from,
            through,
            note: self.note,
            kind: Some(self.kind),
        })
    }
}
