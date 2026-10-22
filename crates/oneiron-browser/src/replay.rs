//! What an effect's receipt keeps for a replay program (CUA E7): the act's
//! own operands as its verb took them, before the act used them up, and
//! the steps that stopped, as a session's history notes them.
//!
//! An `open` keeps the URL it asked for, not the page a redirect left (the
//! receipt's `url` is that); a click, type or select keeps the locator of
//! the row it resolved before it acted; a type keeps its text, its secret
//! by handle, and whether it cleared the field; a select its option; a Fill
//! the field its step named, never text its provenance could not give back.
//!
//! A typed text the shared classifier calls a secret (FIX 8028,
//! `secret_fields`), whether by its field or by its own value, is never kept
//! as text: the session takes that exact text into the run's custody and
//! keeps the run-bound handle and its kind, or, where custody took none,
//! a withheld operand naming why. A proof keeps no handle: its copy is
//! withheld too (`library::secret_slots`).

use crate::{BatchStep, BatchStopCause, FieldSpec, SecretKind};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The act an effect's receipt replays as, by its operands as the verb took
/// them (CUA E7). A receipt holds none for an act no program step can take
/// again: a `click_at`, an engine switch, a desktop's act.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ReplayAction {
    /// The URL the `open` asked for, before any redirect.
    Open { url: String },
    /// The locator of the row the click resolved.
    Click { locator: String },
    /// What the type entered into the row `locator` names, replacing its
    /// text with `clear`.
    Type {
        locator: String,
        operand: TypeOperand,
        #[serde(default)]
        clear: bool,
    },
    /// The option the select asked for, as given.
    Select { locator: String, option: String },
    /// The field a Fill step named, as its step named it.
    Fill { locator: String, field: FieldSpec },
}

/// What a type entered: its literal text, the secret a run-bound handle
/// names, or no operand a program can take, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operand", rename_all = "snake_case")]
pub enum TypeOperand {
    /// Text the classifier calls no secret, as typed.
    Literal { text: String },
    /// A secret by its run-bound handle (`scN`) and kind, never its bytes.
    Secret { kind: SecretKind, handle: String },
    /// No operand: the secret's handle was not kept, for `cause`.
    Withheld {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<SecretKind>,
        cause: OperandGap,
    },
}

/// Why a type's operand was withheld.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperandGap {
    /// The text was a secret and this browser's host keeps no custody.
    NoCustody,
    /// The text was a secret and the host's custody refused it.
    Refused,
    /// The handle typed names a secret no read or type of this session
    /// took, so its kind is unknown.
    UnknownKind,
    /// A proof's copy: the run's handle, or a secret slot's value, came out
    /// (FIX 8028).
    Unbound,
}

/// A step that stopped, as a browser session's history notes it (CUA E7),
/// beside the effects it receipted: the verb or batch step (`open`,
/// `click`, `type`, `fill`, `expect`, ..., or `postcondition` for a library
/// run's final checks), its cause, its stable code, the receipt of an
/// effect it made before it stopped, which the stop marks failed, and the
/// effect class of a control whose press refused it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepStop {
    pub step: String,
    pub cause: BatchStopCause,
    pub error: String,
    pub receipt: Option<u64>,
    pub effect_class: Option<String>,
}

impl BatchStep {
    /// The step's name, as its `step` tag names it.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Open { .. } => "open",
            Self::Click { .. } => "click",
            Self::Type { .. } => "type",
            Self::Select { .. } => "select",
            Self::WaitFor { .. } => "wait_for",
            Self::Expect { .. } => "expect",
            Self::Screenshot { .. } => "screenshot",
            Self::Key { .. } => "key",
            Self::Hotkey { .. } => "hotkey",
            Self::Scroll { .. } => "scroll",
            Self::Decide(_) => "decide",
            Self::Fill { .. } => "fill",
        }
    }
}
