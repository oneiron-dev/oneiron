//! A Fill step's text (CUA E6, DESIGN-2 §4 "Field text = A"): what one
//! field takes, resolved in code before any model writes it, and where the
//! text came from, which the effect's receipt names.
//!
//! A Fill names its text four ways, tried in one order (`fill_order`, CALLS
//! row): `supplied` text is typed as given, ahead of everything else; else
//! the step's references, one typing with no decision and several becoming
//! a routine choice among their ids, NONE falling through; else its
//! template, its `{{slots}}` filled from the run's arguments before the
//! batch began; else, only with `generate`, one call of the host's writer,
//! typed once one yes/no check of it answers YES. A strict run's generation
//! goes up before any writer is asked.
//!
//! Every Fill's template and options are checked as its batch starts,
//! before any step, decision or writer call (`fill_precheck`). No text is
//! refused or cut for its length: the page's own read of the field after
//! the type says whether it took the text (`fill_readback`). A field the
//! page shows as a secret takes no text of any source: a `type` step types
//! a secret by its handle.

mod run;
mod spec;
mod write;

pub(crate) use run::fill;
pub use spec::{FieldSpec, TextReference};
pub use write::{
    FIELD_WRITER, FieldWrite, FieldWriteError, FieldWriter, FieldWritten, NoWriter, TextCheck,
    TextCheckReply, TextVerdict,
};

use crate::stop::Stop;
use crate::{BatchStopCause, BrowserError, EffectReceipt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Where a typed text came from, as its effect's receipt names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TextSource {
    /// The caller's own text: a `type`, or a Fill's `supplied`.
    Supplied,
    /// One of a Fill's references.
    Reference,
    /// A Fill's template.
    Template,
    /// The host's writer, checked YES.
    Generated,
}

/// Why a Fill step's text was not typed, or not taken (CUA E6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum FieldTextReason {
    /// No source gave text: none was named, no reference fit, and no
    /// template or generation followed.
    NoText,
    /// The template holds a slot nothing filled.
    MissingSlot { slot: String },
    /// The template opens a `{{` slot it never closes.
    UnclosedSlot,
    /// The text from `source` is none of the field's `enum_values`; from
    /// references, none of them is.
    NotAnOption { source: TextSource },
    /// The page shows the field as a secret: a `type` step types a secret
    /// by its handle, and a Fill types no text there.
    SecretField,
    /// The host has no writer for the field, or none serves its role.
    WriterUnavailable,
    /// The writer's model admission refused the call, before it went out.
    WriterRefused,
    /// The writer's call failed, or answered no text.
    WriterFailed,
    /// The check of the written text answered NO.
    CheckedNo,
    /// The check of the written text gave no answer.
    CheckAbstained,
    /// The check could not be asked, or failed.
    CheckFailed,
    /// After the type, the page's field reads back other text than the
    /// step typed: the page did not take it as typed.
    PageRejected,
}

/// Where the text an effect typed came from: its source and reference, as
/// its receipt names them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextProvenance {
    pub source: TextSource,
    /// The text's reference (`fill_text_ref`, CALLS row): a reference's
    /// id, a template's digest (`blake3:` and hex), or the writer call's
    /// id; none for supplied text.
    pub text_ref: Option<String>,
    /// The Fill step's field, as its step named it: what its receipt keeps
    /// for a replay (CUA E7), never rebuilt from the text's source. None
    /// for a `type`.
    pub fill: Option<FieldSpec>,
}

impl TextProvenance {
    /// The caller's own text, which names no reference.
    #[must_use]
    pub const fn supplied() -> Self {
        Self {
            source: TextSource::Supplied,
            text_ref: None,
            fill: None,
        }
    }

    /// Names this provenance on `receipt`.
    pub fn stamp(self, receipt: &mut EffectReceipt) {
        receipt.text_source = Some(self.source);
        receipt.text_ref = self.text_ref;
    }
}

/// A Fill step's stop for `reason`.
fn field_text(reason: FieldTextReason, detail: impl Into<String>) -> Stop {
    Stop::new(
        BatchStopCause::FieldText { reason },
        BrowserError::FieldText(detail.into()),
    )
}
