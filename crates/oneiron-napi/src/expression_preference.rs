//! JS bindings for the typed `companion.expression.*` doors.
//!
//! The generic claim doors on this surface — `commit`, `claimUpsert`,
//! `seedClaims` — refuse this predicate family and tell the caller to use the
//! typed door. Without these three wrappers a JS caller could read that
//! refusal and have nowhere to go: the door it names lived only in Rust. The
//! instruction and the door now exist on the same surface.
//!
//! Its own file rather than more of `facade.rs`, which is already the largest
//! module in the crate.

use crate::facade::{ActorScopedVault, BoundaryResult, boundary_error, facade_error, ts_to_engine};

use napi_derive::napi;
use oneiron::{
    ExpressionKeigo, ExpressionPreferenceInput, ExpressionPreferenceKind,
    ExpressionPreferenceOrigin, ExpressionPreferenceValue, ExpressionRegister,
};

/// One typed expression-preference write, in JS terms.
///
/// `kind` + `value` rather than a tagged union, because the four kinds each
/// carry exactly one string and a discriminated union buys nothing here but a
/// shape TypeScript users have to destructure. Unknown kinds and values are
/// typed errors — never a defaulted preference, for the same reason the actor
/// class is never defaulted.
#[napi(object)]
pub struct NapiExpressionPreferenceInput {
    /// Subject entity ref (short ref or 32-hex).
    pub subject_ref: String,
    /// `language` | `register` | `keigo` | `style`.
    pub kind: String,
    /// A BCP-47-ish tag for `language`, a free token for `style`, and one of
    /// the closed vocabularies for `register` / `keigo`.
    pub value: String,
    /// `explicit_user` | `inferred`. `explicit_user` requires a human-class
    /// bound actor; an agent asserting one is refused by the engine.
    pub origin: String,
    /// When the preference takes effect (Unix seconds).
    pub valid_from: i64,
    /// When the write happened (Unix seconds).
    pub occurred_at: i64,
}

/// Receipt for one typed write.
#[napi(object)]
pub struct NapiExpressionPreferenceReceipt {
    pub claim_short_id: String,
    /// `auto` | `proposed`.
    pub approval: String,
    /// EVERY claim this write superseded. A list, not one ref: a preference
    /// write can close several heads, and reporting one would hide the rest.
    pub superseded_short_ids: Vec<String>,
    pub receipt_ref: Option<String>,
}

/// One kind's winner, as a pair rather than a map — a JS `Record` keyed by an
/// enum reads worse across the boundary than an explicit list.
#[napi(object)]
pub struct NapiExpressionPreferenceWinner {
    /// `language` | `register` | `keigo` | `style`.
    pub kind: String,
    /// Short ref of the winning claim; the ref
    /// `retractExpressionPreference` takes.
    pub claim_ref: String,
}

/// The preferences in force for a subject.
#[napi(object)]
pub struct NapiExpressionPreferences {
    pub language: Option<String>,
    /// `casual` | `neutral` | `formal`.
    pub register: Option<String>,
    /// `none` | `teineigo` | `sonkeigo` | `kenjogo` | `adaptive`.
    pub keigo: Option<String>,
    pub style: Option<String>,
    pub winners: Vec<NapiExpressionPreferenceWinner>,
}

fn register_from_wire(value: &str) -> BoundaryResult<ExpressionRegister> {
    match value {
        "casual" => Ok(ExpressionRegister::Casual),
        "neutral" => Ok(ExpressionRegister::Neutral),
        "formal" => Ok(ExpressionRegister::Formal),
        other => Err(format!(
            "unknown expression register {other:?}; use casual, neutral or formal"
        )),
    }
}

fn keigo_from_wire(value: &str) -> BoundaryResult<ExpressionKeigo> {
    match value {
        "none" => Ok(ExpressionKeigo::None),
        "teineigo" => Ok(ExpressionKeigo::Teineigo),
        "sonkeigo" => Ok(ExpressionKeigo::Sonkeigo),
        "kenjogo" => Ok(ExpressionKeigo::Kenjogo),
        "adaptive" => Ok(ExpressionKeigo::Adaptive),
        other => Err(format!(
            "unknown keigo level {other:?}; use none, teineigo, sonkeigo, kenjogo or adaptive"
        )),
    }
}

fn register_to_wire(value: ExpressionRegister) -> &'static str {
    match value {
        ExpressionRegister::Casual => "casual",
        ExpressionRegister::Neutral => "neutral",
        ExpressionRegister::Formal => "formal",
    }
}

fn keigo_to_wire(value: ExpressionKeigo) -> &'static str {
    match value {
        ExpressionKeigo::None => "none",
        ExpressionKeigo::Teineigo => "teineigo",
        ExpressionKeigo::Sonkeigo => "sonkeigo",
        ExpressionKeigo::Kenjogo => "kenjogo",
        ExpressionKeigo::Adaptive => "adaptive",
    }
}

fn kind_to_wire(kind: ExpressionPreferenceKind) -> &'static str {
    match kind {
        ExpressionPreferenceKind::Language => "language",
        ExpressionPreferenceKind::Register => "register",
        ExpressionPreferenceKind::Keigo => "keigo",
        ExpressionPreferenceKind::Style => "style",
    }
}

fn value_from_wire(kind: &str, value: &str) -> BoundaryResult<ExpressionPreferenceValue> {
    match kind {
        "language" => Ok(ExpressionPreferenceValue::Language(value.to_owned())),
        "style" => Ok(ExpressionPreferenceValue::Style(value.to_owned())),
        "register" => Ok(ExpressionPreferenceValue::Register(register_from_wire(
            value,
        )?)),
        "keigo" => Ok(ExpressionPreferenceValue::Keigo(keigo_from_wire(value)?)),
        other => Err(format!(
            "unknown expression preference kind {other:?}; use language, register, keigo or style"
        )),
    }
}

fn origin_from_wire(value: &str) -> BoundaryResult<ExpressionPreferenceOrigin> {
    match value {
        "explicit_user" => Ok(ExpressionPreferenceOrigin::ExplicitUser),
        "inferred" => Ok(ExpressionPreferenceOrigin::Inferred),
        other => Err(format!(
            "unknown expression preference origin {other:?}; use explicit_user or inferred"
        )),
    }
}

#[napi]
impl ActorScopedVault {
    /// Writes one expression preference through its typed door — the door the
    /// generic claim-write refusals point at.
    #[napi]
    pub fn set_expression_preference(
        &self,
        input: NapiExpressionPreferenceInput,
    ) -> napi::Result<NapiExpressionPreferenceReceipt> {
        let engine_input = ExpressionPreferenceInput {
            subject_ref: input.subject_ref,
            value: value_from_wire(&input.kind, &input.value).map_err(boundary_error)?,
            origin: origin_from_wire(&input.origin).map_err(boundary_error)?,
            valid_from: ts_to_engine(input.valid_from, "validFrom").map_err(boundary_error)?,
        };
        let occurred_at = ts_to_engine(input.occurred_at, "occurredAt").map_err(boundary_error)?;
        let receipt = self
            .facade()?
            .set_expression_preference(&engine_input, occurred_at)
            .map_err(facade_error)?;
        Ok(NapiExpressionPreferenceReceipt {
            claim_short_id: receipt.claim_short_id,
            approval: receipt.approval,
            superseded_short_ids: receipt.superseded_short_ids,
            receipt_ref: receipt.receipt_ref,
        })
    }

    /// Retracts an expression preference, restoring the predecessor it had
    /// superseded. The generic retract door refuses this family because it
    /// would perform only the closing half.
    #[napi]
    pub fn retract_expression_preference(&self, claim_ref: String) -> napi::Result<()> {
        self.facade()?
            .retract_expression_preference(&claim_ref)
            .map_err(facade_error)
    }

    /// The preferences in force for a subject at `at`, one winner per kind.
    #[napi]
    pub fn expression_preferences(
        &self,
        subject_ref: String,
        at: i64,
    ) -> napi::Result<NapiExpressionPreferences> {
        let at = ts_to_engine(at, "at").map_err(boundary_error)?;
        let resolved = self
            .facade()?
            .expression_preferences(&subject_ref, at)
            .map_err(facade_error)?;
        Ok(NapiExpressionPreferences {
            language: resolved.language,
            register: resolved.register.map(|r| register_to_wire(r).to_owned()),
            keigo: resolved.keigo.map(|k| keigo_to_wire(k).to_owned()),
            style: resolved.style,
            winners: resolved
                .winning_refs
                .into_iter()
                .map(|(kind, claim_ref)| NapiExpressionPreferenceWinner {
                    kind: kind_to_wire(kind).to_owned(),
                    claim_ref,
                })
                .collect(),
        })
    }
}
