//! Wire adapters for the existing typed expression-preference doors.
use super::{ClaimRefRequest, Memory, MemoryResult, UnitResponse};
use crate::claim::{
    ExpressionKeigo, ExpressionPreferenceKind, ExpressionPreferenceOrigin,
    ExpressionPreferenceValue, ExpressionRegister,
};
use serde::{Deserialize, Serialize};

macro_rules! enum_projection {
    ($name:ident, $engine:ident, $($variant:ident),+) => {
        /// Engine expression vocabulary projected without string guessing.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant,)+ }
        impl From<$name> for $engine { fn from(value: $name) -> Self { match value { $($name::$variant => Self::$variant,)+ } } }
        impl From<$engine> for $name { fn from(value: $engine) -> Self { match value { $($engine::$variant => Self::$variant,)+ } } }
    };
}
enum_projection!(
    ExpressionRegisterDto,
    ExpressionRegister,
    Casual,
    Neutral,
    Formal
);
enum_projection!(
    ExpressionKeigoDto,
    ExpressionKeigo,
    None,
    Teineigo,
    Sonkeigo,
    Kenjogo,
    Adaptive
);
enum_projection!(
    ExpressionKindDto,
    ExpressionPreferenceKind,
    Language,
    Register,
    Keigo,
    Style
);
enum_projection!(
    ExpressionOriginDto,
    ExpressionPreferenceOrigin,
    ExplicitUser,
    Inferred
);

/// One typed expression preference value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ExpressionValueDto {
    Language(String),
    Register(ExpressionRegisterDto),
    Keigo(ExpressionKeigoDto),
    Style(String),
}
/// Write input, with no caller-supplied actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetExpressionPreferenceRequest {
    pub subject_ref: String,
    pub value: ExpressionValueDto,
    pub origin: ExpressionOriginDto,
    pub valid_from: u64,
    pub occurred_at: u64,
}
/// Full typed preference receipt; every supersession survives projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpressionPreferenceReceiptDto {
    pub claim_short_id: String,
    pub approval: String,
    pub superseded_short_ids: Vec<String>,
    pub receipt_ref: Option<String>,
}
/// Reads preferences at an instant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpressionPreferencesRequest {
    pub subject_ref: String,
    pub at: u64,
}
/// Preferences in force, with the winning short references.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpressionPreferenceViewDto {
    pub language: Option<String>,
    pub register: Option<ExpressionRegisterDto>,
    pub keigo: Option<ExpressionKeigoDto>,
    pub style: Option<String>,
    pub winning_refs: std::collections::BTreeMap<ExpressionKindDto, String>,
}

pub(super) fn set(
    memory: &Memory<'_>,
    body: SetExpressionPreferenceRequest,
) -> MemoryResult<ExpressionPreferenceReceiptDto> {
    let value = match body.value {
        ExpressionValueDto::Language(value) => ExpressionPreferenceValue::Language(value),
        ExpressionValueDto::Register(value) => ExpressionPreferenceValue::Register(value.into()),
        ExpressionValueDto::Keigo(value) => ExpressionPreferenceValue::Keigo(value.into()),
        ExpressionValueDto::Style(value) => ExpressionPreferenceValue::Style(value),
    };
    let result = memory.set_expression_preference(
        &super::super::ExpressionPreferenceInput {
            subject_ref: body.subject_ref,
            value,
            origin: body.origin.into(),
            valid_from: body.valid_from,
        },
        body.occurred_at,
    )?;
    Ok(ExpressionPreferenceReceiptDto {
        claim_short_id: result.claim_short_id,
        approval: result.approval,
        superseded_short_ids: result.superseded_short_ids,
        receipt_ref: result.receipt_ref,
    })
}
pub(super) fn retract(memory: &Memory<'_>, body: ClaimRefRequest) -> MemoryResult<UnitResponse> {
    memory.retract_expression_preference(&body.claim_ref)?;
    Ok(UnitResponse { ok: true })
}
pub(super) fn read(
    memory: &Memory<'_>,
    body: ExpressionPreferencesRequest,
) -> MemoryResult<ExpressionPreferenceViewDto> {
    let result = memory.expression_preferences(&body.subject_ref, body.at)?;
    Ok(ExpressionPreferenceViewDto {
        language: result.language,
        register: result.register.map(Into::into),
        keigo: result.keigo.map(Into::into),
        style: result.style,
        winning_refs: result
            .winning_refs
            .into_iter()
            .map(|(kind, reference)| (kind.into(), reference))
            .collect(),
    })
}
