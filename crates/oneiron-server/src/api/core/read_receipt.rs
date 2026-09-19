//! OpenAPI shape for the engine-owned mandatory read receipt.
use utoipa::ToSchema;

#[derive(ToSchema)]
#[expect(
    dead_code,
    reason = "OpenAPI schema mirror; response serializes the engine type"
)]
pub(crate) struct ReadScopeSchema {
    entity_types: Option<Vec<u8>>,
    max_sensitivity_band: u8,
    include_stale: bool,
    min_confidence: f32,
    min_salience: f32,
    deny_all: bool,
}

#[derive(ToSchema)]
#[expect(
    dead_code,
    reason = "OpenAPI schema mirror; response serializes the engine type"
)]
pub(crate) struct ReadReceiptSchema {
    requested: ReadScopeSchema,
    actor_ceiling: ReadScopeSchema,
    applied: ReadScopeSchema,
    narrowed_axes: Vec<String>,
    suppressed_count: usize,
    replan_hint: Vec<String>,
}

#[derive(ToSchema)]
#[expect(dead_code, reason = "OpenAPI mirror of engine read projection")]
#[serde(rename_all = "camelCase")]
pub(crate) struct GrantedDataSchema {
    granted_data: Vec<String>,
    access_limited: Option<AccessLimitedSchema>,
}
#[derive(ToSchema)]
#[expect(dead_code, reason = "OpenAPI mirror of engine read projection")]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessLimitedSchema {
    suppressed_count: usize,
    required_action: String,
}
