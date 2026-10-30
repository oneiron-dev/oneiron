//! OpenAPI and raw JSON-schema shape for the engine-owned legal-hold notice.

use serde_json::{Value, json};
use utoipa::ToSchema;

#[derive(ToSchema)]
#[serde(rename_all = "snake_case")]
#[expect(dead_code, reason = "OpenAPI mirror of the engine legal-hold state")]
pub(crate) enum LegalHoldStateSchema {
    RetainedForLaw,
    UseRestricted,
}

#[derive(ToSchema)]
#[serde(rename_all = "snake_case")]
#[expect(dead_code, reason = "OpenAPI mirror of the engine legal-hold bound kind")]
pub(crate) enum LegalHoldBoundKindSchema {
    Law,
}

#[derive(ToSchema)]
#[expect(dead_code, reason = "OpenAPI mirror of the engine legal-hold bound")]
pub(crate) struct LegalHoldBoundSchema {
    kind: LegalHoldBoundKindSchema,
    order_ref: Option<String>,
    legal_basis_ref: Option<String>,
    jurisdiction: Option<String>,
    issuing_authority_ref: Option<String>,
    ends_at: Option<u64>,
}

#[derive(ToSchema)]
#[expect(dead_code, reason = "OpenAPI mirror of the engine legal-hold notice")]
pub(crate) struct LegalHoldNoticeSchema {
    state: LegalHoldStateSchema,
    bound: LegalHoldBoundSchema,
    works_self_hosted: bool,
    self_hosted_note: String,
}

/// The same notice shape for the hand-written raw error schemas.
pub(crate) fn legal_hold_notice_schema() -> Value {
    json!({
        "type": "object",
        "required": ["state", "bound", "works_self_hosted", "self_hosted_note"],
        "additionalProperties": false,
        "properties": {
            "state": {
                "type": "string",
                "enum": ["retained_for_law", "use_restricted"],
            },
            "bound": {
                "type": "object",
                "required": [
                    "kind",
                    "order_ref",
                    "legal_basis_ref",
                    "jurisdiction",
                    "issuing_authority_ref",
                    "ends_at",
                ],
                "additionalProperties": false,
                "properties": {
                    "kind": { "type": "string", "enum": ["law"] },
                    "order_ref": { "type": ["string", "null"] },
                    "legal_basis_ref": { "type": ["string", "null"] },
                    "jurisdiction": { "type": ["string", "null"] },
                    "issuing_authority_ref": { "type": ["string", "null"] },
                    "ends_at": { "type": ["integer", "null"], "minimum": 0 },
                },
            },
            "works_self_hosted": { "type": "boolean" },
            "self_hosted_note": { "type": "string" },
        },
    })
}
