//! Schema mirrors of the engine's room-join hold and its missing consent parties.

use serde_json::{Value, json};
use utoipa::ToSchema;

#[derive(ToSchema)]
#[expect(dead_code, reason = "OpenAPI mirror of the engine room-join hold")]
pub(crate) struct RoomJoinHoldSchema {
    room: String,
    person: String,
    intent_key: String,
    needs: Vec<ConsentNeedSchema>,
}

#[derive(ToSchema)]
#[expect(dead_code, reason = "OpenAPI mirror of one missing room-join consent")]
pub(crate) struct ConsentNeedSchema {
    part: ConsentPartSchema,
    party: RequiredPartySchema,
}

#[derive(ToSchema)]
#[serde(rename_all = "snake_case")]
#[expect(dead_code, reason = "OpenAPI mirror of the engine consent parts")]
pub(crate) enum ConsentPartSchema {
    Subject,
    Spend,
    Membership,
    Admission,
}

#[derive(ToSchema)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
#[expect(dead_code, reason = "OpenAPI mirror of the engine join subject")]
pub(crate) enum JoinSubjectSchema {
    Person(String),
    Agent(String),
}

#[derive(ToSchema)]
#[serde(rename_all = "snake_case")]
#[expect(
    dead_code,
    reason = "OpenAPI mirror of the engine's required consent party"
)]
pub(crate) enum RequiredPartySchema {
    Subject(JoinSubjectSchema),
    Payer(String),
    PayerUnknown,
    VaultAdmin { vault: u64 },
    RoomHost { room: String },
}

/// The same hold shape for the hand-written raw error schemas.
pub(crate) fn room_join_hold_schema() -> Value {
    let subject = json!({
        "type": "object",
        "required": ["kind", "id"],
        "additionalProperties": false,
        "properties": {
            "kind": { "type": "string", "enum": ["person", "agent"] },
            "id": { "type": "string" },
        },
    });
    let party = json!({
        "oneOf": [
            { "type": "string", "enum": ["payer_unknown"] },
            {
                "type": "object", "required": ["subject"], "additionalProperties": false,
                "properties": { "subject": subject },
            },
            {
                "type": "object", "required": ["payer"], "additionalProperties": false,
                "properties": { "payer": { "type": "string" } },
            },
            {
                "type": "object", "required": ["vault_admin"], "additionalProperties": false,
                "properties": {
                    "vault_admin": {
                        "type": "object", "required": ["vault"], "additionalProperties": false,
                        "properties": { "vault": { "type": "integer", "minimum": 0 } },
                    },
                },
            },
            {
                "type": "object", "required": ["room_host"], "additionalProperties": false,
                "properties": {
                    "room_host": {
                        "type": "object", "required": ["room"], "additionalProperties": false,
                        "properties": { "room": { "type": "string" } },
                    },
                },
            },
        ],
    });
    json!({
        "type": "object",
        "required": ["room", "person", "intent_key", "needs"],
        "additionalProperties": false,
        "properties": {
            "room": { "type": "string" },
            "person": { "type": "string" },
            "intent_key": { "type": "string" },
            "needs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["part", "party"],
                    "additionalProperties": false,
                    "properties": {
                        "part": { "type": "string", "enum": ["subject", "spend", "membership", "admission"] },
                        "party": party,
                    },
                },
            },
        },
    })
}
