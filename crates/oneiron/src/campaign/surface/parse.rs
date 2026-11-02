//! Request-body decoders and field-error helpers for the dispatch door.

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{
    CAMPAIGN_SCHEMA_VERSION, CreateCampaignRequest, MembershipReadRequest, SavedQueryCreateRequest,
    SavedQueryUpdateRequest, UpdateCampaignRequest,
};
use crate::EntityId;
use crate::campaign::presets::SnoozePolicyData;
use crate::error::Error;
use crate::memory::{MemoryError, MemoryResult};
use crate::saved_query::{CreateSavedQueryRequest, UpdateSavedQueryRequest};

pub(super) fn parse_create_campaign_request(body: &Value) -> MemoryResult<CreateCampaignRequest> {
    Ok(CreateCampaignRequest {
        schema_version: optional_u32(body, "schema_version")?.unwrap_or(CAMPAIGN_SCHEMA_VERSION),
        name: required_string(body, "name")?,
        reply_snooze_policy: optional_snooze_policy(body)?,
    })
}

pub(super) fn parse_update_campaign_request(body: &Value) -> MemoryResult<UpdateCampaignRequest> {
    Ok(UpdateCampaignRequest {
        expected_definition_version: required_u64(body, "expected_definition_version")?,
        name: required_string(body, "name")?,
        reply_snooze_policy: optional_snooze_policy(body)?,
    })
}

/// The request's `reply_snooze_policy`, in the preset's own strict shape.
fn optional_snooze_policy(body: &Value) -> MemoryResult<Option<SnoozePolicyData>> {
    match body.get("reply_snooze_policy") {
        None | Some(Value::Null) => Ok(None),
        Some(raw) => SnoozePolicyData::deserialize(raw).map(Some).map_err(|err| {
            field_error(
                "reply_snooze_policy",
                &format!("is not a snooze policy: {err}"),
            )
        }),
    }
}

/// `self.saved_query.create`'s resource body, decoded whole through the SDK's
/// own strict wire type (FIX 9670). The resource path and the typed SDK row
/// read one shape: an unknown or misspelled field, such as a restriction axis,
/// is a BAD_REQUEST rather than an axis left unrestricted.
pub(super) fn parse_create_saved_query_request(
    body: &Value,
) -> MemoryResult<CreateSavedQueryRequest> {
    Ok(strict_saved_query_body::<SavedQueryCreateRequest>(body)?.engine_request())
}

/// `self.saved_query.update`'s resource body, as
/// [`parse_create_saved_query_request`] decodes create's.
pub(super) fn parse_update_saved_query_request(
    body: &Value,
) -> MemoryResult<UpdateSavedQueryRequest> {
    Ok(strict_saved_query_body::<SavedQueryUpdateRequest>(body)?.engine_request())
}

fn strict_saved_query_body<T: DeserializeOwned>(body: &Value) -> MemoryResult<T> {
    T::deserialize(body).map_err(|err| {
        MemoryError::bad_request(format!(
            "campaign surface saved-query body is not the verb's input: {err}"
        ))
    })
}

pub(super) fn parse_membership_request(
    body: &Value,
    ref_field: &str,
) -> MemoryResult<MembershipReadRequest> {
    Ok(MembershipReadRequest {
        owner_ref: required_entity_ref(body, ref_field)?,
        cursor: match body.get("cursor") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or_else(|| field_error("cursor", "must be a string"))?
                    .to_owned(),
            ),
        },
        limit: optional_u32(body, "limit")?.unwrap_or(0),
        at_epoch: optional_u64(body, "at_epoch")?,
    })
}

pub(super) fn required_entity_ref(body: &Value, field: &str) -> MemoryResult<EntityId> {
    body.get(field)
        .and_then(Value::as_str)
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or_else(|| field_error(field, "must be a 32-character hex entity id"))
}

fn required_string(body: &Value, field: &str) -> MemoryResult<String> {
    body.get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| field_error(field, "must be a string"))
}

pub(super) fn required_u64(body: &Value, field: &str) -> MemoryResult<u64> {
    body.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| field_error(field, "must be a non-negative integer"))
}

fn optional_u64(body: &Value, field: &str) -> MemoryResult<Option<u64>> {
    match body.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| field_error(field, "must be a non-negative integer")),
    }
}

fn optional_u32(body: &Value, field: &str) -> MemoryResult<Option<u32>> {
    optional_u64(body, field)?
        .map(|value| u32::try_from(value).map_err(|_| field_error(field, "must fit in a u32")))
        .transpose()
}

fn field_error(field: &str, requirement: &str) -> MemoryError {
    MemoryError::bad_request(format!("campaign surface field {field} {requirement}"))
}

pub(super) fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
