//! OpenAPI document assembly for the HTTP API.

mod booking_schemas;
mod descriptions;
mod endpoints_merge;
mod security;

// The children keep the `super::...` paths they carried in the flat module;
// these names resolve through this module back into `api`.
use super::{
    ApiDoc, BOOKING_ROUTE_PREFIX, RETRIEVAL_EFFORT_VALUES, check_api_auth, skills_pack_artifact,
};

use self::booking_schemas::{
    bind_schema_ref, booking_instructions_block_schema, booking_operation_response_schema,
    mark_entity_response_as_binary, merge_error_components,
};
use self::descriptions::fill_schema_description_gaps;
pub(crate) use self::endpoints_merge::{
    __path_openapi_json, __path_skills_pack, SKILL_PACK_ENDPOINT, SKILL_PACK_FORMAT,
    SKILL_PACK_LAYER_BOUNDARY, SKILL_PACK_LOAD_HINT, SKILL_PACK_MIME_TYPE, SKILL_PACK_NAME,
    SKILL_PACK_RESOLUTION, openapi_json, skills_pack,
};
use self::security::{add_security_scheme, set_schema_property_description};
// Only the test suite names the assembled document bare (`api/tests` calls
// `openapi_document()`); the non-test build reaches it through the handlers.
#[cfg(test)]
pub(crate) use self::endpoints_merge::openapi_document;
