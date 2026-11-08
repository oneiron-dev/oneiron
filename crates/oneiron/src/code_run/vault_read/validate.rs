//! Request-shape validation and short-reference parsing, run before any dispatch.

use crate::entity_id::{EntityId, parse_presentation_id};

use super::context_pack::CoreContextPackRequest;
use super::contract::{VaultReadMethod, VaultReadRequest};
use super::error::{VaultReadResult, invalid_request};
use super::sealed;
use super::types::{
    CoreBatchShortIdHydrateRequest, CoreHydrateRequest, CoreMemoryTimelineRequest, CoreQueryRequest,
};

/// The affect a query is asked in (OF-423), as the engine takes it; one out
/// of range is refused.
pub(super) fn query_affect(
    request: &CoreQueryRequest,
) -> VaultReadResult<Option<oneiron_contracts::affect::Vad>> {
    let Some(affect) = request.query_affect else {
        return Ok(None);
    };
    let vad = oneiron_contracts::affect::Vad {
        valence: affect.valence,
        arousal: affect.arousal,
        dominance: affect.dominance,
    };
    vad.validate().map_err(|error| {
        invalid_request(VaultReadMethod::Query, "query_affect", &error.to_string())
    })?;
    Ok(Some(vad))
}

pub(super) fn non_empty_query(query: Option<&str>) -> Option<&str> {
    query.map(str::trim).filter(|query| !query.is_empty())
}

fn validate_query_seeds(
    method: VaultReadMethod,
    query: Option<&str>,
    vector: Option<&[f32]>,
) -> VaultReadResult<()> {
    if non_empty_query(query).is_none() && vector.is_none() {
        return Err(invalid_request(
            method,
            "query",
            "query or query_vector is required",
        ));
    }
    if vector.is_some_and(|vector| vector.iter().any(|value| !value.is_finite())) {
        return Err(invalid_request(
            method,
            "query_vector",
            "query_vector values must be finite",
        ));
    }
    Ok(())
}

fn validate_context_pack_request(request: &CoreContextPackRequest) -> VaultReadResult<()> {
    const METHOD: VaultReadMethod = VaultReadMethod::ContextPack;

    // A media query seeds the pack on its own, as on the accepted route; a
    // vector beside it is still checked.
    validate_query_seeds(
        METHOD,
        non_empty_query(request.query.as_deref()).or(request.media.as_ref().map(|_| "media")),
        request.query_vector.as_deref(),
    )?;
    if request.axis.is_some() && request.type_ref.is_none() {
        return Err(invalid_request(METHOD, "axis", "axis needs a type_ref"));
    }
    Ok(())
}

fn validate_batch_request(request: &CoreBatchShortIdHydrateRequest) -> VaultReadResult<()> {
    const METHOD: VaultReadMethod = VaultReadMethod::HydrateMany;

    if request.refs.is_empty() {
        return Err(invalid_request(METHOD, "refs", "refs must not be empty"));
    }
    Ok(())
}

pub(super) fn parse_timeline_anchor(
    request: &CoreMemoryTimelineRequest,
) -> VaultReadResult<EntityId> {
    EntityId::from_hex(&request.id).map_err(|_| {
        invalid_request(
            VaultReadMethod::MemoryTimeline,
            "id",
            "id must be a hex entity id",
        )
    })
}

fn parse_short_ref_parts(
    method: VaultReadMethod,
    short_id: &str,
    content_hash: &str,
) -> VaultReadResult<(String, u8)> {
    if parse_presentation_id(short_id).is_err() {
        return Err(invalid_request(
            method,
            "short_id",
            "short_id must be at least two lowercase letters followed by decimal digits",
        ));
    }
    if content_hash.len() != 2 || !content_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_request(
            method,
            "content_hash",
            "content_hash must be exactly two hex digits",
        ));
    }
    let content_hash = u8::from_str_radix(content_hash, 16)
        .map_err(|_| invalid_request(method, "content_hash", "content_hash must be hex"))?;
    Ok((short_id.to_owned(), content_hash))
}

pub(super) fn parse_short_ref(
    method: VaultReadMethod,
    reference: &str,
) -> VaultReadResult<(String, u8)> {
    let Some((short_id, content_hash)) = reference.split_once(':') else {
        return Err(invalid_request(
            method,
            "ref",
            "ref must be in shortId:contentHashHex form",
        ));
    };
    parse_short_ref_parts(method, short_id, content_hash)
}

pub(super) fn parse_short_ref_request(
    request: &CoreHydrateRequest,
) -> VaultReadResult<(String, u8)> {
    const METHOD: VaultReadMethod = VaultReadMethod::Hydrate;

    if let Some(reference) = request.reference.as_deref() {
        return parse_short_ref(METHOD, reference);
    }
    let Some(short_id) = request.short_id.as_deref() else {
        return Err(invalid_request(
            METHOD,
            "ref",
            "ref or short_id/content_hash is required",
        ));
    };
    let Some(content_hash) = request.content_hash.as_deref() else {
        return Err(invalid_request(
            METHOD,
            "content_hash",
            "ref or short_id/content_hash is required",
        ));
    };
    parse_short_ref_parts(METHOD, short_id, content_hash)
}

/// The one validation door. It mirrors accepted route semantics only; no
/// client-only rule is added here.
pub(super) fn validate_request(
    request: VaultReadRequest,
) -> VaultReadResult<sealed::ValidatedVaultReadRequest> {
    match &request {
        // A media query seeds a query on its own, as on the accepted route
        // and the context pack; a vector beside it is still checked.
        VaultReadRequest::Query(query) => {
            validate_query_seeds(
                VaultReadMethod::Query,
                non_empty_query(query.query.as_deref()).or(query.media.as_ref().map(|_| "media")),
                query.query_vector.as_deref(),
            )?;
            query_affect(query)?;
        }
        VaultReadRequest::ContextPack(pack) => validate_context_pack_request(pack)?,
        VaultReadRequest::Hydrate(hydrate) => {
            parse_short_ref_request(hydrate)?;
        }
        VaultReadRequest::HydrateMany(batch) => validate_batch_request(batch)?,
        VaultReadRequest::MemoryTimeline(timeline) => {
            parse_timeline_anchor(timeline)?;
        }
        VaultReadRequest::Ask(_)
        | VaultReadRequest::CodeSearch(_)
        | VaultReadRequest::CodeExecute(_) => {}
    }
    Ok(sealed::ValidatedVaultReadRequest(request))
}

impl VaultReadRequest {
    /// Validates `body`, the inner request of one `method` call, as that
    /// method's dispatch validates it: decoded as the method's own typed
    /// request, then through the one validation door (FIX 1435). A host
    /// checks a verb hook's rewrite of a native read here, so the read never
    /// runs on a request its own validation refuses.
    ///
    /// # Errors
    ///
    /// [`VaultReadError::InvalidRequest`](super::VaultReadError::InvalidRequest)
    /// when `body` does not decode as `method`'s request or fails its
    /// validation.
    pub fn validate_body(method: VaultReadMethod, body: &serde_json::Value) -> VaultReadResult<()> {
        let tagged = serde_json::json!({ "op": method.wire_op().as_str(), "request": body });
        let request: Self = serde_json::from_value(tagged).map_err(|_| {
            invalid_request(
                method,
                "request",
                "request does not match the native method schema",
            )
        })?;
        validate_request(request).map(drop)
    }
}
