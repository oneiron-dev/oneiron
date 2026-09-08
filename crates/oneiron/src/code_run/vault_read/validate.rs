//! Request-shape validation and short-reference parsing, run before any dispatch.

use crate::context_pack::{MAX_CONTEXT_NEIGHBORS, MAX_EDGE_HOP};
use crate::entity_id::{EntityId, parse_presentation_id};

use super::context_pack::CoreContextPackRequest;
use super::contract::{VaultReadMethod, VaultReadRequest};
use super::error::{VaultReadResult, invalid_request};
use super::sealed;
use super::types::{
    CoreBatchShortIdHydrateRequest, CoreHydrateRequest, CoreMemoryTimelineRequest,
    VAULT_READ_MAX_BATCH_REFS,
};

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

// The accepted field names the context-pack validator reports, kept beside
// their only production consumer.
impl CoreContextPackRequest {
    /// Accepted field name reported when the resolved `edge_hop` is rejected.
    pub(super) const fn edge_hop_field(&self) -> &'static str {
        match &self.depth {
            Some(depth) if depth.edge_hop.is_some() => "depth.edge_hop",
            _ => "edge_hop",
        }
    }

    /// Accepted field name reported when the resolved `max_neighbors` is
    /// rejected.
    pub(super) const fn max_neighbors_field(&self) -> &'static str {
        match &self.depth {
            Some(depth) if depth.max_neighbors.is_some() => "depth.max_neighbors",
            _ => "max_neighbors",
        }
    }
}

fn validate_context_pack_request(request: &CoreContextPackRequest) -> VaultReadResult<()> {
    const METHOD: VaultReadMethod = VaultReadMethod::ContextPack;

    validate_query_seeds(
        METHOD,
        request.query.as_deref(),
        request.query_vector.as_deref(),
    )?;
    let depth = request.resolved_depth();
    if depth.edge_hop.is_some_and(|hop| hop > MAX_EDGE_HOP) {
        return Err(invalid_request(
            METHOD,
            request.edge_hop_field(),
            &format!("edge_hop must be less than or equal to {MAX_EDGE_HOP}"),
        ));
    }
    if depth
        .max_neighbors
        .is_some_and(|neighbors| neighbors > MAX_CONTEXT_NEIGHBORS)
    {
        return Err(invalid_request(
            METHOD,
            request.max_neighbors_field(),
            &format!("max_neighbors must be less than or equal to {MAX_CONTEXT_NEIGHBORS}"),
        ));
    }
    if request
        .budget
        .as_ref()
        .and_then(|budget| budget.retrieval.as_ref())
        .and_then(|retrieval| retrieval.selected_edges)
        .is_some_and(|edges| edges > MAX_CONTEXT_NEIGHBORS)
    {
        return Err(invalid_request(
            METHOD,
            "budget.retrieval.selected_edges",
            &format!("selected_edges must be less than or equal to {MAX_CONTEXT_NEIGHBORS}"),
        ));
    }
    Ok(())
}

fn validate_batch_request(request: &CoreBatchShortIdHydrateRequest) -> VaultReadResult<()> {
    const METHOD: VaultReadMethod = VaultReadMethod::HydrateMany;

    if request.refs.is_empty() {
        return Err(invalid_request(METHOD, "refs", "refs must not be empty"));
    }
    if request.refs.len() > VAULT_READ_MAX_BATCH_REFS {
        return Err(invalid_request(
            METHOD,
            "refs",
            &format!("refs must contain at most {VAULT_READ_MAX_BATCH_REFS} entries"),
        ));
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
        VaultReadRequest::Query(query) => validate_query_seeds(
            VaultReadMethod::Query,
            query.query.as_deref(),
            query.query_vector.as_deref(),
        )?,
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
