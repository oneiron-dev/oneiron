//! Contract, validation, projection and adapter tests for the vault-read module.

mod regressions;

use super::*;

use std::sync::Mutex;

use rmpv::Value as MsgpackValue;
use serde_json::json;

use crate::claim::ClaimSubject;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::{RetrievalAction, RetrievalRunRecord};
use crate::temporal::TimeRange;
use crate::test_util::{
    embedding_test_config, entity, open_test_vault_with, put_policy_manifest_bytes,
};

// ── Test doubles ────────────────────────────────────────────────────────

/// Backend that records every dispatched request and answers with a canned
/// response for the requested method.
#[derive(Default)]
struct RecordingBackend {
    dispatched: Mutex<Vec<VaultReadRequest>>,
}

impl RecordingBackend {
    fn calls(&self) -> usize {
        self.dispatched
            .lock()
            .expect("recording backend lock")
            .len()
    }

    fn last(&self) -> Option<VaultReadRequest> {
        self.dispatched
            .lock()
            .expect("recording backend lock")
            .last()
            .cloned()
    }
}

impl sealed::Backend for RecordingBackend {
    fn dispatch_validated(
        &self,
        request: sealed::ValidatedVaultReadRequest,
    ) -> VaultReadResult<VaultReadResponse> {
        let request = request.into_inner();
        let method = request.method();
        self.dispatched
            .lock()
            .expect("recording backend lock")
            .push(request);
        Ok(canned_response(method))
    }
}

/// Transport that records the ops it was asked for and replays one scripted
/// reply.
struct ScriptedTransport {
    ops: Mutex<Vec<VaultReadWireOp>>,
    reply: Vec<u8>,
}

impl ScriptedTransport {
    fn new(reply: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            ops: Mutex::new(Vec::new()),
            reply,
        })
    }

    fn ops(&self) -> Vec<VaultReadWireOp> {
        self.ops.lock().expect("transport lock").clone()
    }
}

impl WireTransport for ScriptedTransport {
    fn round_trip(&self, op: VaultReadWireOp, _request_json: &[u8]) -> VaultReadResult<Vec<u8>> {
        self.ops.lock().expect("transport lock").push(op);
        Ok(self.reply.clone())
    }
}

/// Transport that records the exact canonical body bytes it was handed,
/// beside the op they were sent under.
struct BodyRecordingTransport {
    bodies: Mutex<Vec<(VaultReadWireOp, Vec<u8>)>>,
    reply: Vec<u8>,
}

impl BodyRecordingTransport {
    fn new(reply: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            bodies: Mutex::new(Vec::new()),
            reply,
        })
    }

    fn bodies(&self) -> Vec<(VaultReadWireOp, Vec<u8>)> {
        self.bodies.lock().expect("transport lock").clone()
    }
}

impl WireTransport for BodyRecordingTransport {
    fn round_trip(&self, op: VaultReadWireOp, request_json: &[u8]) -> VaultReadResult<Vec<u8>> {
        self.bodies
            .lock()
            .expect("transport lock")
            .push((op, request_json.to_vec()));
        Ok(self.reply.clone())
    }
}

fn wire_adapter(reply: Value) -> (Arc<ScriptedTransport>, WireTransportVaultReadAdapter) {
    let transport =
        ScriptedTransport::new(serde_json::to_vec(&reply).expect("scripted reply serializes"));
    let adapter = WireTransportVaultReadAdapter::new(transport.clone());
    (transport, adapter)
}

fn empty_projection() -> CoreContextPackProjection {
    CoreContextPackProjection {
        results: Vec::new(),
        neighbors: Vec::new(),
        stats: CoreContextPackStats {
            candidates_considered: 0,
            signals_used: Vec::new(),
            query_time_us: 0,
            entities_hydrated: 0,
            neighbors_hydrated: 0,
            cosine_ghosts_dampened: 0,
            claims_suppressed: 0,
            tokens: CoreContextPackTokenStats {
                tokenizer_id: String::new(),
                total_tokens: 0,
                sections: Vec::new(),
                items: Vec::new(),
            },
            items_truncated: CoreContextPackAccounting {
                count: 0,
                reason: CoreContextPackAccountingReason::ItemBudget,
            },
            items_dropped: CoreContextPackAccounting {
                count: 0,
                reason: CoreContextPackAccountingReason::TokenBudget,
            },
        },
        empty: None,
    }
}

fn canned_response(method: VaultReadMethod) -> VaultReadResponse {
    match method {
        VaultReadMethod::Query => VaultReadResponse::Query(CoreQueryResponse {
            items: Vec::new(),
            next_cursor: None,
            meta: CoreQueryMeta {
                total: 0,
                count_mode: CountMode::Estimate,
            },
        }),
        VaultReadMethod::ContextPack => {
            VaultReadResponse::ContextPack(CoreContextPackResponse(empty_projection()))
        }
        VaultReadMethod::Hydrate => VaultReadResponse::Hydrate(hydrate_response()),
        VaultReadMethod::HydrateMany => {
            VaultReadResponse::HydrateMany(CoreBatchShortIdHydrateResponse {
                results: Vec::new(),
            })
        }
        VaultReadMethod::MemoryTimeline => {
            VaultReadResponse::MemoryTimeline(CoreMemoryTimelineResponse {
                anchor_id: String::new(),
                records: Vec::new(),
            })
        }
        VaultReadMethod::Ask => VaultReadResponse::Ask(AskResponse(Value::Null)),
        VaultReadMethod::CodeSearch => {
            VaultReadResponse::CodeSearch(CodeSearchResponse(Value::Null))
        }
        VaultReadMethod::CodeExecute => {
            VaultReadResponse::CodeExecute(CodeExecuteResponse(Value::Null))
        }
    }
}

fn hydrate_response() -> CoreHydrateResponse {
    CoreHydrateResponse {
        status: CoreHydrateStatus::Live,
        short_id: "cl1".to_owned(),
        content_hash: "a7".to_owned(),
        id: Some("0123456789abcdef0123456789abcdef".to_owned()),
        entity_type: Some(0),
        deletion: None,
        item: None,
    }
}

fn query_request(query: &str) -> CoreQueryRequest {
    CoreQueryRequest {
        query: Some(query.to_owned()),
        query_vector: None,
        limit: default_limit(),
        view: None,
        count_mode: CountMode::default_estimate(),
    }
}

fn context_pack_request() -> CoreContextPackRequest {
    CoreContextPackRequest {
        query: None,
        query_vector: None,
        limit: default_limit(),
        depth: None,
        edge_hop: None,
        max_neighbors: None,
        budget: None,
    }
}

fn hydrate_request(reference: &str) -> CoreHydrateRequest {
    CoreHydrateRequest {
        reference: Some(reference.to_owned()),
        short_id: None,
        content_hash: None,
        view: None,
    }
}

fn msgpack_body(text: &str) -> Vec<u8> {
    let value = MsgpackValue::Map(vec![(MsgpackValue::from("txt"), MsgpackValue::from(text))]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &value).expect("body encodes");
    encoded
}

// ── 1. Contract table ───────────────────────────────────────────────────

#[test]
fn contract_table_is_bijective() {
    assert_eq!(VaultReadMethod::ALL.len(), VAULT_READ_METHOD_MAP.len());
    assert_eq!(VaultReadMethod::COUNT, 8);

    for method in VaultReadMethod::ALL {
        let rows = VAULT_READ_METHOD_MAP
            .iter()
            .filter(|row| row.method == method)
            .count();
        assert_eq!(rows, 1, "{method:?} must own exactly one contract row");
    }

    let mut ops: Vec<&str> = VAULT_READ_METHOD_MAP
        .iter()
        .map(|row| row.wire_op.as_str())
        .collect();
    ops.sort_unstable();
    ops.dedup();
    assert_eq!(ops.len(), VaultReadMethod::COUNT, "wire ops must be unique");

    for row in VAULT_READ_METHOD_MAP {
        assert_eq!(row.method.wire_op(), row.wire_op);
        assert_eq!(row.wire_op.method(), row.method);
        assert_eq!(row.method.availability(), row.availability);
    }

    let structured = VAULT_READ_METHOD_MAP
        .iter()
        .filter(|row| row.availability == VaultReadAvailability::StructuredRead)
        .count();
    let deferred = VAULT_READ_METHOD_MAP
        .iter()
        .filter(|row| row.availability == VaultReadAvailability::RuntimeDeferred)
        .count();
    assert_eq!(structured, 5);
    assert_eq!(deferred, 3);
}

// ── 2. Wire names ───────────────────────────────────────────────────────

#[test]
fn wire_names_are_pinned() {
    let pinned = [
        (VaultReadMethod::Query, "core.query"),
        (VaultReadMethod::ContextPack, "core.context_pack"),
        (VaultReadMethod::Hydrate, "core.hydrate"),
        (VaultReadMethod::HydrateMany, "core.batch_short_id_hydrate"),
        (VaultReadMethod::MemoryTimeline, "core.memory_timeline"),
        (VaultReadMethod::Ask, "runtime.ask"),
        (VaultReadMethod::CodeSearch, "runtime.code_search"),
        (VaultReadMethod::CodeExecute, "runtime.code_execute"),
    ];
    assert_eq!(pinned.len(), VaultReadMethod::COUNT);
    for (method, wire) in pinned {
        assert_eq!(method.wire_op().as_str(), wire);
        assert_eq!(
            serde_json::to_string(&method.wire_op()).expect("wire op serializes"),
            format!("\"{wire}\"")
        );
        assert!(
            !wire.contains("/api/") && !wire.contains('-') && !wire.contains('/'),
            "{wire} must not be a route alias"
        );
    }
}

// ── 3. Accepted validation runs before adapters ─────────────────────────

#[test]
fn missing_query_seeds_reject_before_backend() {
    let backend = RecordingBackend::default();
    let error = backend
        .query(CoreQueryRequest {
            query: Some("   ".to_owned()),
            query_vector: None,
            limit: default_limit(),
            view: None,
            count_mode: CountMode::Estimate,
        })
        .expect_err("blank seeds are rejected");
    assert_eq!(
        error,
        invalid_request(
            VaultReadMethod::Query,
            "query",
            "query or query_vector is required"
        )
    );
    assert_eq!(backend.calls(), 0);

    let error = backend
        .context_pack(context_pack_request())
        .expect_err("seedless context pack is rejected");
    assert!(matches!(
        error,
        VaultReadError::InvalidRequest { method, ref field, .. }
            if method == VaultReadMethod::ContextPack && field == "query"
    ));
    assert_eq!(backend.calls(), 0);
}

#[test]
fn non_finite_vector_rejects_before_backend() {
    let backend = RecordingBackend::default();
    let mut request = query_request("blue hallway");
    request.query_vector = Some(vec![0.25, f32::NAN]);
    let error = backend.query(request).expect_err("non-finite vector");
    assert!(matches!(
        error,
        VaultReadError::InvalidRequest { method, ref field, .. }
            if method == VaultReadMethod::Query && field == "query_vector"
    ));
    assert_eq!(backend.calls(), 0);
}

#[test]
fn invalid_hydrate_ref_and_parts_reject_before_backend() {
    let backend = RecordingBackend::default();
    let error = backend
        .hydrate(hydrate_request("no-colon"))
        .expect_err("malformed ref");
    assert!(matches!(
        error,
        VaultReadError::InvalidRequest { method, ref field, .. }
            if method == VaultReadMethod::Hydrate && field == "ref"
    ));

    let error = backend
        .hydrate(CoreHydrateRequest {
            reference: None,
            short_id: Some("cl1".to_owned()),
            content_hash: None,
            view: None,
        })
        .expect_err("short_id without content hash");
    assert!(matches!(
        error,
        VaultReadError::InvalidRequest { ref field, .. } if field == "content_hash"
    ));

    let error = backend
        .hydrate(CoreHydrateRequest {
            reference: None,
            short_id: Some("cl1".to_owned()),
            content_hash: Some("zz".to_owned()),
            view: None,
        })
        .expect_err("non-hex content hash");
    assert!(matches!(
        error,
        VaultReadError::InvalidRequest { ref field, .. } if field == "content_hash"
    ));
    assert_eq!(backend.calls(), 0);
}

#[test]
fn empty_and_oversized_batch_reject_before_backend() {
    let backend = RecordingBackend::default();
    let error = backend
        .hydrate_many(CoreBatchShortIdHydrateRequest {
            refs: Vec::new(),
            view: None,
        })
        .expect_err("empty batch");
    assert!(matches!(
        error,
        VaultReadError::InvalidRequest { method, ref field, .. }
            if method == VaultReadMethod::HydrateMany && field == "refs"
    ));

    let refs = vec!["cl1:a7".to_owned(); VAULT_READ_MAX_BATCH_REFS + 1];
    let error = backend
        .hydrate_many(CoreBatchShortIdHydrateRequest { refs, view: None })
        .expect_err("oversized batch");
    assert!(matches!(
        error,
        VaultReadError::InvalidRequest { ref field, .. } if field == "refs"
    ));
    assert_eq!(backend.calls(), 0);
}

#[test]
fn vector_only_context_pack_reaches_backend() {
    let backend = RecordingBackend::default();
    let mut request = context_pack_request();
    request.query_vector = Some(vec![0.25, 0.75]);
    backend
        .context_pack(request)
        .expect("vector-only context pack is accepted");
    assert_eq!(backend.calls(), 1);
    assert!(matches!(
        backend.last(),
        Some(VaultReadRequest::ContextPack(_))
    ));
}

#[test]
fn nested_context_pack_depth_overrides_top_level() {
    let mut request = context_pack_request();
    request.query = Some("blue hallway".to_owned());
    request.edge_hop = Some(1);
    request.max_neighbors = Some(7);
    request.depth = Some(ContextPackDepthControls {
        edge_hop: Some(3),
        max_neighbors: None,
    });
    let depth = request.resolved_depth();
    assert_eq!(depth.edge_hop, Some(3), "nested depth wins");
    assert_eq!(depth.max_neighbors, Some(7), "absent nested field inherits");
    assert_eq!(request.edge_hop_field(), "depth.edge_hop");
    assert_eq!(request.max_neighbors_field(), "max_neighbors");

    request.depth = Some(ContextPackDepthControls {
        edge_hop: Some(MAX_EDGE_HOP + 1),
        max_neighbors: None,
    });
    let backend = RecordingBackend::default();
    let error = backend
        .context_pack(request)
        .expect_err("resolved depth is validated");
    assert!(matches!(
        error,
        VaultReadError::InvalidRequest { ref field, .. } if field == "depth.edge_hop"
    ));
    assert_eq!(backend.calls(), 0);
}

#[test]
fn absent_nested_depth_inherits_top_level() {
    let mut request = context_pack_request();
    request.edge_hop = Some(2);
    request.max_neighbors = Some(11);
    request.depth = None;
    let depth = request.resolved_depth();
    assert_eq!(depth.edge_hop, Some(2));
    assert_eq!(depth.max_neighbors, Some(11));
    assert_eq!(request.edge_hop_field(), "edge_hop");
    assert_eq!(request.max_neighbors_field(), "max_neighbors");
}

#[test]
fn recording_transport_sees_no_call_for_rejected_requests() {
    let (transport, adapter) = wire_adapter(json!({ "ok": null }));
    adapter
        .hydrate(hydrate_request("nope"))
        .expect_err("malformed ref rejected before transport");
    adapter
        .hydrate_many(CoreBatchShortIdHydrateRequest {
            refs: Vec::new(),
            view: None,
        })
        .expect_err("empty batch rejected before transport");
    adapter
        .memory_timeline(CoreMemoryTimelineRequest {
            id: "not-hex".to_owned(),
            view: None,
        })
        .expect_err("bad anchor rejected before transport");
    assert!(transport.ops().is_empty());
}

#[test]
fn zero_limit_query_reaches_backend() {
    let backend = RecordingBackend::default();
    let mut request = query_request("blue hallway");
    request.limit = 0;
    backend.query(request).expect("zero limit is accepted");
    assert_eq!(backend.calls(), 1);
}

// ── 4. Response arm is operation-bound and exclusive ─────────────────────

#[test]
fn wrong_op_ok_envelope_is_protocol_mismatch() {
    let wrong_arm = VaultReadResponse::Hydrate(hydrate_response());
    let (transport, adapter) = wire_adapter(json!({ "ok": wrong_arm }));
    let error = adapter
        .query(query_request("blue hallway"))
        .expect_err("wrong op arm");
    assert!(matches!(
        error,
        VaultReadError::ProtocolMismatch { method, .. } if method == VaultReadMethod::Query
    ));
    assert_eq!(transport.ops(), vec![VaultReadWireOp::CoreQuery]);
}

#[test]
fn bare_response_dto_is_protocol_mismatch() {
    let bare = CoreBatchShortIdHydrateResponse {
        results: Vec::new(),
    };
    let (_transport, adapter) = wire_adapter(serde_json::to_value(bare).expect("bare dto"));
    let error = adapter
        .hydrate_many(CoreBatchShortIdHydrateRequest {
            refs: vec!["cl1:a7".to_owned()],
            view: None,
        })
        .expect_err("bare dto is rejected");
    assert!(matches!(error, VaultReadError::ProtocolMismatch { .. }));
}

#[test]
fn envelope_with_ok_and_err_is_protocol_mismatch() {
    let arm = VaultReadResponse::Query(CoreQueryResponse {
        items: Vec::new(),
        next_cursor: None,
        meta: CoreQueryMeta {
            total: 0,
            count_mode: CountMode::Estimate,
        },
    });
    let error = VaultReadError::RuntimeUnavailable {
        method: VaultReadMethod::Query,
    };
    let (_transport, adapter) = wire_adapter(json!({ "ok": arm, "err": error }));
    let error = adapter
        .query(query_request("blue hallway"))
        .expect_err("both keys");
    assert!(matches!(error, VaultReadError::ProtocolMismatch { .. }));
}

#[test]
fn envelope_without_ok_or_err_is_protocol_mismatch() {
    let (_transport, adapter) = wire_adapter(json!({}));
    let error = adapter
        .query(query_request("blue hallway"))
        .expect_err("neither key");
    assert!(matches!(error, VaultReadError::ProtocolMismatch { .. }));
}

#[test]
fn envelope_with_extra_key_is_protocol_mismatch() {
    let arm = VaultReadResponse::Query(CoreQueryResponse {
        items: Vec::new(),
        next_cursor: None,
        meta: CoreQueryMeta {
            total: 0,
            count_mode: CountMode::Estimate,
        },
    });
    let (_transport, adapter) = wire_adapter(json!({ "ok": arm, "trace": "extra" }));
    let error = adapter
        .query(query_request("blue hallway"))
        .expect_err("extra key");
    assert!(matches!(error, VaultReadError::ProtocolMismatch { .. }));
}

#[test]
fn err_envelope_forwards_error_untranslated() {
    let forwarded = VaultReadError::Engine {
        method: VaultReadMethod::Hydrate,
        engine_code: NOT_FOUND_ENGINE_CODE.to_owned(),
        message: "short_id was not found".to_owned(),
    };
    let (_transport, adapter) = wire_adapter(json!({ "err": forwarded }));
    let error = adapter
        .hydrate(hydrate_request("cl1:a7"))
        .expect_err("err arm");
    assert_eq!(error, forwarded);
}

/// The op travels beside the body as `round_trip`'s own argument, so the
/// body is the BARE canonical request DTO, serialized once. Re-wrapping it
/// in this crate's `{"op", "request"}` tagged envelope would double-tag
/// every request and no accepted host would decode it.
#[test]
fn wire_request_body_is_the_inner_dto_not_the_tagged_envelope() {
    let anchor = entity(0x5A);
    let reply = VaultReadResponse::MemoryTimeline(CoreMemoryTimelineResponse {
        anchor_id: anchor.to_hex(),
        records: Vec::new(),
    });
    let transport = BodyRecordingTransport::new(
        serde_json::to_vec(&json!({ "ok": reply })).expect("scripted reply serializes"),
    );
    let adapter = WireTransportVaultReadAdapter::new(transport.clone());
    let request = CoreMemoryTimelineRequest {
        id: anchor.to_hex(),
        view: Some(View::Summary),
    };

    adapter
        .memory_timeline(request.clone())
        .expect("timeline round trip");

    let bodies = transport.bodies();
    assert_eq!(bodies.len(), 1);
    let (op, body) = &bodies[0];
    assert_eq!(*op, VaultReadWireOp::CoreMemoryTimeline);
    assert_eq!(
        body,
        &serde_json::to_vec(&request).expect("canonical body serializes"),
        "the transport body is the inner DTO, byte-for-byte"
    );

    let decoded: serde_json::Map<String, Value> =
        serde_json::from_slice(body).expect("the body is a JSON object");
    assert!(
        !decoded.contains_key("op") && !decoded.contains_key("request"),
        "the body must not carry the tagged envelope keys"
    );
    assert!(
        decoded.len() == 2 && decoded.contains_key("id") && decoded.contains_key("view"),
        "the pinned canonical timeline body is exactly {{id, view}}"
    );
    assert!(
        serde_json::from_slice::<VaultReadRequest>(body).is_err(),
        "a bare canonical DTO never decodes as the tagged request envelope"
    );
}

// ── 5. Runtime peers never reach a backend ──────────────────────────────

#[test]
fn runtime_peers_never_reach_a_backend() {
    let backend = RecordingBackend::default();
    let (transport, adapter) = wire_adapter(json!({ "ok": null }));

    for (method, in_process, wire) in [
        (
            VaultReadMethod::Ask,
            backend.ask(AskRequest(json!({ "prompt": "hi" }))).err(),
            adapter.ask(AskRequest(json!({ "prompt": "hi" }))).err(),
        ),
        (
            VaultReadMethod::CodeSearch,
            backend.code_search(CodeSearchRequest(Value::Null)).err(),
            adapter.code_search(CodeSearchRequest(Value::Null)).err(),
        ),
        (
            VaultReadMethod::CodeExecute,
            backend.code_execute(CodeExecuteRequest(Value::Null)).err(),
            adapter.code_execute(CodeExecuteRequest(Value::Null)).err(),
        ),
    ] {
        let expected = VaultReadError::RuntimeUnavailable { method };
        assert_eq!(in_process, Some(expected.clone()));
        assert_eq!(wire, Some(expected));
    }
    assert_eq!(backend.calls(), 0);
    assert!(transport.ops().is_empty());
}

// ── 6. Cloud is total over the surface ──────────────────────────────────

#[test]
fn cloud_adapter_is_total_over_the_surface() {
    let cloud = CloudVaultReadAdapter;
    let unimplemented = |method| VaultReadError::Unimplemented {
        adapter: VaultReadAdapterKind::Cloud,
        method,
    };

    assert_eq!(
        cloud.query(query_request("blue hallway")).unwrap_err(),
        unimplemented(VaultReadMethod::Query)
    );
    let mut pack = context_pack_request();
    pack.query_vector = Some(vec![0.25, 0.75]);
    assert_eq!(
        cloud.context_pack(pack).unwrap_err(),
        unimplemented(VaultReadMethod::ContextPack)
    );
    assert_eq!(
        cloud.hydrate(hydrate_request("cl1:a7")).unwrap_err(),
        unimplemented(VaultReadMethod::Hydrate)
    );
    assert_eq!(
        cloud
            .hydrate_many(CoreBatchShortIdHydrateRequest {
                refs: vec!["cl1:a7".to_owned()],
                view: None,
            })
            .unwrap_err(),
        unimplemented(VaultReadMethod::HydrateMany)
    );
    assert_eq!(
        cloud
            .memory_timeline(CoreMemoryTimelineRequest {
                id: entity(0x59).to_hex(),
                view: None,
            })
            .unwrap_err(),
        unimplemented(VaultReadMethod::MemoryTimeline)
    );

    assert_eq!(
        cloud.ask(AskRequest(Value::Null)).unwrap_err(),
        VaultReadError::RuntimeUnavailable {
            method: VaultReadMethod::Ask
        }
    );
    assert_eq!(
        cloud
            .code_search(CodeSearchRequest(Value::Null))
            .unwrap_err(),
        VaultReadError::RuntimeUnavailable {
            method: VaultReadMethod::CodeSearch
        }
    );
    assert_eq!(
        cloud
            .code_execute(CodeExecuteRequest(Value::Null))
            .unwrap_err(),
        VaultReadError::RuntimeUnavailable {
            method: VaultReadMethod::CodeExecute
        }
    );
}

// ── 7-10. Pinned accepted recipes ───────────────────────────────────────

#[test]
fn exact_collapses_to_estimate() {
    assert_eq!(CountMode::Exact.for_search_response(), CountMode::Estimate);
    assert_eq!(
        CountMode::Estimate.for_search_response(),
        CountMode::Estimate
    );
    assert_eq!(CountMode::None.for_search_response(), CountMode::None);

    assert_eq!(search_fetch_limit(CountMode::Estimate, 7), 8);
    assert_eq!(search_fetch_limit(CountMode::None, 25), 25);
    assert_eq!(
        search_fetch_limit(CountMode::Estimate, usize::MAX),
        usize::MAX
    );

    assert_eq!(search_total(CountMode::Estimate, 8), 8);
    assert_eq!(search_total(CountMode::None, 25), 0);
}

#[test]
fn single_missing_record_is_not_found() {
    let anchor = entity(0x51);
    let record = |state| MemoryTimelineRecord {
        id: anchor,
        state,
        entity_type: Some(0),
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        body_bytes: None,
        deletion: None,
        supersedes: Vec::new(),
        superseded_by: Vec::new(),
    };

    assert!(timeline_is_absent(&MemoryTimeline {
        anchor,
        records: Vec::new(),
    }));
    assert!(timeline_is_absent(&MemoryTimeline {
        anchor,
        records: vec![record(MemoryTimelineRecordState::Missing)],
    }));
    assert!(!timeline_is_absent(&MemoryTimeline {
        anchor,
        records: vec![record(MemoryTimelineRecordState::Live)],
    }));
    assert!(!timeline_is_absent(&MemoryTimeline {
        anchor,
        records: vec![
            record(MemoryTimelineRecordState::Missing),
            record(MemoryTimelineRecordState::Live),
        ],
    }));
}

#[test]
fn standard_view_omits_body() {
    let id = entity(0x52);
    let body = msgpack_body("blue hallway door");
    let record = |view| entity_record_from_parts(&id, 0, 1_780_000_000, Some(0.75), &body, view);

    let standard = record(View::Standard);
    assert_eq!(standard.id, id.to_hex());
    assert_eq!(standard.entity_type, 0);
    assert_eq!(standard.learned_at, 1_780_000_000);
    assert_eq!(standard.score, Some(0.75));
    assert_eq!(standard.body, None);

    for view in [View::Summary, View::Full] {
        let projected = record(view);
        assert_eq!(projected.id, standard.id);
        assert_eq!(projected.entity_type, standard.entity_type);
        assert_eq!(projected.learned_at, standard.learned_at);
        assert_eq!(projected.score, standard.score);
        assert_eq!(
            projected.body,
            Some(json!({ "txt": "blue hallway door" })),
            "{view:?} carries the public MessagePack projection"
        );
    }

    let mut trailing = body.clone();
    trailing.push(0xC0);
    let projected = entity_record_from_parts(&id, 0, 1, None, &trailing, View::Full);
    assert_eq!(
        projected.body,
        Some(json!({ "bodyBytes": trailing })),
        "trailing bytes are preserved, not silently dropped or treated as corruption"
    );
}

#[test]
fn batch_absence_conversion_is_narrow() {
    let absent = batch_item_from_result(
        "cl9:a7".to_owned(),
        Err(engine_absent(VaultReadMethod::Hydrate, "short_id")),
    )
    .expect("absence converts to a per-item outcome");
    assert_eq!(absent.reference, "cl9:a7");
    assert_eq!(absent.outcome, CoreShortIdHydrateOutcome::NotFound);
    assert_eq!(absent.result, None);

    let live =
        batch_item_from_result("cl1:a7".to_owned(), Ok(hydrate_response())).expect("live item");
    assert_eq!(live.outcome, CoreShortIdHydrateOutcome::Live);
    assert!(live.result.is_some());

    let engine = VaultReadError::Engine {
        method: VaultReadMethod::Hydrate,
        engine_code: INTERNAL_ENGINE_CODE.to_owned(),
        message: "corrupted index".to_owned(),
    };
    assert_eq!(
        batch_item_from_result("cl2:a7".to_owned(), Err(engine.clone())).unwrap_err(),
        engine,
        "a non-NOT_FOUND engine error aborts the batch"
    );

    let transport = VaultReadError::Transport {
        method: VaultReadMethod::Hydrate,
        message: "socket closed".to_owned(),
    };
    assert_eq!(
        batch_item_from_result("cl3:a7".to_owned(), Err(transport.clone())).unwrap_err(),
        transport
    );
}

// ── Scoped-grant denial reads as absence ────────────────────────────────

/// `world_ref` is the grant's world scope spelling: a world id hex, or the
/// literal `"base"` for base reality.
fn scoped_grant_manifest(actor_ref: &str, world_ref: &str) -> Vec<u8> {
    let grant = MsgpackValue::Map(vec![
        (
            MsgpackValue::from("actor_ref"),
            MsgpackValue::from(actor_ref),
        ),
        (
            MsgpackValue::from("effector"),
            MsgpackValue::from("core:read"),
        ),
        (
            MsgpackValue::from("scope"),
            MsgpackValue::Map(vec![(
                MsgpackValue::from("world_ref"),
                MsgpackValue::from(world_ref),
            )]),
        ),
        (
            MsgpackValue::from("receipt_required"),
            MsgpackValue::Boolean(false),
        ),
    ]);
    let manifest = MsgpackValue::Map(vec![
        (
            MsgpackValue::from("schema_version"),
            MsgpackValue::from("1.1"),
        ),
        (
            MsgpackValue::from("pack_id"),
            MsgpackValue::from("vault-read-test"),
        ),
        (MsgpackValue::from("pack_version"), MsgpackValue::from("1")),
        (
            MsgpackValue::from("min_engine_version"),
            MsgpackValue::from("0.0.0"),
        ),
        (
            MsgpackValue::from("defaults"),
            MsgpackValue::Map(Vec::new()),
        ),
        (MsgpackValue::from("rules"), MsgpackValue::Array(Vec::new())),
        (
            MsgpackValue::from("actor_ceilings"),
            MsgpackValue::Array(Vec::new()),
        ),
        (
            MsgpackValue::from("scoped_grants"),
            MsgpackValue::Array(vec![grant]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest).expect("manifest encodes");
    data
}

fn short_ref(vault: &Vault, id: &EntityId) -> String {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let raw = vault
        .store
        .short_ids_reverse
        .get(&rtxn, id.as_bytes())
        .expect("short id row read")
        .expect("entity has a short id row");
    let (short_id, content_hash) =
        crate::batch::parse_short_id_value(&raw).expect("short id row parses");
    format!("{short_id}:{content_hash:02x}")
}

/// Seeds one admitted claim, one grant-denied claim, and the `core:read`
/// scoped-grant manifest that separates them.
fn seed_scoped_grant_vault(vault: &Vault) -> (EntityId, String, String) {
    let subject = entity(0x53);
    let admitted_world = entity(0x54);
    let denied_world = entity(0x55);
    let admitted_id = entity(0x56);
    let denied_id = entity(0x57);
    let occurred = TimeRange {
        start: 1_780_000_000,
        end: 1_780_000_000,
    };

    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, occurred, occurred.start, b"x")
        .expect("subject entity");
    let claim = |world: EntityId, text: &str| {
        let mut body = ClaimBody::new(
            "profile.note",
            ClaimSubject::Entity(subject),
            MsgpackValue::from(text),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.world = Some(world);
        body.source = Some(ClaimSource::UserStated);
        body
    };
    vault
        .put_claim(
            &admitted_id,
            &claim(admitted_world, "admitted note"),
            occurred,
            occurred.start,
        )
        .expect("admitted claim");
    vault
        .put_claim(
            &denied_id,
            &claim(denied_world, "denied note"),
            occurred,
            occurred.start,
        )
        .expect("denied claim");
    let refs = (short_ref(vault, &admitted_id), short_ref(vault, &denied_id));
    put_policy_manifest_bytes(
        vault,
        entity(0x58),
        &scoped_grant_manifest("reader", &admitted_world.to_hex()),
    )
    .expect("policy manifest");
    (denied_id, refs.0, refs.1)
}

/// A claim the actor's `core:read` grant does not admit is INDISTINGUISHABLE
/// from a claim that is not there: the same `Engine { NOT_FOUND }`, the same
/// per-item batch outcome, and no leaked id or body.
#[test]
fn scoped_grant_denial_reads_as_absence() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (denied_id, admitted_ref, denied_ref) = seed_scoped_grant_vault(&vault);
    let adapter = InProcessVaultReadAdapter::new(
        &vault,
        ScopedReadActorKey::new("reader").expect("actor key"),
    );
    let missing_ref = "cl4096:ff";

    let denied = adapter
        .hydrate(hydrate_request(&denied_ref))
        .expect_err("denied claim reads as absence");
    let missing = adapter
        .hydrate(hydrate_request(missing_ref))
        .expect_err("missing ref reads as absence");
    assert_eq!(denied, missing);
    assert_eq!(
        denied,
        engine_absent(VaultReadMethod::Hydrate, "short_id"),
        "denied and missing normalize to the same accepted absence"
    );

    adapter
        .hydrate(hydrate_request(&admitted_ref))
        .expect("admitted claim hydrates");

    let batch = adapter
        .hydrate_many(CoreBatchShortIdHydrateRequest {
            refs: vec![admitted_ref, denied_ref.clone(), missing_ref.to_owned()],
            view: None,
        })
        .expect("batch hydrate");
    assert_eq!(batch.results.len(), 3);
    assert_eq!(batch.results[0].outcome, CoreShortIdHydrateOutcome::Live);
    assert_eq!(
        batch.results[1].outcome,
        CoreShortIdHydrateOutcome::NotFound
    );
    assert_eq!(batch.results[1].result, None);
    assert_eq!(
        batch.results[2].outcome,
        CoreShortIdHydrateOutcome::NotFound
    );
    assert_eq!(batch.results[2].result, None);
    assert_eq!(batch.results[1].reference, denied_ref);

    let serialized = serde_json::to_string(&batch).expect("batch serializes");
    assert!(
        !serialized.contains(&denied_id.to_hex()),
        "a denied entity id never appears in a response"
    );
    assert!(
        !serialized.contains("denied note"),
        "denied body bytes never appear in a response"
    );
}

// ── Response retrieval budget binds the answered pack ───────────────────

/// Seeds one subject plus three admitted, vector-searchable CLAIMs and
/// returns how many claims are in the vault.
fn seed_retrieval_budget_vault(vault: &Vault) -> usize {
    let subject = entity(0x5B);
    let occurred = TimeRange {
        start: 1_780_000_000,
        end: 1_780_000_000,
    };
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            occurred,
            occurred.start,
            b"subject",
        )
        .expect("subject entity");

    // Distinct predicates and vectors: three independent live CLAIM heads,
    // all close to the seed vector.
    let seeds = [
        (0x5C_u8, [1.0_f32, 0.0, 0.0, 0.0], "profile.note_alpha"),
        (0x5D, [0.95, 0.05, 0.0, 0.0], "profile.note_bravo"),
        (0x5E, [0.9, 0.1, 0.0, 0.0], "profile.note_charlie"),
    ];
    let seeded = seeds.len();
    for (seed, vector, predicate) in seeds {
        let id = entity(seed);
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(subject),
            MsgpackValue::from("budget note"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(ClaimSource::UserStated);
        vault
            .put_claim(&id, &body, occurred, occurred.start)
            .expect("admitted claim");
        vault
            .batch()
            .vector(&id, &vector)
            .commit()
            .expect("claim vector");
    }
    seeded
}

/// The response retrieval budget is the UNWIDENED one and it binds the
/// ANSWERED pack: the widened copy exists only so scoped-read clamping
/// cannot starve retrieval. `retrieval.claims = 1` therefore returns at
/// most one CLAIM, and the visible stats describe the delivered pack.
#[test]
fn response_retrieval_budget_caps_claims_after_filtering() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let seeded_claims = seed_retrieval_budget_vault(&vault);
    let adapter = InProcessVaultReadAdapter::new(
        &vault,
        ScopedReadActorKey::new("reader").expect("actor key"),
    );
    let request = |claims: Option<usize>| CoreContextPackRequest {
        query: None,
        query_vector: Some(vec![1.0, 0.0, 0.0, 0.0]),
        limit: 10,
        depth: None,
        edge_hop: None,
        max_neighbors: None,
        budget: claims.map(|claims| ContextPackBudgetControls {
            retrieval: Some(ContextPackRetrievalBudgetControls {
                claims: Some(claims),
                ..ContextPackRetrievalBudgetControls::default()
            }),
            ..ContextPackBudgetControls::default()
        }),
    };
    let claims_in = |response: &CoreContextPackResponse| {
        response
            .0
            .results
            .iter()
            .filter(|record| record.entity_type == ENTITY_TYPE_CLAIM)
            .count()
    };

    let unbudgeted = adapter
        .context_pack(request(None))
        .expect("unbudgeted context pack");
    assert!(
        claims_in(&unbudgeted) > 1,
        "the fixture's {seeded_claims} admitted claims surface without a per-kind budget"
    );

    let budgeted = adapter
        .context_pack(request(Some(1)))
        .expect("budgeted context pack");
    assert_eq!(
        claims_in(&budgeted),
        1,
        "retrieval.claims = 1 binds the answered pack, not just retrieval"
    );
    let results = budgeted.0.results.len();
    let neighbors = budgeted.0.neighbors.len();
    assert_eq!(
        budgeted.0.stats.candidates_considered, results,
        "visible stats describe the pack the caller received"
    );
    assert_eq!(budgeted.0.stats.entities_hydrated, results);
    assert_eq!(budgeted.0.stats.neighbors_hydrated, neighbors);
}

// ── Durable pack telemetry carries only actor-visible ids ───────────────

/// Seeds one BASE-reality claim the `core:read` grant admits and one
/// world-scoped claim it denies, both vector-searchable, so a context-pack
/// assembly surfaces BOTH before the scoped filter runs. Returns
/// `(admitted_id, denied_id)`.
fn seed_scoped_pack_vault(vault: &Vault) -> (EntityId, EntityId) {
    let subject = entity(0x60);
    let denied_world = entity(0x61);
    let admitted_id = entity(0x62);
    let denied_id = entity(0x63);
    let occurred = TimeRange {
        start: 1_780_000_000,
        end: 1_780_000_000,
    };
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, occurred, occurred.start, b"x")
        .expect("subject entity");

    let claim = |predicate: &str, world: Option<EntityId>, text: &str| {
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(subject),
            MsgpackValue::from(text),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.world = world;
        body.source = Some(ClaimSource::UserStated);
        body
    };
    let seeds = [
        (
            admitted_id,
            claim("profile.note_admitted", None, "admitted note"),
            [1.0_f32, 0.0, 0.0, 0.0],
        ),
        (
            denied_id,
            claim(
                "profile.note_denied",
                Some(denied_world),
                "denied world pack note",
            ),
            [0.95, 0.05, 0.0, 0.0],
        ),
    ];
    for (id, body, vector) in seeds {
        vault
            .put_claim(&id, &body, occurred, occurred.start)
            .expect("seeded claim");
        vault
            .batch()
            .vector(&id, &vector)
            .commit()
            .expect("claim vector");
    }

    // The grant names BASE reality: the base claim is readable by `reader`
    // and the world-scoped one is not.
    let manifest = scoped_grant_manifest("reader", "base");
    put_policy_manifest_bytes(vault, entity(0x64), &manifest).expect("policy manifest");
    (admitted_id, denied_id)
}

fn vector_pack_request() -> CoreContextPackRequest {
    CoreContextPackRequest {
        query: None,
        query_vector: Some(vec![1.0, 0.0, 0.0, 0.0]),
        limit: 10,
        depth: None,
        edge_hop: None,
        max_neighbors: None,
        budget: None,
    }
}

fn published_context_pack_run(vault: &Vault) -> RetrievalRunRecord {
    let runs = vault.retrieval_runs(64).expect("published retrieval runs");
    let mut published: Vec<RetrievalRunRecord> = runs
        .into_iter()
        .filter(|record| record.action == RetrievalAction::ContextPack)
        .collect();
    assert_eq!(
        published.len(),
        1,
        "one assembly publishes exactly one context-pack run row"
    );
    published.remove(0)
}

/// The DURABLE retrieval-run row a context pack publishes carries EXACTLY
/// the ids this actor received. The scoped filter runs before the
/// finalize, so an entity the actor may not see is as absent from the
/// telemetry ledger as it is from the response — denied-equals-absent
/// across the operation's effects, not only its answer.
#[test]
fn context_pack_run_row_publishes_only_actor_visible_ids() {
    // Same seed, no actor clamp: the naked builder this method enters
    // surfaces BOTH claims, so a finalize taken before the filter would
    // publish the denied id. That is the leak this ordering closes.
    let (_leak_dir, leak_vault) = open_test_vault_with(embedding_test_config());
    let (_, leaked_id) = seed_scoped_pack_vault(&leak_vault);
    let unfiltered = leak_vault
        .context_pack()
        .limit(10)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .run()
        .expect("unfiltered pack");
    let leaked = unfiltered
        .results
        .iter()
        .any(|entity| entity.id == leaked_id);
    assert!(
        leaked,
        "the fixture is leak-prone: retrieval surfaces the denied claim pre-filter"
    );

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (admitted_id, denied_id) = seed_scoped_pack_vault(&vault);
    let adapter = InProcessVaultReadAdapter::new(
        &vault,
        ScopedReadActorKey::new("reader").expect("actor key"),
    );

    let request = vector_pack_request();
    let response = adapter.context_pack(request).expect("context pack");
    let results = &response.0.results;
    let returned: Vec<String> = results.iter().map(|record| record.id.clone()).collect();
    assert_eq!(
        returned,
        vec![admitted_id.to_hex()],
        "only the admitted claim is answered"
    );
    assert!(
        response.0.stats.claims_suppressed >= 1,
        "the scoped filter removed the denied claim from the assembled pack"
    );

    let denied_bytes = *denied_id.as_bytes();
    let run = published_context_pack_run(&vault);
    assert_eq!(response.0.stats.candidates_considered, results.len());
    assert_eq!(run.total_in_scope, response.0.stats.candidates_considered);
    let published_row = vault.retrieval_run(run.run_id).expect("run row read");
    assert!(
        published_row.is_some(),
        "the row is PUBLISHED, not left provisional"
    );
    assert!(
        !run.result_ids.contains(&denied_bytes),
        "a denied id never reaches the durable result ids"
    );
    assert!(
        run.score_breakdown
            .iter()
            .all(|entry| entry.result_id != denied_bytes),
        "a denied id never reaches the durable score breakdown"
    );
    // The engine path never enables trace capture, so no trace is expected
    // here; if one is ever captured the same absence rule binds it and the
    // fork index that republishes it.
    if let Some(trace) = run.trace.as_ref() {
        assert!(
            trace
                .final_stage
                .candidates
                .iter()
                .all(|entry| entry.result_id != denied_bytes),
            "a denied id never reaches the durable trace candidates"
        );
        if let Some(forked) = vault
            .retrieval_trace_by_fork_hash(trace.fork_hash)
            .expect("trace fork lookup")
        {
            assert!(
                forked
                    .final_stage
                    .candidates
                    .iter()
                    .all(|entry| entry.result_id != denied_bytes),
                "the trace fork index answers no denied id either"
            );
        }
    }

    let row_ids: Vec<String> = run
        .result_ids
        .iter()
        .map(|bytes| EntityId::from_bytes(*bytes).expect("run id").to_hex())
        .collect();
    assert_eq!(
        row_ids, returned,
        "the published ids are exactly the post-filter, post-truncate results"
    );
}

/// When the filter removes EVERYTHING the row still publishes — with no
/// ids and the answered pack's empty reason — and the caller-visible empty
/// context is byte-for-byte what it was before the finalize moved.
#[test]
fn fully_filtered_context_pack_publishes_an_empty_run_row() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let (admitted_id, denied_id) = seed_scoped_pack_vault(&vault);
    // No grant names this actor, so a `core:read` grant exists that never
    // admits it: EVERY claim is denied.
    let adapter = InProcessVaultReadAdapter::new(
        &vault,
        ScopedReadActorKey::new("outsider").expect("actor key"),
    );

    let request = vector_pack_request();
    let response = adapter.context_pack(request).expect("context pack");
    assert!(response.0.results.is_empty());
    assert!(response.0.neighbors.is_empty());
    let empty = response
        .0
        .empty
        .expect("an all-filtered pack reports an empty context");
    // The caller-visible empty context is the scoped filter's own, exactly
    // as it was before the finalize moved behind it.
    let reason = CoreContextPackEmptyReason::FilterMatchedNone;
    let hint = "scoped_read returned no actor-readable entities";
    assert_eq!(empty.reason, reason);
    assert_eq!(empty.total_in_scope, 0);
    assert_eq!(empty.hint, hint);
    assert_eq!(response.0.stats.candidates_considered, 0);
    assert_eq!(response.0.stats.entities_hydrated, 0);
    assert_eq!(response.0.stats.neighbors_hydrated, 0);

    let run = published_context_pack_run(&vault);
    assert_eq!(run.total_in_scope, response.0.stats.candidates_considered);
    assert!(
        run.result_ids.is_empty(),
        "no id survived the filter, so none is published"
    );
    assert!(run.score_breakdown.is_empty());
    assert_eq!(
        run.empty_reason.as_deref(),
        Some("FilterMatchedNone"),
        "the published reason is read off the post-filter pack"
    );
    for id in [admitted_id, denied_id] {
        assert!(!run.result_ids.contains(id.as_bytes()));
    }
}

// ── Batch hydrate errors carry the BATCH method identity ────────────────

/// A single-item failure that ABORTS the batch is an error of
/// `HydrateMany`, not of `Hydrate`: the same helper serves both doors, so
/// the identity travels as an argument. The single-ref door is unchanged.
#[test]
fn batch_aborting_error_carries_the_batch_method() {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let corrupt = entity(0x66);
    let occurred = TimeRange {
        start: 1_780_000_000,
        end: 1_780_000_000,
    };
    // Arbitrary body bytes are valid. Corrupt the short-id index instead:
    // its forward row MUST contain a 16-byte entity id, so a truncated row
    // causes a real storage error before projection in both hydrate doors.
    vault
        .put_entity(
            &corrupt,
            ENTITY_TYPE_PERSON,
            occurred,
            occurred.start,
            &msgpack_body("valid body"),
        )
        .expect("valid entity");
    let reference = short_ref(&vault, &corrupt);
    let (short_id, content_hash) =
        parse_short_ref(VaultReadMethod::Hydrate, &reference).expect("valid short ref");
    let forward_key = crate::batch::encode_short_id_forward_key(&short_id, content_hash);
    vault
        .with_write_txn(|wtxn| {
            vault.store.short_ids.put(wtxn, &forward_key, &[0x66])?;
            Ok(())
        })
        .expect("inject a truncated short-id index row");
    assert!(matches!(
        vault.hydrate_short_id(&short_id, content_hash),
        Err(crate::Error::CorruptedIndex(_))
    ));
    let adapter = InProcessVaultReadAdapter::new(
        &vault,
        ScopedReadActorKey::new("reader").expect("actor key"),
    );

    let single = adapter
        .hydrate(hydrate_request(&reference))
        .expect_err("single hydrate reports corruption");
    assert!(
        matches!(
            &single,
            VaultReadError::Engine { method, engine_code, .. }
                if *method == VaultReadMethod::Hydrate && engine_code == INTERNAL_ENGINE_CODE
        ),
        "the single-ref door still answers with Hydrate identity: {single:?}"
    );

    let batch = adapter
        .hydrate_many(CoreBatchShortIdHydrateRequest {
            refs: vec![reference],
            view: None,
        })
        .expect_err("a non-NOT_FOUND item error aborts the batch");
    assert!(
        matches!(
            &batch,
            VaultReadError::Engine { method, engine_code, .. }
                if *method == VaultReadMethod::HydrateMany
                    && engine_code == INTERNAL_ENGINE_CODE
        ),
        "the aborting error carries the BATCH method identity: {batch:?}"
    );
}
