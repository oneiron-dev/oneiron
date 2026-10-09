//! Contract, validation, projection and adapter tests for the vault-read module.

mod regressions;
mod support;

use self::support::telemetry_config;
use super::*;

use std::sync::Mutex;

use rmpv::Value as MsgpackValue;
use serde_json::json;

use crate::claim::ClaimSubject;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::{RetrievalAction, RetrievalRunRecord};
use crate::temporal::TimeRange;
use crate::test_util::{entity, open_test_vault_with, put_policy_manifest_bytes};

// ── Test doubles ────────────────────────────────────────────────────────

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
        capabilities: Vec::new(),
        access: crate::access_grant::GrantedData::new(Vec::new(), 0),
        narrowing: read_receipt_fixture(),
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
            access: crate::access_grant::GrantedData::new(Vec::new(), 0),
            narrowing: read_receipt_fixture(),
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
                narrowing: read_receipt_fixture(),
                results: Vec::new(),
            })
        }
        VaultReadMethod::MemoryTimeline => {
            VaultReadResponse::MemoryTimeline(CoreMemoryTimelineResponse {
                narrowing: read_receipt_fixture(),
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
        narrowing: read_receipt_fixture(),
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
fn envelope_with_extra_key_is_protocol_mismatch() {
    let arm = VaultReadResponse::Query(CoreQueryResponse {
        access: crate::access_grant::GrantedData::new(Vec::new(), 0),
        narrowing: read_receipt_fixture(),
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

/// The op travels beside the body as `round_trip`'s own argument, so the
/// body is the BARE canonical request DTO, serialized once. Re-wrapping it
/// in this crate's `{"op", "request"}` tagged envelope would double-tag
/// every request and no accepted host would decode it.
#[test]
fn wire_request_body_is_the_inner_dto_not_the_tagged_envelope() {
    let anchor = entity(0x5A);
    let reply = VaultReadResponse::MemoryTimeline(CoreMemoryTimelineResponse {
        narrowing: read_receipt_fixture(),
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
            crate::federation::scope_codec::encode_scope_value(
                &crate::federation::scope_codec::read_preset(),
            )
            .expect("scope fixture"),
        ),
        (
            MsgpackValue::from("selectors"),
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
            MsgpackValue::from("1.2"),
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
        )
        .unwrap();
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
    let (_dir, vault) = open_test_vault_with(telemetry_config());
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
    for (error, suppressed) in [(&denied, 1), (&missing, 0)] {
        assert!(matches!(error,
            VaultReadError::Engine { method: VaultReadMethod::Hydrate, engine_code, narrowing: Some(receipt), .. }
                if engine_code == NOT_FOUND_ENGINE_CODE && receipt.suppressed_count == suppressed));
    }

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
        )
        .unwrap();
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
        executor_model: None,
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
    let (_leak_dir, leak_vault) = open_test_vault_with(telemetry_config());
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

    let (_dir, vault) = open_test_vault_with(telemetry_config());
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

// ── Batch hydrate errors carry the BATCH method identity ────────────────

/// A single-item failure that ABORTS the batch is an error of
/// `HydrateMany`, not of `Hydrate`: the same helper serves both doors, so
/// the identity travels as an argument. The single-ref door is unchanged.
#[test]
fn batch_aborting_error_carries_the_batch_method() {
    let (_dir, vault) = open_test_vault_with(telemetry_config());
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

fn read_receipt_fixture() -> crate::claim::ScopedReadReceipt {
    let (_dir, vault) = crate::test_util::open_test_vault_with(telemetry_config());
    vault
        .scoped_read(crate::claim::ScopedReadActorKey::new("fixture").unwrap())
        .read_receipt(None, 0)
        .unwrap()
}

#[test]
fn wire_read_response_without_narrowing_receipt_fails_closed() {
    for method in [
        VaultReadMethod::Query,
        VaultReadMethod::ContextPack,
        VaultReadMethod::Hydrate,
        VaultReadMethod::HydrateMany,
        VaultReadMethod::MemoryTimeline,
    ] {
        let mut value = serde_json::to_value(canned_response(method)).expect("valid fixture");
        assert!(serde_json::from_value::<VaultReadResponse>(value.clone()).is_ok());
        assert!(
            value["response"]
                .as_object_mut()
                .unwrap()
                .remove("narrowing")
                .is_some()
        );
        assert!(
            serde_json::from_value::<VaultReadResponse>(value).is_err(),
            "{method:?}"
        );
    }
}

#[test]
fn timeline_receipts_survive_success_absence_and_wire_transport() {
    let (_dir, vault) = open_test_vault_with(telemetry_config());
    let (visible, hidden) = seed_scoped_pack_vault(&vault);
    let adapter =
        InProcessVaultReadAdapter::new(&vault, ScopedReadActorKey::new("reader").unwrap());
    let request = |id: EntityId| CoreMemoryTimelineRequest {
        id: id.to_hex(),
        view: None,
    };
    let response = adapter
        .memory_timeline(request(visible))
        .expect("visible timeline");
    assert_eq!(response.narrowing.suppressed_count, 0);
    let (_, remote) =
        wire_adapter(json!({"ok": VaultReadResponse::MemoryTimeline(response.clone())}));
    assert_eq!(remote.memory_timeline(request(visible)).unwrap(), response);
    let error = adapter
        .memory_timeline(request(hidden))
        .expect_err("hidden timeline");
    assert!(
        matches!(&error, VaultReadError::Engine { narrowing: Some(receipt), .. }
        if receipt.suppressed_count > 0)
    );
    let (_, remote) = wire_adapter(json!({"err": error}));
    assert_eq!(remote.memory_timeline(request(hidden)).unwrap_err(), error);
    let mut stripped = serde_json::to_value(&error).unwrap();
    stripped.as_object_mut().unwrap().remove("narrowing");
    let (_, remote) = wire_adapter(json!({"err": stripped}));
    assert!(matches!(
        remote.memory_timeline(request(hidden)),
        Err(VaultReadError::ProtocolMismatch { .. })
    ));
}
