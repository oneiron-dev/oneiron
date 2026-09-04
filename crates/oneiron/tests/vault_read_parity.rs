//! ONE-1433 adapter parity suite: one read contract whose behavior does not
//! change with deployment topology.
//!
//! Every test here reaches ONLY the public crate surface — `Vault`,
//! `ScopedReadActorKey`, and `oneiron::code_run::vault_read::*`. There is not
//! one `facade::*` or `memory::*` DTO import: if a response record cannot be
//! built from `ScopedRead` and public `ContextPack` fields, it is not part of
//! this contract.
//!
//! Fixture denial note: a scoped-grant policy manifest cannot be installed
//! through the public API (policy-manifest writes are a crate-internal door),
//! so the integration fixture denies fixture B through the SAME `ScopedRead`
//! clamp using the claim status gate — B exists in the vault, and every scoped
//! read answers absence for it. The grant-scoped twin of this test lives beside
//! the implementation in `code_run::vault_read`'s in-module suite, where the
//! manifest door is reachable.

use std::sync::{Arc, Mutex};

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::vault_read::{
    AskRequest, CloudVaultReadAdapter, CodeExecuteRequest, CodeSearchRequest,
    ContextPackBudgetControls, ContextPackDepthControls, ContextPackRetrievalBudgetControls,
    CoreBatchShortIdHydrateRequest, CoreContextPackRequest, CoreContextPackResponse,
    CoreHydrateRequest, CoreMemoryTimelineRequest, CoreQueryRequest, CoreShortIdHydrateOutcome,
    CountMode, InProcessVaultReadAdapter, VAULT_READ_METHOD_MAP, VaultReadAdapterKind,
    VaultReadAvailability, VaultReadClient, VaultReadError, VaultReadMethod, VaultReadRequest,
    VaultReadResponse, VaultReadResult, VaultReadWireOp, View, WireTransport,
    WireTransportVaultReadAdapter,
};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;

const ACTOR_REF: &str = "lens-reader";
const ADMITTED_TEXT: &str = "alpha hallway note";
const DENIED_TEXT: &str = "bravo hidden note";
const SEED_VECTOR: [f32; 4] = [1.0, 0.0, 0.0, 0.0];
const MISSING_REF: &str = "cl4096:ff";

// ─── Fixture ─────────────────────────────────────────────────────────────────

/// Fake daemon: decodes the same request DTO, executes it through a
/// SEPARATELY-constructed in-process adapter bound to the same actor, and
/// answers with the `{"ok"}` / `{"err"}` envelope the contract requires.
struct FakeWireTransport {
    vault: Arc<Vault>,
    actor: ScopedReadActorKey,
    ops: Mutex<Vec<VaultReadWireOp>>,
}

impl FakeWireTransport {
    fn ops(&self) -> Vec<VaultReadWireOp> {
        self.ops.lock().expect("transport lock").clone()
    }

    fn reset(&self) {
        self.ops.lock().expect("transport lock").clear();
    }
}

impl WireTransport for FakeWireTransport {
    fn round_trip(&self, op: VaultReadWireOp, request_json: &[u8]) -> VaultReadResult<Vec<u8>> {
        self.ops.lock().expect("transport lock").push(op);
        let request = decode_canonical_body(op, request_json)?;
        let adapter = InProcessVaultReadAdapter::new(&self.vault, self.actor.clone());
        let envelope = match execute(&adapter, request) {
            Ok(response) => json!({ "ok": response }),
            Err(error) => json!({ "err": error }),
        };
        serde_json::to_vec(&envelope).map_err(|error| VaultReadError::Transport {
            method: op.method(),
            message: format!("daemon could not encode the response: {error}"),
        })
    }
}

/// Daemon-side decode: the transport carries the op beside the body, and the
/// body is the BARE canonical request DTO — never the crate's tagged
/// `{"op", "request"}` envelope. The op therefore chooses the DTO to decode,
/// exactly as a real host route would.
fn decode_canonical_body(
    op: VaultReadWireOp,
    request_json: &[u8],
) -> VaultReadResult<VaultReadRequest> {
    fn decode<T: DeserializeOwned>(
        op: VaultReadWireOp,
        request_json: &[u8],
        arm: fn(T) -> VaultReadRequest,
    ) -> VaultReadResult<VaultReadRequest> {
        serde_json::from_slice::<T>(request_json)
            .map(arm)
            .map_err(|error| VaultReadError::Transport {
                method: op.method(),
                message: format!("daemon could not decode the request: {error}"),
            })
    }

    match op {
        VaultReadWireOp::CoreQuery => {
            decode::<CoreQueryRequest>(op, request_json, VaultReadRequest::Query)
        }
        VaultReadWireOp::CoreContextPack => {
            decode::<CoreContextPackRequest>(op, request_json, VaultReadRequest::ContextPack)
        }
        VaultReadWireOp::CoreHydrate => {
            decode::<CoreHydrateRequest>(op, request_json, VaultReadRequest::Hydrate)
        }
        VaultReadWireOp::CoreBatchShortIdHydrate => decode::<CoreBatchShortIdHydrateRequest>(
            op,
            request_json,
            VaultReadRequest::HydrateMany,
        ),
        VaultReadWireOp::CoreMemoryTimeline => {
            decode::<CoreMemoryTimelineRequest>(op, request_json, VaultReadRequest::MemoryTimeline)
        }
        VaultReadWireOp::RuntimeAsk => {
            decode::<AskRequest>(op, request_json, VaultReadRequest::Ask)
        }
        VaultReadWireOp::RuntimeCodeSearch => {
            decode::<CodeSearchRequest>(op, request_json, VaultReadRequest::CodeSearch)
        }
        VaultReadWireOp::RuntimeCodeExecute => {
            decode::<CodeExecuteRequest>(op, request_json, VaultReadRequest::CodeExecute)
        }
    }
}

/// Daemon-side typed execution: the fake host calls the same public methods a
/// real daemon would.
fn execute(
    adapter: &InProcessVaultReadAdapter<'_>,
    request: VaultReadRequest,
) -> VaultReadResult<VaultReadResponse> {
    match request {
        VaultReadRequest::Query(request) => adapter.query(request).map(VaultReadResponse::Query),
        VaultReadRequest::ContextPack(request) => adapter
            .context_pack(request)
            .map(VaultReadResponse::ContextPack),
        VaultReadRequest::Hydrate(request) => {
            adapter.hydrate(request).map(VaultReadResponse::Hydrate)
        }
        VaultReadRequest::HydrateMany(request) => adapter
            .hydrate_many(request)
            .map(VaultReadResponse::HydrateMany),
        VaultReadRequest::MemoryTimeline(request) => adapter
            .memory_timeline(request)
            .map(VaultReadResponse::MemoryTimeline),
        VaultReadRequest::Ask(request) => adapter.ask(request).map(VaultReadResponse::Ask),
        VaultReadRequest::CodeSearch(request) => adapter
            .code_search(request)
            .map(VaultReadResponse::CodeSearch),
        VaultReadRequest::CodeExecute(request) => adapter
            .code_execute(request)
            .map(VaultReadResponse::CodeExecute),
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    actor: ScopedReadActorKey,
    transport: Arc<FakeWireTransport>,
    admitted_id: EntityId,
    denied_id: EntityId,
    admitted_ref: String,
    denied_ref: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault");
        let mut config = VaultConfig::device();
        config.dimensions = SEED_VECTOR.len();
        config.embedding_model = Some("test/model@v1".to_owned());
        config.map_size = 16 * 1024 * 1024;
        let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));

        let subject = seed_id(0x21);
        let admitted_id = seed_id(0x22);
        let denied_id = seed_id(0x23);
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
        vault
            .put_claim(
                &admitted_id,
                &claim(subject, ADMITTED_TEXT, ClaimApprovalStatus::Auto),
                occurred,
                occurred.start,
            )
            .expect("admitted claim");
        vault
            .put_claim(
                &denied_id,
                // Denied through the claim status gate: the row is in the
                // vault, and the scoped read lane refuses it.
                &claim(subject, DENIED_TEXT, ClaimApprovalStatus::Proposed),
                occurred,
                occurred.start,
            )
            .expect("denied claim");
        vault
            .batch()
            .vector(&admitted_id, &SEED_VECTOR)
            .vector(&denied_id, &SEED_VECTOR)
            .commit()
            .expect("fixture vectors");

        let actor = ScopedReadActorKey::new(ACTOR_REF).expect("actor key");
        let admitted_ref = probe_short_ref(&vault, &admitted_id);
        let denied_ref = probe_short_ref(&vault, &denied_id);
        let transport = Arc::new(FakeWireTransport {
            vault: Arc::clone(&vault),
            actor: actor.clone(),
            ops: Mutex::new(Vec::new()),
        });

        Self {
            _dir: dir,
            vault,
            actor,
            transport,
            admitted_id,
            denied_id,
            admitted_ref,
            denied_ref,
        }
    }

    fn in_process(&self) -> InProcessVaultReadAdapter<'_> {
        InProcessVaultReadAdapter::new(&self.vault, self.actor.clone())
    }

    fn wire(&self) -> WireTransportVaultReadAdapter {
        WireTransportVaultReadAdapter::new(Arc::clone(&self.transport) as Arc<dyn WireTransport>)
    }
}

/// Pinned constructor shape: `InProcessVaultReadAdapter` is constructible ONLY
/// with a `ScopedReadActorKey`, so no unkeyed `&Vault` handle exists. This
/// wrapper compiles only while that stays true.
fn keyed_in_process(vault: &Vault, actor: ScopedReadActorKey) -> InProcessVaultReadAdapter<'_> {
    InProcessVaultReadAdapter::new(vault, actor)
}

fn seed_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

fn claim(subject: EntityId, text: &str, approval: ClaimApprovalStatus) -> ClaimBody {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::UserStated);
    body
}

/// Test-oracle only: resolves an entity's canonical short ref through the naked
/// vault, which is exactly what the adapters may never do. The denied fixture
/// has no readable surface, so its caller-echoed ref must come from here.
fn probe_short_ref(vault: &Vault, id: &EntityId) -> String {
    let prefix = oneiron::registry::short_id_prefix(ENTITY_TYPE_CLAIM).expect("claim prefix");
    for counter in 1..=8u32 {
        let short_id = format!("{prefix}{counter}");
        for content_hash in 0..=u8::MAX {
            let hydrated = vault
                .hydrate_short_id(&short_id, content_hash)
                .expect("short id probe");
            if hydrated.is_some_and(|hydrated| hydrated.id == *id) {
                return format!("{short_id}:{content_hash:02x}");
            }
        }
    }
    panic!("fixture entity {} has no short id row", id.to_hex());
}

fn query_request() -> CoreQueryRequest {
    CoreQueryRequest {
        query: None,
        query_vector: Some(SEED_VECTOR.to_vec()),
        limit: 10,
        view: Some(View::Full),
        count_mode: CountMode::Exact,
    }
}

fn context_pack_request() -> CoreContextPackRequest {
    CoreContextPackRequest {
        query: None,
        query_vector: Some(SEED_VECTOR.to_vec()),
        limit: 5,
        depth: None,
        edge_hop: Some(1),
        max_neighbors: Some(4),
        budget: None,
    }
}

fn hydrate_request(reference: &str) -> CoreHydrateRequest {
    CoreHydrateRequest {
        reference: Some(reference.to_owned()),
        short_id: None,
        content_hash: None,
        view: Some(View::Full),
    }
}

fn timeline_request(id: &EntityId) -> CoreMemoryTimelineRequest {
    CoreMemoryTimelineRequest {
        id: id.to_hex(),
        view: Some(View::Summary),
    }
}

/// `query_time_us` measures elapsed wall-clock time, not content: it is the one
/// field two runs of the same read cannot agree on. Both sides are normalized
/// identically before byte comparison; every other field is compared as-is.
fn normalize_pack(response: &mut CoreContextPackResponse) {
    response.0.stats.query_time_us = 0;
}

fn encode<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("dto serializes")
}

fn round_trip<T>(value: &T) -> T
where
    T: Serialize + DeserializeOwned,
{
    serde_json::from_str(&encode(value)).expect("dto round-trips")
}

/// The structured-fields-only equality rule: `reason` and `message` never gate
/// parity.
fn normalized_error(error: &VaultReadError) -> String {
    match error {
        VaultReadError::InvalidRequest { method, field, .. } => {
            format!("invalid_request:{method:?}:{field}")
        }
        VaultReadError::Engine {
            method,
            engine_code,
            ..
        } => format!("engine:{method:?}:{engine_code}"),
        VaultReadError::Transport { method, .. } => format!("transport:{method:?}"),
        VaultReadError::ProtocolMismatch { method, .. } => format!("protocol_mismatch:{method:?}"),
        VaultReadError::RuntimeUnavailable { method } => format!("runtime_unavailable:{method:?}"),
        VaultReadError::Unimplemented { adapter, method } => {
            format!("unimplemented:{adapter:?}:{method:?}")
        }
    }
}

// ─── 1. Structured success parity ────────────────────────────────────────────

#[test]
fn structured_success_parity() {
    let fixture = Fixture::new();
    let in_process = fixture.in_process();
    let wire = fixture.wire();

    let direct = in_process.query(query_request()).expect("in-process query");
    let through_wire = wire.query(query_request()).expect("wire query");
    assert_eq!(encode(&direct), encode(&through_wire));
    assert_eq!(direct.items.len(), 1, "only the admitted claim is surfaced");
    assert_eq!(direct.items[0].id, fixture.admitted_id.to_hex());
    assert_eq!(direct.meta.count_mode, CountMode::Estimate);
    assert_eq!(fixture.transport.ops(), vec![VaultReadWireOp::CoreQuery]);

    fixture.transport.reset();
    let mut direct = in_process
        .context_pack(context_pack_request())
        .expect("in-process context pack");
    let mut through_wire = wire
        .context_pack(context_pack_request())
        .expect("wire context pack");
    normalize_pack(&mut direct);
    normalize_pack(&mut through_wire);
    assert_eq!(encode(&direct), encode(&through_wire));
    assert_eq!(
        fixture.transport.ops(),
        vec![VaultReadWireOp::CoreContextPack]
    );

    fixture.transport.reset();
    let direct = in_process
        .hydrate(hydrate_request(&fixture.admitted_ref))
        .expect("in-process hydrate");
    let through_wire = wire
        .hydrate(hydrate_request(&fixture.admitted_ref))
        .expect("wire hydrate");
    assert_eq!(encode(&direct), encode(&through_wire));
    assert_eq!(
        direct.id.as_deref(),
        Some(fixture.admitted_id.to_hex()).as_deref()
    );
    assert!(direct.item.is_some(), "full view carries the entity record");
    assert_eq!(fixture.transport.ops(), vec![VaultReadWireOp::CoreHydrate]);

    fixture.transport.reset();
    let batch = || CoreBatchShortIdHydrateRequest {
        refs: vec![fixture.admitted_ref.clone(), MISSING_REF.to_owned()],
        view: Some(View::Full),
    };
    let direct = in_process.hydrate_many(batch()).expect("in-process batch");
    let through_wire = wire.hydrate_many(batch()).expect("wire batch");
    assert_eq!(encode(&direct), encode(&through_wire));
    assert_eq!(direct.results.len(), 2);
    assert_eq!(direct.results[0].outcome, CoreShortIdHydrateOutcome::Live);
    assert_eq!(
        direct.results[1].outcome,
        CoreShortIdHydrateOutcome::NotFound
    );
    assert_eq!(
        fixture.transport.ops(),
        vec![VaultReadWireOp::CoreBatchShortIdHydrate]
    );

    fixture.transport.reset();
    let direct = in_process
        .memory_timeline(timeline_request(&fixture.admitted_id))
        .expect("in-process timeline");
    let through_wire = wire
        .memory_timeline(timeline_request(&fixture.admitted_id))
        .expect("wire timeline");
    assert_eq!(encode(&direct), encode(&through_wire));
    assert_eq!(direct.anchor_id, fixture.admitted_id.to_hex());
    assert!(!direct.records.is_empty());
    assert_eq!(
        fixture.transport.ops(),
        vec![VaultReadWireOp::CoreMemoryTimeline]
    );
}

// ─── 2. Denial is absence ────────────────────────────────────────────────────

#[test]
fn scope_denial_is_indistinguishable_from_absence() {
    let fixture = Fixture::new();
    let in_process = fixture.in_process();
    let wire = fixture.wire();
    let denied_hex = fixture.denied_id.to_hex();

    let denied_direct = in_process
        .hydrate(hydrate_request(&fixture.denied_ref))
        .expect_err("denied hydrate");
    let missing_direct = in_process
        .hydrate(hydrate_request(MISSING_REF))
        .expect_err("missing hydrate");
    let denied_wire = wire
        .hydrate(hydrate_request(&fixture.denied_ref))
        .expect_err("denied hydrate through wire");
    let missing_wire = wire
        .hydrate(hydrate_request(MISSING_REF))
        .expect_err("missing hydrate through wire");
    for error in [&denied_direct, &missing_direct, &denied_wire, &missing_wire] {
        assert_eq!(
            normalized_error(error),
            format!("engine:{:?}:NOT_FOUND", VaultReadMethod::Hydrate)
        );
    }
    assert_eq!(denied_direct, missing_direct);
    assert_eq!(denied_wire, missing_wire);

    let batch = |reference: &str| CoreBatchShortIdHydrateRequest {
        refs: vec![reference.to_owned()],
        view: Some(View::Full),
    };
    let denied_item = in_process
        .hydrate_many(batch(&fixture.denied_ref))
        .expect("denied batch")
        .results
        .remove(0);
    let missing_item = in_process
        .hydrate_many(batch(MISSING_REF))
        .expect("missing batch")
        .results
        .remove(0);
    let denied_item_wire = wire
        .hydrate_many(batch(&fixture.denied_ref))
        .expect("denied batch through wire")
        .results
        .remove(0);
    assert_eq!(encode(&denied_item), encode(&denied_item_wire));
    assert_eq!(denied_item.outcome, CoreShortIdHydrateOutcome::NotFound);
    assert_eq!(missing_item.outcome, CoreShortIdHydrateOutcome::NotFound);
    assert_eq!(denied_item.result, None);
    assert_eq!(missing_item.result, None);
    // The ONLY place the denied short id may appear is the caller-echoed ref,
    // byte-identically to the missing case.
    assert_eq!(denied_item.reference, fixture.denied_ref);
    assert_eq!(missing_item.reference, MISSING_REF);
    assert_eq!(
        encode(&denied_item).replace(&fixture.denied_ref, MISSING_REF),
        encode(&missing_item),
        "denied and missing items differ only in the echoed ref"
    );

    let query = in_process.query(query_request()).expect("query");
    let mut pack = in_process
        .context_pack(context_pack_request())
        .expect("context pack");
    normalize_pack(&mut pack);
    let timeline = in_process
        .memory_timeline(timeline_request(&fixture.admitted_id))
        .expect("timeline");
    let denied_timeline = in_process
        .memory_timeline(timeline_request(&fixture.denied_id))
        .expect_err("denied anchor reads as absence");
    assert_eq!(
        normalized_error(&denied_timeline),
        format!("engine:{:?}:NOT_FOUND", VaultReadMethod::MemoryTimeline)
    );

    for payload in [encode(&query), encode(&pack), encode(&timeline)] {
        assert!(
            !payload.contains(&denied_hex),
            "a denied entity id never surfaces: {payload}"
        );
        assert!(
            !payload.contains(DENIED_TEXT),
            "denied body bytes never surface: {payload}"
        );
        assert!(
            !payload.contains(&fixture.denied_ref),
            "a denied short ref never surfaces outside the caller's own echo"
        );
    }
    assert!(
        encode(&query).contains(ADMITTED_TEXT),
        "the admitted claim is still surfaced, so the assertions above are not vacuous"
    );
}

// ─── 3. Validation error parity ──────────────────────────────────────────────

#[test]
fn validation_error_parity() {
    let fixture = Fixture::new();
    let in_process = fixture.in_process();
    let wire = fixture.wire();

    let seedless = || CoreQueryRequest {
        query: Some("   ".to_owned()),
        query_vector: None,
        limit: 10,
        view: None,
        count_mode: CountMode::Estimate,
    };
    assert_eq!(
        normalized_error(&in_process.query(seedless()).expect_err("in-process")),
        normalized_error(&wire.query(seedless()).expect_err("wire"))
    );

    let malformed = || CoreHydrateRequest {
        reference: Some("not-a-ref".to_owned()),
        short_id: None,
        content_hash: None,
        view: None,
    };
    assert_eq!(
        normalized_error(&in_process.hydrate(malformed()).expect_err("in-process")),
        normalized_error(&wire.hydrate(malformed()).expect_err("wire"))
    );

    let empty_batch = || CoreBatchShortIdHydrateRequest {
        refs: Vec::new(),
        view: None,
    };
    let direct = in_process
        .hydrate_many(empty_batch())
        .expect_err("in-process");
    let through_wire = wire.hydrate_many(empty_batch()).expect_err("wire");
    assert_eq!(normalized_error(&direct), normalized_error(&through_wire));
    assert_eq!(
        normalized_error(&direct),
        format!("invalid_request:{:?}:refs", VaultReadMethod::HydrateMany)
    );

    assert!(
        fixture.transport.ops().is_empty(),
        "shared validation rejects before the transport is invoked"
    );
}

// ─── 4. Engine error parity ──────────────────────────────────────────────────

#[test]
fn engine_error_parity() {
    let fixture = Fixture::new();
    let in_process = fixture.in_process();
    let wire = fixture.wire();
    let unresolvable = seed_id(0x7E);

    let direct = in_process
        .memory_timeline(timeline_request(&unresolvable))
        .expect_err("in-process timeline absence");
    let through_wire = wire
        .memory_timeline(timeline_request(&unresolvable))
        .expect_err("wire timeline absence");
    assert_eq!(normalized_error(&direct), normalized_error(&through_wire));
    assert_eq!(
        normalized_error(&direct),
        format!("engine:{:?}:NOT_FOUND", VaultReadMethod::MemoryTimeline)
    );
    assert_eq!(
        fixture.transport.ops(),
        vec![VaultReadWireOp::CoreMemoryTimeline],
        "the engine answer travelled through the transport once"
    );
}

// ─── 5. Runtime-unavailable parity across all three ──────────────────────────

#[test]
fn runtime_unavailable_parity_across_all_three() {
    let fixture = Fixture::new();
    let in_process = fixture.in_process();
    let wire = fixture.wire();
    let cloud = CloudVaultReadAdapter;

    let ask = || AskRequest(json!({ "prompt": "who am i" }));
    let search = || CodeSearchRequest(json!({ "query": "fn main" }));
    let execute = || CodeExecuteRequest(json!({ "source": "1 + 1" }));

    for (method, errors) in [
        (
            VaultReadMethod::Ask,
            vec![
                in_process.ask(ask()).expect_err("in-process ask"),
                wire.ask(ask()).expect_err("wire ask"),
                cloud.ask(ask()).expect_err("cloud ask"),
            ],
        ),
        (
            VaultReadMethod::CodeSearch,
            vec![
                in_process
                    .code_search(search())
                    .expect_err("in-process code search"),
                wire.code_search(search()).expect_err("wire code search"),
                cloud.code_search(search()).expect_err("cloud code search"),
            ],
        ),
        (
            VaultReadMethod::CodeExecute,
            vec![
                in_process
                    .code_execute(execute())
                    .expect_err("in-process code execute"),
                wire.code_execute(execute()).expect_err("wire code execute"),
                cloud
                    .code_execute(execute())
                    .expect_err("cloud code execute"),
            ],
        ),
    ] {
        for error in errors {
            assert_eq!(error, VaultReadError::RuntimeUnavailable { method });
        }
    }
    assert!(
        fixture.transport.ops().is_empty(),
        "runtime peers never reach a transport"
    );
}

// ─── 6. Cloud structured-read contract ───────────────────────────────────────

#[test]
fn cloud_structured_read_contract() {
    let fixture = Fixture::new();
    let cloud = CloudVaultReadAdapter;
    let unimplemented = |method| VaultReadError::Unimplemented {
        adapter: VaultReadAdapterKind::Cloud,
        method,
    };

    assert_eq!(
        cloud.query(query_request()).expect_err("cloud query"),
        unimplemented(VaultReadMethod::Query)
    );
    assert_eq!(
        cloud
            .context_pack(context_pack_request())
            .expect_err("cloud context pack"),
        unimplemented(VaultReadMethod::ContextPack)
    );
    assert_eq!(
        cloud
            .hydrate(hydrate_request(&fixture.admitted_ref))
            .expect_err("cloud hydrate"),
        unimplemented(VaultReadMethod::Hydrate)
    );
    assert_eq!(
        cloud
            .hydrate_many(CoreBatchShortIdHydrateRequest {
                refs: vec![fixture.admitted_ref.clone()],
                view: None,
            })
            .expect_err("cloud batch"),
        unimplemented(VaultReadMethod::HydrateMany)
    );
    assert_eq!(
        cloud
            .memory_timeline(timeline_request(&fixture.admitted_id))
            .expect_err("cloud timeline"),
        unimplemented(VaultReadMethod::MemoryTimeline)
    );

    let structured = VAULT_READ_METHOD_MAP
        .iter()
        .filter(|row| row.availability == VaultReadAvailability::StructuredRead)
        .count();
    assert_eq!(structured, 5, "the cloud stub covers every structured row");
}

// ─── 7. In-process is not privileged ─────────────────────────────────────────

#[test]
fn in_process_is_not_privileged() {
    let fixture = Fixture::new();
    let wire = fixture.wire();
    // Wire FIRST, in-process second: proximity to `Vault` is never authority.
    let wire_hydrate = wire.hydrate(hydrate_request(&fixture.admitted_ref));
    let wire_denied = wire.hydrate(hydrate_request(&fixture.denied_ref));
    let mut wire_pack = wire
        .context_pack(context_pack_request())
        .expect("wire context pack");

    let in_process = keyed_in_process(&fixture.vault, fixture.actor.clone());
    let direct_hydrate = in_process.hydrate(hydrate_request(&fixture.admitted_ref));
    let direct_denied = in_process.hydrate(hydrate_request(&fixture.denied_ref));
    let mut direct_pack = in_process
        .context_pack(context_pack_request())
        .expect("in-process context pack");

    assert_eq!(
        encode(&wire_hydrate.expect("wire hydrate")),
        encode(&direct_hydrate.expect("in-process hydrate"))
    );
    assert_eq!(
        normalized_error(&wire_denied.expect_err("wire denied")),
        normalized_error(&direct_denied.expect_err("in-process denied"))
    );
    normalize_pack(&mut wire_pack);
    normalize_pack(&mut direct_pack);
    assert_eq!(encode(&wire_pack), encode(&direct_pack));
    assert_eq!(
        direct_pack.0.results.len(),
        wire_pack.0.results.len(),
        "in-process never returns more than the wire path"
    );
}

// ─── 8. Serialization round trip ─────────────────────────────────────────────

#[test]
fn serialization_round_trip() {
    let fixture = Fixture::new();
    let in_process = fixture.in_process();

    let query = query_request();
    assert_eq!(round_trip(&query), query);
    let pack_request = CoreContextPackRequest {
        query: Some("blue hallway".to_owned()),
        query_vector: Some(vec![0.25, 0.75]),
        limit: 3,
        depth: Some(ContextPackDepthControls {
            edge_hop: Some(2),
            max_neighbors: Some(9),
        }),
        edge_hop: Some(1),
        max_neighbors: Some(4),
        budget: Some(ContextPackBudgetControls {
            token_budget: Some(4000),
            max_item_tokens: Some(512),
            max_field_chars: Some(500),
            retrieval: Some(ContextPackRetrievalBudgetControls {
                claims: Some(4),
                turns: Some(2),
                summaries: Some(2),
                facets: Some(1),
                other: Some(1),
                selected_edges: Some(50),
            }),
        }),
    };
    assert_eq!(round_trip(&pack_request), pack_request);
    let hydrate = hydrate_request(&fixture.admitted_ref);
    assert_eq!(round_trip(&hydrate), hydrate);
    let batch = CoreBatchShortIdHydrateRequest {
        refs: vec![fixture.admitted_ref.clone(), MISSING_REF.to_owned()],
        view: Some(View::Standard),
    };
    assert_eq!(round_trip(&batch), batch);
    let timeline = timeline_request(&fixture.admitted_id);
    assert_eq!(round_trip(&timeline), timeline);

    let query_response = in_process.query(query_request()).expect("query");
    assert_eq!(round_trip(&query_response), query_response);
    let pack_response = in_process
        .context_pack(context_pack_request())
        .expect("context pack");
    assert_eq!(round_trip(&pack_response), pack_response);
    let hydrate_response = in_process.hydrate(hydrate).expect("hydrate");
    assert_eq!(round_trip(&hydrate_response), hydrate_response);
    let batch_response = in_process.hydrate_many(batch).expect("batch");
    assert_eq!(round_trip(&batch_response), batch_response);
    let timeline_response = in_process.memory_timeline(timeline).expect("timeline");
    assert_eq!(round_trip(&timeline_response), timeline_response);

    let envelope = VaultReadResponse::Query(query_response.clone());
    assert_eq!(round_trip(&envelope), envelope);
    let error = VaultReadError::Engine {
        method: VaultReadMethod::Hydrate,
        engine_code: "NOT_FOUND".to_owned(),
        message: "short_id was not found".to_owned(),
    };
    assert_eq!(round_trip(&error), error);
}

// ─── 9. Golden wire shapes ───────────────────────────────────────────────────

#[test]
fn golden_wire_shapes() {
    // query: canonical spelling, then the accepted alias spellings.
    let canonical_query = r#"{"query":"blue hallway","query_vector":[0.25,0.75],"limit":10,"view":"summary","countMode":"estimate"}"#;
    for literal in [
        canonical_query,
        r#"{"query":"blue hallway","queryVector":[0.25,0.75],"limit":10,"view":"summary","count_mode":"estimate"}"#,
    ] {
        let request: CoreQueryRequest = serde_json::from_str(literal).expect("query literal");
        assert_eq!(encode(&request), canonical_query);
    }
    // Accepted defaults: an omitted limit is 10 and an omitted count mode is
    // estimate.
    let defaulted: CoreQueryRequest =
        serde_json::from_str(r#"{"query":"blue hallway"}"#).expect("defaulted query");
    assert_eq!(defaulted.limit, 10);
    assert_eq!(defaulted.count_mode, CountMode::Estimate);

    // context pack: top-level `edge_hop`, alias spellings, and the vector-only
    // form all canonicalize to snake_case.
    let canonical_pack = r#"{"query":"blue hallway","query_vector":null,"limit":10,"depth":null,"edge_hop":1,"max_neighbors":null,"budget":null}"#;
    for literal in [
        canonical_pack,
        r#"{"query":"blue hallway","edgeHop":1}"#,
        r#"{"query":"blue hallway","edge_hop":1}"#,
    ] {
        let request: CoreContextPackRequest =
            serde_json::from_str(literal).expect("context pack literal");
        assert_eq!(encode(&request), canonical_pack);
    }
    let vector_only_pack = r#"{"query":null,"query_vector":[0.25,0.75],"limit":10,"depth":null,"edge_hop":null,"max_neighbors":null,"budget":null}"#;
    for literal in [
        vector_only_pack,
        r#"{"queryVector":[0.25,0.75]}"#,
        r#"{"query_vector":[0.25,0.75]}"#,
    ] {
        let request: CoreContextPackRequest =
            serde_json::from_str(literal).expect("vector-only literal");
        assert_eq!(encode(&request), vector_only_pack);
        assert_eq!(
            request.resolved_depth(),
            ContextPackDepthControls::default()
        );
    }
    let nested_pack = r#"{"query":null,"query_vector":[0.25,0.75],"limit":10,"depth":{"edge_hop":2,"max_neighbors":9},"edge_hop":1,"max_neighbors":null,"budget":null}"#;
    for literal in [
        nested_pack,
        r#"{"queryVector":[0.25,0.75],"depth":{"edgeHop":2,"maxNeighbors":9},"edgeHop":1}"#,
    ] {
        let request: CoreContextPackRequest =
            serde_json::from_str(literal).expect("nested depth literal");
        assert_eq!(encode(&request), nested_pack);
        assert_eq!(request.resolved_depth().edge_hop, Some(2));
        assert_eq!(request.resolved_depth().max_neighbors, Some(9));
    }
    let budget_pack = r#"{"query":"blue hallway","query_vector":null,"limit":10,"depth":null,"edge_hop":null,"max_neighbors":null,"budget":{"token_budget":4000,"max_item_tokens":512,"max_field_chars":500,"retrieval":{"claims":4,"turns":2,"summaries":2,"facets":1,"other":1,"selected_edges":50}}}"#;
    for literal in [
        budget_pack,
        r#"{"query":"blue hallway","budget":{"tokenBudget":4000,"maxItemTokens":512,"maxFieldChars":500,"retrieval":{"claims":4,"turns":2,"summaries":2,"facets":1,"other":1,"selectedEdges":50}}}"#,
    ] {
        let request: CoreContextPackRequest =
            serde_json::from_str(literal).expect("budget literal");
        assert_eq!(encode(&request), budget_pack);
    }

    // hydrate: `ref` plus every accepted alias, and the parts form.
    let canonical_hydrate = r#"{"ref":"tn1:a7","short_id":null,"content_hash":null,"view":"full"}"#;
    for literal in [
        canonical_hydrate,
        r#"{"short_ref":"tn1:a7","view":"full"}"#,
        r#"{"shortRef":"tn1:a7","view":"full"}"#,
    ] {
        let request: CoreHydrateRequest = serde_json::from_str(literal).expect("hydrate literal");
        assert_eq!(encode(&request), canonical_hydrate);
    }
    let canonical_parts = r#"{"ref":null,"short_id":"tn1","content_hash":"a7","view":null}"#;
    for literal in [canonical_parts, r#"{"shortId":"tn1","contentHash":"a7"}"#] {
        let request: CoreHydrateRequest = serde_json::from_str(literal).expect("parts literal");
        assert_eq!(encode(&request), canonical_parts);
    }

    // batch: every accepted refs alias.
    let canonical_batch = r#"{"refs":["tn1:a7","tn2:ff"],"view":"full"}"#;
    for literal in [
        canonical_batch,
        r#"{"short_refs":["tn1:a7","tn2:ff"],"view":"full"}"#,
        r#"{"shortRefs":["tn1:a7","tn2:ff"],"view":"full"}"#,
        r#"{"short_ids":["tn1:a7","tn2:ff"],"view":"full"}"#,
        r#"{"shortIds":["tn1:a7","tn2:ff"],"view":"full"}"#,
    ] {
        let request: CoreBatchShortIdHydrateRequest =
            serde_json::from_str(literal).expect("batch literal");
        assert_eq!(encode(&request), canonical_batch);
    }

    // timeline: the canonical transport body stays `{"id", "view"}` even though
    // an HTTP host later places those values in path and query.
    let canonical_timeline = r#"{"id":"0123456789abcdef0123456789abcdef","view":"summary"}"#;
    let request: CoreMemoryTimelineRequest =
        serde_json::from_str(canonical_timeline).expect("timeline literal");
    assert_eq!(encode(&request), canonical_timeline);

    // Unknown fields are ignored, exactly like the accepted route DTOs.
    let tolerant: CoreQueryRequest =
        serde_json::from_str(r#"{"query":"blue hallway","unknown":true}"#)
            .expect("unknown fields are ignored");
    assert_eq!(tolerant.query.as_deref(), Some("blue hallway"));

    // The tagged request envelope carries the pinned wire op.
    let tagged = VaultReadRequest::MemoryTimeline(request);
    assert_eq!(
        encode(&tagged),
        format!(r#"{{"op":"core.memory_timeline","request":{canonical_timeline}}}"#)
    );
}
