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

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use oneiron::authority::{HostSlipIssuer, SlipCaveat};
use oneiron::claim::{ScopedReadActorKey, base_world_id};
use oneiron::code_run::vault_read::{
    AskRequest, CodeExecuteRequest, CodeSearchRequest, ContextPackDepthControls,
    CoreBatchShortIdHydrateRequest, CoreContextPackRequest, CoreContextPackResponse,
    CoreHydrateRequest, CoreMemoryTimelineRequest, CoreQueryRequest, CoreShortIdHydrateOutcome,
    CountMode, InProcessVaultReadAdapter, VaultReadClient, VaultReadError, VaultReadMethod,
    VaultReadRequest, VaultReadResponse, VaultReadResult, VaultReadWireOp, View, WireTransport,
    WireTransportVaultReadAdapter,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;

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

/// Explicit base-world read proof for positives: the host root slip
/// attenuated to base `read` only. The status-gated denied claim stays
/// denied through `claim_surfaceable`, exactly as before; the grant gap is
/// closed by the proof instead of a manifest the public API cannot install.
fn base_read_scope() -> Scope {
    Scope {
        worlds: ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())])),
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
        audience: ScopeAxis::All,
        verbs: ScopeAxis::Some(BTreeSet::from(["read".to_owned()])),
        sensitivity: SensitivityCeiling::AtMost(Sensitivity::Restricted),
    }
}

fn base_read_key(vault: &Vault) -> ScopedReadActorKey {
    let issuer =
        HostSlipIssuer::from_secret(b"vault-read-parity-test-host-secret").expect("host issuer");
    let mut slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    issuer
        .attenuate(
            &mut slip,
            SlipCaveat {
                scope: Some(base_read_scope()),
                ..Default::default()
            },
        )
        .expect("narrow root to base read");
    let challenge = b"vault-read-parity";
    let proof_bytes = issuer
        .binding_proof(&slip, challenge)
        .expect("binding proof");
    let verified = vault
        .verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof_bytes)
        .expect("verified base-read slip");
    ScopedReadActorKey::from_verified_slip(&verified).expect("read key")
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    actor: ScopedReadActorKey,
    transport: Arc<FakeWireTransport>,
    admitted_id: EntityId,
    denied_id: EntityId,
    denied_ref: String,
}

impl Fixture {
    fn new() -> Self {
        Self::with_claim_learned_at(1_780_000_000)
    }

    fn with_claim_learned_at(claim_learned_at: u64) -> Self {
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
                claim_learned_at,
            )
            .expect("admitted claim");
        vault
            .put_claim(
                &denied_id,
                // Denied through the claim status gate: the row is in the
                // vault, and the scoped read lane refuses it.
                &claim(subject, DENIED_TEXT, ClaimApprovalStatus::Proposed),
                occurred,
                claim_learned_at,
            )
            .expect("denied claim");
        vault
            .batch()
            .vector(&admitted_id, &SEED_VECTOR)
            .vector(&denied_id, &SEED_VECTOR)
            .commit()
            .expect("fixture vectors");

        let actor = base_read_key(&vault);
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
    )
    .expect("fixture");
    body.source = Some(ClaimSource::UserStated);
    body
}

/// Test-oracle only: resolves an entity's canonical short ref through the naked
/// vault, which is exactly what the adapters may never do. The denied fixture
/// has no readable surface, so its caller-echoed ref must come from here.
fn probe_short_ref(vault: &Vault, id: &EntityId) -> String {
    let prefix = oneiron::registry::short_id_prefix(ENTITY_TYPE_CLAIM).expect("claim prefix");
    // Fresh production open seeds claims before this append-only fixture runs.
    // With no claim deletions here, the live count bounds the per-type counter;
    // a fixed cl1..cl8 probe would only search the bootstrap population.
    let claim_count = vault
        .count_entities_by_type(ENTITY_TYPE_CLAIM)
        .expect("fixture claim count");
    for counter in 1..=claim_count {
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
        executor_model: None,
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

/// Normalize elapsed query time only. Time-dependent scores need a stable
/// fixture input; they and every other field remain byte-compared as-is.
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

// ─── 2. Denial is absence ────────────────────────────────────────────────────

#[test]
fn scope_denial_preserves_not_found_and_reports_withholding() {
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
    assert_eq!(denied_direct, denied_wire);
    assert_eq!(missing_direct, missing_wire);
    // Both adapters keep NOT_FOUND; mandatory receipts distinguish policy
    // exclusions from refs which never resolved, without returning row data.
    for (error, expected) in [(&denied_direct, 1), (&missing_direct, 0)] {
        let VaultReadError::Engine {
            narrowing: Some(receipt),
            ..
        } = error
        else {
            panic!("every resolved read needs a narrowing receipt")
        };
        assert_eq!(receipt.suppressed_count, expected);
        assert_eq!(
            receipt.replan_hint.contains(&"row_authority".to_owned()),
            expected > 0
        );
    }

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
    let canonical_pack = r#"{"executor_model":null,"query":"blue hallway","query_vector":null,"limit":10,"depth":null,"edge_hop":1,"max_neighbors":null,"budget":null}"#;
    for literal in [
        canonical_pack,
        r#"{"query":"blue hallway","edgeHop":1}"#,
        r#"{"query":"blue hallway","edge_hop":1}"#,
    ] {
        let request: CoreContextPackRequest =
            serde_json::from_str(literal).expect("context pack literal");
        assert_eq!(encode(&request), canonical_pack);
    }
    let vector_only_pack = r#"{"executor_model":null,"query":null,"query_vector":[0.25,0.75],"limit":10,"depth":null,"edge_hop":null,"max_neighbors":null,"budget":null}"#;
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
    let nested_pack = r#"{"executor_model":null,"query":null,"query_vector":[0.25,0.75],"limit":10,"depth":{"edge_hop":2,"max_neighbors":9},"edge_hop":1,"max_neighbors":null,"budget":null}"#;
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
    let budget_pack = r#"{"executor_model":null,"query":"blue hallway","query_vector":null,"limit":10,"depth":null,"edge_hop":null,"max_neighbors":null,"budget":{"token_budget":4000,"max_item_tokens":512,"max_field_chars":500,"retrieval":{"claims":4,"turns":2,"summaries":2,"facets":1,"other":1,"selected_edges":50}}}"#;
    for literal in [
        budget_pack,
        r#"{"query":"blue hallway","budget":{"tokenBudget":4000,"maxItemTokens":512,"maxFieldChars":500,"retrieval":{"claims":4,"turns":2,"summaries":2,"facets":1,"other":1,"selectedEdges":50}}}"#,
    ] {
        let request: CoreContextPackRequest =
            serde_json::from_str(literal).expect("budget literal");
        assert_eq!(encode(&request), budget_pack);
    }

    let named_pack: CoreContextPackRequest =
        serde_json::from_str(r#"{"executor_model":"provider/model@rev2","query":"blue hallway"}"#)
            .expect("named executor pack");
    assert_eq!(
        named_pack.executor_model.as_deref(),
        Some("provider/model@rev2")
    );
    assert_eq!(
        encode(&named_pack),
        r#"{"executor_model":"provider/model@rev2","query":"blue hallway","query_vector":null,"limit":10,"depth":null,"edge_hop":null,"max_neighbors":null,"budget":null}"#,
    );
    assert_eq!(round_trip(&named_pack), named_pack);
    assert!(
        serde_json::from_str::<CoreContextPackRequest>(
            r#"{"executorModel":"provider/model@rev2","query":"blue hallway"}"#,
        )
        .is_err(),
        "only canonical executor_model is accepted"
    );

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

    // Native requests are closed, matching the advertised tool schemas.
    // The aliases/defaults above remain accepted, but undeclared fields do not.
    assert!(
        serde_json::from_str::<CoreQueryRequest>(r#"{"query":"blue hallway","unknown":true}"#)
            .is_err()
    );

    // The tagged request envelope carries the pinned wire op.
    let tagged = VaultReadRequest::MemoryTimeline(request);
    assert_eq!(
        encode(&tagged),
        format!(r#"{{"op":"core.memory_timeline","request":{canonical_timeline}}}"#)
    );
}
