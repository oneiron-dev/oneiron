#![cfg(oneiron_test_support)]
//! BOUNDED-LEGACY-READ (RETRIEVAL-04): the legacy reads
//! `GET /api/search/vector`, `/api/entity/{id}` and `/api/edges/{id}` admit a
//! world-bounded `core:read` slip, as `/api/search/text` does (FIX 3604), and
//! read under the slip's own key: a row outside its world is absent, by id,
//! by vector and as an edge target. The owner reads as before. A slip that
//! holds no read, and a revoked one, stay refused.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test bounded_legacy_reads`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, SlipCaveat, holder_proof_challenge,
};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const OCCURRED_AT: u64 = 1_769_947_200;
/// The probe rows' predicate. They sit in different worlds, so neither
/// supersedes the other.
const PROBE_PREDICATE: &str = "profile.preference";
/// The neighbour's own predicate: an owner upsert on the same subject,
/// predicate, world, relationships and scope supersedes the standing head,
/// which would close `readable` and drop it from every read.
const NEIGHBOUR_PREDICATE: &str = "profile.note";
const READABLE_TEXT: &str = "legacy quartz readable";
const NEIGHBOUR_TEXT: &str = "legacy quartz neighbour";
const HIDDEN_TEXT: &str = "legacy quartz hidden";
const HIDDEN_WORLD_NAME: &str = "Legacy private partition";
const READ_RECEIPT: &str = "x-oneiron-read-receipt";

/// Who signs a request: the self-hosted root (the owner), or a holder key.
enum Caller<'a> {
    Owner,
    Holder(&'a Holder),
}

/// A minted slip, possibly caveated by its holder, and the holder's key.
struct Holder {
    slip: CapabilitySlip,
    key: SigningKey,
}

struct Reply {
    status: u16,
    receipt: Option<String>,
    /// The reply's bytes: JSON, or a raw entity body.
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> TestResult<Value> {
        Ok(serde_json::from_slice(&self.body)?)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    /// Base world, with a vector, and edges to `neighbour` and `hidden`.
    readable: EntityId,
    /// Base world, no vector, its own predicate.
    neighbour: EntityId,
    /// The hidden world, with the same vector as `readable`.
    hidden: EntityId,
    hidden_world: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        // A vector write needs the vault's embedding space named; no model runs.
        config.embedding_model = Some("test/model@v1".to_owned());
        let vault = Arc::new(Vault::open(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        let hidden_world = vault.create_world(&owner_proof, HIDDEN_WORLD_NAME, OCCURRED_AT)?;
        let base = base_world_id();
        let write = |world, predicate, value| {
            write_owner_claim(&vault, owner, &owner_proof, world, predicate, value)
        };
        let readable = write(base, PROBE_PREDICATE, READABLE_TEXT)?;
        let neighbour = write(base, NEIGHBOUR_PREDICATE, NEIGHBOUR_TEXT)?;
        let hidden = write(hidden_world, PROBE_PREDICATE, HIDDEN_TEXT)?;
        let probe = probe_vector();
        vault
            .batch()
            .vector(&readable, &probe)
            .vector(&hidden, &probe)
            .commit()?;
        vault.put_edge(&readable, EdgeKind::Mentions, &neighbour, 1.0)?;
        vault.put_edge(&readable, EdgeKind::Mentions, &hidden, 1.0)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("bounded-legacy-reads".into()),
                ..Default::default()
            },
        )?);
        Ok(Self {
            app: build_app(server),
            vault,
            issuer,
            root,
            readable,
            neighbour,
            hidden,
            hidden_world,
            _dir: dir,
        })
    }

    /// A distinct PERSON's slip holding `verbs`, which the holder then
    /// narrows to the base world with its own caveat (as
    /// `self.credential.attenuate` does).
    fn base_world_holder(&self, slip_id: u8, verbs: &[&str]) -> TestResult<Holder> {
        let person = EntityId::now();
        self.vault.put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a distinct reader",
        )?;
        let key = SigningKey::from_bytes(&[slip_id; 32]);
        let mut claims = self.root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [slip_id; 32];
        claims.holder_ref = person.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = verb_axis(verbs);
        let mut slip = self.vault.mint_capability_slip(&self.issuer, claims)?;
        let mut ceiling = Scope::top();
        ceiling.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
        ceiling.verbs = verb_axis(verbs);
        slip.attenuate(
            SlipCaveat {
                scope: Some(ceiling),
                ..Default::default()
            },
            &key,
        )?;
        Ok(Holder { slip, key })
    }

    fn headers(&self, caller: &Caller<'_>) -> TestResult<(String, String)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let (slip, signature) = match caller {
            Caller::Owner => (
                &self.root,
                self.issuer.binding_proof(&self.root, &challenge)?,
            ),
            Caller::Holder(holder) => (
                &holder.slip,
                holder
                    .key
                    .sign(&holder.slip.binding_transcript(&challenge)?)
                    .to_bytes()
                    .to_vec(),
            ),
        };
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        Ok((format!("Bearer {}", slip.to_token()?), binding.to_string()))
    }

    async fn send(&self, caller: &Caller<'_>, request: Request<Body>) -> TestResult<Reply> {
        let (authorization, binding) = self.headers(caller)?;
        let (mut parts, body) = request.into_parts();
        parts
            .headers
            .insert("authorization", authorization.parse()?);
        parts.headers.insert("x-oneiron-binding", binding.parse()?);
        let response = self
            .app
            .clone()
            .oneshot(Request::from_parts(parts, body))
            .await?;
        let status = response.status().as_u16();
        let receipt = response
            .headers()
            .get(READ_RECEIPT)
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()?;
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        Ok(Reply {
            status,
            receipt,
            body: body.to_vec(),
        })
    }

    async fn get(&self, caller: &Caller<'_>, path: &str) -> TestResult<Reply> {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())?;
        self.send(caller, request).await
    }

    async fn facade_get(&self, caller: &Caller<'_>, id: EntityId) -> TestResult<Reply> {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/core/facade/vault.get")
            .header("content-type", "application/json")
            .body(Body::from(json!({ "entity_ref": id.to_hex() }).to_string()))?;
        self.send(caller, request).await
    }

    fn vector_path(&self) -> String {
        let query = probe_vector()
            .iter()
            .map(f32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        format!("/api/search/vector?query={query}&limit=20")
    }

    /// Nothing of the hidden world's row reaches a bounded reply: not its id,
    /// its value, its world's id or its world's name.
    fn assert_hidden_absent(&self, door: &str, reply: &Reply) {
        let body = reply.text();
        for (what, secret) in [
            ("hidden claim id", self.hidden.to_hex()),
            ("hidden claim value", HIDDEN_TEXT.to_owned()),
            ("hidden world id", self.hidden_world.to_hex()),
            ("hidden world name", HIDDEN_WORLD_NAME.to_owned()),
        ] {
            assert!(
                !body.contains(&secret),
                "{door}: the bounded reply names the {what}: {body}"
            );
            if let Some(receipt) = &reply.receipt {
                assert!(
                    !receipt.contains(&secret),
                    "{door}: the bounded read receipt names the {what}: {receipt}"
                );
            }
        }
    }
}

fn write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    world: EntityId,
    predicate: &str,
    value: &str,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: predicate.to_owned(),
            subject_ref: owner.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: world.to_hex(),
                scope_facet_id: vault.default_facet()?.to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(OCCURRED_AT),
            learned_at: Some(OCCURRED_AT),
            salience: None,
        })?;
    Ok(id)
}

fn verb_axis(verbs: &[&str]) -> ScopeAxis<String> {
    ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect())
}

/// One unit vector at the device vault's width.
fn probe_vector() -> Vec<f32> {
    let mut vector = vec![0.0; VaultConfig::device().dimensions];
    vector[0] = 1.0;
    vector
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_world_bounded_core_read_slip_reads_the_legacy_routes_under_its_own_key() -> TestResult {
    on_engine_stack(world_bounded_slip_and_the_legacy_routes)
}

async fn world_bounded_slip_and_the_legacy_routes() -> TestResult {
    let fixture = Fixture::new()?;
    let readable = fixture.readable.to_hex();
    let neighbour = fixture.neighbour.to_hex();
    let hidden = fixture.hidden.to_hex();

    // The owner, unchanged: every row, vector hit and edge exists.
    let owner = Caller::Owner;
    let reply = fixture.get(&owner, &fixture.vector_path()).await?;
    assert_eq!(reply.status, 200, "owner vector search: {}", reply.text());
    assert!(
        reply.text().contains(&readable) && reply.text().contains(&hidden),
        "the owner's vector search holds both probe rows: {}",
        reply.text()
    );
    let reply = fixture
        .get(&owner, &format!("/api/entity/{hidden}?view=full"))
        .await?;
    assert_eq!(reply.status, 200, "owner entity read: {}", reply.text());
    assert!(reply.text().contains(&hidden), "{}", reply.text());
    let reply = fixture
        .get(&owner, &format!("/api/edges/{readable}"))
        .await?;
    assert_eq!(reply.status, 200, "owner edges read: {}", reply.text());
    assert!(
        reply.text().contains(&neighbour) && reply.text().contains(&hidden),
        "the owner's edges hold both targets: {}",
        reply.text()
    );

    // The reader: a distinct person's core:read slip, narrowed by its holder
    // to the base world. The facade read admits it today; it sees the base
    // row and not the hidden one.
    let reader = fixture.base_world_holder(0x51, &["core:read"])?;
    let caller = Caller::Holder(&reader);
    let reply = fixture.facade_get(&caller, fixture.readable).await?;
    assert_eq!(reply.status, 200, "reader facade get: {}", reply.text());
    assert_eq!(
        reply.json()?["value"]["id_hex"],
        readable,
        "the facade serves the reader its base-world row: {}",
        reply.text()
    );
    let reply = fixture.facade_get(&caller, fixture.hidden).await?;
    assert_eq!(reply.status, 200, "reader facade get: {}", reply.text());
    assert!(
        reply.json()?["value"].is_null(),
        "the facade withholds the hidden-world row: {}",
        reply.text()
    );

    // The legacy reads now admit the same slip and clamp it the same way.
    let reply = fixture.get(&caller, &fixture.vector_path()).await?;
    assert_eq!(
        reply.status,
        200,
        "a world-bounded core:read slip reads the legacy vector search: {}",
        reply.text()
    );
    assert!(reply.text().contains(&readable), "{}", reply.text());
    fixture.assert_hidden_absent("vector search", &reply);

    let reply = fixture
        .get(&caller, &format!("/api/entity/{readable}?view=full"))
        .await?;
    assert_eq!(
        reply.status,
        200,
        "a world-bounded core:read slip reads its base-world entity: {}",
        reply.text()
    );
    assert!(reply.text().contains(&readable), "{}", reply.text());
    assert!(
        reply.receipt.is_some(),
        "the legacy entity read carries its read receipt"
    );
    fixture.assert_hidden_absent("entity read", &reply);

    let reply = fixture
        .get(&caller, &format!("/api/entity/{hidden}?view=full"))
        .await?;
    assert_eq!(
        reply.status,
        404,
        "the hidden-world entity is absent to the bounded reader: {}",
        reply.text()
    );
    assert!(!reply.text().contains(HIDDEN_TEXT), "{}", reply.text());

    let reply = fixture
        .get(&caller, &format!("/api/edges/{readable}"))
        .await?;
    assert_eq!(
        reply.status,
        200,
        "a world-bounded core:read slip reads its base-world edges: {}",
        reply.text()
    );
    assert!(reply.text().contains(&neighbour), "{}", reply.text());
    fixture.assert_hidden_absent("edges read", &reply);

    let reply = fixture
        .get(&caller, &format!("/api/edges/{hidden}"))
        .await?;
    assert_eq!(
        reply.status,
        404,
        "a hidden-world anchor is absent to the bounded reader: {}",
        reply.text()
    );

    // A slip that holds no read stays out of every legacy read.
    let writer = fixture.base_world_holder(0x52, &["core:write"])?;
    let writer = Caller::Holder(&writer);
    for path in [
        fixture.vector_path(),
        format!("/api/entity/{readable}?view=full"),
        format!("/api/edges/{readable}"),
    ] {
        let reply = fixture.get(&writer, &path).await?;
        assert!(
            matches!(reply.status, 401 | 403),
            "a slip without core:read is refused {path}: {} {}",
            reply.status,
            reply.text()
        );
        assert!(!reply.text().contains(READABLE_TEXT), "{}", reply.text());
    }

    // The grant is checked at each use: once its mint is revoked, the same
    // caveated slip reads nothing.
    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, reader.slip.claims.slip_id)?;
    let reply = fixture
        .get(&caller, &format!("/api/entity/{readable}?view=full"))
        .await?;
    assert!(
        matches!(reply.status, 401 | 403),
        "a revoked slip is refused the legacy entity read: {} {}",
        reply.status,
        reply.text()
    );
    assert!(!reply.text().contains(READABLE_TEXT), "{}", reply.text());
    Ok(())
}
