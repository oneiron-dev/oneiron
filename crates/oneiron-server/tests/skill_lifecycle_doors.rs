//! A stored skill's lifecycle through the served doors (FIX
//! [SKILL-HUB-PROMOTION-VERBS], ND-001's lifecycle half). `vault.skills.fork`
//! forks under the owner's proof, and `vault.skills.lifecycle.set` moves a
//! skill through the ordinary skill update law: a native fork activates,
//! while a fork of imported ancestry is refused at the hub import-origin gate,
//! so a fork never launders an import. Archive, restore and supersession keep
//! their own doors.
//!
//! Ports `native_owner_forks_keep_their_door_but_imported_ancestry_never_launders`
//! (`crates/oneiron/src/skill_hub/admission_tests.rs`), plus the door's own
//! refusals.
//!
//! Reads JSON only for the new verb, so on a base without it the test fails
//! at its first lifecycle.set status.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --no-fail-fast --test skill_lifecycle_doors`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{
    HubFile, HubPackage, HubPin, HubRef, HubSyncPolicy, SkillCapabilitySurface, SkillHubKind,
    SkillHubRecord, SkillHubTrustTier,
};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

/// A hub package of one SKILL.md, as a hub serves it: Imported, Proposed.
fn package(name: &str) -> HubPackage {
    let content =
        format!("---\nname: {name}\ndescription: fixture\nversion: 1\n---\ncheck result\n");
    let record = SkillRecord::new(
        name,
        "fixture",
        "1",
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.5,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("hub-folder"),
        )]),
    );
    let mut package = HubPackage::new(
        record,
        vec![HubFile::new("SKILL.md", content.into_bytes())],
        SkillCapabilitySurface::default(),
    );
    package.record.content_hash = Some(package.content_hash().expect("package hash"));
    package
}

/// A served vault and its owner's credential.
struct Served {
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
    owner: AuthenticatedOwner,
}

impl Served {
    fn start(path: &Path) -> Self {
        let vault = Arc::new(Vault::open(path, VaultConfig::device()).expect("open vault"));
        // The keystore goes in BEFORE the server: construction roots the vault.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("skill-lifecycle-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server");
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let token = slip.to_token().expect("owner slip token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner = vault
            .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        let app = build_app(Arc::new(server));
        Self {
            vault,
            app,
            issuer,
            slip,
            token,
            owner,
        }
    }

    async fn facade(&self, verb: &str, body: &Value) -> (StatusCode, Value) {
        // Each request proves possession afresh; the host secret is not a bearer.
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.slip, challenge.as_bytes())
            .expect("owner holder proof")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {}", self.token))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    /// An active native skill the owner stated.
    fn native_baseline(&self) -> EntityId {
        let baseline = EntityId::now();
        let mut record = package("fixture.base").record;
        record.source = ClaimSource::UserStated;
        record.content_hash = None;
        let now = self.vault.now_recorded_at();
        self.vault
            .put_skill_record(&baseline, &record, at(now), now)
            .expect("baseline candidate");
        record.lifecycle_status = SkillLifecycle::Active;
        record.approval_status = ClaimApprovalStatus::Approved;
        self.vault
            .update_skill_record(&baseline, &record, at(now + 1), now + 1)
            .expect("active baseline");
        baseline
    }

    /// `package(name)` imported from a configured Verified hub, pinned to its
    /// hash: a Candidate.
    fn import(&self, name: &str) -> EntityId {
        let hub = EntityId::now();
        let record = SkillHubRecord::new(
            SkillHubKind::HttpIndex,
            "https://example.invalid/index.json",
            SkillHubTrustTier::Verified,
            HubSyncPolicy::ContentHashFrozen,
        )
        .expect("hub record");
        let now = self.vault.now_recorded_at();
        self.vault
            .configure_skill_hub(&self.owner, &hub, &record, at(now), now)
            .expect("configure hub");
        let package = package(name);
        let source = HubRef::new(
            hub,
            name,
            HubPin::ContentHash(package.content_hash().expect("package hash").to_hex()),
        )
        .expect("pinned source");
        let now = self.vault.now_recorded_at();
        let id = self
            .vault
            .import_skill_from_hub(&source, &package, at(now), now)
            .expect("import candidate");
        assert_eq!(self.lifecycle(id), SkillLifecycle::Candidate);
        id
    }

    /// `vault.skills.fork` of `parent` under the owner's proof: the fork's id.
    async fn fork(&self, parent: EntityId, skill_id: &str) -> EntityId {
        let (status, view) = self
            .facade(
                "vault.skills.fork",
                &json!({"parent": parent.to_hex(), "skill_id": skill_id}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "fork: {view}");
        assert_eq!(
            view["lifecycle"], "candidate",
            "a fork is a candidate: {view}"
        );
        let entity = view["entity"].as_str().expect("the fork's entity");
        EntityId::from_hex(entity).expect("the fork's id")
    }

    /// `vault.skills.lifecycle.set` of `entity` to `lifecycle`.
    async fn set(&self, entity: EntityId, lifecycle: &str) -> (StatusCode, Value) {
        self.facade(
            "vault.skills.lifecycle.set",
            &json!({"entity": entity.to_hex(), "lifecycle": lifecycle}),
        )
        .await
    }

    /// A set the door refuses: a client error, and the skill keeps `kept`.
    async fn refused(&self, entity: EntityId, lifecycle: &str, kept: SkillLifecycle) {
        let (status, answer) = self.set(entity, lifecycle).await;
        assert!(
            status.is_client_error(),
            "lifecycle.set {lifecycle} is refused: {status} {answer}"
        );
        assert_eq!(self.lifecycle(entity), kept, "{answer}");
    }

    /// The lifecycle `vault.skills.get` serves for `entity`.
    async fn served_lifecycle(&self, entity: EntityId) -> Value {
        let (status, view) = self
            .facade("vault.skills.get", &json!({"entity": entity.to_hex()}))
            .await;
        assert_eq!(status, StatusCode::OK, "get: {view}");
        view["lifecycle"].clone()
    }

    fn lifecycle(&self, entity: EntityId) -> SkillLifecycle {
        self.vault
            .get_skill_record(&entity)
            .expect("read the skill")
            .expect("the skill")
            .lifecycle_status
    }
}

async fn native_forks_activate_and_imported_ancestry_never_launders(host: &Served) {
    // The owner's own fork of a native skill keeps its door: it activates.
    let baseline = host.native_baseline();
    let own = host.fork(baseline, "own.fork").await;
    let (status, view) = host.set(own, "active").await;
    assert_eq!(status, StatusCode::OK, "lifecycle.set active: {view}");
    assert_eq!(view["entity"], own.to_hex().as_str(), "{view}");
    assert_eq!(view["lifecycle"], "active", "{view}");
    assert_eq!(host.lifecycle(own), SkillLifecycle::Active);

    // An import, and a fork of a fork of it: neither activates without the
    // held-out admission's proof.
    let imported = host.import("fixture.imported");
    host.refused(imported, "active", SkillLifecycle::Candidate)
        .await;
    let foreign = host.fork(imported, "foreign.fork").await;
    let descendant = host.fork(foreign, "foreign.descendant").await;
    host.refused(descendant, "active", SkillLifecycle::Candidate)
        .await;
    assert_eq!(host.served_lifecycle(descendant).await, "candidate");
    host.refused(foreign, "active", SkillLifecycle::Candidate)
        .await;

    // Supersession and archiving keep their own doors.
    host.refused(own, "superseded", SkillLifecycle::Active)
        .await;
    host.refused(own, "archived", SkillLifecycle::Active).await;

    // An archived skill returns through vault.skills.restore, never here.
    let (status, view) = host
        .facade("vault.skills.archive", &json!({"entity": own.to_hex()}))
        .await;
    assert_eq!(status, StatusCode::OK, "archive: {view}");
    assert_eq!(view["lifecycle"], "archived", "{view}");
    host.refused(own, "active", SkillLifecycle::Quarantined)
        .await;
    assert_eq!(host.served_lifecycle(own).await, "archived");
}

#[test]
fn a_native_fork_activates_through_the_lifecycle_door_and_imported_ancestry_never_launders() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let path: PathBuf = dir.path().into();
    run_on_engine_stack("skill-lifecycle-set", move || async move {
        let host = Served::start(&path);
        native_forks_activate_and_imported_ancestry_never_launders(&host).await;
    });
}
