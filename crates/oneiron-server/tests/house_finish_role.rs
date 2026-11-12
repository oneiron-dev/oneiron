//! The role a workspace's house runs its org in when the owner finishes the
//! workspace (HOUSE-ROLE-DEPUTY-AFTER-7071 = A, the Engine, 12 Nov 09:36, on
//! DEPUTY = A, the owner, 10 Nov 07:45, and HOUSE-BIND-ROLE-SOURCE).
//!
//! `POST /v1/owner/workspace/finish` takes the finish's `role`, else the
//! host's `house_role` config, else deputy. A finish that names `deputy`
//! seats the house at deputy, and a role no house holds (viewer) is refused
//! and binds nothing.
//!
//! Each case drives the real route with the owner's host-root credential (on
//! a profiled install, as a serving start enrols it) and reads the finish
//! back through the engine, never through the route's answer: the root's
//! leader, the house link receipt, and the house's line on the owner's
//! PEOPLE roster. The owner stores the workspace through the engine's own
//! owner door first; its house is the seeded `sys.default` agent. The root
//! is left unsigned, which the bind accepts, so no case depends on the
//! start's root signature.
//!
//! On unmodified main the finish with no role and no `house_role` is refused
//! ("house role not set") and the finish naming `deputy` answers 400 ("role
//! must be member, steward, admin or owner"). The configured-role and viewer
//! cases pass on main and on the head.
//!
//! Deterministic: in-process vault and router (`oneshot`, no TCP ports, no
//! sleeps, no models).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test house_finish_role`.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::FederationGrantRole;
use oneiron::memory::PeopleListRequest;
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::ENTITY_TYPE_ORG;
use oneiron::store::GateDecisionId;
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const WORKSPACE: &str = "house-finish-role-workspace";
/// The workspace's shared vault. Not 7, the own-device residence scope's id.
const VAULT_ID: u64 = 44;
const VENTURE: &str = "Garden Works";
const FINISH: &str = "/v1/owner/workspace/finish";

/// A served host with one stored workspace, before its finish.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_slip: CapabilitySlip,
    owner_token: String,
    root: EntityId,
    /// The workspace's house: the seeded `sys.default` agent.
    house: EntityId,
}

/// Runs `test` on an engine-sized stack and runtime, as the served doors
/// need more than a test thread's default stack.
fn run_on_engine_stack(name: &str, test: impl std::future::Future<Output = ()> + Send + 'static) {
    let run = std::thread::Builder::new()
        .name(name.into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime")
                .block_on(test)
        })
        .expect("spawn the engine-sized test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A host whose config names `house_role` (or none), with the workspace
/// stored by its owner.
fn host(house_role: Option<FederationGrantRole>) -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("house-finish-role".into()),
                house_role,
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    // The owner's acts are carried by this install's live machine profile,
    // as a serving start or `init` enrols it.
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");

    // The owner stores the workspace through the engine's owner door, as
    // the embedded owner the host root bound.
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the embedded owner's proof");
    let org = EntityId::now();
    vault
        .put_entity(
            &org,
            ENTITY_TYPE_ORG,
            TimeRange { start: 1, end: 1 },
            1,
            b"house finish role org",
        )
        .expect("the org row");
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .expect("read the seeded agents")
        .expect("sys.default is seeded on open");
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: VAULT_ID,
        org_ref: org,
        venture_name: VENTURE.to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    vault
        .establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &owner_proof)
        .expect("the owner stores the workspace");
    let root = vault.root_project().expect("the root project");
    let app = build_app(server);
    Host {
        _dir: dir,
        vault,
        app,
        issuer,
        owner,
        owner_slip,
        owner_token,
        root,
        house,
    }
}

impl Host {
    fn owner_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = hex(&self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())
            .expect("owner holder proof"));
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    /// The owner's finish over actual HTTP: its status and its answer, the
    /// answer as text when it is not JSON.
    async fn finish(&self, body: Value) -> (StatusCode, Value) {
        let request = Request::post(FINISH)
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding())
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("finish request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("finish response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("finish response body");
        let answer = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, answer)
    }

    /// The root project's leader, as the engine reads it.
    fn leader(&self) -> Option<String> {
        self.vault
            .project(self.root)
            .expect("read the root project")
            .map(|project| project.leader)
    }

    /// The house link receipts, oldest first.
    fn receipts(&self) -> Vec<ReceiptRecord> {
        let query = ReceiptQuery::new(100).with_kind(ReceiptKind::IdentityLifecycle);
        let mut receipts: Vec<ReceiptRecord> = self
            .vault
            .receipts(query)
            .expect("read the receipts")
            .into_iter()
            .filter(|receipt| receipt.receipt_id.starts_with("house_link:"))
            .collect();
        receipts.sort_by_key(|receipt| receipt.receipt_id.clone());
        receipts
    }

    /// The house's line on the owner's PEOPLE roster.
    fn house_line(&self) -> String {
        let memory = self.vault.memory(self.owner, EdgeActorClass::Human);
        let mut page = 0;
        loop {
            let listed = memory
                .people_list(&PeopleListRequest {
                    vault: None,
                    page: Some(page),
                })
                .expect("the owner lists the vault's people");
            if let Some(row) = listed
                .people
                .into_iter()
                .find(|row| row.actors.contains(&self.house))
            {
                return row.role;
            }
            assert!(listed.more > 0, "the PEOPLE roster lists the house");
            page += 1;
        }
    }

    /// The finish landed: the house leads the root and runs its org at
    /// `role`, with one bind receipt naming the owner.
    fn assert_bound_at(&self, role: &str) {
        assert_eq!(
            self.leader(),
            Some(self.house.to_hex()),
            "the house leads the root"
        );
        let receipts = self.receipts();
        assert_eq!(receipts.len(), 1, "the finish keeps one bind receipt");
        assert_eq!(receipts[0].outcome, "bind");
        let field = |name: &str| receipts[0].fields.get(name).cloned().unwrap_or_default();
        assert_eq!(field("role"), role);
        assert_eq!(field("binder"), self.owner.to_hex());
        assert_eq!(self.house_line(), format!("runs {VENTURE} as {role}"));
    }
}

#[test]
fn a_finish_naming_no_role_on_a_host_with_no_house_role_runs_the_house_as_deputy() {
    run_on_engine_stack("house-finish-default", async {
        let host = host(None);
        let (status, answer) = host.finish(json!({"workspace_ref": WORKSPACE})).await;
        assert_eq!(status, StatusCode::OK, "the finish lands: {answer}");
        host.assert_bound_at("deputy");
    });
}

#[test]
fn a_finish_naming_deputy_runs_the_house_as_deputy() {
    run_on_engine_stack("house-finish-deputy", async {
        let host = host(Some(FederationGrantRole::Member));
        let (status, answer) = host
            .finish(json!({"workspace_ref": WORKSPACE, "role": "deputy"}))
            .await;
        assert_eq!(status, StatusCode::OK, "the finish lands: {answer}");
        host.assert_bound_at("deputy");
    });
}

#[test]
fn a_finish_naming_no_role_runs_the_house_at_the_hosts_house_role() {
    run_on_engine_stack("house-finish-configured", async {
        let host = host(Some(FederationGrantRole::Member));
        let (status, answer) = host.finish(json!({"workspace_ref": WORKSPACE})).await;
        assert_eq!(status, StatusCode::OK, "the finish lands: {answer}");
        host.assert_bound_at("member");
    });
}

#[test]
fn a_finish_naming_viewer_is_refused_and_binds_nothing() {
    run_on_engine_stack("house-finish-viewer", async {
        let host = host(None);
        let leader = host.leader();
        let (status, answer) = host
            .finish(json!({"workspace_ref": WORKSPACE, "role": "viewer"}))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
        assert_eq!(host.leader(), leader, "the root keeps its leader");
        assert!(host.receipts().is_empty(), "no bind receipt");
    });
}
