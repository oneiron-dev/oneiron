//! Pinned workloads (pass 33 row R2; tests T10, T11, T12, T12b of section
//! 11): the owner approves each exact workload (EN-1 A), an agent cannot,
//! and the check the start gate calls before the reservation refuses a
//! revoked or expired approval, a starter the approval does not name, and a
//! machine it does not list. T9 (the gate itself refuses before the
//! reservation) is carried by the gate's own PR (OPUS-LE-FLEET, LM-8 = A).
//!
//! T10 runs over the served doors. T11, T12 and T12b run on the owner's
//! machines from the mesh harness, whose first machine's vault grants the
//! second the job protocol, so an approval can name it.
//!
//! Run on the fleet, never on a workstation:
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --test job_workloads
#![cfg(all(oneiron_test_support, feature = "mesh"))]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use mesh_machines::Machines;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::job_workload::{
    JOB_ALPN, TEMPLATE_CHANGED, WorkloadApproveRequest, WorkloadError, WorkloadNodeAnswer,
    WorkloadPin, WorkloadPinRequest, WorkloadRef, WorkloadStanding, WorkloadStartAsk,
    WorkloadStartRefusal, WorkloadStarter,
};
use oneiron::test_doors::steward;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const TEMPLATE_DIGEST: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const CONTRACT_SHA256: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const MAXIMUM_SECS: u64 = 1_800;
/// A far expiry: 2100-01-01.
const FAR_EXPIRY_MS: u64 = 4_102_444_800_000;

/// One exact workload, as the pin door takes it; `tag` makes its arguments,
/// and so its digest, its own.
fn pin_json(tag: &str) -> Value {
    json!({
        "pin": {
            "template": "open-models",
            "template_digest": TEMPLATE_DIGEST,
            "commit": COMMIT,
            "contract_sha256": CONTRACT_SHA256,
            "contract_path": "arms/inkling/contract.json",
            "entry": "arms/inkling/run.py",
            "args": ["--arm", tag],
            "request": {
                "gpus": 1,
                "vram_mib": 22_528,
                "memory_mib": 22_528,
                "disk_mib": 2_048,
                "maximum_secs": MAXIMUM_SECS,
            },
            "scope": {"kind": "host"},
            "network": "none",
            "outputs": [{"name": "verdict.json", "returnable": true}],
        }
    })
}

fn pin_request(tag: &str) -> WorkloadPinRequest {
    serde_json::from_value(pin_json(tag)).expect("a pin request")
}

/// The machine's answer when it holds the pin's template unchanged and could
/// take the job.
fn node_takes(pin: &WorkloadPin) -> WorkloadNodeAnswer {
    WorkloadNodeAnswer::Answered {
        template_digest: Some(pin.template_digest.clone()),
        refusal: None,
    }
}

/// The start gate's check of `workload` on `machine` for `starter` at
/// `now_ms`, with a machine that would take it; answers the verdict and
/// whether the machine was asked.
fn gate(
    vault: &Vault,
    workload: &str,
    machine: EntityId,
    starter: WorkloadStarter,
    now_ms: u64,
) -> (Result<WorkloadPin, WorkloadStartRefusal>, bool) {
    let asked = Cell::new(false);
    let ask = WorkloadStartAsk {
        workload,
        machine,
        maximum_secs: MAXIMUM_SECS,
        starter,
    };
    let verdict = vault
        .check_workload_start(
            &ask,
            &mut |pin| {
                asked.set(true);
                node_takes(pin)
            },
            now_ms,
        )
        .expect("the workload check reads the store");
    (verdict, asked.get())
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time after the epoch")
            .as_millis(),
    )
    .expect("milliseconds fit u64")
}

// --- The owner's machines (T11, T12, T12b) -------------------------------

/// The issuer's vault (the first machine's), its owner's proof, and the
/// second machine, which that vault grants the job protocol.
struct Rack {
    mesh: Machines,
    owner: AuthenticatedOwner,
    owner_id: EntityId,
    machine: EntityId,
}

impl Rack {
    async fn start() -> Self {
        let mesh = Machines::start_granted(2, &[JOB_ALPN])
            .await
            .expect("two machines, each granted the job protocol by the other");
        let vault = Arc::clone(&mesh.machine(0).device.vault);
        let owner = steward::owner(&vault).expect("the issuer's owner proof");
        let owner_id = owner.revalidate(&vault).expect("the owner's id");
        let machine = mesh.machine(1).device.machine;
        Self {
            mesh,
            owner,
            owner_id,
            machine,
        }
    }

    fn vault(&self) -> &Vault {
        &self.mesh.machine(0).device.vault
    }

    /// The owner pins `tag`; answers its digest.
    fn pin(&self, tag: &str) -> String {
        let pinned = self
            .vault()
            .pin_job_workload(
                oneiron::job_workload::WorkloadCaller::Owner(&self.owner),
                &pin_request(tag),
                now_ms(),
            )
            .expect("the owner pins");
        assert!(pinned.changed, "a new pin is written");
        assert_eq!(pinned.workload.standing, WorkloadStanding::Pinned);
        pinned.workload.digest
    }

    /// The owner approves `digest` on `machines` for `starters`.
    fn approve(
        &self,
        digest: &str,
        machines: &[EntityId],
        starters: &[EntityId],
        expires_at_ms: u64,
    ) -> Result<oneiron::job_workload::WorkloadChange, WorkloadError> {
        self.vault().approve_job_workload(
            &self.owner,
            &WorkloadApproveRequest {
                workload: digest.to_owned(),
                machines: machines.iter().map(EntityId::to_hex).collect(),
                starters: starters.iter().map(EntityId::to_hex).collect(),
                expires_at_ms,
            },
            now_ms(),
        )
    }

    /// The owner pins `tag` and approves it on the granted machine.
    fn pin_and_approve(&self, tag: &str, starters: &[EntityId], expires_at_ms: u64) -> String {
        let digest = self.pin(tag);
        let approved = self
            .approve(&digest, &[self.machine], starters, expires_at_ms)
            .expect("the owner approves");
        assert!(approved.changed, "a new approval is written");
        assert_eq!(approved.workload.standing, WorkloadStanding::Approved);
        digest
    }
}

/// T11: the approval is read live at each start. A start passes while the
/// approval stands; right after the owner's revoke the next start is
/// refused, and an approval refuses from its expiry on.
#[test]
fn a_revoked_or_expired_approval_refuses_the_next_start() {
    run_on_engine_stack("job-workloads-revoke-expiry", || async {
        let rack = Rack::start().await;
        let owner = WorkloadStarter::Owner(rack.owner_id);
        let digest = rack.pin_and_approve("revoked", &[], FAR_EXPIRY_MS);
        let now = now_ms();
        let (verdict, asked) = gate(rack.vault(), &digest, rack.machine, owner, now);
        assert!(verdict.is_ok(), "the approved workload starts: {verdict:?}");
        assert!(asked, "the machine is asked once the vault half passes");

        let revoked = rack
            .vault()
            .revoke_job_workload(
                &rack.owner,
                &WorkloadRef {
                    workload: digest.clone(),
                },
                now,
            )
            .expect("the owner revokes");
        assert!(revoked.changed, "the revoke is written");
        assert_eq!(revoked.workload.standing, WorkloadStanding::Revoked);
        let (verdict, asked) = gate(rack.vault(), &digest, rack.machine, owner, now);
        assert_eq!(verdict, Err(WorkloadStartRefusal::WorkloadRevoked));
        assert!(!asked, "a revoked workload asks no machine");
        let again = rack
            .vault()
            .revoke_job_workload(
                &rack.owner,
                &WorkloadRef {
                    workload: digest.clone(),
                },
                now,
            )
            .expect("a repeat revoke answers");
        assert!(!again.changed, "a repeat revoke changes nothing");
        assert!(
            matches!(
                rack.approve(&digest, &[rack.machine], &[], FAR_EXPIRY_MS),
                Err(WorkloadError::Revoked)
            ),
            "a revoked workload is not approved again"
        );

        let expires_at_ms = now + 3_600_000;
        let expiring = rack.pin_and_approve("expiring", &[], expires_at_ms);
        let (verdict, _) = gate(
            rack.vault(),
            &expiring,
            rack.machine,
            owner,
            expires_at_ms - 1,
        );
        assert!(verdict.is_ok(), "it starts before its expiry: {verdict:?}");
        let (verdict, asked) = gate(rack.vault(), &expiring, rack.machine, owner, expires_at_ms);
        assert_eq!(verdict, Err(WorkloadStartRefusal::WorkloadExpired));
        assert!(!asked, "an expired workload asks no machine");
        rack.mesh.stop().await;
    });
}

/// T12: an agent starts only a workload whose approval names its Grant. With
/// starters named, exactly those Grants start it; with none named, only the
/// Grant the workload was pinned under does, so an owner's pin with no
/// starters starts for no Grant. The owner starts any approved workload.
#[test]
fn an_agent_starts_only_a_workload_that_names_its_grant() {
    run_on_engine_stack("job-workloads-starter", || async {
        let rack = Rack::start().await;
        let named_grant = EntityId::now();
        let other_grant = EntityId::now();
        let now = now_ms();
        let start = |digest: &str, starter| gate(rack.vault(), digest, rack.machine, starter, now);

        let named = rack.pin_and_approve("named", &[named_grant], FAR_EXPIRY_MS);
        let (verdict, asked) = start(&named, WorkloadStarter::Grant(named_grant));
        assert!(verdict.is_ok(), "the named Grant starts it: {verdict:?}");
        assert!(asked);
        let (verdict, asked) = start(&named, WorkloadStarter::Grant(other_grant));
        assert_eq!(
            verdict,
            Err(WorkloadStartRefusal::StarterNotNamed),
            "a Grant the approval does not name is refused"
        );
        assert!(
            !asked,
            "a starter the approval does not name asks no machine"
        );
        assert!(
            start(&named, WorkloadStarter::Owner(rack.owner_id))
                .0
                .is_ok()
        );

        let owners = rack.pin_and_approve("owners", &[], FAR_EXPIRY_MS);
        assert_eq!(
            start(&owners, WorkloadStarter::Grant(named_grant)).0,
            Err(WorkloadStartRefusal::StarterNotNamed),
            "an owner's pin with no starters named starts for no Grant"
        );
        assert!(
            start(&owners, WorkloadStarter::Owner(rack.owner_id))
                .0
                .is_ok()
        );
        rack.mesh.stop().await;
    });
}

/// T12b: the approval names the machines. A start for a machine it does not
/// list is refused before any machine is asked, so nothing is held. An
/// approval on a machine without the job grant is refused. A machine whose
/// template changed since the pin refuses it, and a quote above the pinned
/// maximum is refused.
#[test]
fn a_start_for_a_machine_the_approval_does_not_list_is_refused_before_the_reservation() {
    run_on_engine_stack("job-workloads-machine", || async {
        let rack = Rack::start().await;
        let owner = WorkloadStarter::Owner(rack.owner_id);
        let digest = rack.pin_and_approve("one-machine", &[], FAR_EXPIRY_MS);
        let elsewhere = EntityId::now();
        let now = now_ms();
        let (verdict, asked) = gate(rack.vault(), &digest, elsewhere, owner, now);
        assert_eq!(verdict, Err(WorkloadStartRefusal::MachineNotApproved));
        assert!(
            !asked,
            "a machine the approval does not list is never asked"
        );

        let ungranted = rack.pin("ungranted");
        let refused = rack.approve(&ungranted, &[elsewhere], &[], FAR_EXPIRY_MS);
        assert!(
            matches!(refused, Err(WorkloadError::MachineNotGranted { .. })),
            "an approval on a machine without the job grant is refused: {refused:?}"
        );
        assert!(
            rack.vault()
                .job_workload(&ungranted)
                .expect("read the workload")
                .expect("the pin stands")
                .approval
                .is_none(),
            "the refused approval wrote nothing"
        );

        let ask = WorkloadStartAsk {
            workload: &digest,
            machine: rack.machine,
            maximum_secs: MAXIMUM_SECS,
            starter: owner,
        };
        let verdict = rack
            .vault()
            .check_workload_start(
                &ask,
                &mut |_| WorkloadNodeAnswer::Answered {
                    template_digest: Some("b2".repeat(32)),
                    refusal: None,
                },
                now,
            )
            .expect("the workload check reads the store");
        assert_eq!(
            verdict,
            Err(WorkloadStartRefusal::MachineRefuses {
                reason: TEMPLATE_CHANGED.to_owned()
            }),
            "a changed template refuses the pin"
        );
        let above = WorkloadStartAsk {
            maximum_secs: MAXIMUM_SECS + 1,
            ..ask
        };
        let verdict = rack
            .vault()
            .check_workload_start(&above, &mut node_takes, now)
            .expect("the workload check reads the store");
        assert_eq!(verdict, Err(WorkloadStartRefusal::RequestAbovePin));
        rack.mesh.stop().await;
    });
}

// --- The served doors (T10) ----------------------------------------------

/// A served vault, its owner's slip and token.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

/// One paired agent credential.
struct Agent {
    principal: EntityId,
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn serve() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("job-workloads".into()),
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
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let app = build_app(Arc::clone(&server));
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
    }
}

/// Pairs one agent as `token agent` does, over the real pairing route.
async fn pair_agent(served: &Served, name: &str, seed: [u8; 32]) -> Agent {
    let principal = served
        .vault
        .ensure_agent_principal(name)
        .expect("agent principal");
    let holder = SigningKey::from_bytes(&seed);
    let binding_key = holder.verifying_key().to_bytes();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let link = served
        .vault
        .issue_pairing_link_for_principal(
            &served.issuer,
            scope,
            3600,
            PairingPrincipal {
                holder_ref: Some(principal.to_hex()),
                actor_class: Some("agent".to_owned()),
                org_ref: None,
                write_facet: None,
                ..Default::default()
            },
        )
        .expect("pairing link");
    let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
        .expect("pairing transcript");
    let signature: String = hex(&holder.sign(&transcript).to_bytes());
    let request = Request::post("/v1/core/pairing/redeem")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": link.code,
                "holder_ref": principal.to_hex(),
                "binding_key": hex(&binding_key),
                "signature": signature,
            })
            .to_string(),
        ))
        .expect("pairing redeem request");
    let response = served
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("pairing redeem response");
    assert_eq!(response.status(), StatusCode::OK, "pairing redeem status");
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("pairing redeem body");
    let body: Value = serde_json::from_slice(&bytes).expect("pairing redeem JSON");
    let token = body["token"].as_str().expect("paired token").to_owned();
    let slip = CapabilitySlip::from_token(&token).expect("paired slip");
    Agent {
        principal,
        holder,
        slip,
        token,
    }
}

fn owner_binding(served: &Served) -> String {
    let timestamp = served.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = hex(&served
        .issuer
        .binding_proof(&served.owner_slip, challenge.as_bytes())
        .expect("owner holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

fn agent_binding(served: &Served, agent: &Agent) -> String {
    let timestamp = served.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let transcript = agent
        .slip
        .binding_transcript(challenge.as_bytes())
        .expect("agent binding transcript");
    let signature: String = hex(&agent.holder.sign(&transcript).to_bytes());
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

async fn post(
    served: &Served,
    verb: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::post(format!("/v1/core/facade/{verb}"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = served
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("facade response body");
    let body: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, body)
}

/// `verb` as the owner, on its own proof.
async fn as_owner(served: &Served, verb: &str, body: Value) -> (StatusCode, Value) {
    let binding = owner_binding(served);
    post(served, verb, &served.owner_token, binding, body).await
}

/// `verb` as `agent`, on its own credential.
async fn as_agent(served: &Served, agent: &Agent, verb: &str, body: Value) -> (StatusCode, Value) {
    let binding = agent_binding(served, agent);
    post(served, verb, &agent.token, binding, body).await
}

/// T10: approving is the owner's own act. An agent whose Grant names every
/// workload verb pins a workload under that Grant, and its approve and
/// revoke are refused; the workload stays pinned, with no approval, and the
/// gate refuses it as not approved without asking any machine.
#[test]
fn an_agent_cannot_approve_a_workload() {
    run_on_engine_stack("job-workloads-agent-approve", || async {
        let served = serve();
        let agent = pair_agent(&served, "workload-agent", [0x71; 32]).await;
        let (status, minted) = as_owner(
            &served,
            "vault.agents.grants.mint",
            json!({
                "agent": agent.principal.to_hex(),
                "authority_scope": {
                    "worlds": {"kind": "all"},
                    "facets": {"kind": "all"},
                    "bands": {"kind": "all"},
                    "audience": {"kind": "all"},
                    "verbs": {"kind": "some", "values": [
                        "read",
                        "vault.jobs.workloads.pin",
                        "vault.jobs.workloads.approve",
                        "vault.jobs.workloads.revoke",
                        "vault.jobs.workloads.get",
                    ]},
                    "sensitivity": {"kind": "at_most", "value": "restricted"},
                },
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner mints the agent's Grant: {minted}"
        );
        let grant = minted["grant"]["grant_ref"]
            .as_str()
            .expect("the Grant's id")
            .to_owned();

        let (status, pinned) = as_agent(
            &served,
            &agent,
            "vault.jobs.workloads.pin",
            pin_json("agent-pin"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the agent pins: {pinned}");
        assert_eq!(pinned["workload"]["standing"], "pinned", "{pinned}");
        assert_eq!(
            pinned["workload"]["pinned_under"],
            json!(grant),
            "the pin records the Grant it was made under: {pinned}"
        );
        let digest = pinned["workload"]["digest"]
            .as_str()
            .expect("the workload digest")
            .to_owned();

        let (status, refused) = as_agent(
            &served,
            &agent,
            "vault.jobs.workloads.approve",
            json!({
                "workload": digest,
                "machines": [EntityId::now().to_hex()],
                "starters": [],
                "expires_at_ms": FAR_EXPIRY_MS,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an agent's approve is refused: {refused}"
        );
        let (status, refused) = as_agent(
            &served,
            &agent,
            "vault.jobs.workloads.revoke",
            json!({"workload": digest}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an agent's revoke is refused: {refused}"
        );

        let (status, read) = as_owner(
            &served,
            "vault.jobs.workloads.get",
            json!({"workload": digest}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the owner reads it: {read}");
        assert_eq!(read["standing"], "pinned", "still not approved: {read}");
        assert_eq!(
            read["approval"],
            Value::Null,
            "no approval was written: {read}"
        );
        let grant = EntityId::from_hex(&grant).expect("a Grant id in hex");
        let (verdict, asked) = gate(
            &served.vault,
            &digest,
            EntityId::now(),
            WorkloadStarter::Grant(grant),
            now_ms(),
        );
        assert_eq!(verdict, Err(WorkloadStartRefusal::WorkloadNotApproved));
        assert!(!asked, "an unapproved workload asks no machine");
    });
}
