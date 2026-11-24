//! Pinned workloads (pass 33 row R2; tests T10, T10b, T11, T12, T12b of
//! section 11): by default the owner approves each exact workload (EN-1 A)
//! and an agent cannot; the owner's Setting `jobs.workloads.agent_may_approve`
//! lets an agent approve under its own Grant, never its own pin; and the
//! check the start gate calls before the reservation refuses a revoked or
//! expired approval, an agent's approval once the key is off, a starter the
//! approval does not name, and a machine it does not list. T9 (the gate
//! itself refuses before the reservation) is carried by the gate's own PR
//! (OPUS-LE-FLEET, LM-8 = A).
//!
//! T10 runs over the served doors. T10b, T11, T12 and T12b run on the
//! owner's machines from the mesh harness, whose first machine's vault grants
//! the second the job protocol, so an approval can name it.
//!
//! Run on the fleet, never on a workstation:
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test job_workloads
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
    ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal,
    pairing_binding_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::job_workload::{
    JOB_ALPN, TEMPLATE_CHANGED, WorkloadAgent, WorkloadApproveRequest, WorkloadCaller,
    WorkloadChange, WorkloadError, WorkloadNodeAnswer, WorkloadPin, WorkloadPinRequest,
    WorkloadRef, WorkloadStanding, WorkloadStartAsk, WorkloadStartRefusal, WorkloadStarter,
};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::steward;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
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
/// The tests' clock: one fixed instant (2027-01-15), so no test reads the
/// wall clock. The doors and the gate take the time they judge an expiry
/// at, and every expiry here is set from this one.
const NOW_MS: u64 = 1_800_000_000_000;
/// The owner's Setting that lets an agent approve and revoke.
const AGENT_MAY_APPROVE: &str = "jobs.workloads.agent_may_approve";
const PIN: &str = "vault.jobs.workloads.pin";
const APPROVE: &str = "vault.jobs.workloads.approve";
const REVOKE: &str = "vault.jobs.workloads.revoke";
const GET: &str = "vault.jobs.workloads.get";

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
            "scope": "host",
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
        self.pin_as(WorkloadCaller::Owner(&self.owner), tag)
    }

    /// `caller` pins `tag`; answers its digest.
    fn pin_as(&self, caller: WorkloadCaller<'_>, tag: &str) -> String {
        let pinned = self
            .vault()
            .pin_job_workload(caller, &pin_request(tag), NOW_MS)
            .expect("the caller pins");
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
    ) -> Result<WorkloadChange, WorkloadError> {
        self.approve_as(
            WorkloadCaller::Owner(&self.owner),
            digest,
            machines,
            starters,
            expires_at_ms,
        )
    }

    /// `caller` approves `digest` on `machines` for `starters`.
    fn approve_as(
        &self,
        caller: WorkloadCaller<'_>,
        digest: &str,
        machines: &[EntityId],
        starters: &[EntityId],
        expires_at_ms: u64,
    ) -> Result<WorkloadChange, WorkloadError> {
        self.vault().approve_job_workload(
            caller,
            &WorkloadApproveRequest {
                workload: digest.to_owned(),
                machines: machines.iter().map(EntityId::to_hex).collect(),
                starters: starters.iter().map(EntityId::to_hex).collect(),
                expires_at_ms,
            },
            NOW_MS,
        )
    }

    /// An enabled agent the owner defines and gives one Grant naming
    /// `verbs`; answers the agent's caller and its Grant.
    fn agent(&self, agent_id: &str, verbs: &[&str]) -> (WorkloadAgent, EntityId) {
        let agent = EntityId::now();
        create_agent_definition_as(
            self.vault(),
            &self.owner,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": agent_id,
                    "desc": "Pins and approves workloads",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("an agent definition"),
            },
        )
        .expect("the owner defines the agent");
        let grant = self.grant_for(agent, verbs);
        let caller = self
            .vault()
            .memory(agent, EdgeActorClass::Agent)
            .workload_agent();
        (caller, grant)
    }

    /// The owner gives the agent `agent` one more Grant, naming `verbs`;
    /// answers the Grant.
    fn grant_for(&self, agent: EntityId, verbs: &[&str]) -> EntityId {
        let mut authority_scope = Scope::top();
        authority_scope.verbs =
            ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
        let minted = mint_agent_grant_as(
            self.vault(),
            &self.owner,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
                check_in_ref: None,
            },
        )
        .expect("the owner mints the agent's Grant");
        minted.grant.grant_ref
    }

    /// `caller`'s read of `digest`.
    fn get_as(&self, caller: WorkloadCaller<'_>, digest: &str) -> Result<(), WorkloadError> {
        self.vault()
            .get_job_workload(
                caller,
                &WorkloadRef {
                    workload: digest.to_owned(),
                },
                NOW_MS,
            )
            .map(drop)
    }

    /// The owner sets `jobs.workloads.agent_may_approve` to `on` at the
    /// vault scope.
    fn let_agents_approve(&self, on: bool) {
        let outcome = self
            .vault()
            .set_setting(
                SettingCaller::Owner(&self.owner),
                SetSetting::vault_value(AGENT_MAY_APPROVE, json!(on)),
            )
            .expect("the owner sets the key");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "FIXTURE: the owner's change of {AGENT_MAY_APPROVE} did not apply: {outcome:?}"
        );
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
        let now = NOW_MS;
        let (verdict, asked) = gate(rack.vault(), &digest, rack.machine, owner, now);
        assert!(verdict.is_ok(), "the approved workload starts: {verdict:?}");
        assert!(asked, "the machine is asked once the vault half passes");

        let revoked = rack
            .vault()
            .revoke_job_workload(
                WorkloadCaller::Owner(&rack.owner),
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
                WorkloadCaller::Owner(&rack.owner),
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
        let now = NOW_MS;
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
        let now = NOW_MS;
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

/// T10: by default (`jobs.workloads.agent_may_approve` off, EN-1 A)
/// approving is the owner's own act. An agent whose Grant names every
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
            NOW_MS,
        );
        assert_eq!(verdict, Err(WorkloadStartRefusal::WorkloadNotApproved));
        assert!(!asked, "an unapproved workload asks no machine");
    });
}

/// T10b: who approves is the owner's Setting `jobs.workloads.agent_may_approve`.
/// Off, an agent whose Grant names the approve verb is refused. On, it
/// approves a workload another agent's Grant pinned, and the gate admits the
/// pinner's start; it is refused on a workload pinned under its own Grant and
/// on an approval naming its own Grant as a starter. Turned off again, the
/// gate no longer admits that approval and asks no machine; on again, it
/// does, and the agent's revoke ends it.
#[test]
fn an_agent_approves_a_workload_only_while_the_owner_lets_agents_approve() {
    run_on_engine_stack("job-workloads-agent-may-approve", || async {
        let rack = Rack::start().await;
        let (approver, approver_grant) = rack.agent("workload-approver", &[PIN, APPROVE, REVOKE]);
        let (pinner, pinner_grant) = rack.agent("workload-pinner", &[PIN]);
        let digest = rack.pin_as(WorkloadCaller::Agent(&pinner), "pinned-by-agent");
        let own = rack.pin_as(WorkloadCaller::Agent(&approver), "pinned-by-approver");
        let machines = [rack.machine];
        let by_approver = WorkloadCaller::Agent(&approver);

        assert!(
            matches!(
                rack.approve_as(by_approver, &digest, &machines, &[], FAR_EXPIRY_MS),
                Err(WorkloadError::Caller(_))
            ),
            "with the key off, an agent's approve is refused"
        );

        rack.let_agents_approve(true);
        assert!(
            matches!(
                rack.approve_as(by_approver, &own, &machines, &[], FAR_EXPIRY_MS),
                Err(WorkloadError::SelfApproval)
            ),
            "an agent does not approve a workload pinned under its own Grant"
        );
        assert!(
            matches!(
                rack.approve_as(
                    by_approver,
                    &digest,
                    &machines,
                    &[approver_grant],
                    FAR_EXPIRY_MS
                ),
                Err(WorkloadError::SelfApproval)
            ),
            "an agent's approval does not name its own Grant as a starter"
        );
        let approved = rack
            .approve_as(by_approver, &digest, &machines, &[], FAR_EXPIRY_MS)
            .expect("with the key on, the agent approves another Grant's pin");
        assert!(approved.changed, "the agent's approval is written");
        assert_eq!(approved.workload.standing, WorkloadStanding::Approved);
        let approval = approved.workload.approval.expect("the approval's view");
        assert_eq!(approval.owner, None, "no owner gave it");
        assert_eq!(approval.agent, Some(approver.actor().to_hex()));
        assert_eq!(approval.under, Some(approver_grant.to_hex()));

        let pinner_starts = WorkloadStarter::Grant(pinner_grant);
        let (verdict, asked) = gate(rack.vault(), &digest, rack.machine, pinner_starts, NOW_MS);
        assert!(
            verdict.is_ok(),
            "the agent's approval admits the pinner: {verdict:?}"
        );
        assert!(asked, "the machine is asked once the vault half passes");

        rack.let_agents_approve(false);
        let (verdict, asked) = gate(rack.vault(), &digest, rack.machine, pinner_starts, NOW_MS);
        assert_eq!(verdict, Err(WorkloadStartRefusal::WorkloadNotApproved));
        assert!(!asked, "an approval not in force asks no machine");

        rack.let_agents_approve(true);
        let (verdict, _) = gate(rack.vault(), &digest, rack.machine, pinner_starts, NOW_MS);
        assert!(
            verdict.is_ok(),
            "with the key on again it admits: {verdict:?}"
        );
        let revoked = rack
            .vault()
            .revoke_job_workload(
                by_approver,
                &WorkloadRef {
                    workload: digest.clone(),
                },
                NOW_MS,
            )
            .expect("with the key on, the agent revokes");
        assert!(revoked.changed, "the agent's revoke is written");
        let (verdict, asked) = gate(rack.vault(), &digest, rack.machine, pinner_starts, NOW_MS);
        assert_eq!(verdict, Err(WorkloadStartRefusal::WorkloadRevoked));
        assert!(!asked, "a revoked workload asks no machine");
        rack.mesh.stop().await;
    });
}

/// Review-1 P1-1: an agent never approves its own work, whichever of its
/// Grants it acts under. One agent holds a Grant naming the pin verb and
/// another naming approve: it cannot approve the workload it pinned, nor an
/// owner's pin for a starter Grant it holds; it approves one for another
/// agent's Grant.
#[test]
fn an_agent_with_two_grants_does_not_approve_its_own_work() {
    run_on_engine_stack("job-workloads-two-grants", || async {
        let rack = Rack::start().await;
        let (agent, pin_grant) = rack.agent("workload-two-grants", &[PIN]);
        let approve_grant = rack.grant_for(agent.actor(), &[APPROVE]);
        assert_ne!(pin_grant, approve_grant, "FIXTURE: two Grants");
        let (_, other_grant) = rack.agent("workload-other-starter", &[PIN]);
        rack.let_agents_approve(true);
        let by_agent = WorkloadCaller::Agent(&agent);
        let machines = [rack.machine];

        let own = rack.pin_as(by_agent, "pinned-under-the-first-grant");
        assert!(
            matches!(
                rack.approve_as(by_agent, &own, &machines, &[], FAR_EXPIRY_MS),
                Err(WorkloadError::SelfApproval)
            ),
            "an agent does not approve a workload it pinned under its other Grant"
        );
        let owners = rack.pin("pinned-by-the-owner");
        assert!(
            matches!(
                rack.approve_as(by_agent, &owners, &machines, &[pin_grant], FAR_EXPIRY_MS),
                Err(WorkloadError::SelfApproval)
            ),
            "an agent does not name a Grant it holds as a starter"
        );
        let approved = rack
            .approve_as(by_agent, &owners, &machines, &[other_grant], FAR_EXPIRY_MS)
            .expect("the agent approves the owner's pin for another agent's Grant");
        assert!(approved.changed, "the agent's approval is written");
        rack.mesh.stop().await;
    });
}

/// Review-1 P1-2, P1-3 and P1-4: an approval that no longer stands shows
/// nothing and blocks nothing. A starter reads the workload only while an
/// approval in force names its Grant; an agent with the revoke verb but no
/// read of the workload revokes nothing; and once an agent's approval is not
/// in force, the owner's approval on the same terms is written as the
/// owner's.
#[test]
fn an_approval_that_no_longer_stands_shows_and_blocks_nothing() {
    run_on_engine_stack("job-workloads-lapsed-approval", || async {
        let rack = Rack::start().await;
        let (approver, _) = rack.agent("workload-lapsing-approver", &[APPROVE, REVOKE, GET]);
        let (starter, starter_grant) = rack.agent("workload-lapsing-starter", &[GET]);
        let (outsider, _) = rack.agent("workload-outsider", &[REVOKE, GET]);
        let machines = [rack.machine];
        let starters = [starter_grant];
        let digest = rack.pin("lapsing");
        rack.let_agents_approve(true);
        rack.approve_as(
            WorkloadCaller::Agent(&approver),
            &digest,
            &machines,
            &starters,
            FAR_EXPIRY_MS,
        )
        .expect("the agent approves the owner's pin for the starter");
        rack.get_as(WorkloadCaller::Agent(&starter), &digest)
            .expect("the starter reads a workload it may start");
        rack.get_as(WorkloadCaller::Agent(&approver), &digest)
            .expect("the approver reads the approval it gave");
        let outsider_revoke = rack.vault().revoke_job_workload(
            WorkloadCaller::Agent(&outsider),
            &WorkloadRef {
                workload: digest.clone(),
            },
            NOW_MS,
        );
        assert!(
            matches!(outsider_revoke, Err(WorkloadError::NotFound)),
            "an agent revokes nothing it may not read: {outsider_revoke:?}"
        );
        assert!(
            rack.vault()
                .job_workload(&digest)
                .expect("the row reads")
                .is_some_and(|row| row.revoked.is_none()),
            "the outsider's revoke wrote nothing"
        );

        rack.let_agents_approve(false);
        assert!(
            matches!(
                rack.get_as(WorkloadCaller::Agent(&starter), &digest),
                Err(WorkloadError::NotFound)
            ),
            "a starter whose approval is no longer in force reads nothing of it"
        );
        let listed = rack
            .vault()
            .list_job_workloads(WorkloadCaller::Agent(&starter), NOW_MS)
            .expect("the starter lists");
        assert!(
            listed.workloads.iter().all(|view| view.digest != digest),
            "nor does its list show it"
        );
        let by_owner = rack
            .approve(&digest, &machines, &starters, FAR_EXPIRY_MS)
            .expect("an approval not in force does not block the owner's");
        assert!(by_owner.changed, "the owner's approval is written");
        let approval = by_owner.workload.approval.expect("the approval's view");
        assert_eq!(approval.owner, Some(rack.owner_id.to_hex()));
        assert_eq!(approval.agent, None, "the agent's approval is replaced");
        rack.get_as(WorkloadCaller::Agent(&starter), &digest)
            .expect("the owner's approval lets the starter read it again");

        let revoked = rack
            .vault()
            .revoke_job_workload(
                WorkloadCaller::Owner(&rack.owner),
                &WorkloadRef {
                    workload: digest.clone(),
                },
                NOW_MS,
            )
            .expect("the owner revokes");
        assert!(revoked.changed, "the revoke is written");
        assert!(
            matches!(
                rack.get_as(WorkloadCaller::Agent(&starter), &digest),
                Err(WorkloadError::NotFound)
            ),
            "a starter reads nothing of a revoked workload"
        );
        rack.mesh.stop().await;
    });
}

/// Review-1 P1-6: the pin is its own key, so no handle can stand in for a
/// secret in it. A pin whose arguments hold a provider token is refused by
/// the vault's secret scan and nothing is stored.
#[test]
fn a_pin_that_holds_a_secret_is_refused() {
    run_on_engine_stack("job-workloads-pin-secret", || async {
        let rack = Rack::start().await;
        let mut request = pin_request("holds-a-token");
        request
            .pin
            .args
            .push("token=ghp_0123456789abcdefghijklmnopqrstuvwxyz".to_owned());
        let digest = request.pin.digest().expect("the pin's digest");
        let refused =
            rack.vault()
                .pin_job_workload(WorkloadCaller::Owner(&rack.owner), &request, NOW_MS);
        assert!(
            matches!(
                refused,
                Err(WorkloadError::Vault(oneiron::Error::Gate(
                    oneiron::error::GateError::GateWriteRejected { .. }
                )))
            ),
            "the secret scan refuses the pin: {refused:?}"
        );
        assert!(
            rack.vault()
                .job_workload(&digest)
                .expect("the row reads")
                .is_none(),
            "nothing is stored"
        );
        rack.pin("holds-no-token");
        rack.mesh.stop().await;
    });
}
