//! The one booker principal of `oneiron jobs` (FIX [ONEIRON-BOOKER-CLI];
//! docs/ops/jobs-booker.md): the runbook's owner acts, each as the owner makes it, give the
//! booker agent all it needs and nothing it does not. Its Grant lists `read` and the booker's
//! verbs; the owner sets a per-job maximum beside that Grant, mints a PROJECT
//! (`vault.projects.mint`) and a `compute.pin` grant for it. Then the agent's pin goes at rung 0
//! with no screen asked, the start gate passes on the granted machine, and the order door takes
//! its order. Each missing piece names itself: a Grant without `vault.gpu.jobs.start` gets no
//! allowance, a pin with no `compute.pin` grant waits on its check-in, and a Grant without
//! `vault.jobs.order` orders nothing.
//!
//! The tests run on the owner's machines from the mesh harness, whose first machine's vault
//! grants the second the job protocol. Every clock here is one fixed instant.
//!
//! Run on the fleet, never on a workstation:
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test jobs_booker_principal
#![cfg(all(oneiron_test_support, feature = "mesh"))]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::collections::BTreeSet;

use engine_stack::run_on_engine_stack;
use mesh_machines::Machines;
use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::consent::lifecycle::{
    ActionBoundRequest, ActionEnvelopeRequest, ComputeEnvelopeRequest, ComputeNetwork,
    ComputeScope, CreateStandingGrantRequest, StandingGrantBound, create_standing_grant,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::gpu_job::GpuJobError;
use oneiron::job_workload::{
    COMPUTE_PIN_CLASS, JOB_ALPN, PinCheckInOutcome, PinGoBasis, PinSignals, ScreenAnswer,
    ScreenVerdict, WorkloadChange, WorkloadError, WorkloadNodeAnswer, WorkloadPinRequest,
    WorkloadScreen, WorkloadStanding, WorkloadStartAsk, WorkloadStarter,
};
use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::test_doors::steward;
use oneiron::test_support::test_host_issuer;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::work_order::{OrderState, OrderedBy, WorkOrderRequest, order_work_as};
use oneiron::workspace_roster::OwnerProjectMintRequest;
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

const TEMPLATE: &str = "oneiron-check";
const TEMPLATE_DIGEST: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const CONTRACT_SHA256: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
/// The booker's per-job maximum in the runbook: the check template's 3 h (docs/ops/jobs-booker.md).
const MAXIMUM_SECS: u64 = 10_800;
/// The tests' clock: one fixed instant (2027-01-15).
const NOW_MS: u64 = 1_800_000_000_000;

/// The runbook's Grant line: `read`, every verb `oneiron jobs` calls, and the verb its
/// allowance needs (the unit test `the_grant_lists_exactly_the_verbs_the_code_calls` holds the
/// command to the same list).
const BOOKER_GRANT: [&str; 8] = [
    "read",
    "vault.machines.execution.get",
    "vault.jobs.workloads.pin",
    "vault.jobs.order",
    "vault.jobs.orders.wait",
    "vault.jobs.orders.cancel",
    "vault.jobs.logs.tail",
    "vault.gpu.jobs.start",
];

/// A screen that is never sure: a pin outside every grant waits.
struct UnsureScreen;

impl WorkloadScreen for UnsureScreen {
    fn screen(&self, _signals: &PinSignals) -> ScreenAnswer {
        ScreenAnswer::Verdict(ScreenVerdict {
            sure: false,
            probability_permille: Some(480),
            rung: Some("head".to_owned()),
            receipt: None,
        })
    }
}

/// The issuer's vault (the first machine's), its owner and the second machine, which holds
/// the job protocol's grant.
struct Rack {
    mesh: Machines,
    owner: AuthenticatedOwner,
    machine: EntityId,
}

/// The booker agent: its actor and its one Grant.
#[derive(Clone, Copy)]
struct Booker {
    actor: EntityId,
    grant: EntityId,
}

impl Rack {
    async fn start() -> Self {
        let mesh = Machines::start_granted(2, &[JOB_ALPN])
            .await
            .expect("two machines, each granted the job protocol by the other");
        let vault = std::sync::Arc::clone(&mesh.machine(0).device.vault);
        let owner = steward::owner(&vault).expect("the issuer's owner proof");
        let machine = mesh.machine(1).device.machine;
        Self {
            mesh,
            owner,
            machine,
        }
    }

    fn vault(&self) -> &Vault {
        &self.mesh.machine(0).device.vault
    }

    /// Runbook act 2: the owner gives the booker agent `agent_id` one Grant naming `verbs`.
    fn booker(&self, agent_id: &str, verbs: &[&str]) -> Booker {
        let actor = EntityId::now();
        create_agent_definition_as(
            self.vault(),
            &self.owner,
            AgentDefinitionCreateRequest {
                agent_def_ref: actor,
                definition: serde_json::from_value(json!({
                    "agent_id": agent_id,
                    "desc": "Books the fleet's jobs on the vault's own machines",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("an agent definition"),
            },
        )
        .expect("the owner defines the agent");
        let mut authority_scope = Scope::top();
        authority_scope.worlds = ScopeAxis::All;
        authority_scope.verbs =
            ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
        let minted = mint_agent_grant_as(
            self.vault(),
            &self.owner,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent: actor,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
                check_in_ref: None,
            },
        )
        .expect("the owner mints the booker's Grant");
        assert!(minted.grant.confers, "the booker's Grant confers");
        Booker {
            actor,
            grant: minted.grant.grant_ref,
        }
    }

    /// Runbook act 3: the per-job maximum beside the booker's Grant.
    fn allow(&self, booker: Booker) -> Result<(), GpuJobError> {
        self.vault()
            .allow_gpu_jobs(&self.owner, &booker.grant, MAXIMUM_SECS, NOW_MS)
            .map(|allowance| assert!(allowance.is_some(), "the maximum stands"))
    }

    /// Runbook act 4: the booker's PROJECT, minted under the root.
    fn project(&self) -> EntityId {
        let issuer = test_host_issuer();
        let signer = self
            .vault()
            .owner_project_signer(&issuer)
            .expect("the owner's project signer");
        self.vault()
            .mint_owner_project(
                &self.owner,
                &signer,
                &OwnerProjectMintRequest {
                    name: "fleet-booker".to_owned(),
                    parent: None,
                    intent_key: "jobs-booker/project".to_owned(),
                },
            )
            .expect("the owner mints the booker's project")
            .project
            .project
    }

    /// Runbook act 5: the `compute.pin` grant over the template, network none, the host scope
    /// and the rack's machine, for `project`.
    fn compute_grant(&self, booker: Booker, project: EntityId) {
        create_standing_grant(
            self.vault(),
            &self.owner,
            CreateStandingGrantRequest {
                bound: StandingGrantBound::Action(ActionBoundRequest {
                    actor: booker.grant.to_hex(),
                    class: COMPUTE_PIN_CLASS.to_owned(),
                    envelope: ActionEnvelopeRequest {
                        project: project.to_hex(),
                        audience: Vec::new(),
                        budget: None,
                        compute: Some(ComputeEnvelopeRequest {
                            templates: vec![TEMPLATE.to_owned()],
                            network: vec![ComputeNetwork::None],
                            scopes: vec![ComputeScope::Host],
                            machines: vec![self.machine.to_hex()],
                        }),
                    },
                }),
                check_in_ref: None,
            },
        )
        .expect("the owner mints the booker's compute grant");
    }

    /// The pin `oneiron jobs run` sends for a check of `COMMIT` on the template.
    fn pin(&self, booker: Booker, project: EntityId) -> Result<WorkloadChange, WorkloadError> {
        let request: WorkloadPinRequest = serde_json::from_value(json!({
            "pin": {
                "template": TEMPLATE,
                "template_digest": TEMPLATE_DIGEST,
                "commit": COMMIT,
                "contract_sha256": CONTRACT_SHA256,
                "contract_path": "scripts/check/oneiron_check.sh",
                "entry": "scripts/check/oneiron_check.sh",
                "args": ["--crate", "oneiron"],
                "request": {
                    "cpu_threads": 6,
                    "memory_mib": 28_672,
                    "disk_mib": 61_440,
                    "devices": [],
                    "maximum_secs": MAXIMUM_SECS,
                },
                "scope": "host",
                "network": "none",
                "outputs": [],
            },
            "project": project.to_hex(),
        }))
        .expect("a pin request");
        self.vault()
            .memory(booker.actor, EdgeActorClass::Agent)
            .pin_job_workload(&request, &UnsureScreen, NOW_MS)
    }

    /// The order `oneiron jobs run --host <machine> --key <key>` sends for `workload`.
    fn order(
        &self,
        booker: Booker,
        workload: &str,
    ) -> oneiron::memory::MemoryResult<oneiron::work_order::WorkOrderView> {
        let request: WorkOrderRequest = serde_json::from_value(json!({
            "workload": workload,
            "charge": { "kind": "offer", "name": "nelly-cpu" },
            "limits": { "machines": [self.machine.to_hex()] },
            "intent_key": "lane/check/1",
        }))
        .expect("an order request");
        order_work_as(
            &self.vault().memory(booker.actor, EdgeActorClass::Agent),
            None,
            &request,
            NOW_MS,
        )
    }
}

/// P1: with the runbook's four owner acts, the booker's pin goes at rung 0 with no screen,
/// the start gate passes for its Grant on the granted machine, and the order door takes its
/// order under that Grant.
#[test]
fn the_runbook_principal_pins_inside_its_grant_and_orders() {
    run_on_engine_stack("jobs-booker-principal", || async {
        let rack = Rack::start().await;
        let booker = rack.booker("oneiron-booker", &BOOKER_GRANT);
        rack.allow(booker)
            .expect("the owner sets the booker's per-job maximum");
        let project = rack.project();
        rack.compute_grant(booker, project);

        let pinned = rack.pin(booker, project).expect("the booker's pin goes");
        assert_eq!(pinned.workload.standing, WorkloadStanding::Cleared);
        let row = rack
            .vault()
            .job_workload(&pinned.workload.digest)
            .expect("the row reads")
            .expect("the row stands");
        assert!(
            matches!(
                row.check_in.map(|check_in| check_in.outcome),
                Some(PinCheckInOutcome::Went {
                    basis: PinGoBasis::StandingRow,
                    ..
                })
            ),
            "it went on the compute grant"
        );
        let started = rack.vault().check_workload_start(
            &WorkloadStartAsk {
                workload: &pinned.workload.digest,
                machine: rack.machine,
                maximum_secs: MAXIMUM_SECS,
                starter: WorkloadStarter::Grant(booker.grant),
            },
            &mut |pin| WorkloadNodeAnswer::Answered {
                template_digest: Some(pin.template_digest.clone()),
                refusal: None,
            },
            NOW_MS,
        );
        assert!(
            matches!(started, Ok(Ok(_))),
            "the start gate passes for the booker's Grant: {started:?}"
        );

        let view = rack
            .order(booker, &pinned.workload.digest)
            .expect("the order door takes it");
        assert!(
            matches!(view.order.state, OrderState::Open { .. }),
            "{:?}",
            view.order.state
        );
        assert_eq!(
            view.order.ordered_by,
            OrderedBy::Agent {
                actor: Some(booker.actor),
                class: EdgeActorClass::Agent,
                grant: booker.grant,
            }
        );
        assert_eq!(view.order.intent_key.as_deref(), Some("lane/check/1"));
        assert_eq!(view.order.limits.machines, vec![rack.machine]);
        rack.mesh.stop().await;
    });
}

/// P2: each missing piece names itself. A Grant without `vault.gpu.jobs.start` carries no
/// per-job maximum; with no `compute.pin` grant the pin waits on its check-in; a Grant without
/// `vault.jobs.order` orders nothing.
#[test]
fn each_missing_piece_names_itself() {
    run_on_engine_stack("jobs-booker-principal-missing", || async {
        let rack = Rack::start().await;
        let project = rack.project();

        let no_start: Vec<&str> = BOOKER_GRANT
            .iter()
            .copied()
            .filter(|verb| *verb != "vault.gpu.jobs.start")
            .collect();
        let refused = rack.allow(rack.booker("booker-no-start", &no_start));
        assert!(
            matches!(&refused, Err(GpuJobError::Caller(_)))
                && format!("{refused:?}").contains("vault.gpu.jobs.start"),
            "the allowance names the start verb its Grant lacks: {refused:?}"
        );

        let uncovered = rack.booker("booker-uncovered", &BOOKER_GRANT);
        let waits = rack.pin(uncovered, project);
        assert!(
            matches!(
                &waits,
                Err(WorkloadError::Vault(oneiron::Error::CheckInPending(_)))
            ),
            "with no compute grant the pin waits on its check-in: {waits:?}"
        );

        let no_order: Vec<&str> = BOOKER_GRANT
            .iter()
            .copied()
            .filter(|verb| *verb != "vault.jobs.order")
            .collect();
        let booker = rack.booker("booker-no-order", &no_order);
        rack.compute_grant(booker, project);
        let pinned = rack.pin(booker, project).expect("its pin goes");
        let refused = rack.order(booker, &pinned.workload.digest);
        assert!(
            matches!(&refused, Err(error) if error.code == MEMORY_CODE_FORBIDDEN),
            "a Grant without the order verb orders nothing: {refused:?}"
        );
        rack.mesh.stop().await;
    });
}
