//! The check-in of an agent's pin (pass 34, `34-compute-general/DESIGN.md`
//! section 6.5; NOTE PASS-34-R2-SHAPE; R2's follow-up with R7): a pin inside
//! the family's `compute.pin` standing grant goes at rung 0 and nobody is
//! asked; `manual` waits even inside a grant; `full-access` goes with a
//! record; outside a grant in `auto` a reversible pin goes only on a sure
//! screen, a network pin always asks, and with no model the deterministic
//! fallback decides; a revoked or narrowed grant stops the next start; and
//! an agent never answers its own pin.
//!
//! The tests run on the owner's machines from the mesh harness, whose first
//! machine's vault grants the second the job protocol. Every clock here is
//! one fixed instant.
//!
//! Run on the fleet, never on a workstation:
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test job_workload_check_in
#![cfg(all(oneiron_test_support, feature = "mesh"))]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::Arc;

use engine_stack::run_on_engine_stack;
use mesh_machines::Machines;
use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::consent::lifecycle::{
    ActionBoundRequest, ActionEnvelopeRequest, ComputeEnvelopeRequest, ComputeNetwork,
    ComputeScope, CreateStandingGrantRequest, RevokeGrantRequest, StandingGrantBound,
    create_standing_grant, revoke,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::job_workload::{
    COMPUTE_PIN_CLASS, JOB_ALPN, JobWorkload, NoScreenModel, PinCheckInMode, PinCheckInOutcome,
    PinGoBasis, PinSignals, ScreenSource, ScreenVerdict, WorkloadChange, WorkloadError,
    WorkloadNodeAnswer, WorkloadPin, WorkloadPinRequest, WorkloadScreen, WorkloadStanding,
    WorkloadStartAsk, WorkloadStartRefusal, WorkloadStarter,
};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::test_doors::steward;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, CheckInAnswerRequest, CheckInAnswerWord,
    check_in_answer_as_person, create_agent_definition_as, mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

const TEMPLATE: &str = "open-models";
const TEMPLATE_DIGEST: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const CONTRACT_SHA256: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const MAXIMUM_SECS: u64 = 1_800;
/// The tests' clock: one fixed instant (2027-01-15).
const NOW_MS: u64 = 1_800_000_000_000;
const PIN: &str = "vault.jobs.workloads.pin";
const MODE_KEY: &str = "jobs.workloads.check_in_mode";

/// One exact workload: `tag` makes its arguments, `memory_mib` its size and
/// `network` its network mode.
fn pin_request(tag: &str, memory_mib: u64, network: &str, project: EntityId) -> WorkloadPinRequest {
    serde_json::from_value(json!({
        "pin": {
            "template": TEMPLATE,
            "template_digest": TEMPLATE_DIGEST,
            "commit": COMMIT,
            "contract_sha256": CONTRACT_SHA256,
            "contract_path": "arms/inkling/contract.json",
            "entry": "arms/inkling/run.py",
            "args": ["--arm", tag],
            "request": {
                "cpu_threads": 2,
                "memory_mib": memory_mib,
                "disk_mib": 2_048,
                "devices": [],
                "maximum_secs": MAXIMUM_SECS,
            },
            "scope": "host",
            "network": network,
            "outputs": [{"name": "verdict.json", "returnable": true}],
        },
        "project": project.to_hex(),
    }))
    .expect("a pin request")
}

/// A screen that answers `sure` and counts the times it is asked.
struct ScriptedScreen {
    sure: bool,
    asked: Cell<u32>,
}

impl ScriptedScreen {
    fn answering(sure: bool) -> Self {
        Self {
            sure,
            asked: Cell::new(0),
        }
    }
}

impl WorkloadScreen for ScriptedScreen {
    fn screen(&self, _signals: &PinSignals) -> oneiron::Result<ScreenVerdict> {
        self.asked.set(self.asked.get() + 1);
        Ok(ScreenVerdict {
            sure: self.sure,
            probability_permille: Some(if self.sure { 920 } else { 480 }),
            rung: Some("head".to_owned()),
            receipt: None,
        })
    }
}

/// The issuer's vault (the first machine's), its owner, the second machine
/// (granted the job protocol) and one project.
struct Rack {
    mesh: Machines,
    owner: AuthenticatedOwner,
    machine: EntityId,
    project: EntityId,
}

/// An agent of the rack: its actor and the Grant it pins under.
#[derive(Clone, Copy)]
struct Agent {
    actor: EntityId,
    grant: EntityId,
}

impl Rack {
    async fn start() -> Self {
        let mesh = Machines::start_granted(2, &[JOB_ALPN])
            .await
            .expect("two machines, each granted the job protocol by the other");
        let vault = Arc::clone(&mesh.machine(0).device.vault);
        let owner = steward::owner(&vault).expect("the issuer's owner proof");
        let machine = mesh.machine(1).device.machine;
        Self {
            mesh,
            owner,
            machine,
            project: EntityId::now(),
        }
    }

    fn vault(&self) -> &Vault {
        &self.mesh.machine(0).device.vault
    }

    /// An enabled agent the owner defines and gives one Grant naming the pin
    /// verb.
    fn agent(&self, agent_id: &str) -> Agent {
        let actor = EntityId::now();
        create_agent_definition_as(
            self.vault(),
            &self.owner,
            AgentDefinitionCreateRequest {
                agent_def_ref: actor,
                definition: serde_json::from_value(json!({
                    "agent_id": agent_id,
                    "desc": "Pins workloads",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("an agent definition"),
            },
        )
        .expect("the owner defines the agent");
        let mut authority_scope = Scope::top();
        authority_scope.verbs =
            ScopeAxis::Some([PIN].iter().map(|verb| (*verb).to_owned()).collect());
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
        .expect("the owner mints the agent's Grant");
        Agent {
            actor,
            grant: minted.grant.grant_ref,
        }
    }

    /// `agent` pins `request`, its screen `screen`.
    fn pin(
        &self,
        agent: Agent,
        request: &WorkloadPinRequest,
        screen: &dyn WorkloadScreen,
    ) -> Result<WorkloadChange, WorkloadError> {
        self.vault()
            .memory(agent.actor, EdgeActorClass::Agent)
            .pin_job_workload(request, screen, NOW_MS)
    }

    /// `agent` pins `request` and it waits: answers its pending check-in.
    fn pin_waits(
        &self,
        agent: Agent,
        request: &WorkloadPinRequest,
        screen: &dyn WorkloadScreen,
    ) -> String {
        match self.pin(agent, request, screen) {
            Err(WorkloadError::Vault(oneiron::Error::CheckInPending(check_in))) => check_in,
            other => panic!("the pin waits on its check-in: {other:?}"),
        }
    }

    /// The owner mints `agent`'s family a `compute.pin` grant over the
    /// template, network `none`, the host scope and `machines`, for the
    /// rack's project; answers its digest.
    fn mint_compute(&self, agent: Agent, machines: &[EntityId]) -> String {
        let receipt = create_standing_grant(
            self.vault(),
            &self.owner,
            CreateStandingGrantRequest {
                bound: StandingGrantBound::Action(ActionBoundRequest {
                    actor: agent.grant.to_hex(),
                    class: COMPUTE_PIN_CLASS.to_owned(),
                    envelope: ActionEnvelopeRequest {
                        project: self.project.to_hex(),
                        audience: Vec::new(),
                        budget: None,
                        compute: Some(ComputeEnvelopeRequest {
                            templates: vec![TEMPLATE.to_owned()],
                            network: vec![ComputeNetwork::None],
                            scopes: vec![ComputeScope::Host],
                            machines: machines.iter().map(EntityId::to_hex).collect(),
                        }),
                    },
                }),
                check_in_ref: None,
            },
        )
        .expect("the owner mints the family's compute grant");
        receipt.grant_ref.expect("the grant's digest")
    }

    /// The owner sets the vault's check-in mode for pins.
    fn set_mode(&self, mode: &str) {
        let outcome = self
            .vault()
            .set_setting(
                SettingCaller::Owner(&self.owner),
                SetSetting::vault_value(MODE_KEY, json!(mode)),
            )
            .expect("the owner sets the pins' check-in mode");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "the owner's change applies: {outcome:?}"
        );
    }

    /// The row pinned under `digest`.
    fn row(&self, digest: &str) -> JobWorkload {
        self.vault()
            .job_workload(digest)
            .expect("the row reads")
            .expect("the row stands")
    }

    /// The start gate's check of `digest` on `machine` for `agent`, with a
    /// machine that would take it.
    fn start_on(
        &self,
        digest: &str,
        machine: EntityId,
        agent: Agent,
    ) -> Result<WorkloadPin, WorkloadStartRefusal> {
        let ask = WorkloadStartAsk {
            workload: digest,
            machine,
            maximum_secs: MAXIMUM_SECS,
            starter: WorkloadStarter::Grant(agent.grant),
        };
        self.vault()
            .check_workload_start(
                &ask,
                &mut |pin| WorkloadNodeAnswer::Answered {
                    template_digest: Some(pin.template_digest.clone()),
                    refusal: None,
                },
                NOW_MS,
            )
            .expect("the workload check reads the store")
    }
}

fn digest_of(request: &WorkloadPinRequest) -> String {
    request.pin.digest().expect("the pin's digest")
}

fn went(row: &JobWorkload) -> Option<PinGoBasis> {
    match row.check_in.as_ref().map(|check_in| &check_in.outcome) {
        Some(PinCheckInOutcome::Went { basis, .. }) => Some(*basis),
        _ => None,
    }
}

/// Rung 0: a pin inside the family's `compute.pin` grant goes, nobody is
/// asked and no model runs; the start passes on a machine the grant names.
/// A pin that names no project is outside every grant.
#[test]
fn a_pin_inside_the_family_grant_goes_at_rung_zero_and_nobody_is_asked() {
    run_on_engine_stack("job-workload-check-in-rung-zero", || async {
        let rack = Rack::start().await;
        let agent = rack.agent("compute-covered");
        let grant = rack.mint_compute(agent, &[rack.machine]);
        let screen = ScriptedScreen::answering(false);
        let request = pin_request("covered", 4_096, "none", rack.project);
        let pinned = rack
            .pin(agent, &request, &screen)
            .expect("the covered pin goes");
        assert!(pinned.changed);
        assert_eq!(pinned.workload.standing, WorkloadStanding::Cleared);
        assert_eq!(screen.asked.get(), 0, "no model is asked at rung 0");
        let row = rack.row(&pinned.workload.digest);
        let record = row.check_in.clone().expect("the pin's check-in record");
        assert_eq!(went(&row), Some(PinGoBasis::StandingRow));
        assert_eq!(record.covering_grant, Some(grant), "it names the grant");
        assert_eq!(record.mode, Some(PinCheckInMode::Auto));
        assert_eq!(record.act, "reversible_work");
        assert!(record.screen.is_none(), "no screen ran");
        assert!(
            rack.start_on(&pinned.workload.digest, rack.machine, agent)
                .is_ok(),
            "the pinning Grant starts it on the granted machine"
        );

        let mut no_project = pin_request("no-project", 4_096, "none", rack.project);
        no_project.project = None;
        rack.pin_waits(agent, &no_project, &screen);
        assert_eq!(screen.asked.get(), 1, "outside every grant the screen runs");
        rack.mesh.stop().await;
    });
}

/// The start gate reads the grant again, live, with the machine added: a
/// grant narrowed to another machine, or revoked, stops the next start.
#[test]
fn a_revoked_or_narrowed_grant_stops_the_next_start() {
    run_on_engine_stack("job-workload-check-in-live-grant", || async {
        let rack = Rack::start().await;
        let agent = rack.agent("compute-revoked");
        let wide = rack.mint_compute(agent, &[rack.machine]);
        let request = pin_request("revoked", 4_096, "none", rack.project);
        let digest = rack
            .pin(agent, &request, &NoScreenModel)
            .expect("the covered pin goes")
            .workload
            .digest;
        assert!(rack.start_on(&digest, rack.machine, agent).is_ok());

        let narrow = rack.mint_compute(agent, &[EntityId::now()]);
        revoke(
            rack.vault(),
            &rack.owner,
            RevokeGrantRequest { grant: wide },
        )
        .expect("the owner revokes the wide grant");
        assert_eq!(
            rack.start_on(&digest, rack.machine, agent),
            Err(WorkloadStartRefusal::ComputeGrantEnded),
            "the narrowed grant does not name this machine"
        );
        revoke(
            rack.vault(),
            &rack.owner,
            RevokeGrantRequest { grant: narrow },
        )
        .expect("the owner revokes the narrow grant");
        assert_eq!(
            rack.start_on(&digest, rack.machine, agent),
            Err(WorkloadStartRefusal::ComputeGrantEnded),
            "with every grant revoked nothing starts"
        );
        rack.mesh.stop().await;
    });
}

/// `manual`: every pin waits, even one a grant covers ("ask me each time").
/// The owner's approval of its check-in lets the call that names it go.
#[test]
fn under_manual_every_agent_pin_waits_even_inside_a_grant() {
    run_on_engine_stack("job-workload-check-in-manual", || async {
        let rack = Rack::start().await;
        let agent = rack.agent("compute-manual");
        rack.mint_compute(agent, &[rack.machine]);
        rack.set_mode("manual");
        let screen = ScriptedScreen::answering(true);
        let mut request = pin_request("manual", 4_096, "none", rack.project);
        let check_in = rack.pin_waits(agent, &request, &screen);
        assert_eq!(screen.asked.get(), 0, "manual asks no model");
        let digest = digest_of(&request);
        let row = rack.row(&digest);
        assert!(
            matches!(
                row.check_in.as_ref().map(|record| &record.outcome),
                Some(PinCheckInOutcome::Waits { reason, .. }) if reason == "always_ask"
            ),
            "it waits for the ladder: {row:?}"
        );
        assert_eq!(
            rack.start_on(&digest, rack.machine, agent),
            Err(WorkloadStartRefusal::WorkloadWaiting)
        );

        check_in_answer_as_person(
            rack.vault(),
            &rack.owner,
            CheckInAnswerRequest {
                handle: check_in.clone(),
                answer: CheckInAnswerWord::Approve,
                effect_digest: digest.clone(),
            },
        )
        .expect("the owner approves the pin's check-in");
        request.check_in_ref = Some(check_in);
        let pinned = rack
            .pin(agent, &request, &screen)
            .expect("the call naming the approved check-in goes");
        assert_eq!(pinned.workload.standing, WorkloadStanding::Cleared);
        assert_eq!(went(&rack.row(&digest)), Some(PinGoBasis::Answered));
        assert!(rack.start_on(&digest, rack.machine, agent).is_ok());
        rack.mesh.stop().await;
    });
}

/// `full-access`: a pin no grant covers goes, inside the agent's Grant, with
/// its record, and no model runs.
#[test]
fn under_full_access_an_uncovered_pin_goes_with_a_record() {
    run_on_engine_stack("job-workload-check-in-full-access", || async {
        let rack = Rack::start().await;
        let agent = rack.agent("compute-full-access");
        rack.set_mode("full-access");
        let screen = ScriptedScreen::answering(false);
        let request = pin_request("full-access", 4_096, "host", rack.project);
        let pinned = rack
            .pin(agent, &request, &screen)
            .expect("full-access goes");
        assert_eq!(screen.asked.get(), 0);
        let row = rack.row(&pinned.workload.digest);
        let record = row.check_in.clone().expect("the record");
        assert_eq!(went(&row), Some(PinGoBasis::NeverAsk));
        assert_eq!(record.mode, Some(PinCheckInMode::FullAccess));
        assert_eq!(record.act, "outbound_send");
        assert!(record.covering_grant.is_none());
        rack.mesh.stop().await;
    });
}

/// `auto`, no grant, no network: the screen runs before the pin goes. An
/// unsure screen waits; a sure one goes. With no model, the deterministic
/// fallback lets a routine pin go: the same template and commit the family
/// ran, no larger.
#[test]
fn an_uncovered_reversible_pin_in_auto_with_an_unsure_screen_waits() {
    run_on_engine_stack("job-workload-check-in-screen", || async {
        let rack = Rack::start().await;
        let agent = rack.agent("compute-screened");
        let unsure = ScriptedScreen::answering(false);
        let request = pin_request("unsure", 8_192, "none", rack.project);
        rack.pin_waits(agent, &request, &unsure);
        assert_eq!(unsure.asked.get(), 1, "the screen ran once");
        let record = rack.row(&digest_of(&request)).check_in.expect("the record");
        let screened = record.screen.expect("the screen's verdict is kept");
        assert!(!screened.sure);
        assert_eq!(screened.by, ScreenSource::Model);
        assert_eq!(screened.probability_permille, Some(480));

        let sure = ScriptedScreen::answering(true);
        let request = pin_request("sure", 8_192, "none", rack.project);
        rack.pin(agent, &request, &sure)
            .expect("a sure screen lets it go");
        assert_eq!(
            went(&rack.row(&digest_of(&request))),
            Some(PinGoBasis::Sure)
        );

        let routine = pin_request("routine", 4_096, "none", rack.project);
        rack.pin(agent, &routine, &NoScreenModel)
            .expect("the fallback lets a routine pin go");
        let row = rack.row(&digest_of(&routine));
        assert_eq!(went(&row), Some(PinGoBasis::Sure));
        let fallback = row
            .check_in
            .and_then(|record| record.screen)
            .expect("the fallback's verdict is kept");
        assert_eq!(fallback.by, ScreenSource::Fallback);
        assert!(fallback.model_failure.is_some());

        let larger = pin_request("larger", 16_384, "none", rack.project);
        rack.pin_waits(agent, &larger, &NoScreenModel);
        rack.mesh.stop().await;
    });
}

/// `auto`, no grant, network `host`: the pin always asks; a sure screen is
/// kept as the ask's recommendation and never clears it.
#[test]
fn an_uncovered_network_pin_always_asks() {
    run_on_engine_stack("job-workload-check-in-network", || async {
        let rack = Rack::start().await;
        let agent = rack.agent("compute-network");
        let sure = ScriptedScreen::answering(true);
        let request = pin_request("network", 4_096, "host", rack.project);
        rack.pin_waits(agent, &request, &sure);
        assert_eq!(sure.asked.get(), 1, "the screen ran for its recommendation");
        let record = rack.row(&digest_of(&request)).check_in.expect("the record");
        assert_eq!(record.act, "outbound_send");
        assert!(
            record.screen.is_some_and(|screen| screen.sure),
            "the sure verdict rides on the ask"
        );
        rack.mesh.stop().await;
    });
}

/// An agent never answers its own pin: naming its own check-in before any
/// holder approved it is refused, and the pin still waits.
#[test]
fn an_agent_never_answers_its_own_pin() {
    run_on_engine_stack("job-workload-check-in-own-answer", || async {
        let rack = Rack::start().await;
        let agent = rack.agent("compute-own-answer");
        let mut request = pin_request("own-answer", 4_096, "host", rack.project);
        let check_in = rack.pin_waits(agent, &request, &NoScreenModel);
        request.check_in_ref = Some(check_in);
        let refused = rack.pin(agent, &request, &NoScreenModel);
        assert!(
            matches!(refused, Err(WorkloadError::Caller(_))),
            "the asker's own call settles nothing: {refused:?}"
        );
        let digest = digest_of(&request);
        assert_eq!(
            rack.row(&digest)
                .check_in
                .map(|record| matches!(record.outcome, PinCheckInOutcome::Waits { .. })),
            Some(true)
        );
        assert_eq!(
            rack.start_on(&digest, rack.machine, agent),
            Err(WorkloadStartRefusal::WorkloadWaiting)
        );
        rack.mesh.stop().await;
    });
}
