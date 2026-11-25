//! The line's notices (design pass 32 r2, section 6; row M2-H) through the
//! engine acts that write them.
//!
//! - T30: a unit's end writes one notice to each of the line's leads, in
//!   the settle's own write: `unit_ended`, `unit_released`, `unit_box_lost`.
//!   A replayed settle writes none. The agent that reserved the unit and is
//!   no lead gets none, a lead whose Grant was revoked gets none, and the
//!   owner gets none while a lead stands.
//! - A line none of whose lead Grants stands tells its owners.
//! - T58: a returning machine writes one notice per outage, keyed by the
//!   machine and its boot id. A machine with no unit lost on it, or one lost
//!   before the line's window, tells nothing. A unit started on it and
//!   unconfirmed now counts whatever its age; its write-off names the
//!   machine it was pinned to.
//! - The clock's notices, as the `lines.notices` job raises them: a promote
//!   that waited the line's review bound is told overdue once, to the leads
//!   and the owners; a started unit past its maximum plus one hour is told
//!   unconfirmed once.
//!
//! The rig is `gpu_line_inputs_and_graduation.rs`'s. A unit claim (row
//! M2-C's reserve) is stood by the test door `experiment_arm_rows`, which
//! also settles it as the job's terminal write does, raises the clock's
//! notices and reads the line notices.
//!
//! On the base (#10457's head) the notice kind does not exist, so this file
//! does not compile there.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test gpu_line_notices`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::experiment_arm::{
    ARMS_ADMIT_VERB, ARMS_VERDICT_VERB, ArmAdmitRequest, ArmContractAsk, ArmDecision,
    ArmEvidenceDigest, ArmVerdictRequest, ExperimentArm, RungState, RunnerRef, arm_admit_as,
    arm_verdict_as,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId, WalletRef};
use oneiron::gpu_job::{GpuJobEnd, GpuJobTerminal, MeterVerdict};
use oneiron::gpu_line::{
    BudgetPolicy, ClaimState, Draw, DrawSource, GpuLineFamilyAdmitRequest, GpuLinePolicy,
    GpuLineSetRequest, LineNoticeKind, Track, UnitClaim, UnitEnd, UnitEndReport, UnitPurpose,
    UnitTerminal, defaults, gpu_seconds,
};
use oneiron::inbox::{NotificationBody, NotificationKind};
use oneiron::llm::run_admission::AllocationRef;
use oneiron::receipt::task_type_ref::TypeRef;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::experiment_arm_rows::{
    line_notices, machine_returned, put_claim, raise_due_line_notices, settle_unit,
};
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const PERIOD_SECS: u64 = 1_209_600;
const ANCHOR_MS: u64 = 1_000_000;
/// Before period 0: the owner sets the line and seats the families.
const BEFORE_MS: u64 = ANCHOR_MS - 1_000;
/// A moment inside period 0: the arms are admitted and the units reserved.
const NOW_MS: u64 = ANCHOR_MS + 60_000;
/// When the rig's units end, inside period 0.
const SETTLED_MS: u64 = NOW_MS + 1_200_000;
/// The verdicts, inside period 0.
const VERDICT_MS: u64 = SETTLED_MS + 60_000;
/// The rung-1 cap: one first allowance, and each unit's maximum.
const RUNG_SECS: u64 = 1_800;
/// What one settled unit is charged.
const CHARGED_SECS: u64 = 1_200;
const RUNNER_MODEL: &str = "open-model-runner";
const HOUR_MS: u64 = 3_600_000;

/// A rooted vault with its embedded owner bound to the host, the owner's
/// proof and the host's slip issuer, and this install's live machine profile
/// (the owner's agent Grant act needs it).
struct Fixture {
    vault: Vault,
    owner: EntityId,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner bound to host");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    vault
        .sign_owner_project(
            &owner_proof,
            &vault
                .owner_project_signer(&issuer)
                .expect("owner project signer"),
            vault.root_project().expect("root project"),
        )
        .expect("the owner signs the root project");
    Fixture {
        vault,
        owner,
        issuer,
        owner_proof,
        _dir: dir,
    }
}

impl Fixture {
    /// An owner-born project under `parent`, with `depth_remaining` levels
    /// left below it.
    fn project_under(&self, parent: EntityId, depth_remaining: u64) -> EntityId {
        let id = EntityId::now();
        let mut record = ProjectRecord::new(
            id,
            Some(parent),
            self.vault.root_project().expect("root project"),
            self.owner,
        )
        .expect("project record");
        record.depth_remaining = depth_remaining;
        create_owner_project(
            &self.vault,
            &self.issuer,
            &self.owner_proof,
            &self
                .vault
                .owner_project_signer(&self.issuer)
                .expect("owner project signer"),
            self.owner,
            id,
            &record,
        )
        .unwrap_or_else(|error| {
            panic!("the owner bears project {id:?} under {parent:?}: {error:?}")
        });
        id
    }

    /// A named agent and the owner's Grant naming it, listing `verbs` (with
    /// `read`, which a Grant needs to confer) over every project. Returns
    /// the agent and the Grant's id.
    fn agent(&self, name: &str, verbs: &[&str]) -> (EntityId, EntityId) {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("named agent principal");
        let mut authority_scope = Scope::top();
        authority_scope.verbs = ScopeAxis::Some(
            std::iter::once("read")
                .chain(verbs.iter().copied())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        authority_scope.audience = ScopeAxis::<ScopeId>::All;
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
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
        .expect("the owner mints the agent a Grant");
        assert!(minted.grant.confers, "agent={name} verbs={verbs:?}");
        (agent, minted.grant.grant_ref)
    }

    /// A lead: an agent whose Grant lists the arm admit and verdict verbs.
    fn lead(&self, name: &str) -> (EntityId, EntityId) {
        self.agent(name, &[ARMS_ADMIT_VERB, ARMS_VERDICT_VERB])
    }

    /// The owner revokes `grant`.
    fn revoke(&self, grant: EntityId) {
        let revoked = revoke_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantRevokeRequest {
                grant_ref: grant,
                seen: None,
            },
        )
        .expect("the owner revokes the Grant");
        assert!(revoked.changed, "the revoke lands");
    }

    /// A lane under the root with its line set before period 0, the Grants
    /// `leads` its leads, and one demand family seated. Returns the lane and
    /// the family.
    fn lane(&self, leads: &[EntityId]) -> (EntityId, EntityId) {
        let root = self.vault.root_project().expect("root project");
        let lane = self.project_under(root, 2);
        let owner = self.vault.memory(self.owner, EdgeActorClass::Human);
        owner
            .set_gpu_line(
                Some(&self.owner_proof),
                &GpuLineSetRequest {
                    intent_key: "set".to_owned(),
                    project: lane,
                    policy: policy(leads),
                },
                BEFORE_MS,
            )
            .unwrap_or_else(|error| panic!("the owner sets lane {lane:?}'s line: {error:?}"));
        let family = self.project_under(lane, 0);
        owner
            .admit_gpu_line_family(
                Some(&self.owner_proof),
                &GpuLineFamilyAdmitRequest {
                    intent_key: format!("seat-{family:?}"),
                    project: lane,
                    family,
                    track: Track::Demand,
                },
                BEFORE_MS,
            )
            .unwrap_or_else(|error| panic!("the owner seats a demand family: {error:?}"));
        (lane, family)
    }

    /// `lead` admits arm `title` on contract number `contract` into
    /// `family` of `lane`'s line.
    fn admit(
        &self,
        lead: EntityId,
        lane: EntityId,
        family: EntityId,
        contract: u8,
        title: &str,
    ) -> ExperimentArm {
        arm_admit_as(
            &self.vault.memory(lead, EdgeActorClass::Agent),
            None,
            &admission(lane, family, contract, title),
            NOW_MS,
        )
        .unwrap_or_else(|error| panic!("{title} is admitted: {error:?}"))
        .arm
    }

    /// Puts a work claim at rung 1 of `arm` in `state`, on `machine`, as
    /// row M2-C's reserve would leave it, reserved by `reserver` under
    /// `grant`.
    fn put(
        &self,
        arm: &ExperimentArm,
        unit_key: &str,
        state: ClaimState,
        machine: Option<EntityId>,
        reserver: Option<(EntityId, EntityId)>,
    ) -> UnitClaim {
        let mut claim = claim(arm, unit_key, state);
        claim.machine = machine;
        claim.reserved_by = reserver.map(|(agent, _)| agent);
        claim.grant = reserver.map(|(_, grant)| grant);
        put_claim(&self.vault, &claim).expect("the test door puts the claim");
        claim
    }

    /// Settles `claim` by `report` at `SETTLED_MS`: whether it was a replay.
    fn settle(&self, claim: &UnitClaim, report: &UnitEndReport) -> bool {
        settle_unit(&self.vault, &claim.key(), &claim.id, report, SETTLED_MS)
            .expect("the settle's write")
            .unwrap_or_else(|refused| panic!("the settle lands: {refused}"))
            .replayed
    }

    /// The vault's line notices of `kind`.
    fn notices(&self, kind: LineNoticeKind) -> Vec<NotificationBody> {
        line_notices(&self.vault)
            .expect("the line notices")
            .into_iter()
            .filter(|notice| notice.source.producer == kind.producer())
            .collect()
    }
}

/// Who `notices` were told to, as actor hex.
fn recipients(notices: &[NotificationBody]) -> BTreeSet<String> {
    notices
        .iter()
        .map(|notice| {
            notice
                .recipient
                .clone()
                .expect("a notice names its recipient")
        })
        .collect()
}

/// `actors` as hex.
fn hex(actors: &[EntityId]) -> BTreeSet<String> {
    actors.iter().map(EntityId::to_hex).collect()
}

/// The line's policy with the Grants `leads` its leads: one demand floor of
/// two first allowances, a market of one more, one rung.
fn policy(leads: &[EntityId]) -> GpuLinePolicy {
    GpuLinePolicy {
        unit: gpu_seconds(),
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        offers: Vec::new(),
        machines: Vec::new(),
        leads: leads.to_vec(),
        reviewers: Vec::new(),
        planners: Vec::new(),
        period_secs: PERIOD_SECS,
        period_anchor_ms: ANCHOR_MS,
        budget: BudgetPolicy {
            allowance_units: 3 * RUNG_SECS,
            pinned_parts: (0, 3),
            floor_arms: 2,
            rung_caps_secs: vec![RUNG_SECS, RUNG_SECS],
            seat_reserve_floors: 0,
            new_idea_slots_per_period: 0,
            window_periods: 1,
            ..BudgetPolicy::default()
        },
    }
}

/// The contract sha256 numbered `contract`.
fn contract_sha(contract: u8) -> String {
    format!("{contract:02x}").repeat(32)
}

/// An evidence digest named `name` whose sha256 repeats `byte`.
fn digest(name: &str, byte: u8) -> ArmEvidenceDigest {
    ArmEvidenceDigest {
        name: name.to_owned(),
        sha256: format!("{byte:02x}").repeat(32),
        bytes: 64,
        rows: None,
    }
}

/// An admission of one arm titled `title`, on contract number `contract`,
/// into `family` of `lane`'s line.
fn admission(lane: EntityId, family: EntityId, contract: u8, title: &str) -> ArmAdmitRequest {
    ArmAdmitRequest {
        intent_key: format!("admit-{family:?}-{contract}"),
        line: lane,
        family,
        type_ref: TypeRef::root(1),
        title: title.to_owned(),
        contract: ArmContractAsk {
            path: "contracts/arm.md".to_owned(),
            sha256: contract_sha(contract),
            note: None,
            claimed_frozen_at_ms: Some(BEFORE_MS),
        },
        runner: RunnerRef {
            model: RUNNER_MODEL.to_owned(),
            actor: None,
        },
        supersedes: None,
        ledger_rows: Vec::new(),
        card_digest: None,
    }
}

/// A work claim at rung 1 of `arm` in `state`, reserved at `NOW_MS` for
/// `RUNG_SECS`.
fn claim(arm: &ExperimentArm, unit_key: &str, state: ClaimState) -> UnitClaim {
    UnitClaim {
        id: EntityId::now(),
        arm: arm.id,
        rung: 1,
        unit_key: unit_key.to_owned(),
        attempt: 1,
        line: arm.line,
        family: arm.family,
        period: 0,
        purpose: UnitPurpose::Work,
        workload: "ab".repeat(32),
        machine: None,
        code_sha: "c0de".repeat(10),
        contract_sha256: arm.contract.sha256.clone(),
        reserved_secs: RUNG_SECS,
        draws: vec![Draw {
            source: DrawSource::FirstAllowance,
            units: RUNG_SECS,
        }],
        wallet: WalletRef {
            issuer: "host".to_owned(),
            id: "gpu".to_owned(),
        },
        allocation: AllocationRef {
            id: "gpu-line-0".to_owned(),
            generation: 1,
        },
        grant: None,
        reserved_by: None,
        reserved_at_ms: NOW_MS,
        ask_digest: "ad".repeat(32),
        state,
        revision: 1,
    }
}

/// The machine's confirmed end of a unit on `machine`.
fn machine_end(end: GpuJobEnd, machine: EntityId) -> UnitEndReport {
    let ran = !matches!(end, GpuJobEnd::Lost { .. });
    UnitEndReport::Machine(GpuJobTerminal {
        end,
        measured_secs: ran.then_some(CHARGED_SECS),
        billed_secs: if ran { CHARGED_SECS } else { 0 },
        meter: if ran {
            MeterVerdict::Agreed
        } else {
            MeterVerdict::Unknown
        },
        machine: Some(machine),
        device_id: Some("GPU-0".to_owned()),
        outputs: Vec::new(),
    })
}

/// A box-lost terminal on `machine` at `ended_at_ms`.
fn lost_on(machine: EntityId, ended_at_ms: u64) -> ClaimState {
    ClaimState::Ended(UnitTerminal {
        end: UnitEnd::BoxLost,
        charged_secs: 0,
        measured_secs: 0,
        lost_secs: 300,
        machine: Some(machine),
        device_id: None,
        node_end: Some("lost(unreachable)".to_owned()),
        outputs: Vec::new(),
        ended_at_ms,
    })
}

/// T30.
#[test]
fn a_unit_end_writes_one_notice_to_the_lines_leads() {
    let fixture = fixture();
    let (lead, lead_grant) = fixture.lead("line-lead");
    let (second, second_grant) = fixture.lead("second-lead");
    let (gone, gone_grant) = fixture.lead("revoked-lead");
    let starter = fixture.agent("unit-starter", &[ARMS_ADMIT_VERB]);
    let (lane, family) = fixture.lane(&[lead_grant, second_grant, gone_grant]);
    fixture.revoke(gone_grant);
    let arm = fixture.admit(lead, lane, family, 1, "the arm");
    let machine = EntityId::now();
    let leads = hex(&[lead, second]);

    // A machine's end: one `unit_ended` to each standing lead.
    let ran = fixture.put(
        &arm,
        "work/0",
        ClaimState::Started,
        Some(machine),
        Some(starter),
    );
    let report = machine_end(GpuJobEnd::Exited { code: 0 }, machine);
    assert!(!fixture.settle(&ran, &report), "a fresh terminal");
    let ended = fixture.notices(LineNoticeKind::UnitEnded);
    assert_eq!(recipients(&ended), leads, "{ended:?}");
    assert_eq!(ended.len(), 2, "one notice per lead: {ended:?}");
    for notice in &ended {
        assert_eq!(notice.kind, NotificationKind::LineNotice);
        assert_eq!(
            notice.source.result,
            Some(ran.id.to_hex()),
            "about the unit's job"
        );
        let detail = notice
            .source
            .detail
            .as_deref()
            .expect("the facts it carries");
        for words in [
            "end=exited(0)",
            "measured_secs=1200",
            "charged_secs=1200",
            "rung=1",
        ] {
            assert!(detail.contains(words), "{words}: {detail}");
        }
    }
    let told = recipients(&line_notices(&fixture.vault).expect("notices"));
    for (who, name) in [
        (starter.0, "the starter who is no lead"),
        (gone, "the lead whose Grant was revoked"),
        (fixture.owner, "the owner, while a lead stands"),
    ] {
        assert!(!told.contains(&who.to_hex()), "{name} is told nothing");
    }

    // The same end again is a replay: it writes nothing.
    assert!(fixture.settle(&ran, &report), "the same terminal replays");
    assert_eq!(fixture.notices(LineNoticeKind::UnitEnded).len(), 2);

    // A refusal before dispatch: `unit_released` with its reason.
    let refused = fixture.put(&arm, "work/1", ClaimState::Claimed, None, Some(starter));
    let release = UnitEndReport::Refused {
        reason: "custody_lapsed".to_owned(),
    };
    assert!(!fixture.settle(&refused, &release));
    let released = fixture.notices(LineNoticeKind::UnitReleased);
    assert_eq!(recipients(&released), leads, "{released:?}");
    assert_eq!(released.len(), 2);
    assert!(
        released[0]
            .source
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("reason=custody_lapsed")),
        "{released:?}"
    );

    // A lost machine: `unit_box_lost` with the machine and the time last
    // seen.
    let lost = fixture.put(&arm, "work/2", ClaimState::Started, Some(machine), None);
    let gone_box = machine_end(
        GpuJobEnd::Lost {
            reason: "unreachable".to_owned(),
            last_seen_secs: 300,
        },
        machine,
    );
    assert!(!fixture.settle(&lost, &gone_box));
    let box_lost = fixture.notices(LineNoticeKind::UnitBoxLost);
    assert_eq!(recipients(&box_lost), leads, "{box_lost:?}");
    let detail = box_lost[0].source.detail.clone().expect("its facts");
    assert!(
        detail.contains(&format!("machine={}", machine.to_hex()))
            && detail.contains("last_seen_secs=300"),
        "{detail}"
    );
    assert_eq!(
        line_notices(&fixture.vault).expect("notices").len(),
        6,
        "three ends, two leads, nothing else"
    );
}

/// A line none of whose lead Grants stands tells its owners, so a fact is
/// never told to no one.
#[test]
fn a_line_with_no_standing_lead_tells_its_owners() {
    let fixture = fixture();
    let (lead, lead_grant) = fixture.lead("line-lead");
    let (lane, family) = fixture.lane(&[lead_grant]);
    let arm = fixture.admit(lead, lane, family, 1, "the arm");
    fixture.revoke(lead_grant);

    let refused = fixture.put(&arm, "work/0", ClaimState::Claimed, None, None);
    let release = UnitEndReport::Refused {
        reason: "period_ended".to_owned(),
    };
    assert!(!fixture.settle(&refused, &release));
    let released = fixture.notices(LineNoticeKind::UnitReleased);
    assert_eq!(recipients(&released), hex(&[fixture.owner]), "{released:?}");
}

/// T58.
#[test]
fn a_returning_machine_writes_one_notice_per_outage() {
    let fixture = fixture();
    let (lead, lead_grant) = fixture.lead("line-lead");
    let (lane, family) = fixture.lane(&[lead_grant]);
    let arm = fixture.admit(lead, lane, family, 1, "the arm");
    let machine = EntityId::now();
    let aged = EntityId::now();
    let idle = EntityId::now();
    fixture.put(&arm, "work/0", lost_on(machine, SETTLED_MS), None, None);
    fixture.put(&arm, "work/1", lost_on(aged, SETTLED_MS), None, None);
    let back_at = SETTLED_MS + 60_000;

    let first =
        machine_returned(&fixture.vault, &machine, "boot-1", back_at).expect("the return's write");
    assert_eq!(first.len(), 1, "one notice, to the one lead");
    let returned = fixture.notices(LineNoticeKind::MachineReturned);
    assert_eq!(recipients(&returned), hex(&[lead]), "{returned:?}");
    assert_eq!(returned[0].source.result, Some(machine.to_hex()));
    assert!(
        returned[0]
            .source
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("boot_id=boot-1")),
        "{returned:?}"
    );

    // The same outage again writes nothing; a new boot is a new outage.
    let again = machine_returned(&fixture.vault, &machine, "boot-1", back_at + 60_000)
        .expect("the return's write");
    assert!(again.is_empty(), "the same boot: {again:?}");
    let rebooted = machine_returned(&fixture.vault, &machine, "boot-2", back_at + 120_000)
        .expect("the return's write");
    assert_eq!(rebooted.len(), 1, "a new boot id is a new outage");

    // A machine with no unit lost on it tells nothing.
    let quiet =
        machine_returned(&fixture.vault, &idle, "boot-1", back_at).expect("the return's write");
    assert!(quiet.is_empty(), "{quiet:?}");

    // A unit lost before the line's window (72 h by default) tells nothing.
    let window_ms = defaults::MACHINE_RETURNED_WINDOW_SECS * 1_000;
    let late = machine_returned(&fixture.vault, &aged, "boot-1", SETTLED_MS + window_ms + 1)
        .expect("the return's write");
    assert!(late.is_empty(), "outside the window: {late:?}");
    let inside = machine_returned(&fixture.vault, &aged, "boot-1", SETTLED_MS + window_ms)
        .expect("the return's write");
    assert_eq!(inside.len(), 1, "at the window's edge it still counts");

    // A unit started on the machine and unconfirmed now counts whatever its
    // age: it is unconfirmed within the window because it is unconfirmed now.
    let pinned = EntityId::now();
    let stale = fixture.put(&arm, "work/2", ClaimState::Started, Some(pinned), None);
    let unconfirmed_ms = NOW_MS + RUNG_SECS * 1_000 + HOUR_MS;
    let long_after = machine_returned(
        &fixture.vault,
        &pinned,
        "boot-1",
        unconfirmed_ms + window_ms + HOUR_MS,
    )
    .expect("the return's write");
    assert_eq!(long_after.len(), 1, "unconfirmed now: {long_after:?}");
    assert_eq!(fixture.notices(LineNoticeKind::MachineReturned).len(), 4);

    // The owner's write-off names the machine the unit was pinned to.
    let owner = EntityId::now();
    let write_off = UnitEndReport::WrittenOff { by: owner };
    assert!(!fixture.settle(&stale, &write_off), "a fresh end");
    let written_off = fixture.notices(LineNoticeKind::UnitWrittenOff);
    assert_eq!(recipients(&written_off), hex(&[lead]), "{written_off:?}");
    let detail = written_off[0].source.detail.clone().expect("its facts");
    assert!(
        detail.contains(&format!("machine={}", pinned.to_hex())),
        "{detail}"
    );
}

/// A promote that waits the line's review bound is told overdue once, to the
/// leads and the owners, by the clock's notices.
#[test]
fn a_review_waiting_past_its_bound_is_told_once_to_leads_and_owners() {
    let fixture = fixture();
    let (lead, lead_grant) = fixture.lead("line-lead");
    let (lane, family) = fixture.lane(&[lead_grant]);
    let arm = fixture.admit(lead, lane, family, 1, "the arm");
    let result = digest("result.json", 0x40);
    let unit = fixture.put(
        &arm,
        "work/0",
        ClaimState::Ended(UnitTerminal {
            end: UnitEnd::Settled,
            charged_secs: CHARGED_SECS,
            measured_secs: CHARGED_SECS,
            lost_secs: 0,
            machine: None,
            device_id: None,
            node_end: Some("exited(0)".to_owned()),
            outputs: vec![result.clone()],
            ended_at_ms: SETTLED_MS,
        }),
        None,
        None,
    );
    let promoted = arm_verdict_as(
        &fixture.vault.memory(lead, EdgeActorClass::Agent),
        None,
        &ArmVerdictRequest {
            intent_key: "promote".to_owned(),
            arm: arm.id,
            rung: 1,
            arm_revision: arm.revision,
            decision: ArmDecision::Promote,
            units: vec![unit.id],
            result: Some(result),
            numbers: BTreeMap::from([("pass_rate".to_owned(), 0.9)]),
            text: String::new(),
            evidence: Vec::new(),
            ledger_row: None,
            contract_sha256: arm.contract.sha256.clone(),
        },
        VERDICT_MS,
    )
    .expect("the lead promotes rung 1");
    assert_eq!(promoted.arm.rungs[0].state, RungState::AwaitingReview);

    let bound_ms = defaults::REVIEW_OVERDUE_SECS * 1_000;
    assert_eq!(
        raise_due_line_notices(&fixture.vault, VERDICT_MS + bound_ms - 1).expect("raise"),
        0,
        "not yet overdue"
    );
    assert_eq!(
        raise_due_line_notices(&fixture.vault, VERDICT_MS + bound_ms).expect("raise"),
        2,
        "overdue: the lead and the owner"
    );
    let overdue = fixture.notices(LineNoticeKind::ReviewOverdue);
    assert_eq!(
        recipients(&overdue),
        hex(&[lead, fixture.owner]),
        "{overdue:?}"
    );
    assert_eq!(overdue[0].source.result, Some(arm.id.to_hex()));
    assert_eq!(
        raise_due_line_notices(&fixture.vault, VERDICT_MS + 2 * bound_ms).expect("raise"),
        0,
        "told once"
    );
}

/// A started unit whose job passed its maximum plus one hour with no end is
/// told unconfirmed once; its end, when it comes, is still told.
#[test]
fn a_started_unit_past_its_maximum_and_an_hour_is_told_unconfirmed_once() {
    let fixture = fixture();
    let (lead, lead_grant) = fixture.lead("line-lead");
    let (lane, family) = fixture.lane(&[lead_grant]);
    let arm = fixture.admit(lead, lane, family, 1, "the arm");
    let machine = EntityId::now();
    let running = fixture.put(&arm, "work/0", ClaimState::Started, Some(machine), None);
    // No job row stands for the claim here, so it counts from its
    // reservation.
    let due_ms = NOW_MS + RUNG_SECS * 1_000 + HOUR_MS;

    assert_eq!(
        raise_due_line_notices(&fixture.vault, due_ms - 1).expect("raise"),
        0,
        "inside its maximum plus an hour"
    );
    assert_eq!(
        raise_due_line_notices(&fixture.vault, due_ms).expect("raise"),
        1,
        "unconfirmed: told to the lead"
    );
    let unconfirmed = fixture.notices(LineNoticeKind::UnitUnconfirmed);
    assert_eq!(recipients(&unconfirmed), hex(&[lead]), "{unconfirmed:?}");
    assert_eq!(unconfirmed[0].source.result, Some(running.id.to_hex()));
    let detail = unconfirmed[0].source.detail.clone().expect("its facts");
    assert!(
        detail.contains(&format!("machine={}", machine.to_hex()))
            && detail.contains(&format!("since_ms={due_ms}")),
        "{detail}"
    );
    assert_eq!(
        raise_due_line_notices(&fixture.vault, due_ms + HOUR_MS).expect("raise"),
        0,
        "told once"
    );

    // The machine's late end settles it and is told as an end.
    let report = machine_end(GpuJobEnd::TimeLimit, machine);
    assert!(!fixture.settle(&running, &report));
    assert_eq!(fixture.notices(LineNoticeKind::UnitEnded).len(), 1);
}
