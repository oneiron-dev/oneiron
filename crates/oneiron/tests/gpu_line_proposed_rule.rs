//! The planner's allowance table and its deterministic fallback (pass 34, section 3.5).
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, WalletRef};
use oneiron::gpu_line::{
    BudgetPolicy, FamilySeat, GpuLine, GpuLineError, GpuLineFamilyAdmitRequest, GpuLinePeriod,
    GpuLinePolicy, GpuLineSetRequest, GpuLineTableProposeRequest, GpuLineView, LineInvalid,
    ProposalAuthor, ProposalMiss, ProposalNote, ProposalRefusal, RuleRef, TableProposal,
    TableSource, Track, VAULT_GPU_LINES_TABLES_PROPOSE, gpu_seconds, mint_period,
    mint_period_with_proposal, payoff_share, period_balances,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const PERIOD_SECS: u64 = 1_209_600;
const PERIOD_MS: u64 = PERIOD_SECS * 1_000;
const ANCHOR_MS: u64 = 1_000_000;
const NOW_MS: u64 = ANCHOR_MS + 5;
const NEXT_MS: u64 = NOW_MS + PERIOD_MS;
const MARKET_POOL: u64 = 60_001;

fn id(n: u8) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x01;
    bytes[15] = n;
    EntityId::from_bytes_unchecked(bytes)
}

fn seat(family: u8) -> FamilySeat {
    FamilySeat {
        seat: id(family + 100),
        project: id(family),
        track: Track::Demand,
        replaces: None,
        graduated: None,
        lapsed_from_period: None,
        effective_from_period: 0,
        late_floor: None,
        admitted_by: None,
        admitted_at_ms: 0,
    }
}

fn policy(leads: &[EntityId], planners: &[EntityId]) -> GpuLinePolicy {
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
        planners: planners.to_vec(),
        period_secs: PERIOD_SECS,
        period_anchor_ms: ANCHOR_MS,
        budget: BudgetPolicy {
            allowance_units: MARKET_POOL,
            rung_caps_secs: vec![1_800],
            rules: vec![RuleRef::PROPOSED_1],
            ..BudgetPolicy::default()
        },
    }
}

fn market_line() -> GpuLine {
    let policy = policy(&[], &[]);
    GpuLine {
        project: id(1),
        unit: policy.unit,
        wallet: policy.wallet,
        offers: policy.offers,
        machines: policy.machines,
        leads: policy.leads,
        reviewers: policy.reviewers,
        planners: policy.planners,
        period_secs: policy.period_secs,
        period_anchor_ms: policy.period_anchor_ms,
        budget: policy.budget,
        families: vec![seat(10), seat(11)],
        set_by: None,
        set_at_ms: 0,
        revision: 1,
    }
}

fn proposal(line: &GpuLine, pool: u64) -> TableProposal {
    TableProposal {
        project: line.project,
        period: 0,
        pool_units: pool,
        ceilings: vec![(id(11), pool - 5), (id(10), 3)],
        unallocated: 2,
        note: ProposalNote {
            by: ProposalAuthor::Grant { grant: id(2) },
            why: "Give the new work more room.".to_owned(),
            submitted_at_ms: ANCHOR_MS - 5,
        },
    }
}

fn payoff_table(line: &GpuLine, record: &GpuLinePeriod, share: u64) -> (Vec<(EntityId, u64)>, u64) {
    let market = record.inputs.iter().collect::<Vec<_>>();
    payoff_share(
        share,
        &market,
        line.budget.first_rung_secs(),
        line.budget.invalid_cost,
    )
}

/// A conserving proposal sets the sorted ceilings and records the planner, reason and time.
#[test]
fn a_proposed_table_that_conserves_its_pool_is_the_periods_table_with_who_and_why() {
    let line = market_line();
    let proposal = proposal(&line, MARKET_POOL);
    let record = mint_period_with_proposal(&line, 0, &BTreeMap::new(), Some(&proposal), NOW_MS)
        .expect("the mint");
    let table = &record.tables[0];
    assert_eq!(record.market_pool, proposal.pool_units);
    assert_eq!(table.rule, RuleRef::PROPOSED_1);
    assert_eq!(table.ceilings, vec![(id(10), 3), (id(11), MARKET_POOL - 5)]);
    assert_eq!(table.unallocated, proposal.unallocated);
    assert_eq!(
        table.source,
        Some(TableSource::Proposed {
            proposal: proposal.note,
        })
    );
    assert!(period_balances(&record));
}

/// A proposal off by one uses the payoff-share table and keeps the failed proposal's note.
#[test]
fn a_proposed_table_that_does_not_sum_to_its_pool_is_replaced_by_the_fallback_rule() {
    let line = market_line();
    let mut proposal = proposal(&line, MARKET_POOL);
    proposal.unallocated += 1;
    let record = mint_period_with_proposal(&line, 0, &BTreeMap::new(), Some(&proposal), NOW_MS)
        .expect("the mint");
    let table = &record.tables[0];
    assert_eq!(table.rule, RuleRef::PROPOSED_1);
    assert_eq!(
        (table.ceilings.clone(), table.unallocated),
        payoff_table(&line, &record, MARKET_POOL)
    );
    assert_eq!(
        table.source,
        Some(TableSource::Replaced {
            by_rule: RuleRef::PAYOFF_SHARE_1,
            cause: ProposalMiss::DoesNotConserve,
            proposal: Some(proposal.note),
        })
    );
}

/// An unseated family causes the line's even-split fallback to supply the ceilings.
#[test]
fn a_proposed_table_naming_a_family_not_seated_is_replaced_by_the_fallback_rule() {
    let mut line = market_line();
    line.budget.proposal_fallback = RuleRef::EVEN_SPLIT_1;
    let mut proposal = proposal(&line, MARKET_POOL);
    proposal.ceilings[0].0 = id(12);
    let record = mint_period_with_proposal(&line, 0, &BTreeMap::new(), Some(&proposal), NOW_MS)
        .expect("the mint");
    let table = &record.tables[0];
    assert_eq!(
        table.ceilings,
        vec![(id(10), MARKET_POOL / 2), (id(11), MARKET_POOL / 2)]
    );
    assert_eq!(table.unallocated, MARKET_POOL % 2);
    assert_eq!(
        table.source,
        Some(TableSource::Replaced {
            by_rule: RuleRef::EVEN_SPLIT_1,
            cause: ProposalMiss::FamilyNotSeated,
            proposal: Some(proposal.note),
        })
    );
}

/// A missing proposal leaves no note and uses the fallback rule's table.
#[test]
fn a_period_minted_with_no_proposal_takes_the_fallback_rules_table() {
    let line = market_line();
    let record = mint_period(&line, 0, &BTreeMap::new(), NOW_MS).expect("the mint");
    let table = &record.tables[0];
    assert_eq!(
        (table.ceilings.clone(), table.unallocated),
        payoff_table(&line, &record, MARKET_POOL)
    );
    assert_eq!(
        table.source,
        Some(TableSource::Replaced {
            by_rule: RuleRef::PAYOFF_SHARE_1,
            cause: ProposalMiss::NoneSubmitted,
            proposal: None,
        })
    );
}

/// In a comparison, each table divides one half and the mint keeps the odd unit.
#[test]
fn the_proposed_half_of_a_comparison_divides_only_its_half() {
    let mut line = market_line();
    line.budget.rules = vec![RuleRef::PAYOFF_SHARE_1, RuleRef::PROPOSED_1];
    let share = MARKET_POOL / 2;
    let proposal = proposal(&line, share);
    let record = mint_period_with_proposal(&line, 0, &BTreeMap::new(), Some(&proposal), NOW_MS)
        .expect("the mint");
    let payoff = &record.tables[0];
    let proposed = &record.tables[1];
    assert_eq!(
        (payoff.rule, payoff.pool_units),
        (RuleRef::PAYOFF_SHARE_1, share)
    );
    assert_eq!(payoff.source, None);
    assert_eq!(
        (payoff.ceilings.clone(), payoff.unallocated),
        payoff_table(&line, &record, share)
    );
    assert_eq!(
        (proposed.rule, proposed.pool_units),
        (RuleRef::PROPOSED_1, share)
    );
    assert_eq!(proposed.ceilings, vec![(id(10), 3), (id(11), share - 5)]);
    assert_eq!(proposed.unallocated, proposal.unallocated);
    assert_eq!(
        proposed.source,
        Some(TableSource::Proposed {
            proposal: proposal.note,
        })
    );
    assert_eq!(record.split_remainder, MARKET_POOL % 2);
    assert!(period_balances(&record));
}

/// The digest is independent of mint time but covers the proposal's reason.
#[test]
fn a_replayed_mint_with_the_same_proposal_gives_the_same_economic_digest() {
    let line = market_line();
    let mut proposal = proposal(&line, MARKET_POOL);
    let mint = |proposal: &TableProposal, now_ms| {
        mint_period_with_proposal(&line, 0, &BTreeMap::new(), Some(proposal), now_ms)
            .expect("the mint")
    };
    let first = mint(&proposal, NOW_MS);
    let replay = mint(&proposal, NOW_MS + 1);
    assert_eq!(first.economic_digest, replay.economic_digest);
    proposal.note.why = "Change the reason, not the ceilings.".to_owned();
    let changed = mint(&proposal, NOW_MS);
    assert_ne!(first.economic_digest, changed.economic_digest);
}

/// A proposed table cannot serve as its own fallback.
#[test]
fn a_line_whose_fallback_is_proposed_is_refused() {
    let mut line = market_line();
    line.budget.proposal_fallback = RuleRef::PROPOSED_1;
    assert_eq!(line.validate(0), Err(LineInvalid::ProposalFallback));
}

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

    fn root(&self) -> EntityId {
        self.vault.root_project().expect("root project")
    }

    /// A named agent and the owner's Grant naming it and listing `verbs` (a
    /// Grant confers only with `read` among its verbs). Returns the agent
    /// and the Grant's id, which a line's role lists name.
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

    fn set_line(
        &self,
        key: &str,
        lane: EntityId,
        policy: GpuLinePolicy,
        now_ms: u64,
    ) -> GpuLineView {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .set_gpu_line(
                Some(&self.owner_proof),
                &GpuLineSetRequest {
                    intent_key: key.to_owned(),
                    project: lane,
                    policy,
                },
                now_ms,
            )
            .expect("the owner sets the line")
    }

    fn propose(
        &self,
        caller: Option<EntityId>,
        request: &GpuLineTableProposeRequest,
    ) -> Result<TableProposal, GpuLineError> {
        match caller {
            None => self
                .vault
                .memory(self.owner, EdgeActorClass::Human)
                .propose_gpu_line_table(Some(&self.owner_proof), request, NOW_MS),
            Some(agent) => self
                .vault
                .memory(agent, EdgeActorClass::Agent)
                .propose_gpu_line_table(None, request, NOW_MS),
        }
    }
}

fn request(lane: EntityId, period: u32, key: &str) -> GpuLineTableProposeRequest {
    GpuLineTableProposeRequest {
        intent_key: key.to_owned(),
        project: lane,
        period,
        pool_units: MARKET_POOL,
        ceilings: Vec::new(),
        unallocated: MARKET_POOL,
        why: "Keep the rest of the pool unallocated.".to_owned(),
    }
}

/// The planner and owner can propose, but the verb alone does not make a lead a planner.
#[test]
fn only_a_planner_of_the_line_or_the_owner_proposes_a_table() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let (lead, lead_grant) = fixture.agent("lead", &[VAULT_GPU_LINES_TABLES_PROPOSE]);
    let (planner, planner_grant) = fixture.agent("planner", &[VAULT_GPU_LINES_TABLES_PROPOSE]);
    fixture.set_line("set", lane, policy(&[lead_grant], &[planner_grant]), NOW_MS);

    let request = request(lane, 1, "propose");
    let error = MemoryError::from(
        fixture
            .propose(Some(lead), &request)
            .expect_err("a lead is not the planner"),
    );
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
    assert!(error.message.contains("not_this_line"));
    let planned = fixture
        .propose(Some(planner), &request)
        .expect("the planner proposes");
    assert_eq!(
        planned.note.by,
        ProposalAuthor::Grant {
            grant: planner_grant
        }
    );
    let owned = fixture.propose(None, &request).expect("the owner proposes");
    assert_eq!(owned.note.by, ProposalAuthor::Owner);
}

/// While period 0 holds now, only a proposal for period 1 is accepted.
#[test]
fn a_proposal_for_a_period_that_has_begun_is_refused() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let set = fixture.set_line("set", lane, policy(&[], &[]), NOW_MS);
    assert_eq!(set.period.expect("period 0 has begun").index, 0);

    let error = fixture
        .propose(None, &request(lane, 0, "old"))
        .expect_err("period 0 has already begun");
    assert!(matches!(
        error,
        GpuLineError::Proposal(ProposalRefusal::PeriodNotNext { next: 1 })
    ));
    assert_eq!(
        fixture
            .propose(None, &request(lane, 1, "next"))
            .expect("the next period")
            .period,
        1
    );
}

/// The next period's first write mints and stores the planner's standing table.
#[test]
fn a_stored_proposal_is_the_next_periods_table() {
    let fixture = fixture();
    let lane = fixture.project_under(fixture.root(), 2);
    let family = fixture.project_under(lane, 0);
    let (planner, grant) = fixture.agent("planner", &[VAULT_GPU_LINES_TABLES_PROPOSE]);
    let policy = policy(&[], &[grant]);
    fixture.set_line("set", lane, policy.clone(), NOW_MS);
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .admit_gpu_line_family(
            Some(&fixture.owner_proof),
            &GpuLineFamilyAdmitRequest {
                intent_key: "seat".to_owned(),
                project: lane,
                family,
                track: Track::Demand,
            },
            NOW_MS,
        )
        .expect("the owner seats a market family");
    let mut request = request(lane, 1, "propose");
    request.ceilings = vec![(family, MARKET_POOL - 7)];
    request.unallocated = 7;
    let proposal = fixture
        .propose(Some(planner), &request)
        .expect("the planner proposes");

    fixture.set_line("first-write", lane, policy, NEXT_MS);
    let record = fixture
        .vault
        .gpu_line_period(&lane, 1)
        .expect("read the period")
        .expect("period 1 was stored");
    let table = &record.tables[0];
    assert_eq!(table.rule, RuleRef::PROPOSED_1);
    assert_eq!(table.ceilings, proposal.ceilings);
    assert_eq!(table.unallocated, proposal.unallocated);
    assert_eq!(
        table.source,
        Some(TableSource::Proposed {
            proposal: proposal.note,
        })
    );
}
