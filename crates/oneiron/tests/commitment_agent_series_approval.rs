//! An agent's commitment mints nothing until the owner approves it
//! (FIX COMMITMENT-AGENT-MINT-NO-DOOR-TEST).
//!
//! Canon `cross/hosting/cross-arch-0022-node-supervisor-vault-lifecycle.md:317`:
//! "An agent minting \"check X every morning\" is minting a commitment". The
//! ten `vault.commitments.*` rows are the owner's and refuse an agent, so an
//! agent's way in is the proposing claim door, `vault.claims.upsert`, with a
//! `commitment.record` value. Landing indexes a commitment series only once
//! it is consented (`commitment_schedule/projection.rs`,
//! `PROJECT_ONLY_CONSENTED_SERIES`), and the owner's approval indexes it in
//! the approval's own write (`claim/deferred.rs`).
//!
//! The test enters the way an agent does: a registered agent definition with
//! an owner-minted grant for `read` and `vault.claims.upsert` in the base
//! world, and no policy authority of its own (the default manifest keeps an
//! agent's landings at Proposed). Its write goes through the generated verb
//! dispatch every transport shares. It asks Auto (`observed`, no sensitivity
//! stamp), so a Proposed landing is the gate's answer, not the source's. The
//! agent is the obligor: a daily series that it owes. Then:
//! - the write lands Proposed, and the engine's projector
//!   (`Vault::reconcile_commitment_schedule`, which no verb runs) mints no
//!   occurrence at an instant when one is due;
//! - the owner reviews and settles it Approved through the owner's claim
//!   settlement (`claim_review_as_owner`, `claim_settle_as_owner`);
//! - the projector at the same instant mints the occurrence, and the owner's
//!   instances read lists it under the agent's series.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test commitment_agent_series_approval`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
    PREDICATE_COMMITMENT_RECORD, encode_commitment_value,
};
use oneiron::commitment_schedule::{CommitmentSchedulePayload, Schedule};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::commitment_doors::CommitmentRefRequest;
use oneiron::memory::{
    AllRelationships, ClaimProposalReviewRequest, ClaimRelationships, ClaimScope,
    ClaimSettleDecision, ClaimSettleRequest, ScopedClaimInput,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{ClaimApprovalStatus, EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const UPSERT_VERB: &str = "vault.claims.upsert";
const DAY: u64 = 86_400;
/// The series' lead: each occurrence is minted this long before it is due.
const LEAD: u64 = 3_600;
const AGENT_SEED: u8 = 0xC7;
const SERIES_SEED: u8 = 0xC8;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
}

fn entity(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture entity id")
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    agent: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// A fresh vault with signing, a rooted serving install, the engine's
    /// MACHINE writers (the projector mints as one of them) and one agent the
    /// owner registered and granted `read` and `vault.claims.upsert` in the
    /// base world.
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing().expect("install signing");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let staging = owner_proof(&vault, owner);
        let agent = entity(AGENT_SEED);
        create_agent_definition_as(
            &vault,
            &staging,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": "commitment_series_agent",
                    "desc": "an agent that promises a daily check",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner registers the agent");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        let mut scope = Scope::top();
        scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), UPSERT_VERB.to_owned()]));
        let minted = mint_agent_grant_as(
            &vault,
            &owner_proof(&vault, owner),
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope: scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner grants the agent its upsert");
        assert!(minted.grant.confers, "the agent's grant confers");
        Self {
            vault,
            owner,
            agent,
            _directory: directory,
        }
    }

    fn owner_proof(&self) -> AuthenticatedOwner {
        owner_proof(&self.vault, self.owner)
    }
}

fn owner_proof(vault: &Vault, owner: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("live owner proof")
}

/// The JSON form of a MessagePack value, as an SDK caller writes it; the
/// claim door turns it back into the same MessagePack value.
fn json_of(value: &rmpv::Value) -> Value {
    match value {
        rmpv::Value::Nil => Value::Null,
        rmpv::Value::Boolean(flag) => json!(flag),
        rmpv::Value::Integer(number) => number
            .as_u64()
            .map(Value::from)
            .or_else(|| number.as_i64().map(Value::from))
            .expect("an integer that fits 64 bits"),
        rmpv::Value::String(text) => json!(text.as_str().expect("UTF-8 text")),
        rmpv::Value::Array(items) => Value::Array(items.iter().map(json_of).collect()),
        rmpv::Value::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.as_str().expect("a text key").to_owned(), json_of(value)))
                .collect(),
        ),
        other => panic!("a commitment value holds no {other:?}"),
    }
}

/// The agent's "check the backups every morning": a daily series the agent
/// owes, first due at `anchor`, for the owner.
fn daily_check_value(agent: EntityId, owner: EntityId, anchor: u64) -> Value {
    let schedule = CommitmentSchedulePayload::series(
        Schedule::Interval {
            period: DAY,
            anchor,
        },
        Some(LEAD),
    )
    .encode()
    .expect("series payload");
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Agent, agent),
        owner,
        CommitmentContent::new("check the backups every morning", None).expect("content"),
        schedule,
        CommitmentStrength::Commitment,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::RunTreeNode, "run:agent-daily-check")
            .expect("birth provenance"),
    )
    .expect("commitment record");
    json_of(&encode_commitment_value(&record).expect("commitment value"))
}

#[test]
fn agent_commitment_series_mints_only_after_owner_approval() {
    let fixture = Fixture::new();
    let vault = &fixture.vault;
    let now = unix_now();
    let anchor = now + 2 * DAY;
    // Past the lead of the first occurrence whether the series counts its
    // anchor as the first due instant or the one a period later.
    let project_at = anchor + DAY;
    let series = entity(SERIES_SEED);
    let facet = vault.default_facet().expect("default facet").to_hex();
    let input = ScopedClaimInput {
        id: Some(series.to_hex()),
        predicate: PREDICATE_COMMITMENT_RECORD.to_owned(),
        subject_ref: fixture.agent.to_hex(),
        value: daily_check_value(fixture.agent, fixture.owner, anchor),
        confidence: 1.0,
        source: "observed".to_owned(),
        scope: ClaimScope {
            world_id: base_world_id().to_hex(),
            scope_facet_id: facet,
            scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
            scope_project_id: default_project_id().to_hex(),
        },
        sensitivity: None,
        evidence_turn_refs: Vec::new(),
        valid_from: Some(now),
        valid_to: Some(now + 30 * DAY),
        occurred_at: Some(now),
        learned_at: Some(now),
        salience: None,
    };

    let agent = vault.memory(fixture.agent, EdgeActorClass::Agent);
    let receipt = oneiron::verbs::invoke(
        &agent,
        UPSERT_VERB,
        serde_json::to_value(&input).expect("upsert input json"),
    )
    .expect("the agent writes its commitment through vault.claims.upsert");
    assert_eq!(
        receipt["approval"],
        json!("proposed"),
        "an agent's commitment lands proposed: {receipt}"
    );
    let stored = vault
        .get_claim(&series)
        .expect("claim read")
        .expect("the agent's series is stored");
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(stored.predicate, PREDICATE_COMMITMENT_RECORD);

    let before = vault
        .reconcile_commitment_schedule(project_at)
        .expect("the projector runs");
    assert_eq!(
        before.projected_series, 0,
        "a proposed series is not projected: {before:?}"
    );
    assert!(
        before.minted_instances.is_empty(),
        "a proposed series mints no occurrence: {before:?}"
    );

    let owner_proof = fixture.owner_proof();
    let owner = vault.memory(fixture.owner, EdgeActorClass::Human);
    let review = owner
        .claim_review_as_owner(
            &owner_proof,
            &ClaimProposalReviewRequest {
                claim_ref: series.to_hex(),
                grant_ref: None,
            },
        )
        .expect("the owner reviews the agent's proposal");
    assert_eq!(review.opener_ref, Some(fixture.agent.to_hex()));
    owner
        .claim_settle_as_owner(
            &owner_proof,
            &ClaimSettleRequest {
                claim_ref: series.to_hex(),
                review_id: review.review_id,
                decision: ClaimSettleDecision::Approve,
                grant_ref: None,
            },
        )
        .expect("the owner approves the agent's commitment");
    let approved = vault
        .get_claim(&series)
        .expect("claim read")
        .expect("the approved series is stored");
    assert_eq!(approved.approval, ClaimApprovalStatus::Approved);

    let after = vault
        .reconcile_commitment_schedule(project_at)
        .expect("the projector runs");
    assert!(
        !after.minted_instances.is_empty(),
        "the approved series mints its occurrence: {after:?}"
    );
    let instances = owner
        .commitments_instances_as(
            &owner_proof,
            CommitmentRefRequest {
                commitment_ref: series.to_hex(),
            },
        )
        .expect("the owner reads the series' occurrences");
    assert_eq!(
        instances.len(),
        after.minted_instances.len(),
        "every minted occurrence is listed: {instances:?}"
    );
    for instance in &instances {
        assert_eq!(
            instance.series_ref.as_deref(),
            Some(series.to_hex().as_str()),
            "each occurrence names the agent's series: {instance:?}"
        );
    }
}
