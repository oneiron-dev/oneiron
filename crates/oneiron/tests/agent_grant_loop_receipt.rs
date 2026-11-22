//! The retrieval loop an agent runs under its own live read Grant reports
//! that Grant's reach in its receipts, as vault.get does, not the agent key's
//! own floor, which reads nothing (FIX-LIST GRANT-RECEIPT-OTHER-READ-LANES,
//! after GRANT-READ-NARROWING-SAYS-DENY-ALL). The loop's own lane is the
//! embedder's, which never opts in, so the loop reports for it. The receipt
//! only reports: after the owner revokes the Grant the same loop ranks
//! nothing and its receipt says deny_all again.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::claim::{ScopedReadActorKey, ScopedReadReceipt};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::pipeline::retrieval_loop::RetrievalLoopAction;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const VECTOR: [f32; 4] = [1.0, 0.0, 0.0, 0.0];

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    agent: EntityId,
    grant: EntityId,
    person: EntityId,
}

impl Fixture {
    /// A vault whose owner gave the identity agent one live read Grant over
    /// every band, world and facet, holding one PERSON with a vector.
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::default();
        config.dimensions = 4;
        config.embedding_model = Some("test/model@v1".to_owned());
        let vault = Vault::open(dir.path(), config)?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let issuer = HostSlipIssuer::from_secret(b"agent-grant-loop-receipt-host")?;
        vault.ensure_host_root_slip(&issuer)?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let owner_proof =
            vault.authenticate_owner(owner, "principal:owen", true, GateDecisionId::now())?;

        let agent = EntityId::now();
        create_agent_definition_as(
            &vault,
            &owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": "loop_receipt_reader",
                    "desc": "Read-only retrieval loop receipt fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))?,
            },
        )?;
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        let minted = mint_agent_grant_as(
            &vault,
            &owner_proof,
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
        )?;
        assert!(minted.grant.confers, "the agent's read Grant is live");

        let person = EntityId::now();
        let mut bytes = Vec::new();
        rmpv::encode::write_value(
            &mut bytes,
            &Value::Map(vec![(Value::from("name"), Value::from("harbour surveyor"))]),
        )?;
        vault.put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 123,
                end: 456,
            },
            789,
            &bytes,
        )?;
        vault.batch().vector(&person, &VECTOR).commit()?;
        Ok(Self {
            vault,
            _dir: dir,
            owner,
            agent,
            grant: minted.grant.grant_ref,
            person,
        })
    }

    fn agent_key(&self) -> TestResult<ScopedReadActorKey> {
        Ok(self
            .vault
            .memory(self.agent, EdgeActorClass::Agent)
            .read_key()?)
    }
}

/// `receipt` states the live Grant's reach, which admitted the loop's rows,
/// not the agent key's own deny-all floor.
fn assert_reports_the_grant(receipt: &ScopedReadReceipt, step: &str) {
    assert!(
        !receipt.actor_ceiling.deny_all,
        "{step}: the ceiling is the live Grant's reach, not deny_all: {receipt:?}"
    );
    assert!(
        !receipt.requested.deny_all,
        "{step}: the request is not deny_all: {receipt:?}"
    );
    assert!(
        !receipt.applied.deny_all,
        "{step}: the applied scope is the Grant's candidates: {receipt:?}"
    );
    assert!(
        !receipt.narrowed_axes.iter().any(|axis| axis == "deny_all")
            && !receipt.replan_hint.iter().any(|hint| hint == "deny_all"),
        "{step}: no axis or hint says deny_all: {receipt:?}"
    );
}

#[test]
fn an_agents_retrieval_loop_under_a_live_read_grant_reports_the_grant_not_deny_all() -> TestResult {
    let fixture = Fixture::new()?;
    let lane = fixture.vault.scoped_read(fixture.agent_key()?);
    let mut retrieval = fixture
        .vault
        .query()
        .search_vector(&VECTOR, 10)
        .limit(10)
        .read_only_loop(&lane)?;
    let seeded = retrieval.observation();
    assert!(
        seeded
            .handles
            .iter()
            .any(|handle| handle.id == fixture.person),
        "the live Grant admits the PERSON to the agent's first page"
    );
    assert_reports_the_grant(&seeded.narrowing, "the loop's seed");
    assert_reports_the_grant(&seeded.last_narrowing, "the first page's release");

    let observation = retrieval.step(RetrievalLoopAction::Read {
        handles: vec![fixture.person],
    })?;
    assert!(
        observation
            .evidence
            .iter()
            .any(|evidence| evidence.handle.id == fixture.person),
        "Read keeps the Grant-admitted PERSON as evidence"
    );
    assert_reports_the_grant(&observation.last_narrowing, "the Read step");
    assert_reports_the_grant(&observation.narrowing, "the loop after Read");
    Ok(())
}

#[test]
fn after_the_owner_revokes_the_grant_the_agents_loop_ranks_nothing_and_says_deny_all() -> TestResult
{
    let fixture = Fixture::new()?;
    let owner_proof = fixture.vault.authenticate_owner(
        fixture.owner,
        "principal:owen",
        true,
        GateDecisionId::now(),
    )?;
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: fixture.grant,
            seen: None,
        },
    )?;
    assert!(revoked.changed, "the owner's revoke lands");

    let lane = fixture.vault.scoped_read(fixture.agent_key()?);
    let started = fixture
        .vault
        .query()
        .search_vector(&VECTOR, 10)
        .limit(10)
        .read_only_loop(&lane);
    // A loop whose reader reads nothing may refuse to start; one that starts
    // ranks nothing and says so.
    if let Ok(retrieval) = started {
        let seeded = retrieval.observation();
        assert!(
            seeded
                .handles
                .iter()
                .all(|handle| handle.id != fixture.person),
            "a revoked Grant admits nothing to the loop"
        );
        assert!(
            seeded.narrowing.actor_ceiling.deny_all,
            "with no live Grant the ceiling is the key's own deny-all floor: {:?}",
            seeded.narrowing
        );
    }
    Ok(())
}
