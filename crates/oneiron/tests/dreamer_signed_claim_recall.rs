//! FIX row DREAMER-MESO-CLAIM-RECALL-MISS: a belief the Dreamer lands is signed by the engine's MACHINE
//! writer (its evidence carries `machine_signature`), and an agent within its read Grant recalls it by its own
//! words, as the owner does. The promotion writer indexes the claim's words in its birth batch so that "an
//! agent's recall finds the belief the pass landed" (dreamer_promotion/writer.rs).
//!
//! On main an agent's recall serves no item for it: recall's CLAIM item reads the body the typed Nulled rule
//! releases (ruling EXPORTDOORS Q4 = A), that rule nulls the evidence's binary ids and proof, and a changed
//! proof-bound body is withheld whole, so the item is dropped. The bench's r5 rerun r7b (main 89577b6adac6)
//! found 0 of 5 Dreamer-landed claims this way. An owner-written claim in the same vault is the control: the
//! agent recalls it on main and on the head.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test
//! dreamer_signed_claim_recall`.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use oneiron::dreamer_promotion::promote_consolidated_claims;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{ClaimInput, Effort, MemoryItem, RecallScope};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::dreamer_promotion_seconds::{candidate, promotion_run};
use oneiron::test_doors::dreamer_signed_claim_recall::permit_dreamer_auto_promotion;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, Vault, VaultConfig};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const DREAMER_PREDICATE: &str = "work.role";
const DREAMER_VALUE: &str = "account manager at Brannock Composites";
const OWNER_PREDICATE: &str = "office.extension";
const OWNER_VALUE: &str = "quillfeather extension 4417";

/// A served vault whose engine MACHINE writers hold signers, whose policy grants the Dreamer's Auto
/// request, and whose agent holds a live read Grant over every row band.
struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    agent: EntityId,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::default();
        config.dimensions = 4;
        config.embedding_model = Some("test/model@v1".to_owned());
        let vault = Vault::open(dir.path(), config)?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let issuer = HostSlipIssuer::from_secret(b"dreamer-signed-claim-recall-host")?;
        vault.ensure_host_root_slip(&issuer)?;
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        // As a host does after its root slip on each open: the engine's MACHINE writers get their keys
        // and the handle retains their signers, so the Dreamer's promotions are signed.
        vault.provision_engine_machine_identities(&issuer)?;
        permit_dreamer_auto_promotion(&vault)?;
        let owner_proof =
            vault.authenticate_owner(owner, "principal:owen", true, GateDecisionId::now())?;

        let agent = EntityId::now();
        create_agent_definition_as(
            &vault,
            &owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition: serde_json::from_value(json!({
                    "agent_id": "dreamer_belief_reader",
                    "desc": "Read-only recall of the Dreamer's beliefs",
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
        Ok(Self {
            vault,
            _dir: dir,
            owner,
            agent,
        })
    }

    /// Lands one Dreamer claim through the promotion writer and checks that it is Active, Auto and
    /// signed by the engine's MACHINE writer.
    fn land_dreamer_claim(&self) -> TestResult<EntityId> {
        let run = promotion_run(&self.vault)?;
        let claim = candidate(&run, DREAMER_PREDICATE, DREAMER_VALUE, None);
        let id = claim.claim_id;
        let outcome = promote_consolidated_claims(&self.vault, &run.run, vec![claim])?;
        assert_eq!(
            outcome.landed,
            vec![id],
            "the Dreamer's claim lands Auto: {outcome:?}"
        );
        let stored = self
            .vault
            .get_claim(&id)?
            .expect("the landed claim decodes as a CLAIM");
        assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
        assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
        let signed = matches!(&stored.evidence, Some(Value::Map(entries))
            if entries.iter().any(|(key, _)| key.as_str() == Some("machine_signature")));
        assert!(
            signed,
            "the engine's MACHINE writer signed the landed claim: its evidence carries machine_signature"
        );
        Ok(id)
    }

    /// Writes the owner's own claim, unsigned, as the control.
    fn write_owner_claim(&self) -> TestResult<EntityId> {
        let id = EntityId::now();
        let written = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .claim_upsert(&ClaimInput {
                id: Some(id.to_hex()),
                predicate: OWNER_PREDICATE.to_owned(),
                subject_ref: self.owner.to_hex(),
                value: json!(OWNER_VALUE),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: None,
                valid_from: None,
                valid_to: None,
                occurred_at: None,
                learned_at: None,
                salience: None,
                confidence_details: None,
            })?;
        assert_eq!(written.approval, "auto", "the owner's claim lands Auto");
        Ok(id)
    }

    /// The Light recall `reader` gets for `query`, limit 20, as the bench's proof asks.
    fn recall(
        &self,
        reader: EntityId,
        class: EdgeActorClass,
        query: &str,
    ) -> TestResult<Vec<MemoryItem>> {
        let pack = self.vault.memory(reader, class).recall(
            query,
            Effort::Light,
            &RecallScope::default(),
            20,
            None,
            None,
        )?;
        Ok(pack.items)
    }
}

/// The item recall serves for the CLAIM `id`, found by the revision its provenance names.
fn item_of<'a>(items: &'a [MemoryItem], id: &EntityId) -> Option<&'a MemoryItem> {
    items
        .iter()
        .find(|item| item.provenance.source_revision_ids.contains(&id.to_hex()))
}

fn served(items: &[MemoryItem]) -> Vec<(String, Option<String>)> {
    items
        .iter()
        .map(|item| (item.kind.clone(), item.predicate.clone()))
        .collect()
}

#[test]
fn an_agent_recalls_the_dreamers_signed_claim_by_its_own_words() -> TestResult {
    let fixture = Fixture::new()?;
    let dreamer_claim = fixture.land_dreamer_claim()?;
    let owner_claim = fixture.write_owner_claim()?;
    let dreamer_query = format!("{DREAMER_VALUE} {DREAMER_PREDICATE}");
    let owner_query = format!("{OWNER_VALUE} {OWNER_PREDICATE}");

    for (reader, class, who) in [
        (fixture.owner, EdgeActorClass::Human, "the owner"),
        (fixture.agent, EdgeActorClass::Agent, "the agent"),
    ] {
        // The control: the owner's unsigned claim reaches this reader's recall.
        let items = fixture.recall(reader, class, &owner_query)?;
        assert!(
            item_of(&items, &owner_claim).is_some(),
            "{who}'s Light recall finds the owner's claim by its own words; served {:?}",
            served(&items)
        );

        let items = fixture.recall(reader, class, &dreamer_query)?;
        let item = item_of(&items, &dreamer_claim).unwrap_or_else(|| {
            panic!(
                "{who}'s Light recall finds the Dreamer's signed claim by its own words; served {:?}",
                served(&items)
            )
        });
        assert_eq!(item.kind, "CLAIM");
        assert_eq!(item.predicate.as_deref(), Some(DREAMER_PREDICATE));
        assert!(
            item.value_text.contains("Brannock Composites"),
            "{who} is served the claim's value: {:?}",
            item.value_text
        );
    }
    Ok(())
}
