//! An agent that reads through one of its own live Grants reads only the
//! records inside that Grant's facets (FIX-LIST AGENT-GRANT-PATH-NO-FACETS;
//! owner ruling FACET-READ = A, ARCH-0072 #boundary: "The scope may carry an
//! opt-in limit of one or more facets. The actor then reads only those
//! facets' records").
//!
//! The agent's identity key carries no credential and no room, so no facet
//! limit of its own; the read admits a row through the agent's Grant, which
//! judges the row's record position. That position names no facet, so the
//! Grant's own facets must be judged as well. A Grant over every facet reads
//! as before, and an agent with no Grant reads nothing.
//!
//! On main the facet-limited agent reads the row: the Grant path checks the
//! position alone (`own_row_under_grant_in`), and the per-row alternative
//! check runs under a Grant only for a key that names its holder (#8340).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test agent_grant_read_facets`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::authority::ActSurface;
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND,
    ScopedClaimInput,
};
use oneiron::registry::ENTITY_TYPE_CLAIM;
use oneiron::test_doors::coach::{define_agent, write_root_goal};
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::json;

const OCCURRED_AT: u64 = 1_769_947_200;

/// A vault, its owner's id and proof, and its root project.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    project: EntityId,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
        let owner_proof = owner(&vault).expect("owner proof");
        let owner = vault.ensure_embedded_owner_actor().expect("owner id");
        let project = write_root_goal(&vault, &owner_proof).expect("goal");
        Self {
            _dir: dir,
            vault,
            owner,
            owner_proof,
            project,
        }
    }

    fn project_band(&self) -> u8 {
        self.vault.project_type_byte().expect("project type")
    }

    /// A fresh agent with no Grant.
    fn agent(&self) -> EntityId {
        define_agent(&self.vault).expect("an agent")
    }

    /// A fresh agent holding the owner's live `read` Grant over rows of type
    /// `band` placed in `facets` alone; every other axis covers every row.
    fn reader_of_in(&self, band: u8, facets: ScopeAxis<ScopeId>) -> EntityId {
        let agent = self.agent();
        let mut authority_scope = Scope::top();
        authority_scope.bands = ScopeAxis::Some(BTreeSet::from([band]));
        authority_scope.facets = facets;
        authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
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
            },
        )
        .expect("the owner's read Grant");
        assert!(minted.grant.confers, "the Grant confers");
        agent
    }

    /// The owner's CLAIM in the base world and the vault's default facet.
    fn owner_claim(&self) -> EntityId {
        let id = EntityId::now();
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .with_owner_authorship(&self.owner_proof)
            .claim_upsert_scoped(&ScopedClaimInput {
                id: Some(id.to_hex()),
                predicate: "profile.preference".to_owned(),
                subject_ref: self.owner.to_hex(),
                value: json!("tea"),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                scope: ClaimScope {
                    world_id: base_world_id().to_hex(),
                    scope_facet_id: self.default_facet().0.to_hex(),
                    scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                    scope_project_id: default_project_id().to_hex(),
                },
                sensitivity: None,
                evidence_turn_refs: Vec::new(),
                valid_from: None,
                valid_to: None,
                occurred_at: Some(OCCURRED_AT),
                learned_at: Some(OCCURRED_AT),
                salience: None,
            })
            .expect("the owner writes a claim in the default facet");
        id
    }

    fn default_facet(&self) -> ScopeId {
        ScopeId(self.vault.default_facet().expect("owner default facet"))
    }

    /// Whether `agent`'s own read lane reads `record`: a withheld row reads
    /// as none, or as a not-found or forbidden refusal.
    fn agent_reads(&self, agent: EntityId, record: EntityId) -> bool {
        match self
            .vault
            .memory(agent, EdgeActorClass::Agent)
            .get_entity(&record.to_hex())
        {
            Ok(read) => read
                .value
                .is_some_and(|view| view.id_hex == record.to_hex()),
            Err(refused) => {
                assert!(
                    refused.code == MEMORY_CODE_NOT_FOUND || refused.code == MEMORY_CODE_FORBIDDEN,
                    "the read answers a row or withholds it: {refused:?}"
                );
                false
            }
        }
    }
}

/// A facet no row of the fixture sits in.
fn elsewhere() -> ScopeAxis<ScopeId> {
    ScopeAxis::Some(BTreeSet::from([ScopeId(EntityId::now())]))
}

#[test]
fn a_grant_over_every_facet_reads_the_project() {
    let fx = Fixture::new();
    let agent = fx.reader_of_in(fx.project_band(), ScopeAxis::All);
    assert!(
        fx.agent_reads(agent, fx.project),
        "the agent's own Grant over projects in every facet reads the project"
    );
    assert!(
        !fx.agent_reads(fx.agent(), fx.project),
        "an agent with no Grant reads nothing"
    );
}

#[test]
fn a_grant_limited_to_other_facets_reads_no_project() {
    let fx = Fixture::new();
    // Every axis of the Grant but the facets covers the project, which sits
    // in no facet the Grant names.
    let agent = fx.reader_of_in(fx.project_band(), elsewhere());
    assert!(
        !fx.agent_reads(agent, fx.project),
        "a row outside the facets of the agent's only Grant is not read"
    );
}

#[test]
fn a_grant_limited_to_a_claims_facet_reads_it_and_one_limited_elsewhere_does_not() {
    let fx = Fixture::new();
    let claim = fx.owner_claim();
    let inside = fx.reader_of_in(
        ENTITY_TYPE_CLAIM,
        ScopeAxis::Some(BTreeSet::from([fx.default_facet()])),
    );
    assert!(
        fx.agent_reads(inside, claim),
        "a Grant limited to the claim's own facet reads the claim"
    );
    let outside = fx.reader_of_in(ENTITY_TYPE_CLAIM, elsewhere());
    assert!(
        !fx.agent_reads(outside, claim),
        "a Grant limited to another facet does not"
    );
}
