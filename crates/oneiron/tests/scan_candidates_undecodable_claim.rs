//! [SCAN-CANDIDATES-UNDECODABLE-CLAIM-TEST]: a live CLAIM whose stored body
//! does not decode is no candidate of a scoped text scan, and it does not end
//! the scan (`ScopedRead::scan_candidates_in`, #10111 round-1 fix 4). An
//! agent's credential key, which reads under the delegated relationship
//! gate, runs `vault.search` twice: filtered on the vault
//! (`Vault::search_text_scoped_observed`) and in a room
//! (`memory::scoped_session_text`). Each meets one such row, holding the
//! query's final token, beside a readable match for the other term, and
//! each serves the readable match. Before the fix, the row gate decoded the
//! damaged body for the relationship gate and the search failed.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test scan_candidates_undecodable_claim`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::code_run::{
    HostSelfDispatcher, SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfMemorySearchCall,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, ReadFilterInput, ScopedClaimInput,
};
use oneiron::off_record::OffRecordBackendClass;
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::test_doors::claim_body_damage::damage_stored_claim_body;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};
use serde_json::json;

const READABLE_WORD: &str = "kestrel";
/// The query's final token: only the damaged claim holds it.
const DAMAGED_WORD: &str = "lantern";
const QUERY: &str = "kestrel lantern";
const SEARCH_LIMIT: usize = 10;
const PUBLIC_BAND: u8 = 0;
const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:scan-candidates-undecodable-claim";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    facet: EntityId,
}

// Rooted machine/profile and owner setup copied from scoped_bm25_no_count_postings.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let facet = vault.default_facet().expect("owner default facet");
    Fixture {
        vault,
        _dir: dir,
        issuer,
        owner,
        owner_proof,
        facet,
    }
}

/// An owner-written, surfaceable claim in the base world and the owner's
/// default facet, with `text` indexed as its body.
fn put_text_claim(fixture: &Fixture, text: &str) -> EntityId {
    let vault = &fixture.vault;
    let subject = EntityId::now();
    let at = TimeRange {
        start: OCCURRED_AT,
        end: OCCURRED_AT,
    };
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            at,
            OCCURRED_AT,
            &rmp_serde::to_vec_named(&json!({ "name": "Wren" })).expect("FIXTURE: name body"),
        )
        .expect("FIXTURE: the claim's PERSON subject");
    let id = EntityId::now();
    vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_owner_authorship(&fixture.owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: subject.to_hex(),
            value: json!("violet quarry"),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: fixture.facet.to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            }
            .into(),
            sensitivity: Some(PUBLIC_BAND),
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(OCCURRED_AT),
            learned_at: Some(OCCURRED_AT),
            salience: None,
        })
        .expect("FIXTURE: owner writes the claim");
    let landed = vault
        .get_claim(&id)
        .expect("FIXTURE: read the landed claim")
        .expect("FIXTURE: claim was stored");
    assert!(
        matches!(
            landed.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ),
        "FIXTURE: the claim lands surfaceable, never Proposed"
    );
    vault
        .batch()
        .text(&id, &[("body", text)])
        .commit()
        .expect("FIXTURE: index the claim's text");
    id
}

/// Damages `claim`'s stored body and checks that only the body changed.
fn damage(fixture: &Fixture, claim: EntityId) {
    damage_stored_claim_body(&fixture.vault, claim).expect("FIXTURE: damage the claim's body");
    assert!(
        !matches!(fixture.vault.get_claim(&claim), Ok(Some(_))),
        "GUARD: the damaged body no longer reads as a claim"
    );
    assert!(
        fixture
            .vault
            .search_text(DAMAGED_WORD, SEARCH_LIMIT)
            .expect("GUARD: the owner's unscoped search for the damaged claim's word")
            .iter()
            .any(|hit| hit.id == claim),
        "GUARD: the damaged claim keeps its text posting"
    );
}

/// An enabled agent with one read Grant over the base world and the owner's
/// default facet, and the credential key its paired slip resolves to.
fn reader(fixture: &Fixture) -> (EntityId, ScopedReadActorKey) {
    let agent = create_enabled_agent(&fixture.vault, &fixture.owner_proof);
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    scope.facets = ScopeAxis::Some(BTreeSet::from([ScopeId(fixture.facet)]));
    // The Grant is minted before pairing, so pairing adds no all-covering
    // default Grant.
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
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
    .expect("owner mints the agent's read Grant");
    assert!(minted.grant.confers, "FIXTURE: the agent's Grant confers");
    let proof = paired_agent_slip(fixture, agent);
    let key = fixture
        .vault
        .credential_read_key(&proof)
        .expect("agent credential read key")
        .expect("agent credential grants read");
    (agent, key)
}

fn create_enabled_agent(vault: &Vault, owner_proof: &AuthenticatedOwner) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "scan_candidates_undecodable_reader",
                "desc": "Scoped text reader",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled, active agent definition");
    agent
}

// The template's possession-verified pairing, with no caveat.
fn paired_agent_slip(fixture: &Fixture, agent: EntityId) -> VerifiedSlip {
    let vault = &fixture.vault;
    let issuer = &fixture.issuer;
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let holder = agent.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            issuer,
            &fixture.owner_proof,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("owner issues the agent's pairing link");
    let signing_key = SigningKey::from_bytes(&[0x6b; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &holder,
        link.pin.as_ref(),
    )
    .expect("agent pairing transcript");
    let slip = vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("agent redeems its pairing link");
    let signature = signing_key
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("agent request transcript"),
        )
        .to_bytes();
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, REQUEST_CHALLENGE, &signature)
        .expect("paired agent proves possession of its credential")
}

/// The ids the run's `vault.search` for [`QUERY`] serves through
/// `dispatcher` under `filter`, or the search's error.
fn searched_ids(
    dispatcher: &HostSelfDispatcher<'_>,
    filter: Option<ReadFilterInput>,
) -> oneiron::Result<BTreeSet<EntityId>> {
    let call = SelfMemorySearchCall::new(QUERY, SEARCH_LIMIT).with_read_filter(filter);
    match dispatcher.dispatch(SelfCall::MemorySearch(call))? {
        SelfDispatchOutcome::MemorySearch(found) => {
            Ok(found.results.iter().map(|hit| hit.id).collect())
        }
        other => panic!("FIXTURE: the run's search must answer with hits, got {other:?}"),
    }
}

/// A caller filter that keeps every CLAIM: it sends the vault's keyed
/// search through the scoped scan (FIX 3977) and narrows nothing here.
fn claims_only() -> ReadFilterInput {
    ReadFilterInput {
        entity_types: Some(BTreeSet::from([ENTITY_TYPE_CLAIM])),
        ..Default::default()
    }
}

/// Runs `search` before and after the damaged claim's body is damaged.
fn assert_damaged_claim_skipped(
    fixture: &Fixture,
    search: impl Fn() -> oneiron::Result<BTreeSet<EntityId>>,
    path: &str,
) {
    let readable = put_text_claim(fixture, READABLE_WORD);
    let damaged = put_text_claim(fixture, DAMAGED_WORD);
    assert_eq!(
        search().expect("FIXTURE: the reader's search before the damage"),
        BTreeSet::from([readable, damaged]),
        "FIXTURE: {path}: the reader's search serves both claims before the damage"
    );
    damage(fixture, damaged);
    let found = search().unwrap_or_else(|error| {
        panic!(
            "FAILBEFORE SCAN-CANDIDATES-UNDECODABLE-CLAIM-TEST: {path}: a CLAIM whose body does \
             not decode ends the scoped scan: {error}"
        )
    });
    assert_eq!(
        found,
        BTreeSet::from([readable]),
        "{path}: the search serves the readable match and passes over the damaged claim"
    );
}

#[test]
fn a_filtered_vault_search_skips_an_undecodable_claim() {
    let fixture = fixture();
    let (agent, key) = reader(&fixture);
    let dispatcher = HostSelfDispatcher::new(
        &fixture.vault,
        WriteActor::new(agent, EdgeActorClass::Agent),
        "scan-candidates-undecodable-claim-vault",
    )
    .expect("FIXTURE: the reader binds a run to the vault")
    .with_agent_verb_door(Arc::new(SearchOnlyReader(key)));
    assert_damaged_claim_skipped(
        &fixture,
        || searched_ids(&dispatcher, Some(claims_only())),
        "the filtered vault search",
    );
}

#[test]
fn a_room_search_skips_an_undecodable_claim() {
    let fixture = fixture();
    let (agent, key) = reader(&fixture);
    let session = fixture
        .vault
        .off_record_session_vault()
        .enter(
            "scan-candidates-undecodable-claim",
            OffRecordBackendClass::Local,
        )
        .expect("FIXTURE: an off-record stretch with an overlay over base");
    let dispatcher = HostSelfDispatcher::for_off_record_session(
        &session,
        WriteActor::new(agent, EdgeActorClass::Agent),
        "scan-candidates-undecodable-claim-room",
    )
    .expect("FIXTURE: the reader binds a run to the live stretch")
    .with_agent_verb_door(Arc::new(SearchOnlyReader(key)));
    assert_damaged_claim_skipped(
        &fixture,
        || searched_ids(&dispatcher, None),
        "the room search",
    );
}

// A host door admits only the run's own search with the reader's key. It
// forwards no SDK verb and grants no write authority.
struct SearchOnlyReader(ScopedReadActorKey);

impl oneiron::code_run::AgentVerbDoor for SearchOnlyReader {
    fn call(
        &self,
        _call: &oneiron::code_run::SelfAgentVerbCall,
        _origin: &oneiron::memory::HostWriteOrigin,
        _invocation: oneiron::runtime_hooks::InvocationId,
    ) -> oneiron::Result<
        Result<oneiron::code_run::AgentVerbAnswer, oneiron::code_run::AgentVerbRefusal>,
    > {
        panic!("GUARD: the fixture forwards no SDK verb");
    }

    fn admit_run_call(
        &self,
        call: oneiron::code_run::RunCall,
    ) -> Result<Option<ScopedReadActorKey>, oneiron::code_run::AgentVerbRefusal> {
        match call {
            oneiron::code_run::RunCall::Bridge(oneiron::code_run::SelfEffect::MemorySearch) => {
                Ok(Some(self.0.clone()))
            }
            _ => Err(oneiron::code_run::AgentVerbRefusal {
                code: "fixture_search_only".to_owned(),
                hook_notice: None,
            }),
        }
    }
}
