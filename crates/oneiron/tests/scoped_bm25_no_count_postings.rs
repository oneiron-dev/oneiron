//! [SCOPED-BM25-DF-COUNTS-NON-WORLD-REFUSED-POSTINGS]: rows a scoped text
//! search refuses without a count contribute no BM25 document frequency.
//! Records and credential-facet refusals are opaque; a cross-axis Grant
//! refusal is counted (Suppressed) and must retain its postings in df.
//! Only df changes: the document count and average field lengths stay global.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test scoped_bm25_no_count_postings`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, SlipCaveat, VerifiedSlip,
};
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig,
};
use serde_json::json;

const RARE: &str = "kestrel";
const COMMON: &str = "lantern";
const QUERY: &str = "kestrel lantern";
const COMMON_CLAIMS: usize = 3;
const REFUSED_ROWS: usize = 8;
const PUBLIC_BAND: u8 = 0;
const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:scoped-bm25-no-count-postings";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    facet: EntityId,
}

// Rooted machine/profile and owner setup copied from world_scope_bm25_hidden_postings.
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

fn second_facet(fixture: &Fixture) -> EntityId {
    fixture
        .vault
        .create_facet(
            &fixture.owner_proof,
            fixture.owner,
            "Other facet",
            OCCURRED_AT,
        )
        .expect("owner creates F2")
}

fn read_scope(world: EntityId, facet: Option<EntityId>) -> Scope {
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(world)]));
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    if let Some(facet) = facet {
        scope.facets = ScopeAxis::Some(BTreeSet::from([ScopeId(facet)]));
    }
    scope
}

// Each Grant is minted before pairing, so pairing adds no all-covering default Grant.
fn reader_key(
    fixture: &Fixture,
    grants: &[Scope],
    caveat: Option<SlipCaveat>,
) -> ScopedReadActorKey {
    let agent = create_enabled_agent(&fixture.vault, &fixture.owner_proof);
    for authority_scope in grants {
        let minted = mint_agent_grant_as(
            &fixture.vault,
            &fixture.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope: authority_scope.clone(),
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("owner mints the agent's read Grant");
        assert!(minted.grant.confers, "FIXTURE: the agent's Grant confers");
    }
    let proof = paired_agent_slip(fixture, agent, caveat);
    fixture
        .vault
        .credential_read_key(&proof)
        .expect("agent credential read key")
        .expect("agent credential grants read")
}

// The template's owner claim writer, with explicit facet and a landed-status check.
fn put_text_claim(fixture: &Fixture, facet: EntityId, text: &str) -> EntityId {
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
                scope_facet_id: facet.to_hex(),
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
        "FIXTURE: every claim lands surfaceable, never Proposed"
    );
    assert_eq!(
        landed.scope_facet, facet,
        "FIXTURE: the claim's stored facet"
    );
    assert_eq!(
        vault
            .targets(&id, EdgeKind::FacetOf, None)
            .expect("FIXTURE: FacetOf edges"),
        vec![facet],
        "FIXTURE: each claim has real FacetOf placement in exactly its stated facet"
    );
    vault
        .batch()
        .text(&id, &[("body", text)])
        .commit()
        .expect("FIXTURE: index the claim's text");
    id
}

fn put_readable_claims(fixture: &Fixture) -> (EntityId, BTreeSet<EntityId>) {
    let rare = put_text_claim(fixture, fixture.facet, RARE);
    let mut readable = BTreeSet::from([rare]);
    for _ in 0..COMMON_CLAIMS {
        readable.insert(put_text_claim(fixture, fixture.facet, COMMON));
    }
    (rare, readable)
}

fn put_refused_claims(fixture: &Fixture, facet: EntityId) -> BTreeSet<EntityId> {
    (0..REFUSED_ROWS)
        .map(|_| put_text_claim(fixture, facet, RARE))
        .collect()
}

fn assert_indexed(fixture: &Fixture, rare: EntityId, refused: &BTreeSet<EntityId>) {
    let owner_found = fixture
        .vault
        .query()
        .search_text(RARE, 20)
        .limit(20)
        .run()
        .expect("FIXTURE: the owner's unscoped search");
    assert_eq!(
        owner_found.len(),
        1 + REFUSED_ROWS,
        "FIXTURE: the owner's search finds the readable RARE claim and all refused rows"
    );
    let mut expected = refused.clone();
    expected.insert(rare);
    assert_eq!(
        owner_found
            .iter()
            .map(|hit| hit.id)
            .collect::<BTreeSet<_>>(),
        expected,
        "FIXTURE: the refused rows themselves reached the text index"
    );
}

fn agent_search_order(fixture: &Fixture, key: &ScopedReadActorKey) -> Vec<EntityId> {
    fixture
        .vault
        .scoped_read(key.clone())
        .search_text(QUERY, 10, None)
        .expect("the agent's scoped text search")
        .value
        .into_iter()
        .map(|hit| hit.id)
        .collect()
}

fn assert_baseline(
    fixture: &Fixture,
    key: &ScopedReadActorKey,
    rare: EntityId,
    readable: &BTreeSet<EntityId>,
) {
    let without = agent_search_order(fixture, key);
    assert_eq!(
        (
            without.first(),
            without.iter().copied().collect::<BTreeSet<_>>()
        ),
        (Some(&rare), readable.clone()),
        "FIXTURE: before refused rows, the search serves exactly the readable set, RARE first"
    );
}

#[test]
fn records_caveat_refusals_contribute_no_document_frequency() {
    let fixture = fixture();
    let (rare, readable) = put_readable_claims(&fixture);
    let key = reader_key(
        &fixture,
        &[read_scope(base_world_id(), None)],
        Some(SlipCaveat {
            records: Some(readable.iter().map(EntityId::to_hex).collect()),
            ..Default::default()
        }),
    );
    assert_baseline(&fixture, &key, rare, &readable);
    let refused = put_refused_claims(&fixture, fixture.facet);
    assert_indexed(&fixture, rare, &refused);
    let with = agent_search_order(&fixture, &key);
    assert_eq!(
        with.iter().copied().collect::<BTreeSet<_>>(),
        readable,
        "FIXTURE: the records-caveated search serves exactly the readable set"
    );
    assert_eq!(
        with.first(),
        Some(&rare),
        "FAILBEFORE SCOPED-BM25-DF-COUNTS-NON-WORLD-REFUSED-POSTINGS: rows outside the \
         credential's records caveat have no count and contribute no df; RARE still leads"
    );
}

#[test]
fn credential_facet_refusals_contribute_no_document_frequency() {
    let fixture = fixture();
    let other_facet = second_facet(&fixture);
    let (rare, readable) = put_readable_claims(&fixture);
    let mut credential_scope = Scope::top();
    credential_scope.facets = ScopeAxis::Some(BTreeSet::from([ScopeId(fixture.facet)]));
    let key = reader_key(
        &fixture,
        &[read_scope(base_world_id(), None)],
        Some(SlipCaveat {
            scope: Some(credential_scope),
            ..Default::default()
        }),
    );
    assert_baseline(&fixture, &key, rare, &readable);
    let refused = put_refused_claims(&fixture, other_facet);
    assert_indexed(&fixture, rare, &refused);
    let with = agent_search_order(&fixture, &key);
    assert_eq!(
        with.iter().copied().collect::<BTreeSet<_>>(),
        readable,
        "FIXTURE: the F1 credential serves exactly the readable F1 set, no F2 row"
    );
    assert_eq!(
        with.first(),
        Some(&rare),
        "FAILBEFORE SCOPED-BM25-DF-COUNTS-NON-WORLD-REFUSED-POSTINGS: rows outside the \
         credential's facet ceiling have no count and contribute no df; RARE still leads"
    );
}

#[test]
fn suppressed_cross_axis_grant_refusals_keep_their_document_frequency() {
    let fixture = fixture();
    let other_facet = second_facet(&fixture);
    let other_world = fixture
        .vault
        .create_world(&fixture.owner_proof, "Other Grant world", OCCURRED_AT)
        .expect("owner creates W2 for the second Grant");
    let (rare, readable) = put_readable_claims(&fixture);
    let key = reader_key(
        &fixture,
        &[
            read_scope(base_world_id(), Some(fixture.facet)),
            read_scope(other_world, Some(other_facet)),
        ],
        None,
    );
    assert_baseline(&fixture, &key, rare, &readable);
    // W1/F2 is inside the key's envelope, but neither Grant alone admits it.
    // No conjunction in admit_with_held_in rejects this ordinary public claim:
    // the gate refuses it, and its admission classification is Suppressed.
    let refused = put_refused_claims(&fixture, other_facet);
    assert_indexed(&fixture, rare, &refused);
    let with = agent_search_order(&fixture, &key);
    assert_eq!(
        with.iter().copied().collect::<BTreeSet<_>>(),
        readable,
        "FIXTURE: the two-Grant search serves exactly the readable W1/F1 set, no W1/F2 row"
    );
    assert_ne!(
        with.first(),
        Some(&rare),
        "GUARD: a refused row the read counts (Suppressed) keeps its postings in df"
    );
}

fn create_enabled_agent(vault: &Vault, owner_proof: &AuthenticatedOwner) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "scoped_bm25_no_count_reader",
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

// Copy of the template's possession-verified pairing, attenuated before signing.
fn paired_agent_slip(
    fixture: &Fixture,
    agent: EntityId,
    caveat: Option<SlipCaveat>,
) -> VerifiedSlip {
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
    let mut slip = vault
        .redeem_pairing_link(
            issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("agent redeems its pairing link");
    // The slip is bound to the agent's key, so the agent attenuates it (a
    // host-key attenuation would not match its binding).
    if let Some(caveat) = caveat {
        slip.attenuate(caveat, &signing_key)
            .expect("the agent attenuates its own credential");
    }
    let signature = signing_key
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("agent request transcript"),
        )
        .to_bytes();
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, REQUEST_CHALLENGE, &signature)
        .expect("paired agent proves possession of its attenuated credential")
}
