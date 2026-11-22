//! [WORLD-SCOPE-BM25-DF-COUNTS-HIDDEN-POSTINGS]: under a world scope, a row
//! the reader may not read counts in no word's BM25 document frequency, as
//! under a disclosure clamp (#9980). Before, an agent whose Grant reads the
//! base world was served none of a second world's claims, but their postings
//! still counted in each word's document frequency. A word those claims
//! hold then weighed less in the agent's own ranking, so which of its
//! readable claims led said whether that word sits in a world it cannot
//! read (DEC-0005: such a row has no name and no count). The document count
//! and the fields' average lengths stay the vault's (Engine ANSWER
//! D19-CLAMP-BM25-CORPUS-STATS = A).
//!
//! A world the reader only leaves out of its selection hides nothing: the
//! owner's base-world pack still counts the second world's postings.
//!
//! The agent fixture is `tests/phonetic_exact_hits_scoped.rs`'s, through its
//! test doors: run the file with `RUSTFLAGS="--cfg oneiron_test_support"
//! cargo test --locked -p oneiron --all-features --test
//! world_scope_bm25_hidden_postings`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, Effort, RecallScope, ScopedClaimInput,
};
use oneiron::pipeline::WorldScope;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

/// The query's rarer word: one readable claim holds it, and the second
/// world's claims hold it too.
const RARE: &str = "kestrel";
/// The query's commoner word among the readable claims.
const COMMON: &str = "lantern";
/// Both words; the last is the commoner readable word, so its prefix
/// expansion reads only readable claims.
const QUERY: &str = "kestrel lantern";
/// Readable claims holding [`COMMON`].
const COMMON_CLAIMS: usize = 3;
/// Second-world claims holding [`RARE`]: counted, they make it the commoner
/// word, so a [`COMMON`] claim outranks the [`RARE`] one.
const HIDDEN_CLAIMS: usize = 8;
const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:world-scope-bm25-hidden-postings";
/// Sensitivity band 0, Public: the world axis alone keeps the second
/// world's claims from the agent.
const PUBLIC_BAND: u8 = 0;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    second_world: EntityId,
    agent: EntityId,
    agent_slip: VerifiedSlip,
    agent_key: ScopedReadActorKey,
}

/// A rooted vault with a second world, and an agent whose one Grant reads
/// the base world (`tests/phonetic_exact_hits_scoped.rs`'s fixture).
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let second_world = vault
        .create_world(
            &owner_proof,
            "World the agent's Grant leaves out",
            OCCURRED_AT,
        )
        .expect("owner creates the second world");

    let agent = create_enabled_agent(&vault, &owner_proof, "world_scope_bm25_agent");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        &vault,
        &owner_proof,
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
    .expect("owner mints the agent a base-world read Grant");
    assert!(minted.grant.confers, "FIXTURE: the agent's Grant confers");
    let agent_slip = paired_agent_slip(&vault, &issuer, &owner_proof, agent, 0x6b);
    let agent_key = vault
        .credential_read_key(&agent_slip)
        .expect("agent credential read key")
        .expect("agent credential grants read");
    Fixture {
        vault,
        _dir: dir,
        owner,
        owner_proof,
        second_world,
        agent,
        agent_slip,
        agent_key,
    }
}

/// The owner's Public claim in `world` (`None` is base reality), its text
/// `text` alone.
fn put_text_claim(fixture: &Fixture, world: Option<EntityId>, text: &str) -> EntityId {
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
                world_id: world.unwrap_or_else(base_world_id).to_hex(),
                scope_facet_id: vault.default_facet().expect("owner default facet").to_hex(),
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
    vault
        .batch()
        .text(&id, &[("body", text)])
        .commit()
        .expect("FIXTURE: index the claim's text");
    id
}

/// The readable claims: one holds [`RARE`], [`COMMON_CLAIMS`] hold
/// [`COMMON`]. Returns the [`RARE`] one and all of them.
fn put_readable_claims(fixture: &Fixture) -> (EntityId, BTreeSet<EntityId>) {
    let rare = put_text_claim(fixture, None, RARE);
    let mut readable = BTreeSet::from([rare]);
    for _ in 0..COMMON_CLAIMS {
        readable.insert(put_text_claim(fixture, None, COMMON));
    }
    (rare, readable)
}

/// [`HIDDEN_CLAIMS`] second-world claims holding [`RARE`], which the
/// owner's unscoped search reaches. Returns them.
fn put_hidden_claims(fixture: &Fixture) -> BTreeSet<EntityId> {
    let hidden: BTreeSet<EntityId> = (0..HIDDEN_CLAIMS)
        .map(|_| put_text_claim(fixture, Some(fixture.second_world), RARE))
        .collect();
    let owner_found = fixture
        .vault
        .query()
        .search_text(RARE, 20)
        .limit(20)
        .run()
        .expect("the owner's search")
        .len();
    assert_eq!(
        owner_found,
        1 + HIDDEN_CLAIMS,
        "FIXTURE: the owner's search finds the second world's claims"
    );
    hidden
}

/// The rows the agent's pack serves for [`QUERY`], in rank order. It blends
/// no recency.
fn agent_pack_order(fixture: &Fixture) -> Vec<EntityId> {
    let read = fixture.vault.scoped_read(fixture.agent_key.clone());
    let plan = read.context_pack_plan().expect("the agent's pack plan");
    let mut pack = plan
        .admit(fixture.vault.context_pack())
        .search_text(QUERY, 10)
        .boost_recency(0.0)
        .limit(10)
        .run()
        .expect("the agent's pack");
    read.filter_context_pack(&mut pack)
        .expect("the agent's filter");
    pack.results.iter().map(|entity| entity.id).collect()
}

/// The rows the agent's scoped text search serves for [`QUERY`], in rank
/// order.
fn agent_search_order(fixture: &Fixture) -> Vec<EntityId> {
    fixture
        .vault
        .scoped_read(fixture.agent_key.clone())
        .search_text(QUERY, 10, None)
        .expect("the agent's search")
        .value
        .into_iter()
        .map(|hit| hit.id)
        .collect()
}

/// The claims of `claims` the agent's memory recall under its credential
/// serves for [`QUERY`] (Light effort), in rank order, each found by the
/// revision its item's provenance names.
fn agent_recall_order(fixture: &Fixture, claims: &BTreeSet<EntityId>) -> Vec<EntityId> {
    fixture
        .vault
        .memory(fixture.agent, EdgeActorClass::Agent)
        .with_read_proof(&fixture.agent_slip)
        .recall(
            QUERY,
            Effort::Light,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .expect("the agent's recall")
        .items
        .iter()
        .filter_map(|item| {
            claims
                .iter()
                .find(|id| item.provenance.source_revision_ids.contains(&id.to_hex()))
                .copied()
        })
        .collect()
}

/// The rows the owner's base-world pack serves for [`QUERY`], in rank
/// order. It blends no recency.
fn owner_base_pack_order(fixture: &Fixture) -> Vec<EntityId> {
    fixture
        .vault
        .context_pack()
        .world(WorldScope::Base)
        .search_text(QUERY, 10)
        .boost_recency(0.0)
        .limit(10)
        .run()
        .expect("the owner's base-world pack")
        .results
        .iter()
        .map(|entity| entity.id)
        .collect()
}

/// The agent's pack: with the second world's claims counted, [`RARE`]
/// became the commoner word, and a [`COMMON`] claim led the pack.
#[test]
fn an_agent_pack_ranks_alike_with_claims_of_a_world_its_grant_leaves_out() {
    let fixture = fixture();
    let (rare, readable) = put_readable_claims(&fixture);
    let without = agent_pack_order(&fixture);
    assert_eq!(
        (
            without.first(),
            without.iter().copied().collect::<BTreeSet<_>>()
        ),
        (Some(&rare), readable.clone()),
        "FIXTURE: the agent's pack serves every readable claim, the rarer word's first"
    );
    put_hidden_claims(&fixture);
    let with = agent_pack_order(&fixture);
    assert_eq!(
        with.iter().copied().collect::<BTreeSet<_>>(),
        readable,
        "FIXTURE: the agent's pack serves no claim of the second world"
    );
    assert_eq!(
        with.first(),
        Some(&rare),
        "FAILBEFORE WORLD-SCOPE-BM25-DF-COUNTS-HIDDEN-POSTINGS: claims of a world the agent's \
         Grant leaves out count in no word's document frequency, so the rarer readable word's \
         claim still leads the agent's pack"
    );
}

/// The agent's scoped text search, the same way.
#[test]
fn an_agent_text_search_ranks_alike_with_claims_of_a_world_its_grant_leaves_out() {
    let fixture = fixture();
    let (rare, readable) = put_readable_claims(&fixture);
    let without = agent_search_order(&fixture);
    assert_eq!(
        (
            without.first(),
            without.iter().copied().collect::<BTreeSet<_>>()
        ),
        (Some(&rare), readable.clone()),
        "FIXTURE: the agent's search serves every readable claim, the rarer word's first"
    );
    put_hidden_claims(&fixture);
    let with = agent_search_order(&fixture);
    assert_eq!(
        with.iter().copied().collect::<BTreeSet<_>>(),
        readable,
        "FIXTURE: the agent's search serves no claim of the second world"
    );
    assert_eq!(
        with.first(),
        Some(&rare),
        "FAILBEFORE WORLD-SCOPE-BM25-DF-COUNTS-HIDDEN-POSTINGS: claims of a world the agent's \
         Grant leaves out count in no word's document frequency, so the rarer readable word's \
         claim still leads the agent's search"
    );
}

/// The agent's memory recall under its credential, whose read is held to its
/// Grant's worlds: the recall pack scored with every posting before, as it
/// named no reader to the pipeline.
#[test]
fn an_agent_recall_ranks_alike_with_claims_of_a_world_its_grant_leaves_out() {
    let fixture = fixture();
    let (rare, readable) = put_readable_claims(&fixture);
    let without = agent_recall_order(&fixture, &readable);
    assert_eq!(
        (
            without.first(),
            without.iter().copied().collect::<BTreeSet<_>>()
        ),
        (Some(&rare), readable.clone()),
        "FIXTURE: the agent's recall serves every readable claim, the rarer word's first"
    );
    let hidden = put_hidden_claims(&fixture);
    let every: BTreeSet<EntityId> = readable.union(&hidden).copied().collect();
    let with = agent_recall_order(&fixture, &every);
    assert_eq!(
        with.iter().copied().collect::<BTreeSet<_>>(),
        readable,
        "FIXTURE: the agent's recall serves no claim of the second world"
    );
    assert_eq!(
        with.first(),
        Some(&rare),
        "FAILBEFORE WORLD-SCOPE-BM25-DF-COUNTS-HIDDEN-POSTINGS: claims of a world the agent's \
         Grant leaves out count in no word's document frequency, so the rarer readable \
         word's claim still leads the agent's recall"
    );
}

/// Guard: a world the owner only leaves out of the pack's selection is no
/// refusal. Its claims count in the words' document frequency, so with the
/// second world's claims a [`COMMON`] claim leads the owner's base-world
/// pack. Passes before and after the fix.
#[test]
fn a_world_the_owner_only_leaves_out_of_the_selection_still_counts() {
    let fixture = fixture();
    let (rare, readable) = put_readable_claims(&fixture);
    let without = owner_base_pack_order(&fixture);
    assert_eq!(
        (
            without.first(),
            without.iter().copied().collect::<BTreeSet<_>>()
        ),
        (Some(&rare), readable.clone()),
        "FIXTURE: the owner's base-world pack serves every base claim, the rarer word's first"
    );
    put_hidden_claims(&fixture);
    let with = owner_base_pack_order(&fixture);
    assert_eq!(
        with.iter().copied().collect::<BTreeSet<_>>(),
        readable,
        "FIXTURE: the owner's base-world pack serves no claim of the second world"
    );
    assert_ne!(
        with.first(),
        Some(&rare),
        "the second world's claims count in the owner's document frequency: the commoner \
         word's claim leads"
    );
}

/// An enabled, active agent definition the owner creates as `agent_id`.
fn create_enabled_agent(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent_id: &str,
) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "World-scoped text reader",
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

/// The agent's paired credential, as `token_pair` mints it: only the verbs
/// axis narrows the pairing; the Grant imposes the world ceiling.
fn paired_agent_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner: &AuthenticatedOwner,
    agent: EntityId,
    binding_seed: u8,
) -> VerifiedSlip {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let holder = agent.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            issuer,
            owner,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("owner issues the agent's pairing link");
    let signing_key = SigningKey::from_bytes(&[binding_seed; 32]);
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
