//! [GRANT-READER-BM25-DF-COUNTS-HIDDEN-WORLDS]: a key with no proof, no
//! Scope and no owner, such as an embedded agent's own identity lane, reads
//! a row its own floor refuses through one of its actor's own live Grants
//! alone (FIX 7462). Before, no world ceiling stood on such a key, so the
//! BM25 statistics of its reads counted the postings of claims in a world
//! every one of its Grants leaves out, though no door served it one. A word
//! those claims hold then weighed less in the agent's own ranking, so which
//! of its readable claims led said whether that word sits in a world it
//! cannot read (DEC-0005: such a row has no name and no count). The
//! credential-backed lane has been held to its Grants' worlds since
//! [WORLD-SCOPE-BM25-DF-COUNTS-HIDDEN-POSTINGS] (#10062).
//!
//! Its receipts counted such a claim the same way: a withheld row it counts
//! said a row exists there (DEC-0005: hidden worlds stay hidden, no name, no
//! count).
//!
//! A world one of its Grants reaches hides nothing: the claims there are
//! served and counted.
//!
//! The agent fixture is `tests/world_scope_bm25_hidden_postings.rs`'s, with
//! no credential, through its test doors: run the file with
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test grant_reader_bm25_hidden_worlds`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, Effort, RecallScope, ScopedClaimInput,
};
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
/// Sensitivity band 0, Public: the world axis alone keeps the second
/// world's claims from the agent's Grant.
const PUBLIC_BAND: u8 = 0;

/// Which worlds the agent's one Grant reads.
#[derive(Clone, Copy)]
enum GrantWorlds {
    /// Base reality alone: the second world's claims are no row of the
    /// agent's.
    BaseOnly,
    /// Base reality and the second world: the agent reads its claims.
    BaseAndSecond,
}

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    second_world: EntityId,
    agent: EntityId,
}

/// A rooted vault with a second world, and an agent whose one Grant reads
/// `grant_worlds` (`tests/world_scope_bm25_hidden_postings.rs`'s fixture).
/// The agent holds no credential: it reads on its own identity lane.
fn fixture(grant_worlds: GrantWorlds) -> Fixture {
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
            "World the agent's Grant may leave out",
            OCCURRED_AT,
        )
        .expect("owner creates the second world");

    let agent = create_enabled_agent(&vault, &owner_proof, "grant_reader_bm25_agent");
    let mut worlds = BTreeSet::from([ScopeId(base_world_id())]);
    if matches!(grant_worlds, GrantWorlds::BaseAndSecond) {
        worlds.insert(ScopeId(second_world));
    }
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(worlds);
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
        },
    )
    .expect("owner mints the agent its read Grant");
    assert!(minted.grant.confers, "FIXTURE: the agent's Grant confers");
    Fixture {
        vault,
        _dir: dir,
        owner,
        owner_proof,
        second_world,
        agent,
    }
}

/// The agent's own identity key, as its memory lane builds one with no
/// credential (`memory/read_lane.rs`, `base_identity_read_key_in_txn`):
/// no proof, no Scope, not the owner's, so a row its floor refuses is read
/// through its own live Grants alone.
fn agent_identity_key(fixture: &Fixture) -> ScopedReadActorKey {
    ScopedReadActorKey::with_actor_class(
        fixture.agent.to_hex(),
        EdgeActorClass::Agent.gate_actor_class(),
    )
    .expect("the agent's identity key")
    .require_access_grants(Some(fixture.agent))
}

/// The claims of `claims` the agent's memory recall serves for [`QUERY`]
/// (Light effort) on its own identity lane, with no credential, in rank
/// order, each found by the revision its item's provenance names.
fn agent_recall_order(fixture: &Fixture, claims: &BTreeSet<EntityId>) -> Vec<EntityId> {
    fixture
        .vault
        .memory(fixture.agent, EdgeActorClass::Agent)
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

/// The rows the agent's pack under its identity key serves for [`QUERY`],
/// in rank order. It blends no recency.
fn agent_pack_order(fixture: &Fixture) -> Vec<EntityId> {
    let read = fixture.vault.scoped_read(agent_identity_key(fixture));
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

/// The rows the agent's scoped text search under its identity key serves
/// for [`QUERY`], in rank order.
fn agent_search_order(fixture: &Fixture) -> Vec<EntityId> {
    fixture
        .vault
        .scoped_read(agent_identity_key(fixture))
        .search_text(QUERY, 10, None)
        .expect("the agent's search")
        .value
        .into_iter()
        .map(|hit| hit.id)
        .collect()
}

/// The agent's memory recall with no credential: the recall pack's
/// statistics counted the second world's postings, as no world ceiling
/// stood on its identity key, so [`RARE`] became the commoner word and a
/// [`COMMON`] claim led.
#[test]
fn an_agent_identity_recall_ranks_alike_with_claims_of_a_world_its_grant_leaves_out() {
    let fixture = fixture(GrantWorlds::BaseOnly);
    let (rare, readable) = put_readable_claims(&fixture);
    let without = agent_recall_order(&fixture, &readable);
    assert_eq!(
        (
            without.first(),
            without.iter().copied().collect::<BTreeSet<_>>()
        ),
        (Some(&rare), readable.clone()),
        "FIXTURE: the agent's recall serves every readable claim through its Grant, the rarer \
         word's first"
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
        "FAILBEFORE GRANT-READER-BM25-DF-COUNTS-HIDDEN-WORLDS: claims of a world every Grant of \
         the agent leaves out count in no word's document frequency on its identity lane, so the \
         rarer readable word's claim still leads its recall"
    );
}

/// The agent's pack under its identity key, the same way.
#[test]
fn an_agent_identity_pack_ranks_alike_with_claims_of_a_world_its_grant_leaves_out() {
    let fixture = fixture(GrantWorlds::BaseOnly);
    let (rare, readable) = put_readable_claims(&fixture);
    let without = agent_pack_order(&fixture);
    assert_eq!(
        (
            without.first(),
            without.iter().copied().collect::<BTreeSet<_>>()
        ),
        (Some(&rare), readable.clone()),
        "FIXTURE: the agent's pack serves every readable claim through its Grant, the rarer \
         word's first"
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
        "FAILBEFORE GRANT-READER-BM25-DF-COUNTS-HIDDEN-WORLDS: claims of a world every Grant of \
         the agent leaves out count in no word's document frequency under its identity key, so \
         the rarer readable word's claim still leads its pack"
    );
}

/// The agent's scoped text search under its identity key, the same way.
#[test]
fn an_agent_identity_text_search_ranks_alike_with_claims_of_a_world_its_grant_leaves_out() {
    let fixture = fixture(GrantWorlds::BaseOnly);
    let (rare, readable) = put_readable_claims(&fixture);
    let without = agent_search_order(&fixture);
    assert_eq!(
        (
            without.first(),
            without.iter().copied().collect::<BTreeSet<_>>()
        ),
        (Some(&rare), readable.clone()),
        "FIXTURE: the agent's search serves every readable claim through its Grant, the rarer \
         word's first"
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
        "FAILBEFORE GRANT-READER-BM25-DF-COUNTS-HIDDEN-WORLDS: claims of a world every Grant of \
         the agent leaves out count in no word's document frequency under its identity key, so \
         the rarer readable word's claim still leads its search"
    );
}

/// The agent's receipt under its identity key: `edges_out` adds a withheld
/// centre to its receipt's suppressed count, and a claim of a world the
/// agent's Grant leaves out was such a centre, so the count said a row exists
/// in that world.
#[test]
fn an_agent_identity_receipt_counts_no_claim_of_a_world_its_grant_leaves_out() {
    let fixture = fixture(GrantWorlds::BaseOnly);
    let base = put_text_claim(&fixture, None, COMMON);
    let hidden = put_text_claim(&fixture, Some(fixture.second_world), RARE);
    let read = fixture.vault.scoped_read(agent_identity_key(&fixture));
    let readable = read
        .edges_out(&base)
        .expect("the agent's edges of a base claim");
    assert!(
        readable.value.is_some(),
        "FIXTURE: the agent reads a base claim through its Grant"
    );
    let withheld = read
        .edges_out(&hidden)
        .expect("the agent's edges of a second-world claim");
    assert!(
        withheld.value.is_none(),
        "FIXTURE: the agent reads no claim of the second world"
    );
    assert_eq!(
        withheld.receipt.suppressed_count, 0,
        "FAILBEFORE GRANT-READER-BM25-DF-COUNTS-HIDDEN-WORLDS: a claim of a world every Grant of \
         the agent leaves out has no count in its receipt under its identity key"
    );
}

/// Guard: a world the agent's Grant reaches keeps nothing from it. Its
/// identity lane's recall serves the second world's claims and counts them,
/// so with them [`RARE`] is the commoner word and a [`COMMON`] claim leads.
/// Passes before and after the fix.
#[test]
fn an_agent_identity_recall_counts_the_claims_of_a_world_its_grant_reaches() {
    let fixture = fixture(GrantWorlds::BaseAndSecond);
    let (rare, readable) = put_readable_claims(&fixture);
    let without = agent_recall_order(&fixture, &readable);
    assert_eq!(
        (
            without.first(),
            without.iter().copied().collect::<BTreeSet<_>>()
        ),
        (Some(&rare), readable.clone()),
        "FIXTURE: the agent's recall serves every base claim through its Grant, the rarer word's \
         first"
    );
    let hidden = put_hidden_claims(&fixture);
    let every: BTreeSet<EntityId> = readable.union(&hidden).copied().collect();
    let with = agent_recall_order(&fixture, &every);
    assert!(
        hidden.iter().any(|claim| with.contains(claim)),
        "FIXTURE: the agent's recall serves the claims of the second world its Grant reads"
    );
    assert!(
        with.first()
            .is_some_and(|first| first != &rare && readable.contains(first)),
        "the second world's claims count in the agent's document frequency: a commoner-word \
         base claim leads, {with:?}"
    );
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
