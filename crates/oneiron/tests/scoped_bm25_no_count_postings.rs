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
                check_in_ref: None,
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

fn records_reader_proof(
    fixture: &Fixture,
    readable: &BTreeSet<EntityId>,
) -> (EntityId, VerifiedSlip) {
    let agent = create_enabled_agent(&fixture.vault, &fixture.owner_proof);
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: read_scope(base_world_id(), None),
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("FIXTURE: owner mints the credential reader's Grant");
    assert!(minted.grant.confers, "FIXTURE: the reader's Grant confers");
    let proof = paired_agent_slip(
        fixture,
        agent,
        Some(SlipCaveat {
            records: Some(readable.iter().map(EntityId::to_hex).collect()),
            ..Default::default()
        }),
    );
    (agent, proof)
}

// Return the vault after dropping the utterance so the same fixture can gain
// refused postings between its baseline and its next first warm result.
fn credential_speculative_order(
    vault: Vault,
    agent: EntityId,
    proof: &VerifiedSlip,
) -> (Vault, Vec<EntityId>) {
    use oneiron::memory::RecallScope;
    use oneiron::speculative::{
        SpeculativeFireDecision, SpeculativePartial, SpeculativeSessionConfig,
    };

    let vault = Arc::new(vault);
    let order = {
        let mut session = vault
            .memory(agent, EdgeActorClass::Agent)
            .with_read_proof(proof)
            .speculative_session(
                Arc::clone(&vault),
                SpeculativeSessionConfig {
                    max_fires: 1,
                    fire_limit: 10,
                    final_limit: 10,
                    ..Default::default()
                },
                &RecallScope::default(),
            )
            .expect("FIXTURE: credential-bound speculative utterance");
        let terms = [RARE.to_owned(), COMMON.to_owned()];
        let decision = session
            .observe_partial(SpeculativePartial {
                text: QUERY,
                query_vector: None,
                entity_labels: &[],
                salient_terms: &terms,
            })
            .expect("FIXTURE: first speculative pass succeeds");
        assert!(
            matches!(
                decision,
                SpeculativeFireDecision::Fired { partial: false, .. }
            ),
            "GUARD: the first partial fires a complete pass, with no deadline"
        );
        session
            .scoped_warm_candidates()
            .expect("FIXTURE: release the credential's first warm result")
            .value
            .into_iter()
            .map(|hit| hit.id)
            .collect()
    };
    let vault = Arc::try_unwrap(vault)
        .unwrap_or_else(|_| panic!("GUARD: the dropped utterance retains no vault Arc"));
    (vault, order)
}

#[test]
fn speculative_recall_skips_no_count_postings_in_df() {
    let fixture = fixture();
    let (rare, readable) = put_readable_claims(&fixture);
    let (agent, proof) = records_reader_proof(&fixture, &readable);
    let (vault, without) = credential_speculative_order(fixture.vault, agent, &proof);
    let fixture = Fixture { vault, ..fixture };
    assert_eq!(
        (
            without.first(),
            without.iter().copied().collect::<BTreeSet<_>>()
        ),
        (Some(&rare), readable.clone()),
        "FIXTURE: before refused rows, the speculative result serves exactly the readable set, \
         RARE first"
    );
    let refused = put_refused_claims(&fixture, fixture.facet);
    assert_indexed(&fixture, rare, &refused);
    let (_vault, with) = credential_speculative_order(fixture.vault, agent, &proof);
    assert_eq!(
        with.iter().copied().collect::<BTreeSet<_>>(),
        readable,
        "FIXTURE: the speculative result serves exactly the readable set, none of the eight \
         refused rows"
    );
    assert_eq!(
        with.first(),
        Some(&rare),
        "FAILBEFORE SCOPED-BM25-DF-COUNTS-NON-WORLD-REFUSED-POSTINGS speculative: \
         records-caveat refusals contribute no df, so the readable RARE claim still leads"
    );
}

fn deadline_recall_ids(
    fixture: &Fixture,
    agent: EntityId,
    proof: &VerifiedSlip,
    effort: oneiron::memory::Effort,
) -> BTreeSet<EntityId> {
    deadline_recall_ids_within(fixture, agent, proof, effort, 10)
}

fn deadline_recall_ids_within(
    fixture: &Fixture,
    agent: EntityId,
    proof: &VerifiedSlip,
    effort: oneiron::memory::Effort,
    limit: usize,
) -> BTreeSet<EntityId> {
    use oneiron::memory::RecallScope;
    use oneiron::retrieval_depth::{
        RecallExecution, RetrievalDeadline, still_deadline_clock_for_test,
    };
    use std::time::Duration;

    // Only this deadline captures the still clock; restore the thread's setting
    // immediately so it cannot affect the next test on this thread.
    let was_still = still_deadline_clock_for_test(true);
    let deadline = RetrievalDeadline::after(Duration::from_secs(60));
    still_deadline_clock_for_test(was_still);
    let pack = fixture
        .vault
        .memory(agent, EdgeActorClass::Agent)
        .with_read_proof(proof)
        .recall_with_execution(
            RARE,
            effort,
            &RecallScope::default(),
            limit,
            None,
            None,
            &RecallExecution {
                deadline: Some(&deadline),
                as_of: Some(OCCURRED_AT + 1),
                ..Default::default()
            },
        )
        .expect("FIXTURE: the credential's recall with a deadline succeeds");
    assert!(
        !deadline.was_cut_short() && !pack.retrieval_meta.partial,
        "GUARD: the generous still-clock deadline cuts no retrieval stage or pack"
    );
    pack.items
        .iter()
        .map(|item| {
            let (short, hash) = oneiron::entity_id::parse_short_ref_syntax(&item.short_id)
                .expect("FIXTURE: the pack's public short reference parses");
            fixture
                .vault
                .hydrate_short_id(short, hash)
                .expect("FIXTURE: resolve the pack item's identity")
                .expect("FIXTURE: the pack item names a stored row")
                .id
        })
        .collect()
}

#[test]
fn deadline_recall_seeds_readable_match_past_refused_rows() {
    use oneiron::memory::Effort;

    let fixture = fixture();
    // The sole readable text match is much longer than the refused TF=2 rows.
    let text = format!("{RARE} {}", "quartz ".repeat(32));
    let seed = put_text_claim(&fixture, fixture.facet, &text);
    let neighbour = put_text_claim(&fixture, fixture.facet, "harbourrope");
    let readable = BTreeSet::from([seed, neighbour]);
    fixture
        .vault
        .put_edge(&seed, EdgeKind::Supports, &neighbour, 1.0)
        .expect("FIXTURE: a traversable one-hop edge from the text match to N");
    assert_eq!(
        fixture
            .vault
            .targets(&seed, EdgeKind::Supports, None)
            .expect("FIXTURE: read the seed's Supports edge"),
        vec![neighbour],
        "FIXTURE: only the readable match directly supports N"
    );
    let (agent, proof) = records_reader_proof(&fixture, &readable);
    let key = fixture
        .vault
        .credential_read_key(&proof)
        .expect("FIXTURE: resolve the records credential")
        .expect("FIXTURE: the credential grants read");
    // PPR_SEED_LIMIT in memory/recall/mod.rs is 8. This fresh lane has no
    // audience, peer or manifest scoped grants, so its window stays 8, not 1000.
    let seed_window = fixture
        .vault
        .scoped_read(key)
        .with_live_grant_receipts()
        .search_candidate_limit(8)
        .expect("FIXTURE: the recall lane's preparatory search window");
    assert_eq!(
        seed_window, 8,
        "GUARD: this credential's seed window is eight"
    );
    let light = deadline_recall_ids(&fixture, agent, &proof, Effort::Light);
    assert_eq!(
        light,
        BTreeSet::from([seed]),
        "FIXTURE: without PPR, only R matches; N is neither a text nor a temporal hit"
    );
    let without = deadline_recall_ids(&fixture, agent, &proof, Effort::Medium);
    assert_eq!(
        without, readable,
        "FIXTURE: before refused rows, Medium seeds R and reaches graph-only N"
    );

    let refused_text = format!("{RARE} {RARE}");
    let refused: BTreeSet<_> = (0..=seed_window)
        .map(|_| put_text_claim(&fixture, fixture.facet, &refused_text))
        .collect();
    assert!(
        refused.len() > seed_window,
        "GUARD: more refused claims than the complete preparatory seed window"
    );
    let owner = fixture
        .vault
        .search_text(RARE, refused.len() + 1)
        .expect("FIXTURE: owner's unscoped BM25 rank of every query match");
    assert_eq!(
        owner.iter().map(|hit| hit.id).collect::<BTreeSet<_>>(),
        refused
            .iter()
            .copied()
            .chain([seed])
            .collect::<BTreeSet<_>>(),
        "FIXTURE: the unscoped search finds R and every refused posting, but not N"
    );
    assert_eq!(
        owner.last().map(|hit| hit.id),
        Some(seed),
        "FIXTURE: every shorter refused TF=2 row ranks above the readable TF=1 match"
    );
    let seed_score = owner.last().expect("FIXTURE: R has a score").score;
    assert!(
        owner
            .iter()
            .take(refused.len())
            .all(|hit| hit.score > seed_score),
        "FIXTURE: refused rows strictly outrank R, with no tie at the seed cut"
    );
    assert!(
        owner
            .iter()
            .take(seed_window)
            .all(|hit| refused.contains(&hit.id)),
        "FIXTURE: the entire old unscoped seed window is filled by refused rows"
    );
    let with = deadline_recall_ids(&fixture, agent, &proof, Effort::Medium);
    assert!(
        with.is_disjoint(&refused) && with.is_subset(&readable) && with.contains(&seed),
        "FIXTURE: the credential's pack still serves R and no refused row"
    );
    assert!(
        with.contains(&neighbour),
        "FAILBEFORE RECALL-PPR-SEED-SCANS-UNSCOPED-CUT: refused rows take no seed \
         place before the cut, so readable R still seeds its graph-only neighbour N"
    );
}

#[test]
fn room_union_count_floor_ignores_no_count_postings() {
    use oneiron::WriteActor;
    use oneiron::code_run::{
        HostSelfDispatcher, SelfCall, SelfDispatchOutcome, SelfDispatcher, SelfMemorySearchCall,
    };
    use oneiron::off_record::OffRecordBackendClass;

    let fixture = fixture();
    let rare = put_text_claim(&fixture, fixture.facet, RARE);
    let common = put_text_claim(&fixture, fixture.facet, COMMON);
    let readable = BTreeSet::from([rare, common]);
    let (agent, proof) = records_reader_proof(&fixture, &readable);
    let key = fixture
        .vault
        .credential_read_key(&proof)
        .expect("FIXTURE: resolve the room reader's records credential")
        .expect("FIXTURE: the credential grants read");
    let base_docs = fixture
        .vault
        .text_index_status()
        .expect("FIXTURE: base's document count before the room indexes")
        .total_docs;
    let session = fixture
        .vault
        .off_record_session_vault()
        .enter("room-union-count-floor", OffRecordBackendClass::Local)
        .expect("FIXTURE: an off-record stretch with an overlay over base");
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_owner_authorship(&fixture.owner_proof)
        .create_note_in_session(&session, "research", "roomcountpin", &[])
        .expect("FIXTURE: one indexed room NOTE pins the overlay's document count");
    let room_marker = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .in_off_record_session(session.session_ref())
        .raw_search_text("roomcountpin", 2)
        .expect("FIXTURE: the owner's composed search reads the indexed room NOTE");
    assert_eq!(
        room_marker.len(),
        1,
        "FIXTURE: the count-pinning NOTE is indexed in the room"
    );
    assert!(
        fixture
            .vault
            .search_text("roomcountpin", 2)
            .expect("GUARD: base search for the room's marker")
            .is_empty(),
        "GUARD: the indexed count-pinning write belongs to the room, not base"
    );
    // The first room Text op copies base's total_docs and adds this NOTE.
    // The overlay's single-value sentinel then shadows later base counts;
    // its posting cursors still merge later base duplicates. No further room
    // text writes occur below. The room count has no public getter.
    let pinned_docs = usize::try_from(base_docs).expect("FIXTURE: base count fits usize") + 1;
    let h = pinned_docs + 1;
    assert!(h > pinned_docs, "GUARD: H exceeds the room's pinned count");
    let dispatcher = HostSelfDispatcher::for_off_record_session(
        &session,
        WriteActor::new(agent, EdgeActorClass::Agent),
        "room-union-count-floor-reader",
    )
    .expect("FIXTURE: the reader binds a run to the live stretch")
    .with_agent_verb_door(Arc::new(RoomRecordsReader(key)));
    let scores = || {
        let outcome = dispatcher
            .dispatch(SelfCall::MemorySearch(SelfMemorySearchCall::new(QUERY, 10)))
            .expect("FIXTURE: records-caveated BM25 search through the room's union");
        let SelfDispatchOutcome::MemorySearch(found) = outcome else {
            panic!("FIXTURE: the room search must answer with scores, got {outcome:?}");
        };
        assert_eq!(
            found.results.len(),
            2,
            "FIXTURE: the room search serves exactly two hits, before and after refused rows"
        );
        assert_eq!(
            found
                .results
                .iter()
                .map(|hit| hit.id)
                .collect::<BTreeSet<_>>(),
            readable,
            "FIXTURE: the room search serves A and B only, no refused base row or room NOTE"
        );
        let a = f64::from(
            found
                .results
                .iter()
                .find(|hit| hit.id == rare)
                .expect("FIXTURE: A has a room BM25 score")
                .score,
        );
        let b = f64::from(
            found
                .results
                .iter()
                .find(|hit| hit.id == common)
                .expect("FIXTURE: B has a room BM25 score")
                .score,
        );
        assert!(
            a.is_finite() && b.is_finite() && a > 0.0 && b > 0.0,
            "FIXTURE: both readable matches have finite positive scores: A={a}, B={b}"
        );
        (a, b)
    };
    let (a, b) = scores();
    println!("ROOM-UNION-COUNT-FLOOR baseline: pinned={pinned_docs}, H={h}, A={a}, B={b}");
    assert!(
        (a - b).abs() <= 1e-6 * a.abs().max(1.0),
        "FIXTURE: equal-shape RARE and COMMON matches score alike in the room: A={a}, B={b}"
    );
    assert_eq!(
        fixture
            .vault
            .text_index_status()
            .expect("GUARD: base count after room indexing and baseline search")
            .total_docs,
        base_docs,
        "GUARD: room indexing and retrieval do not change base's document count"
    );

    // Deliberately use the base writer, never the session-bound memory handle.
    let refused: BTreeSet<_> = (0..h)
        .map(|_| put_text_claim(&fixture, fixture.facet, RARE))
        .collect();
    assert_eq!(refused.len(), h, "GUARD: H distinct refused base claims");
    let owner = fixture
        .vault
        .search_text(RARE, h + 2)
        .expect("GUARD: the owner's unscoped base search sees every RARE posting");
    assert_eq!(
        owner.len(),
        h + 1,
        "GUARD: base indexes A and all H refused RARE rows"
    );
    assert_eq!(
        owner.iter().map(|hit| hit.id).collect::<BTreeSet<_>>(),
        refused
            .iter()
            .copied()
            .chain([rare])
            .collect::<BTreeSet<_>>(),
        "GUARD: every refused claim itself reached the base text index"
    );
    assert_eq!(
        usize::try_from(
            fixture
                .vault
                .text_index_status()
                .expect("GUARD: base count after the late writes")
                .total_docs,
        )
        .expect("GUARD: base count fits usize"),
        pinned_docs - 1 + h,
        "GUARD: base gained exactly H documents after the room pinned its own sentinel"
    );
    let (a, b) = scores();
    println!("ROOM-UNION-COUNT-FLOOR with refused rows: pinned={pinned_docs}, H={h}, A={a}, B={b}");
    assert!(
        (a - b).abs() <= 1e-6 * a.abs().max(1.0),
        "FAILBEFORE ROOM-UNION-COUNT-FLOOR: a room's count floor takes the counted postings, \
         so the H refused base rows raise no term's IDF and A still scores as B: A={a}, B={b}"
    );
}

// A host door admits only the run's own search with the verified records key.
// It forwards no SDK verb and grants no write authority.
struct RoomRecordsReader(ScopedReadActorKey);

impl oneiron::code_run::AgentVerbDoor for RoomRecordsReader {
    fn call(
        &self,
        _call: &oneiron::code_run::SelfAgentVerbCall,
        _origin: &oneiron::memory::HostWriteOrigin,
        _invocation: oneiron::runtime_hooks::InvocationId,
    ) -> oneiron::Result<
        Result<oneiron::code_run::AgentVerbAnswer, oneiron::code_run::AgentVerbRefusal>,
    > {
        panic!("GUARD: the room fixture forwards no SDK verb");
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
                code: "room_fixture_search_only".to_owned(),
                hook_notice: None,
                reason_codes: Vec::new(),
            }),
        }
    }
}

// put_text_claim with a chosen id, both of its times at `at`.
fn put_text_claim_at(fixture: &Fixture, id: EntityId, text: &str, at: u64) -> EntityId {
    let vault = &fixture.vault;
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: at, end: at },
            at,
            &rmp_serde::to_vec_named(&json!({ "name": "Wren" })).expect("FIXTURE: name body"),
        )
        .expect("FIXTURE: the claim's PERSON subject");
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
            occurred_at: Some(at),
            learned_at: Some(at),
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
    vault
        .batch()
        .text(&id, &[("body", text)])
        .commit()
        .expect("FIXTURE: index the claim's text");
    id
}

#[test]
fn deadline_recall_seed_lookup_blends_default_recency() {
    use oneiron::memory::Effort;

    const SEED_WINDOW: usize = 8;
    const YEAR: u64 = 365 * 86_400;
    let fixture = fixture();
    // One more equal lexical match than the seed window. The match with the
    // greatest id was learned a year after the others.
    let mut ids: Vec<EntityId> = (0..=SEED_WINDOW).map(|_| EntityId::now()).collect();
    ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let (newest, older) = ids.split_last().expect("FIXTURE: nine ids");
    let newest = *newest;
    let first = older[0];
    for id in older {
        put_text_claim_at(&fixture, *id, RARE, OCCURRED_AT - YEAR);
    }
    put_text_claim_at(&fixture, newest, RARE, OCCURRED_AT);
    // Graph-only rows: N hangs off the newest match, N0 off the first older
    // match (a seed with or without the blend: the positive control).
    let neighbour = put_text_claim(&fixture, fixture.facet, "harbourrope");
    let control = put_text_claim(&fixture, fixture.facet, "mooringpost");
    for (from, to) in [(newest, neighbour), (first, control)] {
        fixture
            .vault
            .put_edge(&from, EdgeKind::Supports, &to, 1.0)
            .expect("FIXTURE: a traversable one-hop edge from a text match");
    }
    let readable: BTreeSet<EntityId> = ids.iter().copied().chain([neighbour, control]).collect();
    let (agent, proof) = records_reader_proof(&fixture, &readable);
    let key = fixture
        .vault
        .credential_read_key(&proof)
        .expect("FIXTURE: resolve the records credential")
        .expect("FIXTURE: the credential grants read");
    assert_eq!(
        fixture
            .vault
            .scoped_read(key)
            .with_live_grant_receipts()
            .search_candidate_limit(SEED_WINDOW)
            .expect("FIXTURE: the recall lane's preparatory search window"),
        SEED_WINDOW,
        "GUARD: this credential's seed window is eight"
    );
    let owner = fixture
        .vault
        .search_text(RARE, ids.len())
        .expect("FIXTURE: the owner's direct search, which blends the default recency");
    assert_eq!(
        owner.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        std::iter::once(newest)
            .chain(older.iter().copied())
            .collect::<Vec<_>>(),
        "FIXTURE: the blend ranks the newest match first; the eight older matches tie and order \
         by id, so with no blend the newest (greatest id) sorts ninth, past the seed window"
    );
    let light = deadline_recall_ids_within(&fixture, agent, &proof, Effort::Light, readable.len());
    assert!(
        !light.contains(&neighbour) && !light.contains(&control),
        "FIXTURE: without PPR, N and N0 are neither text nor temporal hits"
    );
    let medium =
        deadline_recall_ids_within(&fixture, agent, &proof, Effort::Medium, readable.len());
    assert!(
        medium.contains(&control),
        "FIXTURE: PPR from a seed reaches its graph-only neighbour N0 in this pack"
    );
    assert!(
        medium.contains(&neighbour),
        "FAILBEFORE REVIEW-10111-R2 recency: the deadline seed lookup blends the default \
         recency, as the direct search it replaced does, so the newest equal match keeps its \
         seed place and reaches N"
    );
}
