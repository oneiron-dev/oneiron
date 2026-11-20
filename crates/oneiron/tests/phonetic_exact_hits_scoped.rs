//! [PHONETIC-EXACT-HITS-UNSCOPED-BEFORE-BLEND]: the phonetic code rung's
//! exact-code hits have no cut, so no admission asked them, and they joined
//! the first blend asked only by the device-local worlds, the memory lane,
//! entity-type authority and the call's made_by slice. A hit outside the
//! call's type, time, world, corpus, relationship or candidate filter then
//! counted in the run's candidates in scope, made an empty run read
//! `FilterMatchedNone` where nothing in scope matched (`NoData`), and, as a
//! dead claim, counted as a suppressed claim. A scoped reader's pack keeps
//! the run's empty context when it served nothing, so an agent learned that
//! a row its Grant cannot read matched its query (DEC-0005). Now the call's
//! scope asks each row of that list before the blend, as the bounded
//! channels' admission does.
//!
//! The agent fixture is `tests/pack_member_count.rs`'s, through its test
//! doors: run the file with `RUSTFLAGS="--cfg oneiron_test_support" cargo
//! test --locked -p oneiron --all-features --test phonetic_exact_hits_scoped`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, PairingPrincipal, VerifiedSlip};
use oneiron::batch::generate_phonetic_codes;
use oneiron::claim::{ScopedReadActorKey, base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::registry::{ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::RetrievalRunRecord;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EdgeKind,
    EmptyReason, EntityId, PipelineBuilder, TimeRange, Vault, VaultConfig, WriteActor,
    WriteEnvelope, WriteProvenance,
};
use serde_json::json;

/// The searched name. No phonetic code of it is a code of [`OTHER_NAME`]
/// (`tests/made_by_bounded_channels.rs` pairs the same two names).
const NAME: &str = "Numbat";
const OTHER_NAME: &str = "Bilby";
/// The name the agent fixture's withheld claim is posted under; no code of
/// it is a code of the claims' PERSON subjects' names.
const WITHHELD_NAME: &str = "Quandong";
const OCCURRED_AT: u64 = 1_769_947_200;
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:phonetic-exact-hits-scoped";
/// Sensitivity band 0, Public: the world axis alone keeps the withheld
/// claim from the agent.
const PUBLIC_BAND: u8 = 0;

/// The exact (non-sound-key) phonetic codes of `name`: the codes whose
/// postings the code rung reads in full, with no cut.
fn exact_codes(name: &str) -> Vec<String> {
    let exact: Vec<String> = generate_phonetic_codes(name)
        .into_iter()
        .filter(|code| !code.starts_with("ipa:"))
        .collect();
    assert!(!exact.is_empty(), "FIXTURE: {name} has exact codes");
    exact
}

fn name_body(name: &str) -> Vec<u8> {
    rmp_serde::to_vec_named(&json!({ "name": name })).expect("FIXTURE: name body")
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

/// A device vault whose runs record their telemetry, so a test reads each
/// run's candidates in scope, suppressed claims and empty reason.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    Fixture { _dir: dir, vault }
}

/// What a run returned and what its record says of it.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    ids: Vec<EntityId>,
    total_in_scope: usize,
    claims_suppressed: usize,
    empty_reason: Option<String>,
}

impl Fixture {
    /// An entity of `entity_type` named `name`; its put publishes the
    /// name's phonetic codes.
    fn named(&self, entity_type: u8, name: &str) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                entity_type,
                TimeRange { start: 1, end: 1 },
                1,
                &name_body(name),
            )
            .expect("FIXTURE: put the named entity");
        id
    }

    /// A phonetic search for `NAME`'s exact codes, narrowed to `types` when
    /// given, with an implicit expansion one hop out from its top results
    /// when `expand` is set.
    fn phonetic(&self, types: Option<&[u8]>, expand: bool) -> Run {
        let exact = exact_codes(NAME);
        let codes: Vec<&str> = exact.iter().map(String::as_str).collect();
        let query = self.vault.query().search_phonetic(&codes);
        let query = match types {
            Some(types) => query.filter_types(types),
            None => query,
        };
        let query = if expand {
            query.expand_ppr(&[], 1)
        } else {
            query
        };
        self.recorded(query)
    }

    fn recorded(&self, query: PipelineBuilder<'_>) -> Run {
        let run = query
            .limit(10)
            .capture_retrieval_trace(true)
            .run_with_telemetry()
            .expect("query");
        let run_id = run
            .run_id
            .expect("FIXTURE: a captured run names its record");
        let record: RetrievalRunRecord = self
            .vault
            .retrieval_run(run_id)
            .expect("read the run record")
            .expect("FIXTURE: the run record is readable");
        Run {
            ids: run.value.into_iter().map(|row| row.id).collect(),
            total_in_scope: record.total_in_scope,
            claims_suppressed: record.claims_suppressed,
            empty_reason: record.empty_reason,
        }
    }
}

/// An empty run's record.
fn empty_run(claims_suppressed: usize, empty_reason: &str) -> Run {
    Run {
        ids: Vec::new(),
        total_in_scope: 0,
        claims_suppressed,
        empty_reason: Some(empty_reason.to_owned()),
    }
}

/// A search narrowed to organisations whose only exact hit is a person
/// counts no candidate in scope and reads `NoData`. Before, the person
/// joined the blend, counted as a candidate, and the post-blend type
/// filter made the run read `FilterMatchedNone`.
#[test]
fn a_type_filtered_search_counts_no_exact_hit_of_another_type() {
    let fixture = fixture();
    let person = fixture.named(ENTITY_TYPE_PERSON, NAME);
    assert_eq!(
        fixture.phonetic(None, false),
        Run {
            ids: vec![person],
            total_in_scope: 1,
            claims_suppressed: 0,
            empty_reason: None,
        },
        "FIXTURE: unnarrowed, the exact codes find the person"
    );
    assert_eq!(
        fixture.phonetic(Some(&[ENTITY_TYPE_ORG]), false),
        empty_run(0, "NoData"),
        "FAILBEFORE PHONETIC-EXACT-HITS-UNSCOPED-BEFORE-BLEND: a person counts no candidate \
         in an organisation search, and nothing in scope matched"
    );
}

/// A proposed claim holding the query's exact codes is a suppressed claim
/// of the run that may retrieve it, and none of a run narrowed to persons.
/// Before, the D19 gate judged it in the person search too, so that run
/// counted it and read `AllActivated`. The run that may retrieve it counts
/// it as no candidate in scope, as the text channel counts a suppressed
/// claim its exact posting holds (FIX 199): the gate drops it before the
/// blend, and its suppression still makes the run read `AllActivated`.
#[test]
fn a_type_filtered_search_counts_no_suppressed_claim_of_another_type() {
    let fixture = fixture();
    let claim = put_claim(&fixture.vault, ClaimApprovalStatus::Proposed);
    let exact = exact_codes(NAME);
    let codes: Vec<&str> = exact.iter().map(String::as_str).collect();
    fixture
        .vault
        .batch()
        .phonetic(&claim, &codes)
        .commit()
        .expect("FIXTURE: post the claim under the exact codes");
    let unnarrowed = fixture.phonetic(None, false);
    assert_eq!(
        (
            unnarrowed.ids.len(),
            unnarrowed.claims_suppressed,
            unnarrowed.empty_reason.as_deref()
        ),
        (0, 1, Some("AllActivated")),
        "unnarrowed, the D19 gate suppresses the proposed claim, as before"
    );
    assert_eq!(
        fixture.phonetic(Some(&[ENTITY_TYPE_PERSON]), false),
        empty_run(0, "NoData"),
        "FAILBEFORE PHONETIC-EXACT-HITS-UNSCOPED-BEFORE-BLEND: a person search counts no \
         suppressed claim"
    );
    assert_eq!(
        unnarrowed.total_in_scope, 0,
        "FAILBEFORE PHONETIC-EXACT-HITS-UNSCOPED-BEFORE-BLEND: a suppressed claim is no \
         candidate in scope"
    );
}

/// A narrowed search still finds its exact hit of the type it asks for
/// (the guard), and counts that one alone.
#[test]
fn a_type_filtered_search_keeps_its_exact_hit_of_that_type() {
    let fixture = fixture();
    fixture.named(ENTITY_TYPE_PERSON, NAME);
    let org = fixture.named(ENTITY_TYPE_ORG, NAME);
    assert_eq!(
        fixture.phonetic(None, false).total_in_scope,
        2,
        "FIXTURE: unnarrowed, both exact hits count"
    );
    let narrowed = fixture.phonetic(Some(&[ENTITY_TYPE_ORG]), false);
    assert_eq!(
        narrowed.ids,
        [org],
        "an organisation search finds the organisation"
    );
    assert_eq!(
        narrowed,
        Run {
            ids: vec![org],
            total_in_scope: 1,
            claims_suppressed: 0,
            empty_reason: None,
        },
        "FAILBEFORE PHONETIC-EXACT-HITS-UNSCOPED-BEFORE-BLEND: an organisation search counts \
         the organisation alone"
    );
}

/// Guard: an exact hit outside the type filter seeds no implicit expansion,
/// so the organisation it is about stays unreached. (The narrowed walk's
/// visibility already refused such a seed; this keeps it so.)
#[test]
fn an_exact_hit_of_another_type_seeds_no_expansion() {
    let fixture = fixture();
    let person = fixture.named(ENTITY_TYPE_PERSON, NAME);
    let org = fixture.named(ENTITY_TYPE_ORG, OTHER_NAME);
    fixture
        .vault
        .put_edge(&person, EdgeKind::About, &org, 1.0)
        .expect("FIXTURE: link the person to the organisation");
    assert!(
        fixture.phonetic(None, true).ids.contains(&org),
        "FIXTURE: unnarrowed, the expansion from the person reaches the organisation"
    );
    assert_eq!(
        fixture.phonetic(Some(&[ENTITY_TYPE_ORG]), true).ids,
        Vec::<EntityId>::new(),
        "an organisation search seeds no expansion from a person"
    );
}

/// An agent whose Grant reads the base world asks for a name only a
/// second-world claim holds. Its pack serves nothing and counts nothing:
/// no candidate in scope, `NoData`. Before, the claim counted in the run's
/// candidates in scope, and the scoped filter kept the run's empty context
/// for a pack it served nothing from, so the agent read
/// `FilterMatchedNone` with one candidate: a row it cannot read matched.
#[test]
fn an_agent_pack_counts_no_exact_hit_its_grant_cannot_read() {
    let fixture = agent_fixture();
    let exact = exact_codes(WITHHELD_NAME);
    let codes: Vec<&str> = exact.iter().map(String::as_str).collect();
    let owner_found: Vec<EntityId> = fixture
        .vault
        .query()
        .search_phonetic(&codes)
        .limit(10)
        .run()
        .expect("the owner's search")
        .into_iter()
        .map(|row| row.id)
        .collect();
    assert_eq!(
        owner_found,
        [fixture.withheld],
        "FIXTURE: the owner's search finds the second-world claim by its exact codes"
    );

    let read = fixture.vault.scoped_read(fixture.agent_key.clone());
    let plan = read.context_pack_plan().expect("the agent's pack plan");
    let mut pack = plan
        .admit(fixture.vault.context_pack())
        .search_phonetic(&codes)
        .limit(10)
        .non_base_world_claim_fraction(1.0)
        .include_stats(true)
        .run()
        .expect("the agent's pack");
    read.filter_context_pack(&mut pack)
        .expect("the agent's filter");
    assert!(
        pack.results.is_empty() && pack.neighbors.is_empty(),
        "the agent's pack serves no row its Grant cannot read"
    );
    let empty = pack
        .empty
        .as_ref()
        .expect("FIXTURE: an empty pack says why it is empty");
    assert_eq!(
        (
            empty.reason,
            empty.total_in_scope,
            pack.stats.candidates_considered
        ),
        (EmptyReason::NoData, 0, 0),
        "FAILBEFORE PHONETIC-EXACT-HITS-UNSCOPED-BEFORE-BLEND: the agent's pack counts no \
         candidate it cannot read, and says nothing in its scope matched"
    );
}

/// One live, UserStated claim by a human writer about a person, written
/// with approval `approval` through the public batch, as
/// `tests/made_by_bounded_channels.rs` writes it.
fn put_claim(vault: &Vault, approval: ClaimApprovalStatus) -> EntityId {
    let actor = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    let subject = EntityId::now();
    for id in [actor.entity_ref(), subject] {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"",
            )
            .expect("FIXTURE: put person");
    }
    let envelope = WriteEnvelope::new(
        actor,
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("phonetic exact hits scoped"))
            .expect("FIXTURE: provenance"),
        approval,
    );
    let claim = EntityId::now();
    vault
        .batch()
        .claim_candidate(
            &claim,
            ClaimCandidate::new(
                "profile.phonetic_exact_hits",
                ClaimSubject::Entity(subject),
                rmpv::Value::from("fact"),
                1.0,
            ),
            &envelope,
            TimeRange { start: 10, end: 99 },
            10,
        )
        .commit()
        .expect("FIXTURE: write the claim");
    claim
}

struct AgentFixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    withheld: EntityId,
    agent_key: ScopedReadActorKey,
}

/// A rooted vault whose owner wrote one Public claim in a second world,
/// posted under `WITHHELD_NAME`'s exact codes, and an agent whose one Grant
/// reads the base world (`tests/pack_member_count.rs`'s fixture).
fn agent_fixture() -> AgentFixture {
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
    let withheld = write_owner_claim(&vault, owner, &owner_proof, (second_world, "noor"));
    let exact = exact_codes(WITHHELD_NAME);
    let codes: Vec<&str> = exact.iter().map(String::as_str).collect();
    vault
        .batch()
        .phonetic(&withheld, &codes)
        .commit()
        .expect("FIXTURE: post the withheld claim under the exact codes");

    let agent = create_enabled_agent(&vault, &owner_proof, "phonetic_exact_hits_agent");
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
        },
    )
    .expect("owner mints the agent a base-world read Grant");
    assert!(minted.grant.confers, "FIXTURE: the agent's Grant confers");
    let agent_slip = paired_agent_slip(&vault, &issuer, &owner_proof, agent, 0x5d);
    let agent_key = vault
        .credential_read_key(&agent_slip)
        .expect("agent credential read key")
        .expect("agent credential grants read");
    AgentFixture {
        vault,
        _dir: dir,
        withheld,
        agent_key,
    }
}

/// The owner's Public claim, in `world`, about a fresh PERSON named
/// `subject_name`.
fn write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    (world, subject_name): (EntityId, &str),
) -> EntityId {
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
            &name_body(subject_name),
        )
        .expect("the claim's PERSON subject");
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: subject.to_hex(),
            value: json!("violet quarry"),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: world.to_hex(),
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
        .expect("owner writes a claim in the named world");
    id
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
                "desc": "Phonetic exact hit reader",
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
