//! Restriction census C29: an owner hands a Dreamer consent bundle's settlement to a named
//! agent with the `gate.consent_bundle.delegate_resolution` key. With the key on for an agent,
//! that agent reviews a run's bundle (`vault.gate.consent_bundle.review_as`) and approves or
//! declines it as a unit (`vault.gate.consent_bundle.resolve_as`), each under its own live Grant
//! listing the verb and only a bundle its read lane reads whole. Whatever the key says, the
//! opener's lineage and its forks never settle their own bundle, and a bundle holding a
//! proactivity policy request waits for the owner. With the key off (the default) the agent is
//! refused and the owner's own doors settle as before.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test gate_consent_bundle_agent_settle`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_consolidation::{
    ConsolidationEvidenceEnvelope, encode_consolidation_evidence,
};
use oneiron::federation::{Scope, ScopeId};
use oneiron::memory::{Memory, MemoryError};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, GateConsentBundleAction, TimeRange, Vault, VaultConfig, WriteActor,
    WriteEnvelope, WriteProvenance,
};
use oneiron_store::ports::manual_clock::ManualClock;
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

const DELEGATE_KEY: &str = "gate.consent_bundle.delegate_resolution";
const REVIEW_AS: &str = "vault.gate.consent_bundle.review_as";
const RESOLVE_AS: &str = "vault.gate.consent_bundle.resolve_as";
const SET: &str = "vault.settings.set";

const BUNDLE_VERBS: &[&str] = &[REVIEW_AS, RESOLVE_AS];

/// The vault clock's fixed time for every test here: no wall time, no sleeps for the clock.
const T0: u64 = 1_780_000_000;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
}

/// A rooted vault with its install enrolled and its embedded owner.
fn rooted_vault() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    Fixture {
        vault,
        _dir: dir,
        owner,
    }
}

fn owner_proof(fixture: &Fixture) -> AuthenticatedOwner {
    fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof")
}

fn owner_memory(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

fn agent_memory(fixture: &Fixture, agent: EntityId) -> Memory<'_> {
    fixture.vault.memory(agent, EdgeActorClass::Agent)
}

/// `name`'s agent definition with an owner Grant of base reach, listing the
/// full-access tier's verbs and `extra`.
fn granted_agent(fixture: &Fixture, name: &str, extra: &[&str]) -> EntityId {
    granted_agent_in_bands(fixture, name, extra, None)
}

/// [`granted_agent`], whose Grant reaches only the row kinds `bands` when
/// they are given: every row of another kind is withheld from its lane.
fn granted_agent_in_bands(
    fixture: &Fixture,
    name: &str,
    extra: &[&str],
    bands: Option<&[u8]>,
) -> EntityId {
    let agent = define_agent(&fixture.vault, name).expect("agent");
    mint_base_grant(fixture, agent, extra, bands);
    agent
}

/// The owner Grant [`granted_agent_in_bands`] mints, for an agent definition
/// the caller already wrote (a fork): base world, the full-access tier's
/// verbs plus `extra`, and only `bands` when they are given.
fn mint_base_grant(fixture: &Fixture, agent: EntityId, extra: &[&str], bands: Option<&[u8]>) {
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    if let Some(bands) = bands {
        authority_scope.bands = bands.iter().copied().collect();
    }
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .chain(extra.iter())
        .map(|verb| (*verb).to_owned())
        .collect();
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &owner_proof(fixture),
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
    .expect("the owner grants the agent base reach");
    assert!(minted.grant.confers, "the grant confers");
}

/// An agent definition forked from `parent`, with the same base Grant as
/// [`granted_agent`]: its settling lineage meets its parent's.
fn granted_forked_agent(fixture: &Fixture, name: &str, parent: EntityId) -> EntityId {
    let definition = AgentDefinition::new(
        name,
        "Consent bundle fork fixture agent",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        Some(parent),
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    );
    let id = EntityId::now();
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .put_agent_definition(&id, &definition, TimeRange { start: at, end: at }, at)
        .expect("the forked definition lands");
    mint_base_grant(fixture, id, BUNDLE_VERBS, None);
    id
}

/// The owner turns `key` on: for `agent` alone, or with `None` for every
/// agent. At the red pin the key does not exist yet, so the set is refused as
/// unknown; the red tests then fail at the new verb, and the guards still
/// hold.
fn owner_turns_on(fixture: &Fixture, key: &str, agent: Option<EntityId>) {
    let scope = agent.map_or_else(
        || json!({ "kind": "vault" }),
        |agent| json!({ "kind": "agent", "id": agent.to_hex() }),
    );
    match invoke(
        &owner_memory(fixture),
        SET,
        json!({ "key": key, "scope": scope, "value": true }),
    ) {
        Ok(applied) => assert_eq!(applied["status"], json!("applied"), "{applied}"),
        Err(refused) => assert!(
            refused.message.contains("no setting key is named"),
            "at the red pin the key does not exist yet: {refused:?}"
        ),
    }
}

/// A refusal for the lineage rule: at the red pin the verb itself is unknown.
fn assert_lineage_refused(refused: &MemoryError) {
    assert!(
        refused.message.contains("lineage") || refused.message.contains("unknown SDK agent verb"),
        "the opener's own lineage is refused as its own: {refused:?}"
    );
}

/// Lowercase hex of `bytes`, as the bundle id reads on the wire.
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `agent` writes two Proposed claims in Dreamer run `run` on the public
/// batch door, with the run's provenance and citable evidence, as the gate's
/// consent-bundle fixtures do. The default policy parks both: the write
/// answers Pending and each claim stays Proposed with an open consent row
/// stamped with the run. Answers the two claim ids.
fn park_two_in_run(fixture: &Fixture, agent: EntityId, run: &str) -> (EntityId, EntityId) {
    let at = fixture.vault.now_recorded_at();
    let range = TimeRange { start: at, end: at };
    let subject = EntityId::now();
    fixture
        .vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, range, at, b"bundle subject")
        .expect("the subject lands");
    let first = EntityId::now();
    let second = EntityId::now();
    for (id, value) in [(first, "first bundle note"), (second, "second bundle note")] {
        // A Dreamer write cites what was said, never the PERSON it is about.
        let said = EntityId::now();
        fixture
            .vault
            .put_entity(&said, ENTITY_TYPE_TURN, range, at, b"what was said")
            .expect("the cited turn lands");
        let evidence = encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
            refs: vec![said],
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        });
        let candidate = ClaimCandidate::new(
            "profile.weave_note",
            ClaimSubject::Entity(subject),
            RmpValue::from(value),
            0.9,
        )
        .with_evidence(evidence);
        let envelope = WriteEnvelope::new(
            WriteActor::new(agent, EdgeActorClass::Agent),
            ClaimSource::Generated,
            WriteProvenance::new(RmpValue::Map(vec![
                (RmpValue::from("runner"), RmpValue::from("dreamer")),
                (RmpValue::from("run_id"), RmpValue::from(run)),
            ]))
            .expect("provenance"),
            ClaimApprovalStatus::Proposed,
        );
        fixture
            .vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, range, at)
            .commit()
            .unwrap_or_else(|error| panic!("the run parks its proposal: {error:?}"));
        // Members sort by their parked decision id, which is time-ordered: the
        // pause keeps the two-claim order stable across runs.
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    for id in [first, second] {
        let parked = fixture
            .vault
            .get_claim(&id)
            .expect("the parked claim reads")
            .expect("the parked claim is stored");
        assert_eq!(
            parked.approval,
            ClaimApprovalStatus::Proposed,
            "the gate parks the run's proposal"
        );
    }
    (first, second)
}

/// The owner's review of `run`: the bundle id as 64 hex and the member claim
/// ids as sorted 32 hex, as the agent's review spells them.
fn owner_bundle_hex(fixture: &Fixture, run: &str) -> (String, Vec<String>) {
    let bundle = fixture
        .vault
        .review_gate_consent_bundle(&WriteActor::new(fixture.owner, EdgeActorClass::Human), run)
        .unwrap_or_else(|error| panic!("the owner reviews the run: {error:?}"));
    let mut members: Vec<String> = bundle
        .members
        .iter()
        .map(|member| member.claim_id.to_hex())
        .collect();
    members.sort();
    (hex_lower(&bundle.bundle_id), members)
}

/// The agent's review of `run` through `vault.gate.consent_bundle.review_as`.
fn agent_review(fixture: &Fixture, agent: EntityId, run: &str) -> Value {
    invoke(
        &agent_memory(fixture, agent),
        REVIEW_AS,
        json!({ "dreamer_run_id": run }),
    )
    .unwrap_or_else(|error| panic!("the delegated agent reviews the run: {error:?}"))
}

/// The agent's settlement of `bundle_hex` through
/// `vault.gate.consent_bundle.resolve_as`.
fn agent_resolve(
    fixture: &Fixture,
    agent: EntityId,
    bundle_hex: &str,
    run: &str,
    action: &str,
) -> Value {
    invoke(
        &agent_memory(fixture, agent),
        RESOLVE_AS,
        json!({
            "bundle_id": bundle_hex,
            "dreamer_run_id": run,
            "action": action,
        }),
    )
    .unwrap_or_else(|error| panic!("the delegated agent settles the bundle: {error:?}"))
}

/// The claim's approval and lifecycle, as the vault stores them now.
fn claim_status(fixture: &Fixture, id: &EntityId) -> (ClaimApprovalStatus, ClaimLifecycleStatus) {
    let body = fixture
        .vault
        .get_claim(id)
        .expect("the claim reads")
        .expect("the claim is stored");
    (body.approval, body.lifecycle)
}

/// The sorted member claim ids a `resolve_as` answer settled.
fn settled_members(answer: &Value) -> Vec<String> {
    let mut members: Vec<String> = answer["member_claim_ids"]
        .as_array()
        .unwrap_or_else(|| panic!("no settled members: {answer}"))
        .iter()
        .map(|id| {
            id.as_str()
                .unwrap_or_else(|| panic!("no member id: {answer}"))
                .to_owned()
        })
        .collect();
    members.sort();
    members
}

#[test]
fn an_agent_the_owner_turns_the_key_on_for_reviews_and_approves_a_bundle() {
    let fixture = rooted_vault();
    let run = "consent-bundle-agent-approve";
    let opener = granted_agent(&fixture, "bundle-opener", BUNDLE_VERBS);
    let settler = granted_agent(&fixture, "bundle-settler", BUNDLE_VERBS);
    let (first, second) = park_two_in_run(&fixture, opener, run);
    let mut expected = vec![first.to_hex(), second.to_hex()];
    expected.sort();
    owner_turns_on(&fixture, DELEGATE_KEY, Some(settler));

    let review = agent_review(&fixture, settler, run);
    let (owner_hex, owner_members) = owner_bundle_hex(&fixture, run);
    assert_eq!(review["dreamer_run_id"], json!(run), "{review}");
    assert_eq!(review["bundle_id"], json!(owner_hex), "{review}");
    assert_eq!(owner_members, expected, "the owner sees both parked claims");
    let members = review["members"].as_array().expect("review members");
    assert_eq!(members.len(), 2, "{review}");
    let mut seen: Vec<String> = members
        .iter()
        .map(|member| {
            member["claim_id"]
                .as_str()
                .expect("member claim id")
                .to_owned()
        })
        .collect();
    seen.sort();
    assert_eq!(seen, expected, "{review}");

    let bundle_hex = review["bundle_id"].as_str().expect("bundle id").to_owned();
    let settled = agent_resolve(&fixture, settler, &bundle_hex, run, "approve");
    assert_eq!(settled["bundle_id"], json!(bundle_hex), "{settled}");
    assert_eq!(settled_members(&settled), expected, "{settled}");
    for id in [first, second] {
        assert_eq!(
            claim_status(&fixture, &id).0,
            ClaimApprovalStatus::Approved,
            "the approval lands"
        );
    }
}

#[test]
fn an_agent_declines_a_bundle_as_a_unit() {
    let fixture = rooted_vault();
    let run = "consent-bundle-agent-decline";
    let opener = granted_agent(&fixture, "bundle-opener", BUNDLE_VERBS);
    let settler = granted_agent(&fixture, "bundle-settler", BUNDLE_VERBS);
    let (first, second) = park_two_in_run(&fixture, opener, run);
    let mut expected = vec![first.to_hex(), second.to_hex()];
    expected.sort();
    owner_turns_on(&fixture, DELEGATE_KEY, Some(settler));

    let review = agent_review(&fixture, settler, run);
    let bundle_hex = review["bundle_id"].as_str().expect("bundle id").to_owned();
    let settled = agent_resolve(&fixture, settler, &bundle_hex, run, "decline");
    assert_eq!(settled_members(&settled), expected, "{settled}");
    for id in [first, second] {
        let (approval, lifecycle) = claim_status(&fixture, &id);
        assert_eq!(approval, ClaimApprovalStatus::Rejected, "the decline lands");
        assert_eq!(
            lifecycle,
            ClaimLifecycleStatus::Retracted,
            "a declined agent claim retracts"
        );
    }
}

#[test]
fn the_key_off_leaves_the_bundle_to_the_owner() {
    let fixture = rooted_vault();
    let run = "consent-bundle-key-off";
    let opener = granted_agent(&fixture, "bundle-opener", BUNDLE_VERBS);
    let settler = granted_agent(&fixture, "bundle-settler", BUNDLE_VERBS);
    let (first, second) = park_two_in_run(&fixture, opener, run);
    let (owner_hex, _) = owner_bundle_hex(&fixture, run);

    let refused = invoke(
        &agent_memory(&fixture, settler),
        REVIEW_AS,
        json!({ "dreamer_run_id": run }),
    )
    .expect_err("with the key off the agent reviews nothing");
    assert!(
        !refused.to_string().is_empty(),
        "the refusal says why: {refused:?}"
    );
    invoke(
        &agent_memory(&fixture, settler),
        RESOLVE_AS,
        json!({
            "bundle_id": owner_hex,
            "dreamer_run_id": run,
            "action": "approve",
        }),
    )
    .expect_err("with the key off the agent settles nothing");
    for id in [first, second] {
        assert_eq!(
            claim_status(&fixture, &id).0,
            ClaimApprovalStatus::Proposed,
            "the refused agent changed nothing"
        );
    }

    let bundle = fixture
        .vault
        .review_gate_consent_bundle(&WriteActor::new(fixture.owner, EdgeActorClass::Human), run)
        .expect("the owner reviews");
    let now = fixture.vault.now_recorded_at();
    fixture
        .vault
        .resolve_gate_consent_bundle(
            &owner_proof(&fixture),
            bundle.bundle_id,
            run,
            GateConsentBundleAction::Approve,
            now,
        )
        .expect("the owner settles its own bundle");
    for id in [first, second] {
        assert_eq!(
            claim_status(&fixture, &id).0,
            ClaimApprovalStatus::Approved,
            "the owner's approval lands"
        );
    }
}

#[test]
fn the_opener_and_its_forks_never_settle_their_bundle() {
    let fixture = rooted_vault();
    let run = "consent-bundle-opener-lineage";
    let opener = granted_agent(&fixture, "bundle-opener", BUNDLE_VERBS);
    let fork = granted_forked_agent(&fixture, "bundle-opener-fork", opener);
    let outsider = granted_agent(&fixture, "bundle-outsider", BUNDLE_VERBS);
    let (first, second) = park_two_in_run(&fixture, opener, run);
    owner_turns_on(&fixture, DELEGATE_KEY, None);
    let (owner_hex, _) = owner_bundle_hex(&fixture, run);

    let own = invoke(
        &agent_memory(&fixture, opener),
        RESOLVE_AS,
        json!({
            "bundle_id": owner_hex,
            "dreamer_run_id": run,
            "action": "approve",
        }),
    )
    .expect_err("the opener never settles its own bundle");
    assert_lineage_refused(&own);
    let kin = invoke(
        &agent_memory(&fixture, fork),
        RESOLVE_AS,
        json!({
            "bundle_id": owner_hex,
            "dreamer_run_id": run,
            "action": "approve",
        }),
    )
    .expect_err("a fork of the opener never settles its bundle");
    assert_lineage_refused(&kin);
    for id in [first, second] {
        assert_eq!(
            claim_status(&fixture, &id).0,
            ClaimApprovalStatus::Proposed,
            "the refused lineage changed nothing"
        );
    }

    let settled = agent_resolve(&fixture, outsider, &owner_hex, run, "approve");
    let mut expected = vec![first.to_hex(), second.to_hex()];
    expected.sort();
    assert_eq!(settled_members(&settled), expected, "{settled}");
    for id in [first, second] {
        assert_eq!(
            claim_status(&fixture, &id).0,
            ClaimApprovalStatus::Approved,
            "an agent outside the opener's lineage settles"
        );
    }
}

#[test]
fn a_bundle_with_a_member_its_lane_withholds_reads_as_none() {
    let fixture = rooted_vault();
    let run = "consent-bundle-withheld-lane";
    let opener = granted_agent(&fixture, "bundle-opener", BUNDLE_VERBS);
    let narrow = granted_agent_in_bands(
        &fixture,
        "no-claims-bundle-reader",
        BUNDLE_VERBS,
        Some([ENTITY_TYPE_TURN, ENTITY_TYPE_TASK].as_slice()),
    );
    let settler = granted_agent(&fixture, "bundle-settler", BUNDLE_VERBS);
    let (first, second) = park_two_in_run(&fixture, opener, run);
    owner_turns_on(&fixture, DELEGATE_KEY, None);
    let (owner_hex, _) = owner_bundle_hex(&fixture, run);

    invoke(
        &agent_memory(&fixture, narrow),
        REVIEW_AS,
        json!({ "dreamer_run_id": run }),
    )
    .expect_err("a lane that withholds a member's claim reviews no bundle");
    invoke(
        &agent_memory(&fixture, narrow),
        RESOLVE_AS,
        json!({
            "bundle_id": owner_hex,
            "dreamer_run_id": run,
            "action": "approve",
        }),
    )
    .expect_err("a lane that withholds a member's claim settles no bundle");
    for id in [first, second] {
        assert_eq!(
            claim_status(&fixture, &id).0,
            ClaimApprovalStatus::Proposed,
            "the withheld lane changed nothing"
        );
    }

    let settled = agent_resolve(&fixture, settler, &owner_hex, run, "approve");
    let mut expected = vec![first.to_hex(), second.to_hex()];
    expected.sort();
    assert_eq!(settled_members(&settled), expected, "{settled}");
}
