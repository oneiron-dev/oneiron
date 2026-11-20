//! An agent that reads through its own live read Grant sees, in its weave's
//! Admissions section, a loop decision reached only through the read
//! position its writer kept, when ONE of its live Grants alone holds that
//! position's world, facet and band (Engine ANSWER
//! LOOP-KEPT-POSITION-FLOOR-AND-GRANT = A). The kept position was judged
//! under the agent key's own floor AND one Grant alone; an identity agent's
//! own floor reads nothing, so such a decision was always withheld from it,
//! while the same position on a named row it reads was admitted (FIX-LIST
//! LOOP-KEPT-POSITION-FLOOR-AND-GRANT).
//!
//! Two Grants never combine: Grants that hold the position only together,
//! or a Grant whose facets miss the position's facet, show nothing. A
//! revoked Grant shows nothing, and so does a Grant once a legal use limit
//! keeps the stored claim for storage alone (a hosted vault, where the
//! owner's customer hold refuses its privacy erase; review round 2).
//!
//! The decision is the agent's own refused applied-maintenance decision
//! about a candidate claim that never landed, its one read context the
//! position the owner's stored claim about the agent stamps, with no
//! `about` row, recorded by the cfg door
//! `test_doors::loop_kept_position::record_kept_position_receipt` with no
//! claim and no maintenance write. The shipped weave policy gives an agent
//! the Digest section only; the owner opts the vault's `agent` row into
//! Admissions by installing the stored default manifest with that one
//! section added, as `tests/agent_grant_loop_decisions.rs` does. Every read
//! is a public verb: the embedded owner's door and the agent's own
//! `Vault::memory` handle. Worlds and facets are made under the owner's
//! proof (the cfg door `test_doors::steward::owner`).
//!
//! Red (main): the agent's Admissions serve no such decision under any
//! Grant.
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test loop_kept_position_grant`

#![cfg(oneiron_test_support)]

use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{EraseOptions, EraseReason, Memory};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM};
use oneiron::test_doors::loop_kept_position::record_kept_position_receipt;
use oneiron::test_doors::steward::owner as owner_proof;
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The predicate the owner's claim about the agent carries.
const PREDICATE: &str = "project.note";

/// The time each fixture world and facet says it was made.
const WRITTEN_AT: u64 = 1_700_000_000;

/// The weave report recipe: one Admissions section.
fn admissions_recipe() -> Value {
    json!({"sections": [{"kind": "admissions"}]})
}

/// Runs `verb` as `caller`, panicking with its refusal.
fn call(caller: &Memory<'_>, verb: &str, input: Value) -> Value {
    door::invoke(caller, verb, input).unwrap_or_else(|error| panic!("{verb}: {error}"))
}

/// The id of a written record in `answer` at `pointer`.
fn id_at(answer: &Value, pointer: &str) -> String {
    answer
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no id at {pointer}: {answer:#}"))
        .to_owned()
}

/// A Grant axis that holds everything.
fn all() -> Value {
    json!({"kind": "all"})
}

/// A Grant axis that holds `values` alone.
fn some(values: &[Value]) -> Value {
    json!({"kind": "some", "values": values})
}

/// `id` as a Grant axis value.
fn named(id: EntityId) -> Value {
    Value::String(id.to_hex())
}

/// A read Grant's Scope over `worlds`, `facets` and `bands`, every audience
/// and sensitivity.
fn read_scope(worlds: Value, facets: Value, bands: Value) -> Value {
    json!({
        "worlds": worlds,
        "facets": facets,
        "bands": bands,
        "audience": {"kind": "all"},
        "verbs": {"kind": "some", "values": ["read"]},
        "sensitivity": {"kind": "all"},
    })
}

/// The loop decision items of a weave answer's sections.
fn loop_decisions(answer: &Value) -> Vec<&Value> {
    answer["sections"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|section| section["items"].as_array())
        .flatten()
        .filter(|item| item["item"] == "loop_decision")
        .collect()
}

/// The served item of the decision `decision` in a weave answer, if any.
fn decision_item<'a>(answer: &'a Value, decision: &str) -> Option<&'a Value> {
    loop_decisions(answer)
        .into_iter()
        .find(|item| item["decision_ref"] == decision)
}

/// Adds `admissions` to the sections of the vault-wide `agent` row of the
/// stored default manifest's weave report policy, and installs the
/// manifest at its own id as the owner.
fn allow_agent_admissions(vault: &Vault, proof: &AuthenticatedOwner) {
    use rmpv::Value as Mp;

    let id = oneiron_store::policy_record::default_policy_manifest_id()
        .expect("the default policy manifest id");
    let body = vault
        .get(&id)
        .expect("the default policy manifest reads")
        .expect("FIXTURE: a fresh vault stores the default policy manifest");
    let Mp::Map(mut fields) =
        rmpv::decode::read_value(&mut body.as_slice()).expect("the manifest decodes")
    else {
        panic!("FIXTURE: the default policy manifest is a map");
    };
    let Some((_, Mp::Array(rows))) = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("weave_report_policy"))
    else {
        panic!("FIXTURE: the default policy manifest has a weave_report_policy array");
    };
    let row_field = |row: &Mp, name: &str| -> Option<Mp> {
        let Mp::Map(entries) = row else {
            return None;
        };
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value.clone())
    };
    let agent_row = rows
        .iter_mut()
        .find(|row| {
            row_field(&**row, "role").is_some_and(|role| role.as_str() == Some("agent"))
                && row_field(&**row, "holder_ref").is_none()
        })
        .expect("FIXTURE: the weave report policy has a vault-wide agent row");
    let Mp::Map(entries) = agent_row else {
        unreachable!("the agent row is a map");
    };
    let Some((_, Mp::Array(sections))) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("sections"))
    else {
        panic!("FIXTURE: the agent row lists its sections");
    };
    sections.push(Mp::from("admissions"));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Mp::Map(fields)).expect("the manifest encodes");
    vault
        .install_owner_policy_manifest(proof, id, bytes, vault.now_recorded_at())
        .expect("the owner installs the manifest with agent Admissions");
}

/// A vault this process owns with an identity agent that holds no Grant
/// yet, the owner's claim about that agent in base reality, a second world
/// and a second facet of the owner's that the claim does not sit in, an
/// `agent` weave row that allows Admissions, and the agent's own refused
/// decision about a candidate that never landed, kept at the claim's
/// position. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    agent: EntityId,
    claim: String,
    candidate: EntityId,
    decision: String,
    harbor: EntityId,
    elsewhere: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        Self::open_in(VaultConfig::device())
    }

    /// [`Self::open`] on a hosted vault, where a refused privacy erase keeps
    /// a record as storage only.
    fn open_hosted() -> Self {
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        Self::open_in(config)
    }

    fn open_in(config: VaultConfig) -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open_owned(dir.path(), config).expect("fresh vault");
        oneiron_testkit::dreamer::attach_test_host(&vault).expect("the test host");
        let owner_id = vault.ensure_embedded_owner_actor().expect("the owner");
        let owner = door::owner(&vault).expect("the embedded owner");

        let agent = vault.new_entity_id().expect("an agent id");
        call(
            &owner,
            "vault.agents.create",
            json!({
                "agent_def_ref": agent.to_hex(),
                "definition": {
                    "agent_id": "kept-position-reader",
                    "desc": "an agent that reads its own loop decisions through the owner's read Grant",
                    "version": "1",
                },
            }),
        );
        let remembered = call(
            &owner,
            "vault.remember",
            json!({
                "predicate": PREDICATE,
                "subject_ref": agent.to_hex(),
                "value": "The kept-position reader files the lighthouse logbook by tide.",
                "confidence": 0.9,
                "source": "user_stated",
            }),
        );
        let claim = id_at(&remembered, "/claim/id");

        let proof = owner_proof(&vault).expect("the owner's proof");
        let harbor = vault
            .create_world(&proof, "Harbor", WRITTEN_AT)
            .expect("FIXTURE: the owner creates the Harbor world");
        let elsewhere = vault
            .create_facet(&proof, owner_id, "Elsewhere", WRITTEN_AT)
            .expect("FIXTURE: the owner creates a second facet");
        allow_agent_admissions(&vault, &proof);

        let claim_id = EntityId::from_hex(&claim).expect("the claim id");
        let (row, candidate) = record_kept_position_receipt(&vault, agent, claim_id).expect(
            "FIXTURE: the agent's refused decision about a candidate at the claim's position",
        );
        Self {
            vault,
            agent,
            claim,
            candidate,
            decision: row.decision_id.to_hex(),
            harbor,
            elsewhere,
            _dir: dir,
        }
    }

    fn owner(&self) -> Memory<'_> {
        door::owner(&self.vault).expect("the embedded owner")
    }

    fn reader(&self) -> Memory<'_> {
        self.vault.memory(self.agent, EdgeActorClass::Agent)
    }

    /// The owner mints the agent a read Grant of `scope`; its id.
    fn mint(&self, scope: Value) -> String {
        let minted = call(
            &self.owner(),
            "vault.agents.grants.mint",
            json!({"agent": self.agent.to_hex(), "authority_scope": scope}),
        );
        assert_eq!(
            minted.pointer("/grant/confers"),
            Some(&Value::Bool(true)),
            "FIXTURE: the owner's read Grant is live: {minted:#}"
        );
        id_at(&minted, "/grant/grant_ref")
    }

    fn revoke(&self, grant: &str) {
        call(
            &self.owner(),
            "vault.agents.grants.revoke",
            json!({"grant_ref": grant}),
        );
    }

    /// The agent's live weave report of one Admissions section.
    fn agent_admissions(&self) -> Value {
        door::invoke(&self.reader(), "vault.weave.report", admissions_recipe()).unwrap_or_else(
            |error| panic!("FIXTURE: the agent row allows an Admissions recipe: {error}"),
        )
    }

    /// Whether the agent reads the owner's stored claim on vault.get: the
    /// same position on the named-row route.
    fn agent_reads_the_claim(&self) -> bool {
        door::invoke(
            &self.reader(),
            "vault.get",
            json!({"entity_ref": self.claim}),
        )
        .is_ok_and(|read| read.get("value").is_some_and(|value| !value.is_null()))
    }

    /// The owner places a customer hold on the stored claim and runs its
    /// privacy erase, which the hold refuses: the claim stays stored, kept
    /// for storage alone under a legal use limit (C6).
    fn keep_the_claim_use_limited(&self) {
        let claim = EntityId::from_hex(&self.claim).expect("the claim id");
        let proof = owner_proof(&self.vault).expect("the owner's proof");
        let hold = self
            .vault
            .place_legal_hold(
                &proof,
                vec![LegalHoldTarget::Record(claim)],
                Some("matter-kept-position".to_owned()),
            )
            .expect("FIXTURE: the owner places a customer hold on the claim");
        assert!(hold.stands(), "FIXTURE: the customer hold stands: {hold:?}");
        let owner = self.owner();
        let preview = owner
            .preview_entity_delete(&claim)
            .expect("FIXTURE: the owner previews the claim's privacy erase");
        let outcome = owner
            .confirm_entity_erase(
                &preview,
                EraseOptions {
                    reason: EraseReason::GdprDelete,
                    also_same_bytes: false,
                    veto_starter: None,
                },
            )
            .expect("FIXTURE: the claim's privacy erase runs");
        assert_eq!(
            outcome.first.reason.as_str(),
            "privacy_erase_kept",
            "FIXTURE: the held privacy erase is kept: {outcome:?}"
        );
        assert!(
            self.vault
                .legal_hold_use_limit(&claim)
                .expect("FIXTURE: the use limit reads")
                .is_some(),
            "FIXTURE: the kept erase use-limits the claim"
        );
    }

    /// The fixture's own facts: the candidate never landed, and the owner
    /// sees the decision.
    fn assert_fixture(&self) {
        assert!(
            self.vault
                .get(&self.candidate)
                .expect("the candidate's row reads")
                .is_none(),
            "FIXTURE: the decision's candidate never landed"
        );
        let owners = call(&self.owner(), "vault.weave.report", admissions_recipe());
        let item = decision_item(&owners, &self.decision).unwrap_or_else(|| {
            panic!("FIXTURE: the owner's Admissions list the agent's decision: {owners:#}")
        });
        assert_eq!(
            item["kind"], "dreamer_maintenance_apply",
            "FIXTURE: the decision keeps its tag: {item:#}"
        );
    }
}

#[test]
fn one_grant_over_the_kept_positions_world_and_band_shows_the_decision() {
    let fixture = Fixture::open();
    fixture.assert_fixture();
    fixture.mint(read_scope(
        some(&[named(base_world_id())]),
        all(),
        some(&[json!(ENTITY_TYPE_CLAIM)]),
    ));
    let reads_claim = fixture.agent_reads_the_claim();

    let report = fixture.agent_admissions();
    let item = decision_item(&report, &fixture.decision).unwrap_or_else(|| {
        panic!(
            "the agent's one live Grant holds the kept position's world, facet and band (it reads \
             the owner's claim at that position on vault.get: {reads_claim}), yet its Admissions \
             leave out its own decision about the candidate kept there: {report:#}"
        )
    });
    assert_eq!(
        item["kind"], "dreamer_maintenance_apply",
        "the agent's loop decision keeps its tag: {item:#}"
    );
}

#[test]
fn the_decision_goes_once_the_one_grant_that_holds_it_is_revoked() {
    let fixture = Fixture::open();
    fixture.assert_fixture();
    let grant = fixture.mint(read_scope(all(), all(), all()));
    let report = fixture.agent_admissions();
    assert!(
        decision_item(&report, &fixture.decision).is_some(),
        "the agent's live Grant over every world, facet and band holds the kept position, yet its \
         Admissions leave out its own decision about the candidate kept there: {report:#}"
    );

    fixture.revoke(&grant);
    let report = fixture.agent_admissions();
    assert!(
        decision_item(&report, &fixture.decision).is_none(),
        "the owner revoked the agent's only read Grant, yet its Admissions still list the \
         decision kept at the claim's position: {report:#}"
    );
}

#[test]
fn grants_that_hold_the_kept_position_only_together_show_nothing() {
    let fixture = Fixture::open();
    fixture.assert_fixture();
    // One Grant misses the position's band, the other its world: their
    // envelope holds it, neither alone does.
    fixture.mint(read_scope(all(), all(), some(&[json!(ENTITY_TYPE_ASSET)])));
    fixture.mint(read_scope(some(&[named(fixture.harbor)]), all(), all()));
    let reads_claim = fixture.agent_reads_the_claim();

    let report = fixture.agent_admissions();
    assert!(
        decision_item(&report, &fixture.decision).is_none(),
        "neither of the agent's Grants alone holds the kept position (one misses its band, the \
         other its world; it reads the owner's claim at that position on vault.get: \
         {reads_claim}), yet its Admissions list the decision kept there: {report:#}"
    );
}

#[test]
fn a_grant_whose_facets_miss_the_kept_positions_facet_shows_nothing() {
    let fixture = Fixture::open();
    fixture.assert_fixture();
    fixture.mint(read_scope(all(), some(&[named(fixture.elsewhere)]), all()));
    let reads_claim = fixture.agent_reads_the_claim();

    let report = fixture.agent_admissions();
    assert!(
        decision_item(&report, &fixture.decision).is_none(),
        "the agent's one Grant holds only a facet the kept position does not sit in (it reads \
         the owner's claim at that position on vault.get: {reads_claim}), yet its Admissions \
         list the decision kept there: {report:#}"
    );
}

/// Review round 2 of #10040: a stored claim a legal use limit keeps for
/// storage alone is absent to every ordinary reader on the named-row route,
/// so one Grant alone never shows a decision through its kept position.
#[test]
fn a_grant_shows_no_decision_kept_at_a_use_limited_claim() {
    let fixture = Fixture::open_hosted();
    fixture.assert_fixture();
    fixture.mint(read_scope(
        some(&[named(base_world_id())]),
        all(),
        some(&[json!(ENTITY_TYPE_CLAIM)]),
    ));
    let report = fixture.agent_admissions();
    assert!(
        decision_item(&report, &fixture.decision).is_some(),
        "FIXTURE: the agent's one Grant shows its decision before the hold: {report:#}"
    );

    fixture.keep_the_claim_use_limited();
    let reads_claim = fixture.agent_reads_the_claim();
    let report = fixture.agent_admissions();
    assert!(
        decision_item(&report, &fixture.decision).is_none(),
        "a legal use limit keeps the claim at the kept position for storage alone (the agent \
         reads it on vault.get: {reads_claim}), yet its one Grant still shows the decision kept \
         there: {report:#}"
    );
}
