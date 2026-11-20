//! An agent that reads through its own live read Grant sees, in its weave's
//! Admissions section, the loop decision about the owner's claim about it
//! that the Grant admits, as it reads that claim on vault.get. The loop read
//! bound no read for a reader whose key floor reads nothing, and judged each
//! decision's named row under that floor alone, so such an agent saw no loop
//! decision (FIX-LIST SCOPED-READ-UNKNOWN-AUTHORITY-CALLERS, part 2f). After
//! the owner revokes the Grant the decision is gone again.
//!
//! The shipped weave policy gives an agent the Digest section only; the
//! owner opts the vault's `agent` row into Admissions by installing the
//! stored default manifest with that one section added
//! (`Vault::install_owner_policy_manifest`, as `tests/resident_busy_wakes.rs`
//! does for a rule). The decision is an approved applied-maintenance receipt
//! about the claim, recorded by the cfg door
//! `test_doors::gate_receipt_rows::record_maintenance_apply_receipt` with no
//! maintenance write. Every read is a public verb: the embedded owner's door
//! and the agent's own `Vault::memory` handle.
//!
//! Red (main): the agent's Admissions section serves no loop decision.
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_grant_loop_decisions`

#![cfg(oneiron_test_support)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::gate_receipt_rows::record_maintenance_apply_receipt;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The predicate the owner's claim about the agent carries.
const PREDICATE: &str = "project.note";

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

/// A vault this process owns with an identity agent holding a live read
/// Grant over every world, facet, band, audience and sensitivity, the
/// owner's claim about that agent, an `agent` weave row that allows
/// Admissions, and one approved loop decision about the claim decided by
/// the owner. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    agent: EntityId,
    claim: String,
    grant: String,
    decision: String,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh vault");
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
                    "agent_id": "loop-reader",
                    "desc": "an agent that reads its weave's loop decisions through the owner's read Grant",
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
                "value": "The loop reader keeps the ferry timetable's winter column.",
                "confidence": 0.9,
                "source": "user_stated",
            }),
        );
        let claim = id_at(&remembered, "/claim/id");
        let minted = call(
            &owner,
            "vault.agents.grants.mint",
            json!({
                "agent": agent.to_hex(),
                "authority_scope": {
                    "worlds": {"kind": "all"},
                    "facets": {"kind": "all"},
                    "bands": {"kind": "all"},
                    "audience": {"kind": "all"},
                    "verbs": {"kind": "some", "values": ["read"]},
                    "sensitivity": {"kind": "all"},
                },
            }),
        );
        assert_eq!(
            minted.pointer("/grant/confers"),
            Some(&Value::Bool(true)),
            "the owner's read Grant is live: {minted:#}"
        );
        let grant = id_at(&minted, "/grant/grant_ref");

        let proof = vault
            .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        allow_agent_admissions(&vault, &proof);
        let claim_id = EntityId::from_hex(&claim).expect("the claim id");
        let decision = record_maintenance_apply_receipt(&vault, owner_id, claim_id)
            .expect("the owner's applied-maintenance receipt about the claim")
            .decision_id
            .to_hex();
        Self {
            vault,
            agent,
            claim,
            grant,
            decision,
            _dir: dir,
        }
    }

    fn reader(&self) -> Memory<'_> {
        self.vault.memory(self.agent, EdgeActorClass::Agent)
    }

    fn revoke(&self) {
        let owner = door::owner(&self.vault).expect("the embedded owner");
        call(
            &owner,
            "vault.agents.grants.revoke",
            json!({"grant_ref": self.grant}),
        );
    }

    /// The agent's live weave report of one Admissions section.
    fn agent_admissions(&self) -> Value {
        door::invoke(&self.reader(), "vault.weave.report", admissions_recipe()).unwrap_or_else(
            |error| panic!("FIXTURE: the agent row allows an Admissions recipe: {error}"),
        )
    }
}

#[test]
fn an_agents_admissions_list_the_loop_decision_about_the_claim_its_grant_reads() {
    let fixture = Fixture::open();
    let owner = door::owner(&fixture.vault).expect("the embedded owner");
    let owners = call(&owner, "vault.weave.report", admissions_recipe());
    let item = decision_item(&owners, &fixture.decision).unwrap_or_else(|| {
        panic!("FIXTURE: the owner's Admissions list the receipt as a loop decision: {owners:#}")
    });
    assert_eq!(
        item["claim_ref"], fixture.claim,
        "FIXTURE: the loop decision names the claim: {item:#}"
    );
    let read = call(
        &fixture.reader(),
        "vault.get",
        json!({"entity_ref": fixture.claim}),
    );
    assert!(
        read.get("value").is_some_and(|value| !value.is_null()),
        "FIXTURE: the live Grant admits the owner's claim on vault.get: {read:#}"
    );

    let report = fixture.agent_admissions();
    let item = decision_item(&report, &fixture.decision).unwrap_or_else(|| {
        panic!(
            "the agent reads the claim about it under its live Grant, yet its Admissions leave \
             out the loop decision about that claim: {report:#}"
        )
    });
    assert_eq!(
        item["claim_ref"], fixture.claim,
        "the agent's loop decision names the claim its Grant reads: {item:#}"
    );
    assert_eq!(
        item["kind"], "dreamer_maintenance_apply",
        "the agent's loop decision keeps its tag: {item:#}"
    );
}

#[test]
fn an_agents_admissions_drop_the_loop_decision_once_its_grant_is_revoked() {
    let fixture = Fixture::open();
    fixture.revoke();
    let report = fixture.agent_admissions();
    assert!(
        decision_item(&report, &fixture.decision).is_none(),
        "the owner revoked the agent's only read Grant, yet its Admissions still list the loop \
         decision about the claim: {report:#}"
    );
}
