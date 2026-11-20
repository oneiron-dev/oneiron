//! An agent that reads through its own live read Grant sees, in its weave,
//! the owner's claim about it that the Grant admits, as it reads that claim
//! on vault.get: in its live report (`vault.weave.report`), whose receipt
//! names the Grant's reach, and in its saved digest period
//! (`vault.weave.digest`). The weave judged its rows under the agent key's
//! own floor alone, which reads nothing, so the live report left the claim
//! out under a deny-all receipt and the saved period was withheld whole
//! (FIX-LIST SCOPED-READ-UNKNOWN-AUTHORITY-CALLERS, part 2d). After the owner
//! revokes the Grant neither shows the claim.
//!
//! Public paths only: the embedded owner's door, the agent's own `Vault::memory`
//! handle, and `ScopedRead::render_due_weave_digest` on `Vault::scoped_read`
//! of the agent's key, the render the timer and `vault.weave.digest.render`
//! run. The claim takes the vault's own time (no `occurred_at` or
//! `learned_at`), so the test reads no wall clock.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_grant_weave_reads`

use oneiron::claim::WeaveReader;
use oneiron::memory::Memory;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The predicate the owner's claim about the agent carries, and the one the
/// agent's Digest section reads.
const PREDICATE: &str = "project.note";

/// The agent's digest schedule's first due second, and the render's clock
/// a minute past it: fixed, so the test reads no wall clock.
const FIRST_DUE_AT: u64 = 1_700_000_000;
const RENDER_AT: u64 = FIRST_DUE_AT + 60;

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

/// Whether the receipt list `list` names `entry`.
fn lists(list: &Value, entry: &str) -> bool {
    list.as_array()
        .is_some_and(|entries| entries.iter().any(|named| named == entry))
}

/// Whether a weave answer's sections serve the claim `claim` as an item.
fn serves_claim(answer: &Value, claim: &str) -> bool {
    answer["sections"].as_array().is_some_and(|sections| {
        sections.iter().any(|section| {
            section["items"].as_array().is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item["item"] == "claim" && item["claim"]["claim_ref"] == claim)
            })
        })
    })
}

/// A vault this process owns with an identity agent holding a live read
/// Grant over every world, facet, band, audience and sensitivity, and the
/// owner's claim about that agent. The vault closes before its directory
/// goes.
struct Fixture {
    vault: Vault,
    agent: EntityId,
    claim: String,
    grant: String,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh vault");
        oneiron_testkit::dreamer::attach_test_host(&vault).expect("the test host");
        vault.ensure_embedded_owner_actor().expect("the owner");
        let owner = door::owner(&vault).expect("the embedded owner");

        let agent = vault.new_entity_id().expect("an agent id");
        call(
            &owner,
            "vault.agents.create",
            json!({
                "agent_def_ref": agent.to_hex(),
                "definition": {
                    "agent_id": "weave-reader",
                    "desc": "an agent that reads its weave through the owner's read Grant",
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
                "value": "The weave reader keeps the harbour survey's lantern list.",
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
        Self {
            vault,
            agent,
            claim,
            grant,
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

    /// The agent reads the owner's claim about it on vault.get under its
    /// live Grant.
    fn assert_agent_reads_the_claim(&self) {
        let read = call(
            &self.reader(),
            "vault.get",
            json!({"entity_ref": self.claim}),
        );
        assert!(
            read.get("value").is_some_and(|value| !value.is_null()),
            "FIXTURE: the live Grant admits the owner's claim on vault.get: {read:#}"
        );
    }

    /// The agent's live weave report: one Digest section over the claim's
    /// predicate, the section an agent's weave policy row allows.
    fn report(&self) -> Value {
        call(
            &self.reader(),
            "vault.weave.report",
            json!({"sections": [{"kind": "digest", "predicates": [PREDICATE]}]}),
        )
    }

    /// The owner schedules the agent's daily digest over the same section,
    /// first due at [`FIRST_DUE_AT`].
    fn schedule_digest(&self) {
        let owner = door::owner(&self.vault).expect("the embedded owner");
        call(
            &owner,
            "vault.weave.schedules.put",
            json!({
                "reader": {"kind": "agent", "reader_ref": self.agent.to_hex()},
                "cadence": "daily",
                "next_due_at": FIRST_DUE_AT,
                "sections": [{"kind": "digest", "predicates": [PREDICATE]}],
            }),
        );
    }

    /// The agent's due period, rendered under the agent's own key.
    fn render_digest(&self) {
        let key = self.reader().read_key().expect("the agent's read key");
        let rendered = self
            .vault
            .scoped_read(key)
            .render_due_weave_digest(WeaveReader::Agent(self.agent), RENDER_AT)
            .expect("the agent's due period renders");
        assert!(
            rendered.is_some(),
            "FIXTURE: the agent's schedule is due at {RENDER_AT} and renders a period"
        );
    }

    /// The agent's newest saved period, as `vault.weave.digest` serves it.
    fn digest(&self) -> Value {
        call(&self.reader(), "vault.weave.digest", json!({}))
    }
}

#[test]
fn an_agents_live_weave_report_under_a_live_read_grant_serves_the_claim_and_names_the_grant() {
    let fixture = Fixture::open();
    fixture.assert_agent_reads_the_claim();

    let report = fixture.report();
    assert!(
        serves_claim(&report, &fixture.claim),
        "the live Grant admits the owner's claim about the agent, yet the agent's weave \
         report leaves it out: {report:#}"
    );
    let narrowing = &report["narrowing"];
    for scope in ["requested", "actor_ceiling", "applied"] {
        assert_eq!(
            narrowing[scope]["deny_all"], false,
            "the weave report's {scope} scope denies all under the live Grant: {narrowing:#}"
        );
    }
    for list in ["narrowed_axes", "replan_hint"] {
        for entry in ["deny_all", "grant_scope"] {
            assert!(
                !lists(&narrowing[list], entry),
                "the weave report's {list} names {entry} under the live Grant: {narrowing:#}"
            );
        }
    }

    fixture.revoke();
    let revoked = fixture.report();
    assert!(
        !serves_claim(&revoked, &fixture.claim),
        "the agent's weave report still serves the claim after the revoke: {revoked:#}"
    );
}

#[test]
fn an_agents_saved_digest_under_a_live_read_grant_serves_the_claim() {
    let fixture = Fixture::open();
    fixture.assert_agent_reads_the_claim();
    fixture.schedule_digest();
    fixture.render_digest();

    let digest = fixture.digest();
    assert!(
        !digest.is_null(),
        "the live Grant admits the owner's claim about the agent, yet the agent's saved \
         period is withheld whole"
    );
    assert!(
        serves_claim(&digest, &fixture.claim),
        "the live Grant admits the owner's claim about the agent, yet the agent's saved \
         period leaves it out: {digest:#}"
    );

    fixture.revoke();
    let revoked = fixture.digest();
    assert!(
        !serves_claim(&revoked, &fixture.claim),
        "the agent's saved period still serves the claim after the revoke: {revoked:#}"
    );
}
