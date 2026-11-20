//! An identity agent that reads through its own live read Grant sees, on its
//! people roster (vault.people.list and vault.people.get), the stored `about`
//! line of a person that Grant reads, when the same Grant also reads every
//! fact the line was written from. The roster picked the line at the band of
//! the key's own floor, which reads nothing for an identity agent, so such a
//! person stood on its roster with no line at all (FIX-LIST
//! GRANT-RECEIPT-OTHER-READ-LANES part 4). The line still comes from one
//! Grant alone (RULING GRANT-COMBINE Q1 = A): a Grant that reads the person
//! but not the fact shows none, and neither do two Grants, one reading only
//! the PERSON row and one only CLAIM rows. A revoked Grant drops the person.
//! Nor does a second Grant lend a row a fact was written from: a line that
//! stands on the owner's stated intent, which quotes a MESSAGE, shows only
//! where one Grant reads the person, the intent and that MESSAGE (review
//! round 1 of #9929).
//!
//! Public paths, plus three test doors: two that land the Dreamer's `about`
//! lines (`oneiron::test_doors::derive::{about_facts, commit}`, as
//! `derive_artifact.rs` lands them) and the owner's proof
//! (`oneiron::test_doors::steward::owner`) his stated intent is written on.
//! The rest: the embedded owner's door, the agent's own `Vault::memory`
//! handle and its read key, `Vault::record_owner_intent`, and
//! `Vault::put_entity` for the MESSAGEs a new person's identity and the
//! owner's intent cite.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_grant_people_about`
#![cfg(oneiron_test_support)]

use oneiron::memory::{MEMORY_CODE_NOT_FOUND, Memory};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::derive::{About, Derived, Named, about_facts, commit};
use oneiron::test_doors::steward::{dreamer, owner as owner_proof};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The person's name, as the owner created it.
const NAME: &str = "Owen Marsh";

/// The person's `about` line, at every band its fact takes a line.
const LINE: &str = "Owen keeps the reading group's lantern list.";

/// The intent the owner states, in the words of the MESSAGE it quotes.
const INTENT: &str = "I'll bring the lantern list to the reading group on Thursday.";

/// Runs `verb` as `caller`, panicking with its refusal.
fn call(caller: &Memory<'_>, verb: &str, input: Value) -> Value {
    door::invoke(caller, verb, input).unwrap_or_else(|error| panic!("{verb}: {error}"))
}

/// The id of a written record in `answer` at `pointer`.
fn id_at(answer: &Value, pointer: &str) -> EntityId {
    let hex = answer
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no id at {pointer}: {answer:#}"));
    EntityId::from_hex(hex).unwrap_or_else(|_| panic!("{hex} at {pointer} is no entity id"))
}

/// A Grant's `bands` axis: every row type, or only `types`.
fn bands(types: &[u8]) -> Value {
    if types.is_empty() {
        json!({"kind": "all"})
    } else {
        json!({"kind": "some", "values": types})
    }
}

/// A vault this process owns with an identity agent that holds no Grant yet,
/// whose model channel may be told every name, and a person with one fact
/// about that person and the Dreamer's `about` line written from it: a
/// person the owner created, with a fact he remembered about them
/// ([`Fixture::open`]), or the owner's own person, with an intent he stated
/// quoting a MESSAGE ([`Fixture::open_owner_intent`]). The vault closes
/// before its directory goes.
struct Fixture {
    vault: Vault,
    agent: EntityId,
    person: EntityId,
    claim: EntityId,
    /// The MESSAGE the fact quotes, for the owner's intent.
    quoted: Option<EntityId>,
    /// The person's name as the owner's roster reads it.
    name: Value,
    _dir: tempfile::TempDir,
}

/// The person a fixture's line is about, its one fact, and the MESSAGE that
/// fact quotes, if it quotes one.
type Fact = (EntityId, EntityId, Option<EntityId>);

impl Fixture {
    /// A person the owner created, with a project note he remembered about
    /// them.
    fn open() -> Self {
        let fixture = Self::with_fact(|vault, owner| {
            let evidence = message(
                vault,
                &format!("{NAME} introduced themself at the reading group"),
            );
            let created = call(
                owner,
                "vault.people.create",
                json!({
                    "identity": {"name": NAME},
                    "identity_evidence_refs": [evidence.to_hex()],
                    "occurred_at": vault.now_recorded_at(),
                }),
            );
            let person = id_at(&created, "/person/id_hex");
            let remembered = call(
                owner,
                "vault.remember",
                json!({
                    "predicate": "project.note",
                    "subject_ref": person.to_hex(),
                    "value": "Owen keeps the lantern list for the reading group.",
                    "confidence": 0.9,
                    "source": "user_stated",
                }),
            );
            (person, id_at(&remembered, "/claim/id"), None)
        });
        assert_eq!(
            fixture.name, NAME,
            "FIXTURE: the owner reads the name of the person he created"
        );
        fixture
    }

    /// The owner's own person, with an intent he stated in his own words,
    /// citing the MESSAGE they came from: the intent's words are that
    /// MESSAGE's, so a reader reads the intent only where it reads the
    /// MESSAGE too.
    fn open_owner_intent() -> Self {
        Self::with_fact(|vault, _| {
            let person = vault.ensure_embedded_owner_actor().expect("the owner");
            let quoted = message(vault, INTENT);
            let proof = owner_proof(vault).expect("the owner's proof");
            let intent = vault
                .record_owner_intent(&proof, INTENT, None, Some(quoted))
                .expect("the owner states his intent");
            (person, intent, Some(quoted))
        })
    }

    /// The vault, the agent and the fact `fact` writes as the owner, with
    /// the Dreamer's `about` line written from that fact.
    fn with_fact(fact: impl FnOnce(&Vault, &Memory<'_>) -> Fact) -> Self {
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
                    "agent_id": "people-reader",
                    "desc": "an agent that reads the roster through the owner's read Grant",
                    "version": "1",
                },
            }),
        );
        // The name ceiling only says what the model channel may be told; it
        // grants no read (vault.disclosure.ceiling.set). A masked name clears
        // the `about` line too, so it is opened here for every test.
        call(
            &owner,
            "vault.disclosure.ceiling.set",
            json!({"connection": format!("agent:{}", agent.to_hex()), "ceiling": "restricted"}),
        );

        let (person, claim, quoted) = fact(&vault, &owner);

        let dreamer = dreamer(&vault).expect("the Dreamer");
        let (digest, line_bands) = about_facts(&vault, dreamer, EdgeActorClass::System, person)
            .expect("the person's facts");
        assert!(
            !line_bands.is_empty(),
            "FIXTURE: the Dreamer reads the owner's fact about the person"
        );
        let committed = commit(
            &vault,
            dreamer,
            EdgeActorClass::System,
            "run-people-about",
            &[Derived::About(About {
                local: "about",
                person: Named::Stored(person),
                written_from: digest,
                lines: line_bands.iter().map(|band| (*band, LINE)).collect(),
            })],
        )
        .expect("the about commit");
        let [item] = committed.items.as_slice() else {
            panic!("FIXTURE: one about item: {:?}", committed.items);
        };
        assert!(
            item.landed,
            "FIXTURE: the Dreamer's about lines land: {:?}",
            item.reasons
        );
        let mut fixture = Self {
            vault,
            agent,
            person,
            claim,
            quoted,
            name: Value::Null,
            _dir: dir,
        };
        fixture.name = fixture.assert_owner_sees_the_line();
        fixture
    }

    fn owner(&self) -> Memory<'_> {
        door::owner(&self.vault).expect("the embedded owner")
    }

    fn reader(&self) -> Memory<'_> {
        self.vault.memory(self.agent, EdgeActorClass::Agent)
    }

    /// The owner mints the agent a live read Grant over every world, facet,
    /// audience and sensitivity, and the row types `types` (every one when
    /// empty); its ref.
    fn mint(&self, types: &[u8]) -> String {
        let minted = call(
            &self.owner(),
            "vault.agents.grants.mint",
            json!({
                "agent": self.agent.to_hex(),
                "authority_scope": {
                    "worlds": {"kind": "all"},
                    "facets": {"kind": "all"},
                    "bands": bands(types),
                    "audience": {"kind": "all"},
                    "verbs": {"kind": "some", "values": ["read"]},
                    "sensitivity": {"kind": "all"},
                },
            }),
        );
        assert_eq!(
            minted.pointer("/grant/confers"),
            Some(&Value::Bool(true)),
            "FIXTURE: the owner's read Grant is live: {minted:#}"
        );
        minted
            .pointer("/grant/grant_ref")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no grant ref: {minted:#}"))
            .to_owned()
    }

    fn revoke(&self, grant: &str) {
        call(
            &self.owner(),
            "vault.agents.grants.revoke",
            json!({"grant_ref": grant}),
        );
    }

    /// Whether the agent's own read admits `id` now.
    fn agent_reads(&self, id: EntityId) -> bool {
        let key = self.reader().read_key().expect("the agent's read key");
        self.vault
            .scoped_read(key)
            .is_entity_readable(&id)
            .expect("the agent's row check")
    }

    /// The person's row on `caller`'s roster, every page read.
    fn roster_row(&self, caller: &Memory<'_>) -> Option<Value> {
        let person = self.person.to_hex();
        for page in 0..100_u32 {
            let listed = call(caller, "vault.people.list", json!({"page": page}));
            let rows = listed["people"]
                .as_array()
                .unwrap_or_else(|| panic!("a people page holds no `people` array: {listed:#}"));
            if let Some(row) = rows.iter().find(|row| row["person"] == person.as_str()) {
                return Some(row.clone());
            }
            if listed["more"] == 0 || rows.is_empty() {
                return None;
            }
        }
        panic!("the roster never ended");
    }

    /// The owner's roster shows the person, by a name, with its line, on
    /// list and get alike; the name it shows.
    fn assert_owner_sees_the_line(&self) -> Value {
        let owner = self.owner();
        let row = self
            .roster_row(&owner)
            .expect("FIXTURE: the owner's roster lists the person");
        assert!(
            row["name"].as_str().is_some_and(|name| !name.is_empty()),
            "FIXTURE: the owner reads the name: {row:#}"
        );
        assert_eq!(
            row["about"], LINE,
            "FIXTURE: the owner's roster shows the Dreamer's line: {row:#}"
        );
        let got = call(&owner, "vault.people.get", json!({"pr": row["handle"]}));
        assert_eq!(got, row, "FIXTURE: the owner's get answers the listed row");
        row["name"].clone()
    }

    /// The agent's roster lists the person by the name the owner reads, on
    /// list and get alike, and its `about` is `about`.
    fn assert_agent_row(&self, about: &Value, why: &str) {
        let reader = self.reader();
        let row = self
            .roster_row(&reader)
            .unwrap_or_else(|| panic!("FIXTURE: the agent's roster lists the person ({why})"));
        assert_eq!(
            row["name"], self.name,
            "FIXTURE: the agent may be told the name, so the name does not hide the line \
             ({why}): {row:#}"
        );
        assert_eq!(&row["about"], about, "{why}: {row:#}");
        let got = call(&reader, "vault.people.get", json!({"pr": row["handle"]}));
        assert_eq!(got, row, "the agent's get answers the listed row ({why})");
    }
}

/// A MESSAGE row holding `content`, the existing record a new person's
/// identity cites ("A name alone is not identity evidence").
fn message(vault: &Vault, content: &str) -> EntityId {
    let id = vault.new_entity_id().expect("a message id");
    let now = vault.now_recorded_at();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("content"),
            rmpv::Value::from(content),
        )]),
    )
    .expect("the message body");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_MESSAGE,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )
        .expect("the message");
    id
}

#[test]
fn an_agents_roster_shows_the_about_line_its_live_grant_reads_with_every_fact() {
    let fixture = Fixture::open();
    fixture.mint(&[]);
    assert!(
        fixture.agent_reads(fixture.person) && fixture.agent_reads(fixture.claim),
        "FIXTURE: the live Grant admits the person and the fact its line stands on"
    );
    fixture.assert_agent_row(
        &json!(LINE),
        "one live Grant reads the person and every fact of its line, yet the agent's roster \
         shows no about line",
    );
}

#[test]
fn an_agents_roster_drops_the_person_and_its_line_once_its_grant_is_revoked() {
    let fixture = Fixture::open();
    let grant = fixture.mint(&[]);
    fixture.revoke(&grant);
    assert!(
        !fixture.agent_reads(fixture.person),
        "the revoked Grant no longer admits the person"
    );
    assert!(
        fixture.roster_row(&fixture.reader()).is_none(),
        "the agent's roster drops the person once its Grant is revoked"
    );
    let refused = door::invoke(
        &fixture.reader(),
        "vault.people.get",
        json!({"pr": fixture.roster_row(&fixture.owner()).expect("owner row")["handle"]}),
    )
    .expect_err("the agent's get finds no person once its Grant is revoked");
    assert_eq!(refused.code, MEMORY_CODE_NOT_FOUND, "{refused}");
}

#[test]
fn a_grant_that_reads_the_person_but_not_the_fact_shows_no_about_line() {
    let fixture = Fixture::open();
    fixture.mint(&[ENTITY_TYPE_PERSON]);
    assert!(
        fixture.agent_reads(fixture.person) && !fixture.agent_reads(fixture.claim),
        "FIXTURE: a PERSON-only Grant admits the person and not the fact"
    );
    fixture.assert_agent_row(
        &Value::Null,
        "a Grant that reads the person but not the fact its line stands on shows no line",
    );
}

#[test]
fn two_grants_never_lend_each_other_the_person_or_the_fact_of_an_about_line() {
    let fixture = Fixture::open();
    fixture.mint(&[ENTITY_TYPE_PERSON]);
    fixture.mint(&[ENTITY_TYPE_CLAIM]);
    assert!(
        fixture.agent_reads(fixture.person) && fixture.agent_reads(fixture.claim),
        "FIXTURE: the two Grants together admit the person and the fact, each one alone"
    );
    fixture.assert_agent_row(
        &Value::Null,
        "one Grant reads only the person and the other only the fact: no one Grant reads the \
         whole line, so it shows none",
    );
}

#[test]
fn a_second_grant_never_lends_a_row_the_fact_of_an_about_line_was_written_from() {
    let fixture = Fixture::open_owner_intent();
    let quoted = fixture
        .quoted
        .expect("FIXTURE: the owner's intent quotes a MESSAGE");
    fixture.mint(&[ENTITY_TYPE_PERSON, ENTITY_TYPE_CLAIM]);
    fixture.mint(&[ENTITY_TYPE_MESSAGE]);
    assert!(
        fixture.agent_reads(fixture.person)
            && fixture.agent_reads(fixture.claim)
            && fixture.agent_reads(quoted),
        "FIXTURE: one Grant admits the person and the intent, the other the MESSAGE the intent \
         quotes"
    );
    fixture.assert_agent_row(
        &Value::Null,
        "the Grant that reads the person and the intent does not read the MESSAGE the intent \
         quotes, and the other Grant never lends it: no one Grant reads the whole line, so it \
         shows none",
    );
    fixture.mint(&[ENTITY_TYPE_PERSON, ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE]);
    fixture.assert_agent_row(
        &json!(LINE),
        "a third Grant reads the person, the intent and the MESSAGE it quotes, yet the agent's \
         roster shows no about line",
    );
}
