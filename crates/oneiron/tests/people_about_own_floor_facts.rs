//! A reader whose own floor reads a person but not the fact that person's
//! `about` line was written from sees no line on its people roster
//! (vault.people.list and vault.people.get). The roster took the line of
//! the highest band the key's own floor reads and never judged the PERSON or
//! the line's facts under that floor, so a paired agent whose one live read
//! Grant names base reality alone read a line written from the owner's fact
//! in another world (FIX-LIST PEOPLE-ABOUT-OWN-FLOOR-FACTS-UNJUDGED; a line
//! written from a world follows its strictest input, DEC-0005). Where the
//! same floor reads the person and the fact, the line still shows.
//!
//! The reader is a paired agent's credential, as `oneiron token pair` gives
//! one: its pairing Scope narrows verbs only, and the owner's agent Grant
//! sets its world ceiling. A key that carries a proof reads by its own floor
//! alone; no Grant alternative stands beside it on the roster.
//!
//! Public paths, plus three test doors: two that land the Dreamer's `about`
//! line (`oneiron::test_doors::derive::{about_facts, commit}`, as
//! `agent_grant_people_about.rs` lands it) and the owner's proof
//! (`oneiron::test_doors::steward::owner`) the second world, the agent's
//! Grant and its pairing link are made under. The rest: the embedded
//! owner's door, the owner's pairing link and its redemption, the agent's
//! own `Vault::memory` handle bound to its credential, and
//! `Vault::put_entity` for the MESSAGE a new person's identity cites.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test people_about_own_floor_facts`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActSurface, PairingPrincipal, VerifiedSlip, pairing_binding_transcript_pinned,
};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_MESSAGE;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::derive::{About, Derived, Named, about_facts, commit};
use oneiron::test_doors::steward::{dreamer, owner as owner_proof};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The person's name, as the owner created it.
const NAME: &str = "Owen Marsh";

/// The person's `about` line, at every band its fact takes a line.
const LINE: &str = "Owen keeps the reading group's lantern list.";

/// The challenge the paired agent signs to prove its credential.
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:people-about-own-floor-facts";

/// The seed of the paired agent's binding key.
const BINDING_SEED: u8 = 0x52;

/// The world the owner writes the person's one fact in.
#[derive(Clone, Copy)]
enum FactWorld {
    /// Base reality, which the agent's Grant names.
    Base,
    /// A second world the owner creates, which the agent's Grant does not
    /// name.
    Second,
}

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

/// A vault this process owns, rooted under the kit's test host, with a
/// paired agent whose one live read Grant names base reality alone and whose
/// model channel may be told every name, and a person the owner created with
/// one fact he remembered about them in `world` and the Dreamer's `about`
/// line written from it. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    agent: EntityId,
    person: EntityId,
    claim: EntityId,
    /// The agent's credential, verified.
    slip: VerifiedSlip,
    /// The person's name as the owner's roster reads it.
    name: Value,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open(world: FactWorld) -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh vault");
        oneiron_testkit::dreamer::attach_test_host(&vault).expect("the test host");
        vault.ensure_embedded_owner_actor().expect("the owner");
        let owner = door::owner(&vault).expect("the embedded owner");
        let proof = owner_proof(&vault).expect("the owner's proof");
        let second = vault
            .create_world(
                &proof,
                "World the agent's Grant does not name",
                vault.now_recorded_at(),
            )
            .expect("FIXTURE: the owner creates a second world");

        let agent = vault.new_entity_id().expect("an agent id");
        call(
            &owner,
            "vault.agents.create",
            json!({
                "agent_def_ref": agent.to_hex(),
                "definition": {
                    "agent_id": "paired-people-reader",
                    "desc": "a paired agent that reads the roster under its own credential",
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
        let mut authority_scope = Scope::top();
        authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
        authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        let minted = mint_agent_grant_as(
            &vault,
            &proof,
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
        .expect("FIXTURE: the owner mints the agent a read Grant over base reality");
        assert!(
            minted.grant.confers,
            "FIXTURE: the agent's read Grant over base reality is live"
        );
        let slip = paired_agent_slip(&vault, &proof, agent);

        let evidence = message(
            &vault,
            &format!("{NAME} introduced themself at the reading group"),
        );
        let created = call(
            &owner,
            "vault.people.create",
            json!({
                "identity": {"name": NAME},
                "identity_evidence_refs": [evidence.to_hex()],
                "occurred_at": vault.now_recorded_at(),
            }),
        );
        let person = id_at(&created, "/person/id_hex");
        let mut fact = json!({
            "predicate": "project.note",
            "subject_ref": person.to_hex(),
            "value": "Owen keeps the lantern list for the reading group.",
            "confidence": 0.9,
            "source": "user_stated",
        });
        if let FactWorld::Second = world {
            fact["world_ref"] = json!(second.to_hex());
        }
        let remembered = call(&owner, "vault.remember", fact);
        let claim = id_at(&remembered, "/claim/id");

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
            "run-people-about-own-floor",
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
            "FIXTURE: the Dreamer's about line lands: {:?}",
            item.reasons
        );
        let mut fixture = Self {
            vault,
            agent,
            person,
            claim,
            slip,
            name: Value::Null,
            _dir: dir,
        };
        fixture.name = fixture.assert_owner_sees_the_line();
        fixture
    }

    fn owner(&self) -> Memory<'_> {
        door::owner(&self.vault).expect("the embedded owner")
    }

    /// The agent's handle, every read bound to its credential.
    fn reader(&self) -> Memory<'_> {
        self.vault
            .memory(self.agent, EdgeActorClass::Agent)
            .with_read_proof(&self.slip)
    }

    /// Whether the agent's credential admits `id` now.
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

/// `agent` pairs as class `agent` on a link the owner issues, redeems it
/// and proves possession of its credential: the pairing Scope narrows verbs
/// only, so the owner's Grant, not the pairing request, sets the agent's
/// world ceiling.
fn paired_agent_slip(vault: &Vault, owner: &AuthenticatedOwner, agent: EntityId) -> VerifiedSlip {
    let issuer = oneiron_testkit::dreamer::test_host_issuer().expect("the test host's issuer");
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let holder = agent.to_hex();
    let link = vault
        .issue_owner_pairing_link(
            &issuer,
            owner,
            scope,
            3_600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some("agent".to_owned()),
                ..PairingPrincipal::default()
            },
        )
        .expect("FIXTURE: the owner issues the agent's pairing link");
    let signing_key = SigningKey::from_bytes(&[BINDING_SEED; 32]);
    let binding_key = signing_key.verifying_key().to_bytes();
    let transcript =
        pairing_binding_transcript_pinned(&link.code, &binding_key, &holder, link.pin.as_ref())
            .expect("the agent's pairing transcript");
    let slip = vault
        .redeem_pairing_link(
            &issuer,
            &link.code,
            &holder,
            binding_key,
            &signing_key.sign(&transcript).to_bytes(),
        )
        .expect("FIXTURE: the agent redeems its pairing link");
    let signature = signing_key
        .sign(
            &slip
                .binding_transcript(REQUEST_CHALLENGE)
                .expect("the agent's request transcript"),
        )
        .to_bytes();
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, REQUEST_CHALLENGE, &signature)
        .expect("FIXTURE: the paired agent proves possession of its credential")
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
fn a_paired_agents_roster_shows_no_about_line_written_from_a_fact_its_floor_does_not_read() {
    let fixture = Fixture::open(FactWorld::Second);
    assert!(
        fixture.agent_reads(fixture.person),
        "FIXTURE: the agent's credential reads the person"
    );
    assert!(
        !fixture.agent_reads(fixture.claim),
        "FIXTURE: the agent's credential does not read the fact in the world its Grant does not \
         name"
    );
    fixture.assert_agent_row(
        &Value::Null,
        "the agent's own floor reads the person but not the fact the line was written from, in a \
         world its Grant does not name, yet its roster shows the line",
    );
}

#[test]
fn a_paired_agents_roster_shows_the_about_line_its_floor_reads_with_every_fact() {
    let fixture = Fixture::open(FactWorld::Base);
    assert!(
        fixture.agent_reads(fixture.person) && fixture.agent_reads(fixture.claim),
        "FIXTURE: the agent's credential reads the person and the fact in base reality"
    );
    fixture.assert_agent_row(
        &json!(LINE),
        "the agent's own floor reads the person and every fact the line was written from, yet its \
         roster shows no about line",
    );
}
