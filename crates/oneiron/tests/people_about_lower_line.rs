//! A reader sees, on its people roster (vault.people.list and
//! vault.people.get), the highest `about` line at or below its ceiling that
//! one of its alternatives reads whole (ARCH-0067 PEOPLE: "The renderer
//! shows the highest line at or below the reader's ceiling"). Each
//! alternative, a live Grant alone or the key's own floor, asked only for
//! the line at its own band and showed nothing when it did not read that
//! line's every fact, though a lower line stood only on facts it reads
//! (FIX-LIST PEOPLE-ABOUT-GRANT-LOWER-LINE, from review round 1 of #9929).
//!
//! The person has two facts: a private one in base reality and a sensitive
//! one in a second world. The Dreamer's line at band 1 stands on the first
//! alone; its lines at bands 2 and 3 stand on both. A reader whose one
//! Grant names base reality alone reads the band-1 line whole and no higher
//! one, so it sees the band-1 line; with a Grant over both worlds it sees
//! the band-3 line. Grants are still never combined (RULING GRANT-COMBINE
//! Q1 = A): each line shown is read whole by one alternative.
//!
//! Two readers: an identity agent, whose own floor reads nothing, so each
//! live Grant is one alternative; and a paired agent's credential, as
//! `oneiron token pair` gives one, whose own floor is the envelope of the
//! owner's Grants that name it, one of which must read every row of a line
//! alone (`people_about_own_floor_facts.rs`).
//!
//! Public paths, plus three test doors: two that land the Dreamer's `about`
//! lines (`oneiron::test_doors::derive::{about_facts, commit}`, as
//! `agent_grant_people_about.rs` lands them) and the owner's proof
//! (`oneiron::test_doors::steward::owner`) the second world, the agent's
//! Grants and its pairing link are made under. The rest: the embedded
//! owner's door, the owner's pairing link and its redemption, the agent's
//! own `Vault::memory` handle, bound to its credential for the paired agent,
//! and `Vault::put_entity` for the MESSAGE a new person's identity cites.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test people_about_lower_line`
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

/// The Dreamer's line at band 1, written from the private fact in base
/// reality alone.
const BASE_LINE: &str = "Owen keeps the reading group's lantern list.";

/// The Dreamer's line at bands 2 and 3, written from both facts.
const BOTH_LINE: &str = "Owen keeps the lantern list and moves to Lisbon in the spring.";

/// The bands the Dreamer writes a line at: band 1 from the private fact,
/// bands 2 and 3 from it and the sensitive fact.
const LINE_BANDS: [u8; 3] = [1, 2, 3];

/// The band of the private fact in base reality ("private" is band 1).
const BASE_FACT_BAND: u8 = 1;

/// The challenge the paired agent signs to prove its credential.
const REQUEST_CHALLENGE: &[u8] = b"oneiron-request:people-about-lower-line";

/// The seed of the paired agent's binding key.
const BINDING_SEED: u8 = 0x53;

/// Who reads the roster.
#[derive(Clone, Copy)]
enum Reader {
    /// An identity agent with no credential: its own floor reads nothing,
    /// so each of its live Grants is one alternative on its own.
    GrantAlone,
    /// A paired agent's credential: it reads by its own floor, the
    /// envelope of the owner's Grants that name it.
    PairedCredential,
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

/// A vault this process owns, rooted under the kit's test host, with an
/// agent whose one live read Grant names base reality alone and whose model
/// channel may be told every name, read as `reader` says, and a person the
/// owner created with a private fact in base reality, a sensitive fact in a
/// second world, and the Dreamer's `about` lines written from them. The
/// vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    agent: EntityId,
    person: EntityId,
    /// The private fact in base reality.
    base_fact: EntityId,
    /// The sensitive fact in the second world.
    second_fact: EntityId,
    /// The second world the owner created.
    second: EntityId,
    /// The paired agent's credential, verified; none for an identity agent.
    slip: Option<VerifiedSlip>,
    /// The person's name as the owner's roster reads it.
    name: Value,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open(reader: Reader) -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh vault");
        oneiron_testkit::dreamer::attach_test_host(&vault).expect("the test host");
        vault.ensure_embedded_owner_actor().expect("the owner");
        let owner = door::owner(&vault).expect("the embedded owner");
        let proof = owner_proof(&vault).expect("the owner's proof");
        let second = vault
            .create_world(
                &proof,
                "World the agent's first Grant does not name",
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
                    "agent_id": "lower-line-reader",
                    "desc": "an agent that reads the roster under one Grant over base reality",
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
        mint_read_grant(&vault, &proof, agent, &[base_world_id()], "base reality");
        let slip = match reader {
            Reader::GrantAlone => None,
            Reader::PairedCredential => Some(paired_agent_slip(&vault, &proof, agent)),
        };

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
        let remembered = call(
            &owner,
            "vault.remember",
            json!({
                "predicate": "project.note",
                "subject_ref": person.to_hex(),
                "value": "Owen keeps the lantern list for the reading group.",
                "confidence": 0.9,
                "source": "user_stated",
                "scope": {"sensitivity": "private"},
            }),
        );
        let base_fact = id_at(&remembered, "/claim/id");
        let remembered = call(
            &owner,
            "vault.remember",
            json!({
                "predicate": "travel.plan",
                "subject_ref": person.to_hex(),
                "value": "Owen moves to Lisbon in the spring.",
                "confidence": 0.9,
                "source": "user_stated",
                "world_ref": second.to_hex(),
            }),
        );
        let second_fact = id_at(&remembered, "/claim/id");

        let dreamer = dreamer(&vault).expect("the Dreamer");
        let (digest, line_bands) = about_facts(&vault, dreamer, EdgeActorClass::System, person)
            .expect("the person's facts");
        assert_eq!(
            line_bands, LINE_BANDS,
            "FIXTURE: the Dreamer reads the private fact at band {BASE_FACT_BAND}, so a line \
             is written at each band from it up"
        );
        let committed = commit(
            &vault,
            dreamer,
            EdgeActorClass::System,
            "run-people-about-lower-line",
            &[Derived::About(About {
                local: "about",
                person: Named::Stored(person),
                written_from: digest,
                lines: line_bands
                    .iter()
                    .map(|band| {
                        let text = if *band == BASE_FACT_BAND {
                            BASE_LINE
                        } else {
                            BOTH_LINE
                        };
                        (*band, text)
                    })
                    .collect(),
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
            base_fact,
            second_fact,
            second,
            slip,
            name: Value::Null,
            _dir: dir,
        };
        fixture.name = fixture.assert_owner_sees_the_top_line();
        fixture
    }

    fn owner(&self) -> Memory<'_> {
        door::owner(&self.vault).expect("the embedded owner")
    }

    /// The owner mints the agent one more live read Grant, over `worlds`.
    fn grant_the_agent(&self, worlds: &[EntityId], named: &str) {
        let proof = owner_proof(&self.vault).expect("the owner's proof");
        mint_read_grant(&self.vault, &proof, self.agent, worlds, named);
    }

    /// The agent's handle, every read bound to its credential when it has
    /// one.
    fn reader(&self) -> Memory<'_> {
        let memory = self.vault.memory(self.agent, EdgeActorClass::Agent);
        match &self.slip {
            Some(slip) => memory.with_read_proof(slip),
            None => memory,
        }
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

    /// The owner's roster shows the person, by a name, with the line of the
    /// top band, on list and get alike; the name it shows.
    fn assert_owner_sees_the_top_line(&self) -> Value {
        let owner = self.owner();
        let row = self
            .roster_row(&owner)
            .expect("FIXTURE: the owner's roster lists the person");
        assert!(
            row["name"].as_str().is_some_and(|name| !name.is_empty()),
            "FIXTURE: the owner reads the name: {row:#}"
        );
        assert_eq!(
            row["about"], BOTH_LINE,
            "FIXTURE: the owner's roster shows the Dreamer's line of the top band: {row:#}"
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
        assert_ne!(
            row["about"], BOTH_LINE,
            "FIXTURE: the lines at bands 2 and 3 stand on the fact in the second world, which \
             the agent's Grant over base reality does not read ({why}): {row:#}"
        );
        assert_eq!(&row["about"], about, "{why}: {row:#}");
        let got = call(&reader, "vault.people.get", json!({"pr": row["handle"]}));
        assert_eq!(got, row, "the agent's get answers the listed row ({why})");
    }

    /// The agent's roster shows the line of the top band once the owner
    /// mints it a Grant over both worlds.
    fn assert_a_grant_over_both_worlds_shows_the_top_line(&self) {
        self.grant_the_agent(&[base_world_id(), self.second], "both worlds");
        assert!(
            self.agent_reads(self.second_fact),
            "FIXTURE: the Grant over both worlds reads the fact in the second world"
        );
        let row = self
            .roster_row(&self.reader())
            .expect("FIXTURE: the agent's roster lists the person under both Grants");
        assert_eq!(
            row["about"], BOTH_LINE,
            "one Grant reads the person and both facts, yet the agent's roster does not show \
             the line of the top band: {row:#}"
        );
    }

    /// The agent's Grant over base reality reads the person and the private
    /// fact, and not the fact in the second world.
    fn assert_the_first_grant_reads_the_base_fact_alone(&self) {
        assert!(
            self.agent_reads(self.person),
            "FIXTURE: the agent's Grant over base reality reads the person"
        );
        assert!(
            self.agent_reads(self.base_fact),
            "FIXTURE: the agent's Grant over base reality reads the private fact there"
        );
        assert!(
            !self.agent_reads(self.second_fact),
            "FIXTURE: the agent's Grant over base reality does not read the fact in the \
             second world"
        );
    }
}

/// The owner mints `agent` one live read Grant over `worlds` alone, `named`
/// in the fixture's words.
fn mint_read_grant(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    agent: EntityId,
    worlds: &[EntityId],
    named: &str,
) {
    let mut authority_scope = Scope::top();
    authority_scope.worlds = ScopeAxis::Some(worlds.iter().copied().map(ScopeId).collect());
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let minted = mint_agent_grant_as(
        vault,
        owner,
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
    .unwrap_or_else(|error| {
        panic!("FIXTURE: the owner mints the agent a read Grant over {named}: {error}")
    });
    assert!(
        minted.grant.confers,
        "FIXTURE: the agent's read Grant over {named} is live"
    );
}

/// `agent` pairs as class `agent` on a link the owner issues, redeems it
/// and proves possession of its credential: the pairing Scope narrows verbs
/// only, so the owner's Grants, not the pairing request, set the agent's
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
fn a_grant_shows_the_highest_lower_line_it_reads_whole() {
    let fixture = Fixture::open(Reader::GrantAlone);
    fixture.assert_the_first_grant_reads_the_base_fact_alone();
    fixture.assert_agent_row(
        &json!(BASE_LINE),
        "the agent's one live Grant reads the person and the private fact the band-1 line \
         stands on, yet its roster shows no line: the Grant tried only the line at its own band, \
         which stands on a fact in a world it does not name",
    );
    fixture.assert_a_grant_over_both_worlds_shows_the_top_line();
}

#[test]
fn a_paired_agents_own_floor_shows_the_highest_lower_line_it_reads_whole() {
    let fixture = Fixture::open(Reader::PairedCredential);
    fixture.assert_the_first_grant_reads_the_base_fact_alone();
    fixture.assert_agent_row(
        &json!(BASE_LINE),
        "the paired agent's own floor reads the person and the private fact the band-1 line \
         stands on, yet its roster shows no line: the floor tried only the line at its own \
         band, which stands on a fact in a world its Grant does not name",
    );
    fixture.assert_a_grant_over_both_worlds_shows_the_top_line();
}
