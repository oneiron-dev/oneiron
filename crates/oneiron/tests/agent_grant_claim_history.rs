//! An agent that reads through its own live read Grant sees a claim's
//! supersession history on vault.claims.history, as it reads each revision
//! on vault.get. The timeline's anchor and record checks took the agent
//! key's own floor alone, which reads nothing, so the history listed no
//! revision (FIX-LIST SCOPED-READ-UNKNOWN-AUTHORITY-CALLERS, part 2b). The
//! history's receipt also reports that Grant's reach, not deny_all, and so
//! does `ScopedRead::memory_timeline` on the agent's own key, a lane that
//! never opted in. After the owner revokes the Grant neither lists a
//! revision.
//!
//! Public paths only: the embedded owner's door, where the owner's second
//! vault.remember of one subject and predicate supersedes the first (a
//! predicate the registry does not declare keeps one head, ARCH-0044 S3),
//! the agent's own `Vault::memory` handle and `Vault::scoped_read` of its
//! key.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_grant_claim_history`

use oneiron::memory::Memory;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The time the owner's first claim says it was learned: fixed, so the test
/// reads no wall clock. The correction is learned a minute later.
const RECORDED_AT: u64 = 1_700_000_000;

/// Runs `verb` as `caller`, panicking with its refusal.
fn call(caller: &Memory<'_>, verb: &str, input: Value) -> Value {
    door::invoke(caller, verb, input).unwrap_or_else(|error| panic!("{verb}: {error}"))
}

/// Whether the receipt list `list` names `entry`.
fn lists(list: &Value, entry: &str) -> bool {
    list.as_array()
        .is_some_and(|entries| entries.iter().any(|named| named == entry))
}

/// The id of a written record in `answer` at `pointer`.
fn id_at(answer: &Value, pointer: &str) -> String {
    answer
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no id at {pointer}: {answer:#}"))
        .to_owned()
}

/// A vault this process owns with one of the owner's claims superseded by
/// its correction, and an identity agent holding a live read Grant over
/// every world, facet, band, audience and sensitivity. The vault closes
/// before its directory goes.
struct Fixture {
    vault: Vault,
    first: EntityId,
    correction: EntityId,
    agent: EntityId,
    grant: String,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("fresh vault");
        oneiron_testkit::dreamer::attach_test_host(&vault).expect("the test host");
        let owner_id = vault.ensure_embedded_owner_actor().expect("the owner");
        let owner = door::owner(&vault).expect("the embedded owner");
        let remember = |value: &str, learned_at: u64| {
            let remembered = call(
                &owner,
                "vault.remember",
                json!({
                    "predicate": "project.note",
                    "subject_ref": owner_id.to_hex(),
                    "value": value,
                    "confidence": 0.9,
                    "source": "user_stated",
                    "occurred_at": learned_at,
                    "learned_at": learned_at,
                }),
            );
            let id = EntityId::from_hex(&id_at(&remembered, "/claim/id")).expect("a claim id");
            (id, remembered)
        };
        let (first, _) = remember("The tide tables arrive on Thursday.", RECORDED_AT);
        let (correction, corrected) =
            remember("The tide tables arrive on Friday.", RECORDED_AT + 60);
        assert_eq!(
            id_at(&corrected, "/superseded/id").to_ascii_lowercase(),
            first.to_hex().to_ascii_lowercase(),
            "the owner's correction supersedes the first claim: {corrected:#}"
        );

        let agent = vault.new_entity_id().expect("an agent id");
        call(
            &owner,
            "vault.agents.create",
            json!({
                "agent_def_ref": agent.to_hex(),
                "definition": {
                    "agent_id": "history-reader",
                    "desc": "an agent that reads claim history through the owner's read Grant",
                    "version": "1",
                },
            }),
        );
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
            first,
            correction,
            agent,
            grant,
            _dir: dir,
        }
    }

    fn owner(&self) -> Memory<'_> {
        door::owner(&self.vault).expect("the embedded owner")
    }

    fn reader(&self) -> Memory<'_> {
        self.vault.memory(self.agent, EdgeActorClass::Agent)
    }

    fn revoke(&self) {
        call(
            &self.owner(),
            "vault.agents.grants.revoke",
            json!({"grant_ref": self.grant}),
        );
    }
}

fn history_of(caller: &Memory<'_>, claim: &EntityId) -> Result<Value, String> {
    door::invoke(
        caller,
        "vault.claims.history",
        json!({"claim_ref": claim.to_hex()}),
    )
    .map_err(|error| error.to_string())
}

/// The claim ids a vault.claims.history `answer` lists, in its order, in
/// lower-case hex.
fn revisions(answer: &Value) -> Vec<String> {
    answer
        .pointer("/value")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("vault.claims.history answered no claim list: {answer:#}"))
        .iter()
        .map(|view| {
            view["claim_ref"]
                .as_str()
                .unwrap_or_else(|| panic!("a history entry without a claim_ref: {view:#}"))
                .to_ascii_lowercase()
        })
        .collect()
}

#[test]
fn an_agents_claim_history_under_a_live_read_grant_lists_both_revisions() {
    let fixture = Fixture::open();
    let both = [
        fixture.first.to_hex().to_ascii_lowercase(),
        fixture.correction.to_hex().to_ascii_lowercase(),
    ];
    let owners =
        history_of(&fixture.owner(), &fixture.correction).expect("the owner's claim history");
    assert_eq!(
        revisions(&owners),
        both,
        "the owner reads its own claim's history, oldest first: {owners:#}"
    );
    let reader = fixture.reader();
    for revision in [fixture.first, fixture.correction] {
        let read = call(
            &reader,
            "vault.get",
            json!({"entity_ref": revision.to_hex()}),
        );
        assert!(
            read.get("value").is_some_and(|value| !value.is_null()),
            "the live Grant admits the revision {revision:?} on vault.get: {read:#}"
        );
    }

    for anchor in [fixture.correction, fixture.first] {
        let read = history_of(&reader, &anchor).expect("the agent's claim history");
        assert_eq!(
            revisions(&read),
            both,
            "the live Grant admits both revisions, yet the history of {anchor:?} misses them: \
             {read:#}"
        );
        let narrowing = &read["narrowing"];
        for scope in ["requested", "actor_ceiling", "applied"] {
            assert_eq!(
                narrowing[scope]["deny_all"], false,
                "the {scope} scope denies all under the live Grant: {narrowing:#}"
            );
        }
        for list in ["narrowed_axes", "replan_hint"] {
            assert!(
                !lists(&narrowing[list], "deny_all"),
                "{list} names deny_all under the live Grant: {narrowing:#}"
            );
        }
    }

    fixture.revoke();
    for anchor in [fixture.correction, fixture.first] {
        if let Ok(after) = history_of(&reader, &anchor) {
            assert!(
                revisions(&after).is_empty(),
                "the agent still reads the history after the revoke: {after:#}"
            );
        }
    }
}

#[test]
fn an_agents_memory_timeline_under_a_live_read_grant_reads_both_revisions() {
    let fixture = Fixture::open();
    let reader = fixture.reader();
    let timeline = || {
        let key = reader.read_key().expect("the agent's read key");
        fixture
            .vault
            .scoped_read(key)
            .memory_timeline(&fixture.correction)
    };
    let read = timeline().expect("the agent's memory timeline");
    let mut listed: Vec<EntityId> = read.value.records.iter().map(|record| record.id).collect();
    listed.sort_unstable();
    let mut both = vec![fixture.first, fixture.correction];
    both.sort_unstable();
    assert_eq!(
        listed, both,
        "the live Grant admits both revisions, yet the timeline misses them"
    );
    let receipt = read.receipt;
    for (scope, read) in [
        ("requested", &receipt.requested),
        ("actor_ceiling", &receipt.actor_ceiling),
        ("applied", &receipt.applied),
    ] {
        assert!(
            !read.deny_all,
            "the {scope} scope of the timeline's receipt denies all under the live Grant: \
             {receipt:?}"
        );
    }
    assert!(
        !receipt.narrowed_axes.iter().any(|axis| axis == "deny_all")
            && !receipt.replan_hint.iter().any(|hint| hint == "deny_all"),
        "the timeline's receipt names deny_all under the live Grant: {receipt:?}"
    );

    fixture.revoke();
    if let Ok(after) = timeline() {
        assert!(
            after.value.records.is_empty(),
            "the agent still reads the timeline after the revoke"
        );
    }
}
