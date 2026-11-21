//! An identity agent that reads through its own live read Grant keeps, in a
//! search its session narrows to a facet, the owner's claim in that facet that
//! the Grant admits, as it reads that claim on vault.get and in the same
//! search with no session hint. The hint's facet check judged the claim and
//! its `facet_of` edge under the agent key's own floor alone, which reads
//! nothing, so an agent's facet-narrowed search dropped every row its Grant
//! admits (FIX-LIST SCOPED-READ-UNKNOWN-AUTHORITY-CALLERS, census row 10). The
//! hint still only narrows: a facet the claim does not carry, a request that
//! leaves the claim's type out, and a revoked Grant each keep the claim out.
//!
//! Public paths only: the embedded owner's door, the agent's own
//! `Vault::memory` handle and its read key, `Vault::edges_out`, and
//! `ScopedRead::search_with_effort` with a `SessionScope` (the depth read a
//! session context narrows) on `Vault::scoped_read` of a read key. The claim
//! takes the vault's own time, so the test reads no wall clock.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_grant_session_facet_hint`

use std::collections::BTreeSet;

use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_NOTE;
use oneiron::retrieval_depth::{DepthSearchRequest, SearchProbe, SessionScope};
use oneiron::{EdgeActorClass, EdgeKind, Effort, EntityId, RetrievalFilter, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The one word only the owner's claim holds, so a text search for it finds
/// that claim or nothing.
const WORD: &str = "facetquartz";

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

/// A vault this process owns with an identity agent holding a live read
/// Grant over every world, facet, band, audience and sensitivity, and the
/// owner's claim about that agent, which holds [`WORD`] and carries one
/// `facet_of` edge. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    agent: EntityId,
    claim: EntityId,
    facet: EntityId,
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
                    "agent_id": "facet-hint-reader",
                    "desc": "an agent that searches one facet through the owner's read Grant",
                    "version": "1",
                },
            }),
        );
        let remembered = call(
            &owner,
            "vault.remember",
            json!({
                "predicate": "project.note",
                "subject_ref": agent.to_hex(),
                "value": format!("The hint reader keeps the {WORD} lantern list."),
                "confidence": 0.9,
                "source": "user_stated",
            }),
        );
        let claim = EntityId::from_hex(&id_at(&remembered, "/claim/id")).expect("the claim's id");
        let facets: Vec<EntityId> = vault
            .edges_out(&claim)
            .expect("the claim's edges")
            .iter()
            .filter(|edge| edge.kind == EdgeKind::FacetOf)
            .map(|edge| edge.target)
            .collect();
        let [facet] = facets.as_slice() else {
            panic!("FIXTURE: the owner's claim carries one facet_of edge: {facets:?}");
        };
        let facet = *facet;
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
            facet,
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

    /// The agent reads the owner's claim on vault.get under its live Grant.
    fn assert_agent_reads_the_claim(&self) {
        let read = call(
            &self.reader(),
            "vault.get",
            json!({"entity_ref": self.claim.to_hex()}),
        );
        assert!(
            read.get("value").is_some_and(|value| !value.is_null()),
            "FIXTURE: the live Grant admits the owner's claim on vault.get: {read:#}"
        );
    }

    /// Whether `memory`'s light text search for [`WORD`], under `requested`
    /// and narrowed to `facet` when one is named, finds the owner's claim.
    fn finds_claim(
        &self,
        memory: &Memory<'_>,
        facet: Option<EntityId>,
        requested: Option<&RetrievalFilter>,
    ) -> bool {
        let key = memory.read_key().expect("the reader's read key");
        let scope = SessionScope {
            facet_ref: facet,
            ..SessionScope::default()
        };
        let request = DepthSearchRequest {
            probe: SearchProbe::Text {
                query: WORD.to_owned(),
            },
            effort: Effort::Light,
            limit: 10,
            session_scope: facet.is_some().then_some(&scope),
            lease: None,
            backend: None,
            token_budget: None,
            deadline: None,
        };
        let found = self
            .vault
            .scoped_read(key)
            .with_read_filter(requested)
            .search_with_effort(&request)
            .unwrap_or_else(|error| panic!("the light search for {WORD}: {error}"));
        found.hits.iter().any(|hit| hit.id == self.claim)
    }

    /// The owner's own search narrowed to the claim's facet finds it, so the
    /// hint names the facet the claim carries.
    fn assert_owner_finds_the_claim_in_its_facet(&self) {
        let owner = door::owner(&self.vault).expect("the embedded owner");
        assert!(
            self.finds_claim(&owner, Some(self.facet), None),
            "FIXTURE: the owner's search narrowed to the claim's facet finds the claim"
        );
    }
}

#[test]
fn an_agents_facet_narrowed_search_under_a_live_read_grant_keeps_the_claim_in_that_facet() {
    let fixture = Fixture::open();
    fixture.assert_agent_reads_the_claim();
    fixture.assert_owner_finds_the_claim_in_its_facet();
    let reader = fixture.reader();
    assert!(
        fixture.finds_claim(&reader, None, None),
        "FIXTURE: the agent's search with no session hint finds the owner's claim under its \
         live Grant"
    );
    // Not asserted: whether the agent reads the facet's own row on vault.get
    // only tells a failure below apart (the hint's edge check judges it too).
    let reads_facet = door::invoke(
        &reader,
        "vault.get",
        json!({"entity_ref": fixture.facet.to_hex()}),
    )
    .is_ok_and(|read| read.get("value").is_some_and(|value| !value.is_null()));
    assert!(
        fixture.finds_claim(&reader, Some(fixture.facet), None),
        "the live Grant admits the owner's claim in its facet, yet the agent's search narrowed \
         to that facet leaves it out (the agent reads the facet on vault.get: {reads_facet})"
    );
}

#[test]
fn an_agents_facet_narrowed_search_still_narrows_under_its_live_read_grant() {
    let fixture = Fixture::open();
    fixture.assert_agent_reads_the_claim();
    let reader = fixture.reader();
    let other_facet = fixture
        .vault
        .new_entity_id()
        .expect("an id no facet_of edge names");
    assert!(
        !fixture.finds_claim(&reader, Some(other_facet), None),
        "the agent's search narrowed to a facet the claim does not carry finds the claim"
    );
    let notes_only = RetrievalFilter {
        entity_types: Some(BTreeSet::from([ENTITY_TYPE_NOTE])),
        ..RetrievalFilter::default()
    };
    assert!(
        !fixture.finds_claim(&reader, Some(fixture.facet), Some(&notes_only)),
        "the agent's NOTE-only search narrowed to the claim's facet finds the claim"
    );
}

#[test]
fn an_agents_facet_narrowed_search_drops_the_claim_once_its_grant_is_revoked() {
    let fixture = Fixture::open();
    fixture.assert_agent_reads_the_claim();
    fixture.revoke();
    fixture.assert_owner_finds_the_claim_in_its_facet();
    assert!(
        !fixture.finds_claim(&fixture.reader(), Some(fixture.facet), None),
        "the agent's search narrowed to the claim's facet finds the claim after the owner \
         revoked its only read Grant"
    );
}
