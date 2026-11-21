//! A search that asks for CLAIMs alone and names a session facet finds the
//! claims in that facet, for the owner and for an identity agent that reads
//! through its own live read Grant. The hint's facet check judged the claim's
//! `facet_of` edge with both its ends under the request, so a request naming
//! only CLAIMs refused the FACET row at its far end and dropped every hit, for
//! every reader (FIX-LIST SESSION-FACET-HINT-KIND-NARROWED-PEER). The request
//! names the kinds of the rows it asks for, never of the facet they sit in:
//! the claim is still judged under the request, the FACET under the reader's
//! own authority. The hint still only narrows: a facet the agent's Grant does
//! not read admits no row.
//!
//! Public paths only: the embedded owner's door, the agent's own
//! `Vault::memory` handle and its read key, `Vault::edges_out`, and
//! `ScopedRead::search_with_effort` with a `SessionScope` on
//! `Vault::scoped_read` of a read key bound to the caller's filter
//! (`with_read_filter`). The claim takes the vault's own time, so the test
//! reads no wall clock.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test session_facet_hint_kind_narrowed`

use std::collections::BTreeSet;

use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_CLAIM;
use oneiron::retrieval_depth::{DepthSearchRequest, SearchProbe, SessionScope};
use oneiron::{EdgeActorClass, EdgeKind, Effort, EntityId, RetrievalFilter, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

/// The one word only the owner's claim holds, so a text search for it finds
/// that claim or nothing.
const WORD: &str = "kindfacetopal";

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

/// A request for CLAIM rows alone.
fn claims_only() -> RetrievalFilter {
    RetrievalFilter {
        entity_types: Some(BTreeSet::from([ENTITY_TYPE_CLAIM])),
        ..RetrievalFilter::default()
    }
}

/// A vault this process owns with an identity agent holding a live read
/// Grant over every world, facet, audience and sensitivity and the bands
/// `bands`, and the owner's claim about that agent, which holds [`WORD`] and
/// carries one `facet_of` edge. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    agent: EntityId,
    claim: EntityId,
    facet: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open(bands: Value) -> Self {
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
                    "agent_id": "kind-facet-reader",
                    "desc": "an agent that searches a facet for claims through the owner's Grant",
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
                "value": format!("The kind reader keeps the {WORD} beacon list."),
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
                    "bands": bands,
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
        Self {
            vault,
            agent,
            claim,
            facet,
            _dir: dir,
        }
    }

    fn reader(&self) -> Memory<'_> {
        self.vault.memory(self.agent, EdgeActorClass::Agent)
    }

    /// Whether `memory` reads the row `id` on vault.get.
    fn reads(&self, memory: &Memory<'_>, id: EntityId) -> bool {
        door::invoke(memory, "vault.get", json!({"entity_ref": id.to_hex()}))
            .is_ok_and(|read| read.get("value").is_some_and(|value| !value.is_null()))
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
}

#[test]
fn the_owners_claims_only_search_narrowed_to_the_claims_facet_finds_the_claim() {
    let fixture = Fixture::open(json!({"kind": "all"}));
    let owner = door::owner(&fixture.vault).expect("the embedded owner");
    assert!(
        fixture.finds_claim(&owner, Some(fixture.facet), None),
        "FIXTURE: the owner's search narrowed to the claim's facet finds the claim"
    );
    assert!(
        fixture.finds_claim(&owner, None, Some(&claims_only())),
        "FIXTURE: the owner's search for CLAIMs alone finds the claim"
    );
    assert!(
        fixture.finds_claim(&owner, Some(fixture.facet), Some(&claims_only())),
        "the owner's search for CLAIMs alone narrowed to the claim's facet leaves the claim out"
    );
}

#[test]
fn an_agents_claims_only_search_narrowed_to_the_claims_facet_finds_the_claim_its_grant_reads() {
    let fixture = Fixture::open(json!({"kind": "all"}));
    let reader = fixture.reader();
    assert!(
        fixture.reads(&reader, fixture.claim),
        "FIXTURE: the live Grant admits the owner's claim on vault.get"
    );
    assert!(
        fixture.reads(&reader, fixture.facet),
        "FIXTURE: the live Grant admits the claim's facet on vault.get"
    );
    assert!(
        fixture.finds_claim(&reader, Some(fixture.facet), None),
        "FIXTURE: the agent's search narrowed to the claim's facet finds the claim"
    );
    assert!(
        fixture.finds_claim(&reader, None, Some(&claims_only())),
        "FIXTURE: the agent's search for CLAIMs alone finds the claim"
    );
    assert!(
        fixture.finds_claim(&reader, Some(fixture.facet), Some(&claims_only())),
        "the agent's search for CLAIMs alone narrowed to the claim's facet leaves out the claim \
         its live Grant reads"
    );
}

#[test]
fn a_facet_hint_admits_no_claim_when_the_agents_grant_does_not_read_the_facet() {
    let fixture = Fixture::open(json!({"kind": "some", "values": [ENTITY_TYPE_CLAIM]}));
    let reader = fixture.reader();
    assert!(
        fixture.reads(&reader, fixture.claim),
        "FIXTURE: a Grant over CLAIM rows alone admits the owner's claim on vault.get"
    );
    assert!(
        !fixture.reads(&reader, fixture.facet),
        "FIXTURE: a Grant over CLAIM rows alone does not admit the claim's facet on vault.get"
    );
    assert!(
        fixture.finds_claim(&reader, None, Some(&claims_only())),
        "FIXTURE: the agent's search for CLAIMs alone finds the claim its Grant reads"
    );
    assert!(
        !fixture.finds_claim(&reader, Some(fixture.facet), None),
        "the agent's search narrowed to a facet its Grant does not read finds the claim"
    );
    assert!(
        !fixture.finds_claim(&reader, Some(fixture.facet), Some(&claims_only())),
        "the agent's search for CLAIMs alone narrowed to a facet its Grant does not read finds \
         the claim"
    );
}
