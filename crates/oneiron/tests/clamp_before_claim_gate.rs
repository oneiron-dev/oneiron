//! [D19-GATE-COUNTS-CLAIMS-THE-DISCLOSURE-CLAMP-REFUSES]: in a pack clamped
//! for an audience, a claim the audience may not read whatever its status
//! leaves no trace in what the pack says of itself. Before, the run's D19
//! gate judged such a claim before the clamp asked: a dead claim (Proposed)
//! the audience may not read counted in `PackStats::claims_suppressed` and
//! made an empty pack read `AllActivated`, so the audience learned that a
//! claim it may not read matched. It held for a bounded channel's fetch
//! (the shared admission asked the gate before the clamp) and for a list
//! that reaches the blend unasked (the run's gate over the fused union
//! judged it before the pack's preselection withheld it). The phonetic code
//! rung's half landed with #9911 (`tests/phonetic_exact_hits_scoped.rs`).
//!
//! A claim the audience may read still counts when the gate refuses it, and
//! a live claim the clamp refuses still counts among the pack's clamped rows.
//!
//! The clamp's contact and Tier-A mark are written through test doors: run
//! the file with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test clamp_before_claim_gate`.
#![cfg(oneiron_test_support)]

use oneiron::counterparty_contact::CounterpartyFirstTouch;
use oneiron::federation::Scope;
use oneiron::interlocutor::{Interlocutor, InterlocutorSet};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::test_doors::disclosure_word_sources::{
    clamp_admits_with_contact, mark_tier_a, seed_cleared_contact,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, DisclosureContext,
    EmptyReason, EntityId, TimeRange, Vault, VaultConfig,
};

const DIMENSIONS: usize = 4;
/// The word every text search asks for, and the only word a claim's text
/// holds.
const WORD: &str = "quokka";
/// The contact a clamped pack is assembled for.
const COUNTERPARTY: &str = "owen@example.com";

/// An owned vault with a vector space and one contact, cleared for every
/// axis, present with the owner: the pack's clamp is the contact's row test.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    contact: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    // A vector write needs a declared embedding model.
    config.embedding_model = Some("test/model@v1".to_owned());
    let vault = Vault::open_owned(dir.path(), config).expect("open vault");
    vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault's owner");
    let contact = EntityId::now();
    seed_cleared_contact(&vault, contact, COUNTERPARTY, Scope::top())
        .expect("FIXTURE: seed the cleared contact");
    Fixture {
        _dir: dir,
        vault,
        contact,
    }
}

/// The query vector every vector search asks with.
fn query_vector() -> Vec<f32> {
    vec![1.0, 0.0, 0.0, 0.0]
}

/// The clamp of a pack the owner holds with `contact` present.
fn with_contact(vault: &Vault, contact: EntityId) -> DisclosureContext {
    DisclosureContext::resolve(
        vault,
        InterlocutorSet::with_session_owner(vec![Interlocutor::known_contact(
            contact,
            COUNTERPARTY,
            CounterpartyFirstTouch::UserIntroduction,
        )]),
    )
    .expect("FIXTURE: resolve the contact's clamp")
}

#[derive(Clone, Copy)]
enum Search {
    Text,
    Vector,
}

/// A claim about a person, put with approval `approval`, whose text is
/// [`WORD`] and whose vector is the query's. With `hidden` it is marked
/// Tier A: the contact may not read it, whatever its status.
fn put_matching_claim(fixture: &Fixture, approval: ClaimApprovalStatus, hidden: bool) -> EntityId {
    let vault = &fixture.vault;
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"",
        )
        .expect("FIXTURE: put the subject");
    let body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("fact"),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: claim body");
    let claim = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_claim(&claim, &body, TimeRange { start: at, end: at }, at)
        .expect("FIXTURE: put the claim");
    vault
        .batch()
        .text(&claim, &[("body", WORD)])
        .commit()
        .expect("FIXTURE: index the claim's text");
    vault
        .put_vector(&claim, &query_vector())
        .expect("FIXTURE: put the claim's vector");
    if hidden {
        mark_tier_a(vault, &claim).expect("FIXTURE: mark the claim Tier A");
    }
    assert_eq!(
        clamp_admits_with_contact(vault, fixture.contact, COUNTERPARTY, &claim)
            .expect("FIXTURE: ask the clamp"),
        !hidden,
        "FIXTURE: the contact may read the claim exactly when it is not hidden"
    );
    claim
}

/// What a pack says of itself: its empty reason and candidates in scope
/// (when it served nothing), and its suppressed claims.
type PackSays = (Option<(EmptyReason, usize)>, usize);

/// The pack of one `search` (only claims with `claims_only`), clamped for
/// the contact when `clamped`; it serves nothing.
fn pack_says(fixture: &Fixture, search: Search, claims_only: bool, clamped: bool) -> PackSays {
    let vault = &fixture.vault;
    let mut builder = match search {
        Search::Text => vault.context_pack().search_text(WORD, 10),
        Search::Vector => vault.context_pack().search_vector(&query_vector(), 10),
    };
    if claims_only {
        builder = builder.filter_types(&[ENTITY_TYPE_CLAIM]);
    }
    if clamped {
        builder = builder.disclosure_context(with_contact(vault, fixture.contact));
    }
    let pack = builder
        .limit(10)
        .include_stats(true)
        .run()
        .expect("the pack");
    assert!(pack.results.is_empty(), "FIXTURE: the pack serves nothing");
    (
        pack.empty
            .as_ref()
            .map(|empty| (empty.reason, empty.total_in_scope)),
        pack.stats.claims_suppressed,
    )
}

/// A clamped `search` reads the same with and without a proposed claim the
/// contact may not read, and counts no suppressed claim; the owner's own
/// pack counts it, so the search reaches it.
fn reads_alike_with_a_hidden_proposed_claim(search: Search, claims_only: bool) {
    let fixture = fixture();
    let without = pack_says(&fixture, search, claims_only, true);
    put_matching_claim(&fixture, ClaimApprovalStatus::Proposed, true);
    assert_eq!(
        pack_says(&fixture, search, claims_only, false).1,
        1,
        "FIXTURE: the owner's pack reaches the claim and its gate refuses it"
    );
    let with = pack_says(&fixture, search, claims_only, true);
    assert_eq!(
        with, without,
        "FAILBEFORE D19-CLAMP: the hidden proposed claim changes nothing the clamped pack says"
    );
    assert_eq!(
        with.1, 0,
        "FAILBEFORE D19-CLAMP: the clamped pack counts no claim its audience may not read"
    );
}

/// A bounded text fetch (a claim search): the shared admission asked the
/// gate before the clamp.
#[test]
fn a_clamped_text_search_of_claims_reads_alike_with_a_hidden_proposed_claim() {
    reads_alike_with_a_hidden_proposed_claim(Search::Text, true);
}

/// A text list that reaches the blend unasked: the run's gate over the
/// fused union judged the claim before the preselection withheld it.
#[test]
fn a_clamped_text_search_reads_alike_with_a_hidden_proposed_claim() {
    reads_alike_with_a_hidden_proposed_claim(Search::Text, false);
}

/// A bounded vector fetch (a claim search).
#[test]
fn a_clamped_vector_search_of_claims_reads_alike_with_a_hidden_proposed_claim() {
    reads_alike_with_a_hidden_proposed_claim(Search::Vector, true);
}

/// A vector list that reaches the blend unasked.
#[test]
fn a_clamped_vector_search_reads_alike_with_a_hidden_proposed_claim() {
    reads_alike_with_a_hidden_proposed_claim(Search::Vector, false);
}

/// Guard: a proposed claim the contact may read still counts as suppressed
/// in the clamped pack, and its empty reason is the owner's, on both paths
/// of both searches. (An empty clamped pack's candidates in scope are the
/// rows it surfaced, never the pre-clamp count the owner's reports.)
#[test]
fn a_clamped_search_counts_a_proposed_claim_its_audience_may_read() {
    for (search, claims_only) in [
        (Search::Text, false),
        (Search::Text, true),
        (Search::Vector, false),
        (Search::Vector, true),
    ] {
        let fixture = fixture();
        put_matching_claim(&fixture, ClaimApprovalStatus::Proposed, false);
        let reason_and_suppressed =
            |(empty, suppressed): PackSays| (empty.map(|(reason, _)| reason), suppressed);
        let owner = reason_and_suppressed(pack_says(&fixture, search, claims_only, false));
        assert_eq!(owner.1, 1, "FIXTURE: the owner's gate refuses the claim");
        assert_eq!(
            reason_and_suppressed(pack_says(&fixture, search, claims_only, true)),
            owner,
            "the clamped pack's empty reason and suppressed claims are the owner's for a claim \
             its audience may read"
        );
    }
}

/// Guard: a live claim the contact may not read, reached by a list the
/// clamp did not ask before the blend, is served to no one and still counts
/// among the pack's clamped rows.
#[test]
fn a_clamped_search_counts_a_live_hidden_claim_among_its_clamped_rows() {
    for search in [Search::Text, Search::Vector] {
        let fixture = fixture();
        let claim = put_matching_claim(&fixture, ClaimApprovalStatus::Auto, true);
        let vault = &fixture.vault;
        let owner: Vec<EntityId> = match search {
            Search::Text => vault.context_pack().search_text(WORD, 10),
            Search::Vector => vault.context_pack().search_vector(&query_vector(), 10),
        }
        .limit(10)
        .run()
        .expect("the owner's pack")
        .results
        .iter()
        .map(|entity| entity.id)
        .collect();
        assert_eq!(owner, [claim], "FIXTURE: the owner's pack serves the claim");
        let run = match search {
            Search::Text => vault.context_pack().search_text(WORD, 10),
            Search::Vector => vault.context_pack().search_vector(&query_vector(), 10),
        }
        .limit(10)
        .disclosure_context(with_contact(vault, fixture.contact))
        .run_unfinalized_with_telemetry()
        .expect("the clamped pack");
        assert!(
            run.value.results.is_empty(),
            "the clamped pack serves no row its audience may not read"
        );
        assert_eq!(
            run.clamped_out(),
            1,
            "the clamp's withheld rows count the live hidden claim"
        );
    }
}
