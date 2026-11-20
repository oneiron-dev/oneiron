//! [D19-GATE-COUNTS-CLAIMS-THE-DISCLOSURE-CLAMP-REFUSES]: in a pack clamped
//! for an audience, a claim the audience may not read whatever its status
//! leaves no trace in what the pack says of itself. Before, the run's D19
//! gate judged such a claim before the clamp asked: a dead claim (Proposed)
//! the audience may not read (Tier A) counted in
//! `PackStats::claims_suppressed` and made an empty pack read
//! `AllActivated`, so the audience learned that a claim it may not read
//! matched. The phonetic code rung's half landed with #9911
//! (`tests/phonetic_exact_hits_scoped.rs`).
//!
//! A pack's text channel reaches the gate both ways. A claim search bounds
//! its fetch, and the shared admission asked the gate before the clamp. An
//! unnarrowed search's widening probe asked the gate of the hidden posting
//! and its rejection joined the run; with the probe fixed, the list still
//! reached the blend holding the hidden claim, and the run's gate judged it
//! there. (A pack's vector walk is narrowed to the memory lane in caches of
//! its own, whose rejections never join the run, so it counted none.)
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
    clamp_admits_claim_revision_with_contact, clamp_admits_with_contact, mark_tier_a,
    seed_cleared_contact,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, DisclosureContext,
    EmptyReason, EntityId, TimeRange, Vault, VaultConfig,
};

/// The word every search asks for, and the only word a claim's text holds.
const WORD: &str = "quokka";
/// The contact a clamped pack is assembled for.
const COUNTERPARTY: &str = "owen@example.com";

/// An owned vault and one contact, cleared for every axis, present with the
/// owner: the pack's clamp is the contact's row test.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    contact: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("open vault");
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

fn claim_body(subject: EntityId, approval: ClaimApprovalStatus) -> ClaimBody {
    ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("fact"),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: claim body")
}

/// A claim about a person, put with approval `approval`, whose text is
/// [`WORD`]. With `hidden` it is marked Tier A: the contact may not read it
/// whatever its status, so not even served as a live (Auto) revision.
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
    let claim = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_claim(
            &claim,
            &claim_body(subject, approval),
            TimeRange { start: at, end: at },
            at,
        )
        .expect("FIXTURE: put the claim");
    vault
        .batch()
        .text(&claim, &[("body", WORD)])
        .commit()
        .expect("FIXTURE: index the claim's text");
    if hidden {
        mark_tier_a(vault, &claim).expect("FIXTURE: mark the claim Tier A");
        let live = claim_body(subject, ClaimApprovalStatus::Auto);
        assert!(
            !clamp_admits_claim_revision_with_contact(
                vault,
                fixture.contact,
                COUNTERPARTY,
                &claim,
                &live,
            )
            .expect("FIXTURE: ask the clamp"),
            "FIXTURE: the contact may not read the claim, not even as a live one"
        );
    } else if matches!(approval, ClaimApprovalStatus::Auto) {
        assert!(
            clamp_admits_with_contact(vault, fixture.contact, COUNTERPARTY, &claim)
                .expect("FIXTURE: ask the clamp"),
            "FIXTURE: the contact may read the live claim"
        );
    }
    claim
}

/// What a pack says of itself: its empty reason and candidates in scope
/// (when it served nothing), and its suppressed claims.
type PackSays = (Option<(EmptyReason, usize)>, usize);

/// The pack of a text search for [`WORD`] (only claims with `claims_only`),
/// clamped for the contact when `clamped`; it serves nothing.
fn pack_says(fixture: &Fixture, claims_only: bool, clamped: bool) -> PackSays {
    let vault = &fixture.vault;
    let mut builder = vault.context_pack().search_text(WORD, 10);
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

/// A clamped text search reads the same with and without a proposed claim
/// the contact may not read, and counts no suppressed claim; the owner's own
/// pack counts it, so the search reaches it.
fn reads_alike_with_a_hidden_proposed_claim(claims_only: bool) {
    let fixture = fixture();
    let without = pack_says(&fixture, claims_only, true);
    put_matching_claim(&fixture, ClaimApprovalStatus::Proposed, true);
    assert_eq!(
        pack_says(&fixture, claims_only, false).1,
        1,
        "FIXTURE: the owner's pack reaches the claim and its gate refuses it"
    );
    let with = pack_says(&fixture, claims_only, true);
    assert_eq!(
        with, without,
        "FAILBEFORE D19-CLAMP: the hidden proposed claim changes nothing the clamped pack says"
    );
    assert_eq!(
        with.1, 0,
        "FAILBEFORE D19-CLAMP: the clamped pack counts no claim its audience may not read"
    );
}

/// A claim search bounds the text fetch: the shared admission asked the gate
/// before the clamp, and the fetch's rejections join the run.
#[test]
fn a_clamped_text_search_of_claims_reads_alike_with_a_hidden_proposed_claim() {
    reads_alike_with_a_hidden_proposed_claim(true);
}

/// An unnarrowed text search: its widening probe asked the gate of the
/// hidden posting, and its list reached the blend holding the hidden claim.
#[test]
fn a_clamped_text_search_reads_alike_with_a_hidden_proposed_claim() {
    reads_alike_with_a_hidden_proposed_claim(false);
}

/// Guard: a proposed claim the contact may read still counts as suppressed
/// in the clamped pack, and its empty reason is the owner's, on both paths.
/// (An empty clamped pack's candidates in scope are the rows it surfaced,
/// never the pre-clamp count the owner's reports.)
#[test]
fn a_clamped_text_search_counts_a_proposed_claim_its_audience_may_read() {
    for claims_only in [false, true] {
        let fixture = fixture();
        put_matching_claim(&fixture, ClaimApprovalStatus::Proposed, false);
        let reason_and_suppressed =
            |(empty, suppressed): PackSays| (empty.map(|(reason, _)| reason), suppressed);
        let owner = reason_and_suppressed(pack_says(&fixture, claims_only, false));
        assert_eq!(owner.1, 1, "FIXTURE: the owner's gate refuses the claim");
        assert_eq!(
            reason_and_suppressed(pack_says(&fixture, claims_only, true)),
            owner,
            "the clamped pack's empty reason and suppressed claims are the owner's for a claim \
             its audience may read"
        );
    }
}

/// Guard: a live claim the contact may not read, reached by an unnarrowed
/// text search, is served to no one and still counts among the pack's
/// clamped rows.
#[test]
fn a_clamped_text_search_counts_a_live_hidden_claim_among_its_clamped_rows() {
    let fixture = fixture();
    let claim = put_matching_claim(&fixture, ClaimApprovalStatus::Auto, true);
    let vault = &fixture.vault;
    let owner: Vec<EntityId> = vault
        .context_pack()
        .search_text(WORD, 10)
        .limit(10)
        .run()
        .expect("the owner's pack")
        .results
        .iter()
        .map(|entity| entity.id)
        .collect();
    assert_eq!(owner, [claim], "FIXTURE: the owner's pack serves the claim");
    let run = vault
        .context_pack()
        .search_text(WORD, 10)
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
