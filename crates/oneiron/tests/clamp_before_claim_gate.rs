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
//! Nor does a claim the audience may not read take a place in a fetch's
//! window (REVIEW-9980 round 1). Dropped only before the blend, hidden
//! claims that outranked a readable one filled the unnarrowed text scan's
//! window, or the temporal channel's cut, and the readable claim never
//! reached the run: the pack read `NoData` where it read `AllActivated`.
//!
//! The clamp's contact and Tier-A mark are written through test doors: run
//! the file with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test clamp_before_claim_gate`.
#![cfg(oneiron_test_support)]

use oneiron::counterparty_contact::CounterpartyFirstTouch;
use oneiron::federation::Scope;
use oneiron::interlocutor::{Interlocutor, InterlocutorSet};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::temporal::TemporalAnchorMode;
use oneiron::test_doors::disclosure_word_sources::{
    clamp_admits_claim_revision_with_contact, clamp_admits_with_contact, mark_tier_a,
    seed_cleared_contact,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, DisclosureContext,
    EmptyReason, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_retrieval::fusion::FUSION_LIST_LENGTH;

/// The word every search asks for, and the only word a claim's text holds.
const WORD: &str = "quokka";
/// The contact a clamped pack is assembled for.
const COUNTERPARTY: &str = "owen@example.com";
/// More rows than a channel's list holds: its window or cut is 80 rows.
const OUTRANKING_CLAIMS: usize = FUSION_LIST_LENGTH + 20;
/// The words of the readable claim the hidden ones outrank: one of the two
/// the query asks for, in a field as long as theirs.
const READABLE_TEXT: &str = "cobalt quartz";
/// The words of each hidden claim, and the query: both words match.
const OUTRANKING_TEXT: &str = "cobalt zircon";
const DAY: u64 = 86_400;
/// The temporal calls' clock and anchor: the anchor window is the day on
/// each side of `ANCHOR`, and every temporal claim was learned at `ANCHOR`.
const NOW: u64 = 1_700_000_000;
const ANCHOR: u64 = NOW - 10 * DAY;

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
    put_claim(fixture, approval, hidden, WORD, None)
}

/// [`put_matching_claim`] with the claim's text, and, when `occurred_at` is
/// given, the time it occurred, learned at [`ANCHOR`]; otherwise it occurred
/// and was learned now.
fn put_claim(
    fixture: &Fixture,
    approval: ClaimApprovalStatus,
    hidden: bool,
    text: &str,
    occurred_at: Option<u64>,
) -> EntityId {
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
    let (occurred, learned) = match occurred_at {
        Some(occurred) => (occurred, ANCHOR),
        None => {
            let at = vault.now_recorded_at();
            (at, at)
        }
    };
    vault
        .put_claim(
            &claim,
            &claim_body(subject, approval),
            TimeRange {
                start: occurred,
                end: occurred,
            },
            learned,
        )
        .expect("FIXTURE: put the claim");
    vault
        .batch()
        .text(&claim, &[("body", text)])
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
    pack_says_for(fixture, WORD, claims_only, clamped)
}

/// [`pack_says`] for a text search for `query`.
fn pack_says_for(fixture: &Fixture, query: &str, claims_only: bool, clamped: bool) -> PackSays {
    let vault = &fixture.vault;
    let mut builder = vault.context_pack().search_text(query, 10);
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

/// The empty reason a pack's [`PackSays`] reads.
fn reason_of((empty, _): PackSays) -> Option<EmptyReason> {
    empty.map(|(reason, _)| reason)
}

/// REVIEW-9980 round 1, text: proposed claims the contact may not read,
/// matching both words of the query, outrank a readable proposed claim that
/// matches one. They took the unnarrowed text scan's window and left it
/// only before the blend, so the readable claim never reached the run's gate.
#[test]
fn a_clamped_text_search_reads_alike_with_hidden_claims_that_outrank_a_readable_one() {
    let fixture = fixture();
    put_claim(
        &fixture,
        ClaimApprovalStatus::Proposed,
        false,
        READABLE_TEXT,
        None,
    );
    let without = pack_says_for(&fixture, OUTRANKING_TEXT, false, true);
    assert_eq!(
        (reason_of(without), without.1),
        (Some(EmptyReason::AllActivated), 1),
        "FIXTURE: the clamped pack reaches the readable claim and its gate refuses it"
    );
    for _ in 0..OUTRANKING_CLAIMS {
        put_claim(
            &fixture,
            ClaimApprovalStatus::Proposed,
            true,
            OUTRANKING_TEXT,
            None,
        );
    }
    assert!(
        pack_says_for(&fixture, OUTRANKING_TEXT, false, false).1 > 1,
        "FIXTURE: the owner's pack reaches the hidden claims and its gate refuses them"
    );
    assert_eq!(
        pack_says_for(&fixture, OUTRANKING_TEXT, false, true),
        without,
        "FAILBEFORE REVIEW-9980-TEXT-WINDOW: hidden claims take no place in the text scan's \
         window, so the clamped pack reads as it did without them"
    );
}

/// The pack of a temporal search over the day on each side of [`ANCHOR`]
/// (Occurred mode, one row), clamped for the contact when `clamped`.
fn temporal_pack(fixture: &Fixture, clamped: bool) -> oneiron::ContextPackBuilder<'_> {
    let vault = &fixture.vault;
    let builder = vault
        .context_pack()
        .with_temporal_now(NOW)
        .search_temporal_with_sigma(
            ANCHOR - DAY,
            ANCHOR + DAY,
            DAY,
            TemporalAnchorMode::Occurred,
            1,
        )
        .limit(1);
    if clamped {
        builder.disclosure_context(with_contact(vault, fixture.contact))
    } else {
        builder
    }
}

/// What [`temporal_pack`] says of itself; it serves nothing.
fn temporal_pack_says(fixture: &Fixture, clamped: bool) -> PackSays {
    let pack = temporal_pack(fixture, clamped)
        .include_stats(true)
        .run()
        .expect("the temporal pack");
    assert!(pack.results.is_empty(), "FIXTURE: the pack serves nothing");
    (
        pack.empty
            .as_ref()
            .map(|empty| (empty.reason, empty.total_in_scope)),
        pack.stats.claims_suppressed,
    )
}

/// REVIEW-9980 round 1, temporal: proposed claims the contact may not read,
/// at the anchor's midpoint, outrank a readable proposed claim off its
/// centre. The unnarrowed temporal list cut them in and the readable claim
/// out, and the clamp dropped them only before the blend.
#[test]
fn a_clamped_temporal_search_reads_alike_with_hidden_claims_nearer_its_anchor() {
    let fixture = fixture();
    put_claim(
        &fixture,
        ClaimApprovalStatus::Proposed,
        false,
        READABLE_TEXT,
        Some(ANCHOR + DAY / 2),
    );
    let without = temporal_pack_says(&fixture, true);
    assert_eq!(
        (reason_of(without), without.1),
        (Some(EmptyReason::AllActivated), 1),
        "FIXTURE: the clamped pack reaches the readable claim and its gate refuses it"
    );
    for _ in 0..OUTRANKING_CLAIMS {
        put_claim(
            &fixture,
            ClaimApprovalStatus::Proposed,
            true,
            OUTRANKING_TEXT,
            Some(ANCHOR),
        );
    }
    assert!(
        temporal_pack_says(&fixture, false).1 > 1,
        "FIXTURE: the owner's pack cuts in the hidden claims and its gate refuses them"
    );
    assert_eq!(
        temporal_pack_says(&fixture, true),
        without,
        "FAILBEFORE REVIEW-9980-TEMPORAL-CUT: hidden claims take no place in the temporal \
         window or its cut, so the clamped pack reads as it did without them"
    );
}

/// Guard: a live claim the contact may not read, inside an unnarrowed
/// temporal window, is served to no one and still counts among the pack's
/// clamped rows, as it did when the clamp asked only before the blend.
#[test]
fn a_clamped_temporal_search_counts_a_live_hidden_claim_among_its_clamped_rows() {
    let fixture = fixture();
    let claim = put_claim(
        &fixture,
        ClaimApprovalStatus::Auto,
        true,
        WORD,
        Some(ANCHOR),
    );
    let owner: Vec<EntityId> = temporal_pack(&fixture, false)
        .run()
        .expect("the owner's pack")
        .results
        .iter()
        .map(|entity| entity.id)
        .collect();
    assert_eq!(owner, [claim], "FIXTURE: the owner's pack serves the claim");
    let run = temporal_pack(&fixture, true)
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
