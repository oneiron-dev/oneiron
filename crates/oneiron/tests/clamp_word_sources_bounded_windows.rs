//! PACK-PRESELECT-CLAMP-ROW-ONLY-DISPLACES-READABLE-HIT, the bounded
//! fetches' half (FIX-LIST 30970). A clamped pack's bounded windows asked
//! the clamp of a row's own row alone: a `conversation.summary` claim the
//! contact could read by its row, but whose words came from a Tier-A row,
//! took a place in a text or temporal window. Enough of them outranked a
//! readable claim and cut it out of the window; the preselection before the
//! cuts (#9911) then dropped them, and the pack served nothing. Each window
//! now asks the sources of a row's words too, as the preselection and the
//! pack's sweep do, so the readable claim keeps its place.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test clamp_word_sources_bounded_windows`.
#![cfg(oneiron_test_support)]

use oneiron::counterparty_contact::CounterpartyFirstTouch;
use oneiron::federation::Scope;
use oneiron::interlocutor::{Interlocutor, InterlocutorSet};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::temporal::TemporalAnchorMode;
use oneiron::test_doors::disclosure_word_sources::{
    clamp_admits_with_contact, install_shipped_policy_with_ordinary_predicate, mark_tier_a,
    seed_cleared_contact,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ContextPackBuilder,
    DisclosureContext, EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_retrieval::fusion::FUSION_LIST_LENGTH;
use rmpv::Value;

/// The contact a clamped pack is assembled for.
const COUNTERPARTY: &str = "owen@example.com";
/// The predicate whose claims carry the words of the rows they cover.
const SUMMARY_PREDICATE: &str = "conversation.summary";
/// More rows than a channel's window holds: its window or cut is 80 rows.
const OUTRANKING_CLAIMS: usize = FUSION_LIST_LENGTH + 20;
/// The words of the readable claim the others outrank: one of the two the
/// query asks for, in a field as long as theirs.
const READABLE_TEXT: &str = "cobalt quartz";
/// The words of each claim with a hidden source, and the query: both words
/// match.
const OUTRANKING_TEXT: &str = "cobalt zircon";
const DAY: u64 = 86_400;
/// The temporal calls' clock and anchor: the anchor window is the day on
/// each side of `ANCHOR`, and every temporal claim was learned at `ANCHOR`.
const NOW: u64 = 1_700_000_000;
const ANCHOR: u64 = NOW - 10 * DAY;

/// An owned vault, one contact cleared for every axis, and two rows a
/// summary claim can cover: one the contact may read, one marked Tier A
/// once the claims that cover it are written.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    contact: EntityId,
    readable_source: EntityId,
    hidden_source: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("open vault");
    vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault's owner");
    // The raw claim door lands a `conversation.summary` claim live only once
    // the policy labels the predicate ordinary.
    install_shipped_policy_with_ordinary_predicate(&vault, SUMMARY_PREDICATE)
        .expect("FIXTURE: label the summary predicate ordinary");
    let contact = EntityId::now();
    seed_cleared_contact(&vault, contact, COUNTERPARTY, Scope::top())
        .expect("FIXTURE: seed the cleared contact");
    let readable_source = put_person(&vault);
    let hidden_source = put_person(&vault);
    Fixture {
        _dir: dir,
        vault,
        contact,
        readable_source,
        hidden_source,
    }
}

fn put_person(vault: &Vault) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"",
        )
        .expect("FIXTURE: put the person");
    person
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

/// Puts an approved, active `conversation.summary` claim whose words came
/// from `covered`, with `text` indexed as its body. When `occurred_at` is
/// given it occurred then and was learned at [`ANCHOR`]; otherwise both are
/// now.
fn put_summary_claim(
    fixture: &Fixture,
    text: &str,
    covered: EntityId,
    occurred_at: Option<u64>,
) -> EntityId {
    let vault = &fixture.vault;
    let subject = put_person(vault);
    let body = ClaimBody::new(
        SUMMARY_PREDICATE,
        ClaimSubject::Entity(subject),
        Value::Map(vec![
            ("text".into(), text.into()),
            (
                "covers".into(),
                Value::Array(vec![Value::Binary(covered.as_bytes().to_vec())]),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: summary claim body");
    let (occurred, learned) = match occurred_at {
        Some(occurred) => (occurred, ANCHOR),
        None => {
            let at = vault.now_recorded_at();
            (at, at)
        }
    };
    let claim = EntityId::now();
    vault
        .put_claim(
            &claim,
            &body,
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
    claim
}

fn admits(fixture: &Fixture, id: &EntityId) -> bool {
    clamp_admits_with_contact(&fixture.vault, fixture.contact, COUNTERPARTY, id)
        .expect("FIXTURE: ask the clamp")
}

/// Writes [`OUTRANKING_CLAIMS`] summary claims of [`OUTRANKING_TEXT`] that
/// cover the fixture's hidden source, then marks that source Tier A: the
/// contact could read each claim before the mark, and may not after it, so
/// only the source of its words hides it.
fn put_claims_with_a_hidden_source(fixture: &Fixture, occurred_at: Option<u64>) -> Vec<EntityId> {
    let claims: Vec<EntityId> = (0..OUTRANKING_CLAIMS)
        .map(|_| put_summary_claim(fixture, OUTRANKING_TEXT, fixture.hidden_source, occurred_at))
        .collect();
    assert!(
        admits(fixture, &claims[0]),
        "FIXTURE: the contact reads a claim whose source it may read"
    );
    mark_tier_a(&fixture.vault, &fixture.hidden_source).expect("FIXTURE: mark the source Tier A");
    assert!(
        !admits(fixture, &fixture.hidden_source),
        "FIXTURE: a Tier-A row reaches no one but the owner"
    );
    assert!(
        !admits(fixture, &claims[0]),
        "FIXTURE: the claim carries a Tier-A row's words"
    );
    claims
}

/// The rows `builder` serves, clamped for the fixture's contact with
/// `clamped`.
fn serves(fixture: &Fixture, builder: ContextPackBuilder<'_>, clamped: bool) -> Vec<EntityId> {
    let builder = if clamped {
        builder.disclosure_context(with_contact(&fixture.vault, fixture.contact))
    } else {
        builder
    };
    builder
        .run()
        .expect("the pack")
        .results
        .iter()
        .map(|entity| entity.id)
        .collect()
}

/// A text search for [`OUTRANKING_TEXT`] that blends no recency, so its
/// text window holds [`FUSION_LIST_LENGTH`] rows; only claims with
/// `claims_only`, which scans every posting through the run's scope.
fn text_pack(fixture: &Fixture, claims_only: bool) -> ContextPackBuilder<'_> {
    let builder = fixture
        .vault
        .context_pack()
        .search_text(OUTRANKING_TEXT, 10)
        .boost_recency(0.0)
        .limit(10);
    if claims_only {
        builder.filter_types(&[ENTITY_TYPE_CLAIM])
    } else {
        builder
    }
}

fn serves_the_readable_claim_past_claims_with_a_hidden_source(claims_only: bool) {
    let fixture = fixture();
    let readable = put_summary_claim(&fixture, READABLE_TEXT, fixture.readable_source, None);
    assert!(
        admits(&fixture, &readable),
        "FIXTURE: the contact reads the readable claim and its source"
    );
    assert_eq!(
        serves(&fixture, text_pack(&fixture, claims_only), true),
        [readable],
        "FIXTURE: the clamped pack serves the readable claim"
    );
    let hidden = put_claims_with_a_hidden_source(&fixture, None);
    let owner = serves(&fixture, text_pack(&fixture, claims_only), false);
    assert!(
        !owner.is_empty() && owner.iter().all(|id| hidden.contains(id)),
        "FIXTURE: the claims with a hidden source outrank the readable one in the owner's pack"
    );
    assert_eq!(
        serves(&fixture, text_pack(&fixture, claims_only), true),
        [readable],
        "FAILBEFORE PACK-PRESELECT-CLAMP-ROW-ONLY-DISPLACES-READABLE-HIT: claims whose words \
         come from a Tier-A row take no place in the text window, so the readable claim keeps \
         its own"
    );
}

/// The memory lane's text window.
#[test]
fn a_clamped_text_search_serves_a_readable_claim_past_claims_with_a_hidden_source() {
    serves_the_readable_claim_past_claims_with_a_hidden_source(false);
}

/// The scoped scan's window: each posting meets the bounded channel's
/// admission.
#[test]
fn a_clamped_claims_only_text_search_serves_a_readable_claim_past_claims_with_a_hidden_source() {
    serves_the_readable_claim_past_claims_with_a_hidden_source(true);
}

/// A one-row temporal search over the day on each side of [`ANCHOR`].
fn temporal_pack(fixture: &Fixture) -> ContextPackBuilder<'_> {
    fixture
        .vault
        .context_pack()
        .with_temporal_now(NOW)
        .search_temporal_with_sigma(
            ANCHOR - DAY,
            ANCHOR + DAY,
            DAY,
            TemporalAnchorMode::Occurred,
            1,
        )
        .limit(1)
}

/// Claims with a hidden source at the anchor's midpoint outrank a readable
/// claim off its centre in the temporal window.
#[test]
fn a_clamped_temporal_search_serves_a_readable_claim_past_claims_with_a_hidden_source() {
    let fixture = fixture();
    let readable = put_summary_claim(
        &fixture,
        READABLE_TEXT,
        fixture.readable_source,
        Some(ANCHOR + DAY / 2),
    );
    assert_eq!(
        serves(&fixture, temporal_pack(&fixture), true),
        [readable],
        "FIXTURE: the clamped pack serves the readable claim"
    );
    let hidden = put_claims_with_a_hidden_source(&fixture, Some(ANCHOR));
    let owner = serves(&fixture, temporal_pack(&fixture), false);
    assert!(
        owner.len() == 1 && hidden.contains(&owner[0]),
        "FIXTURE: a claim with a hidden source outranks the readable one in the owner's pack"
    );
    assert_eq!(
        serves(&fixture, temporal_pack(&fixture), true),
        [readable],
        "FAILBEFORE PACK-PRESELECT-CLAMP-ROW-ONLY-DISPLACES-READABLE-HIT: claims whose words \
         come from a Tier-A row take no place in the temporal window, so the readable claim \
         keeps its own"
    );
}
