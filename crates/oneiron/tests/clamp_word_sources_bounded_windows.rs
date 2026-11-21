//! PACK-PRESELECT-CLAMP-ROW-ONLY-DISPLACES-READABLE-HIT, the bounded
//! fetches' half (FIX-LIST 30970). A clamped pack's bounded windows asked
//! the clamp of a row's own row alone: a `conversation.summary` claim the
//! contact could read by its row, but whose words came from a Tier-A row,
//! took a place in a text or temporal window. Enough of them outranked a
//! readable claim and cut it out of the window; the preselection before the
//! cuts (#9911) then dropped them, and the pack served nothing. The phonetic
//! sound match's cut did the same: its nearest admitted distance sets the
//! distance it keeps, so a claim with a hidden source at distance 0 kept out
//! every readable near match. Each window now asks the sources of a row's
//! words too, as the preselection and the pack's sweep do, so the readable
//! claim keeps its place.
//!
//! The PPR walk did the same (REVIEW-10215 round 1). A clamped pack's walk
//! is narrowed: a group of edges above the owner's hub cap spreads no mass,
//! and the cap counted a claim with a hidden source among the subject's
//! claims, so the walk never reached a readable claim beside it. And an
//! exact phonetic hit with a hidden source took an implicit seed slot from
//! a readable hit below it, so the rows reachable only from the readable hit
//! never entered the run. The walk's visibility and the implicit seeds now
//! ask the sources of a row's words too.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test clamp_word_sources_bounded_windows`.
#![cfg(oneiron_test_support)]

use oneiron::batch::generate_phonetic_codes;
use oneiron::counterparty_contact::CounterpartyFirstTouch;
use oneiron::federation::Scope;
use oneiron::interlocutor::{Interlocutor, InterlocutorSet};
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TemporalAnchorMode;
use oneiron::test_doors::disclosure_word_sources::{
    clamp_admits_with_contact, install_shipped_policy_with_ordinary_predicate, mark_tier_a,
    row_admits_with_contact, seed_cleared_contact,
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

/// Puts an approved, active `conversation.summary` claim about a new person
/// whose words came from `covered`, with `text` indexed as its body. When
/// `occurred_at` is given it occurred then and was learned at [`ANCHOR`];
/// otherwise both are now.
fn put_summary_claim(
    fixture: &Fixture,
    text: &str,
    covered: EntityId,
    occurred_at: Option<u64>,
) -> EntityId {
    let subject = put_person(&fixture.vault);
    put_summary_claim_about(fixture, subject, text, covered, occurred_at)
}

/// [`put_summary_claim`] about `subject`: the claim's `claim_of` edge joins
/// it to the subject.
fn put_summary_claim_about(
    fixture: &Fixture,
    subject: EntityId,
    text: &str,
    covered: EntityId,
    occurred_at: Option<u64>,
) -> EntityId {
    let vault = &fixture.vault;
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

/// The clamp's test of `id`'s own row alone, without its words' sources.
fn row_admits(fixture: &Fixture, id: &EntityId) -> bool {
    row_admits_with_contact(&fixture.vault, fixture.contact, COUNTERPARTY, id)
        .expect("FIXTURE: ask the clamp's row test")
}

/// Writes `count` summary claims of [`OUTRANKING_TEXT`] that cover the
/// fixture's hidden source, then marks that source Tier A: the contact could
/// read each claim before the mark, and may not after it, so only the source
/// of its words hides it: the clamp's test of its own row still passes.
fn put_claims_with_a_hidden_source(
    fixture: &Fixture,
    count: usize,
    occurred_at: Option<u64>,
) -> Vec<EntityId> {
    let claims: Vec<EntityId> = (0..count)
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
    assert!(
        row_admits(fixture, &claims[0]),
        "FIXTURE: the clamp admits the claim's own row; only its source hides it"
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
    let hidden = put_claims_with_a_hidden_source(&fixture, OUTRANKING_CLAIMS, None);
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
    let hidden = put_claims_with_a_hidden_source(&fixture, OUTRANKING_CLAIMS, Some(ANCHOR));
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

/// The sound key the phonetic searches ask for: the first `ipa:` key of a
/// long name, so one more segment moves a key well inside the match
/// threshold.
fn query_sound_key() -> String {
    generate_phonetic_codes("Bartholomew")
        .into_iter()
        .find(|code| code.starts_with("ipa:"))
        .expect("FIXTURE: the name has a sound key")
}

fn post_codes(fixture: &Fixture, id: &EntityId, codes: &[&str]) {
    fixture
        .vault
        .batch()
        .phonetic(id, codes)
        .commit()
        .expect("FIXTURE: post the codes");
}

/// A one-row phonetic search for `key`.
fn phonetic_pack<'v>(fixture: &'v Fixture, key: &str) -> ContextPackBuilder<'v> {
    fixture
        .vault
        .context_pack()
        .search_phonetic(&[key])
        .limit(1)
}

/// The sound match keeps its admitted matches within the keep ratio of the
/// nearest admitted distance. Claims with a hidden source that match the
/// query's sound key exactly set that distance to 0 and cut out a readable
/// claim whose key is one segment longer.
#[test]
fn a_clamped_sound_match_serves_a_readable_claim_past_claims_with_a_hidden_source() {
    let fixture = fixture();
    let key = query_sound_key();
    let near_key = format!("{key}s");
    let readable = put_summary_claim(&fixture, READABLE_TEXT, fixture.readable_source, None);
    post_codes(&fixture, &readable, &[&near_key]);
    assert_eq!(
        serves(&fixture, phonetic_pack(&fixture, &key), true),
        [readable],
        "FIXTURE: the clamped pack's sound match serves the readable claim"
    );
    let hidden = put_claims_with_a_hidden_source(&fixture, OUTRANKING_CLAIMS, None);
    for claim in &hidden {
        post_codes(&fixture, claim, &[&key]);
    }
    let owner = serves(&fixture, phonetic_pack(&fixture, &key), false);
    assert!(
        owner.len() == 1 && hidden.contains(&owner[0]),
        "FIXTURE: a claim with a hidden source matches nearer in the owner's pack"
    );
    assert_eq!(
        serves(&fixture, phonetic_pack(&fixture, &key), true),
        [readable],
        "FAILBEFORE PACK-PRESELECT-CLAMP-ROW-ONLY-DISPLACES-READABLE-HIT: claims whose words \
         come from a Tier-A row set no distance in the sound match, so the readable claim keeps \
         its place"
    );
}

/// The owner's Setting of the narrowed PPR walk's hub cap.
const HUB_CAP_KEY: &str = "retrieval.ppr.narrowed_hub_fanout_cap";

/// The owner sets the narrowed walk's hub cap to `cap` edges.
fn set_hub_cap(fixture: &Fixture, cap: u32) {
    let vault = &fixture.vault;
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault's owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the owner proof");
    let outcome = vault
        .set_setting(
            SettingCaller::Owner(&proof),
            SetSetting::vault_value(HUB_CAP_KEY, serde_json::json!(cap)),
        )
        .expect("FIXTURE: the owner sets the hub cap");
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "FIXTURE: the owner's change applies: {outcome:?}"
    );
}

/// A one-hop walk from `subject`, ten rows.
fn walk_pack(fixture: &Fixture, subject: EntityId) -> ContextPackBuilder<'_> {
    fixture
        .vault
        .context_pack()
        .search_ppr(&[subject], 1)
        .limit(10)
}

/// A clamped pack's walk is narrowed, and a narrowed walk's group of edges
/// above the owner's hub cap spreads no mass; the cap counts only the edges
/// to rows the walk can see. The subject's two claims are one group (their
/// `claim_of` edges into it). With a cap of one edge, the claim with a hidden
/// source must not count there, or the group spreads nothing and the walk
/// never reaches the readable claim.
#[test]
fn a_clamped_walk_reaches_a_readable_claim_past_a_claim_with_a_hidden_source_under_the_hub_cap() {
    let fixture = fixture();
    let subject = put_person(&fixture.vault);
    let readable = put_summary_claim_about(
        &fixture,
        subject,
        READABLE_TEXT,
        fixture.readable_source,
        None,
    );
    let hidden = put_summary_claim_about(
        &fixture,
        subject,
        OUTRANKING_TEXT,
        fixture.hidden_source,
        None,
    );
    mark_tier_a(&fixture.vault, &fixture.hidden_source).expect("FIXTURE: mark the source Tier A");
    assert!(
        admits(&fixture, &subject) && admits(&fixture, &readable),
        "FIXTURE: the contact reads the subject and the readable claim"
    );
    assert!(
        !admits(&fixture, &hidden) && row_admits(&fixture, &hidden),
        "FIXTURE: only the source of its words hides the other claim"
    );
    assert!(
        serves(&fixture, walk_pack(&fixture, subject), true).contains(&readable),
        "FIXTURE: under the default hub cap the clamped walk reaches the readable claim"
    );
    set_hub_cap(&fixture, 1);
    assert!(
        serves(&fixture, walk_pack(&fixture, subject), true).contains(&readable),
        "FAILBEFORE PACK-PRESELECT-CLAMP-ROW-ONLY-DISPLACES-READABLE-HIT (REVIEW-10215 round 1): \
         a claim whose words come from a Tier-A row does not count toward the walk's hub cap, so \
         the subject's one readable claim spreads mass and the walk reaches it"
    );
}

/// Exact hits with a hidden source that outrank the readable hit: more than
/// the pack's ten implicit seeds, fewer than a channel's window.
const HIDDEN_SEED_HITS: usize = 12;

/// The first exact (non-sound-key) phonetic code of `name`: a code whose
/// posting the code rung reads in full, with no cut.
fn exact_code(name: &str) -> String {
    generate_phonetic_codes(name)
        .into_iter()
        .find(|code| !code.starts_with("ipa:"))
        .expect("FIXTURE: the name has an exact code")
}

/// A ten-row phonetic search for `codes` whose expansion walks two hops
/// from its implicit seeds: its ten best rows.
fn expanded_phonetic_pack<'v>(fixture: &'v Fixture, codes: &[&str]) -> ContextPackBuilder<'v> {
    fixture
        .vault
        .context_pack()
        .search_phonetic(codes)
        .expand_ppr(&[], 2)
        .limit(10)
}

/// The exact codes have no cut, and their hits' rank pass asks the clamp of
/// a row's own row, so exact hits with a hidden source reach the run's
/// preliminary blend, where the pack's sweep drops them later. Each matches
/// both of the query's codes and outranks the readable hit, which matches
/// one. They must not take the expansion's implicit seed slots, or the
/// readable hit seeds nothing and a claim reachable only through it (a
/// second claim about its subject) never enters the run.
#[test]
fn a_clamped_expansion_seeds_a_readable_hit_past_hits_with_a_hidden_source() {
    let fixture = fixture();
    let first = exact_code("Bartholomew");
    let second = exact_code("Maximilian");
    assert_ne!(first, second, "FIXTURE: the query asks two codes");
    let codes = [first.as_str(), second.as_str()];
    let subject = put_person(&fixture.vault);
    let readable = put_summary_claim_about(
        &fixture,
        subject,
        READABLE_TEXT,
        fixture.readable_source,
        None,
    );
    post_codes(&fixture, &readable, &[&first]);
    let reached = put_summary_claim_about(
        &fixture,
        subject,
        READABLE_TEXT,
        fixture.readable_source,
        None,
    );
    assert!(
        admits(&fixture, &subject) && admits(&fixture, &reached),
        "FIXTURE: the contact reads the subject and the claim beside the readable hit"
    );
    assert!(
        serves(&fixture, expanded_phonetic_pack(&fixture, &codes), true).contains(&reached),
        "FIXTURE: the expansion from the readable hit reaches the claim beside it"
    );
    let hidden = put_claims_with_a_hidden_source(&fixture, HIDDEN_SEED_HITS, None);
    for claim in &hidden {
        post_codes(&fixture, claim, &codes);
    }
    assert!(
        !serves(&fixture, expanded_phonetic_pack(&fixture, &codes), false).contains(&reached),
        "FIXTURE: the hits with a hidden source take every implicit seed in the owner's pack"
    );
    assert!(
        serves(&fixture, expanded_phonetic_pack(&fixture, &codes), true).contains(&reached),
        "FAILBEFORE PACK-PRESELECT-CLAMP-ROW-ONLY-DISPLACES-READABLE-HIT (REVIEW-10215 round 1): \
         exact hits whose words come from a Tier-A row take no implicit seed slot, so the \
         readable hit seeds the expansion and it reaches the claim beside it"
    );
}
