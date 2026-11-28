//! The owner publishes, revises, confirms and retracts a booking page on the
//! booking home alone (FIX [BK-PUBLICATION-CLAIM-REFUSED-AT-SYNC-INGRESS];
//! lead ruling BK-PUBLICATION-OFF-HOME-WRITE = B with B1, 21 Nov 17:3x). The
//! public routes serve a page from the home, and every peer refuses a
//! publication claim at its put choke point, so a publish on another device
//! answered the owner "committed" with a page no visitor reached. Now:
//! - a publish, revision, confirm or retract on a device whose election names
//!   another node home is refused with the typed reason
//!   `booking.publication.not_booking_home`, and writes no publication there;
//! - a vault no election names a home for refuses too
//!   (`booking.publication.no_booking_home`), and the refusal offers the one
//!   owner act that lets the write run: make this device the booking home;
//! - a former home whose rows a home move froze refuses
//!   (`booking.publication.booking_home_moving`), and the new home publishes;
//! - ordinary sync ships no `booking.public_page` claim: the home's window
//!   export holds none, beside the owner's ordinary claim written with it.
//!
//! The two devices are copies of one vault, as
//! `tests/booking_home_move_carries_public_page.rs` makes them, each with its
//! own sync node id and both elections naming the first one home; the peer's
//! node-local booking rows are dropped, as a device born by pairing and sync
//! holds none.
//!
//! Red on main 47b5f60c15c7, where the writer reads no home: every refused
//! write lands, and the window export holds the publication claim.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test booking_publication_home_only`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

#[path = "booking_deposit_support/fixture.rs"]
mod fixture;

use std::sync::Arc;

use fixture::{Fixture, NOW, event_type};
use oneiron::booking::{
    BOOKING_PUBLIC_PAGE_PREDICATE, BOOKING_PUBLIC_PAGE_SCHEMA_VERSION, BookingLandingContent,
    BookingPagePublication, ConstraintFieldConfig, EventTypeCard, PublicBookingAvailability,
    PublicBookingPageToken, ThemeTokens, booking_config_hash, load_public_booking_page_listing,
    resolve_public_booking_token,
};
use oneiron::memory::{ClaimInput, CommitReceipt, MEMORY_CODE_INVALID_STATE, MemoryError};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window;
use oneiron::test_doors::booking_home_move::{drop_node_local_booking_rows, move_booking_home};
use oneiron::test_doors::untangle_regressions::load_or_mint_client_id;
use oneiron::{
    DreamerHomeNodeCandidate, DreamerRunnerStore, EdgeActorClass, EntityId, VaultConfig,
};
use oneiron_store::ports::manual_clock::ManualClock;

const DAY: u64 = 86_400;
/// The month window the fixture's `NOW` (Monday 2 March 2026) falls in.
const NOW_WINDOW: &str = "2026-03";
const NOT_BOOKING_HOME: &str = "booking.publication.not_booking_home";
const NO_BOOKING_HOME: &str = "booking.publication.no_booking_home";
const BOOKING_HOME_MOVING: &str = "booking.publication.booking_home_moving";
const REVISION_NOT_PENDING: &str = "booking.publication.revision_not_pending";
/// The egress test's control: a claim predicate every sync door ships.
const ORDINARY_PREDICATE: &str = "profile.preference";

/// A vault config whose store clock reads `clock`.
fn config(clock: &Arc<ManualClock>) -> VaultConfig {
    let mut config = VaultConfig::default();
    config.store_clock = clock.bundle();
    config
}

/// One machine with the booking fixture (no deposit), its clock at the
/// fixture's `NOW`, and its embedded owner. The fixture's election names its
/// node 9 home, and the machine has no sync node id yet, so its own
/// election names no other node home: it is the vault's one device.
fn seed() -> (Fixture, Arc<ManualClock>, EntityId) {
    let clock = ManualClock::new(NOW);
    let machine = Fixture::open_in(tempfile::tempdir().expect("temp dir"), config(&clock), None);
    let owner = machine
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    (machine, clock, owner)
}

/// `machine`'s own election, re-run over `home_node_id` alone.
fn elect_home(machine: &Fixture, home_node_id: u64) {
    let elected = DreamerRunnerStore::new(&machine.vault)
        .elect_home_node(
            &[DreamerHomeNodeCandidate::always_on_local(home_node_id)],
            NOW,
        )
        .expect("FIXTURE: the election");
    assert_eq!(
        elected.map(|home| home.node_id),
        Some(home_node_id),
        "FIXTURE: the election names the home"
    );
}

/// The seed's two copies, each with its own sync node id, and both
/// elections naming the first one the booking home: the home, a peer device
/// of the same vault with none of the home's node-local booking rows, and
/// the home's node id.
fn home_and_peer(seed: Fixture, clock: &Arc<ManualClock>) -> (Fixture, Fixture, u64) {
    let (home, peer) = seed.into_machines(|| config(clock));
    drop_node_local_booking_rows(&peer.vault).expect("FIXTURE: the peer's own rows");
    let home_id = load_or_mint_client_id(&home.vault).expect("FIXTURE: the home's node id");
    let peer_id = load_or_mint_client_id(&peer.vault).expect("FIXTURE: the peer's node id");
    assert_ne!(home_id, peer_id, "FIXTURE: two devices, two sync node ids");
    elect_home(&home, home_id);
    elect_home(&peer, home_id);
    (home, peer, home_id)
}

/// The owner's publication claim of the page on `machine`, `published` or
/// not.
fn publication_input(machine: &Fixture, published: bool) -> ClaimInput {
    let publication = BookingPagePublication {
        schema_version: BOOKING_PUBLIC_PAGE_SCHEMA_VERSION,
        published,
        event_config_hashes: [(
            event_type().0,
            booking_config_hash(&machine.config).expect("config hash"),
        )]
        .into(),
        owner_display: "Page owner".to_owned(),
        event_types: vec![EventTypeCard {
            key: event_type(),
            title: "Intro call".to_owned(),
            deposit: None,
            duration_min: u32::from(machine.config.duration_min),
            allowed_durations_min: Vec::new(),
            description: "A first call".to_owned(),
        }],
        constraint_field: ConstraintFieldConfig {
            enabled: false,
            placeholder: String::new(),
        },
        theme: ThemeTokens(serde_json::json!({})),
        landing: BookingLandingContent::default(),
        initial_availability: PublicBookingAvailability {
            event_type: event_type(),
            start_after_secs: DAY,
            window_secs: DAY,
            visitor_tz: "UTC".to_owned(),
        },
        constraint_front: None,
        sponsor: None,
    };
    ClaimInput {
        id: None,
        predicate: BOOKING_PUBLIC_PAGE_PREDICATE.to_owned(),
        subject_ref: machine.page.to_hex(),
        value: serde_json::to_value(publication).expect("publication"),
        confidence: 1.0,
        source: "user_stated".to_owned(),
        world_ref: None,
        relationship_ref: None,
        scope: None,
        valid_from: Some(1),
        valid_to: Some(NOW + 15 * DAY),
        occurred_at: None,
        learned_at: None,
        salience: None,
        confidence_details: None,
    }
}

/// The owner's publication write on `machine`, unconfirmed: a write over an
/// earlier publication lands proposed.
fn write_publication(
    machine: &Fixture,
    owner: EntityId,
    published: bool,
) -> Result<CommitReceipt, MemoryError> {
    machine
        .vault
        .memory(owner, EdgeActorClass::Human)
        .claim_upsert(&publication_input(machine, published))
}

/// The owner's publication write on `machine`, confirmed when it lands
/// proposed; the short id of the head it leaves.
fn publish(machine: &Fixture, owner: EntityId, published: bool) -> String {
    let receipt = write_publication(machine, owner, published)
        .expect("FIXTURE: the owner's publication write");
    if receipt.approval == "proposed" {
        machine
            .vault
            .memory(owner, EdgeActorClass::Human)
            .confirm_booking_publication(&receipt.claim_short_id, NOW)
            .expect("FIXTURE: the owner confirms the publication");
    }
    receipt.claim_short_id
}

/// The page a visitor's link resolves on `machine`, if any.
fn resolved_page(machine: &Fixture) -> Option<EntityId> {
    resolve_public_booking_token(
        &machine.vault,
        &PublicBookingPageToken::for_page(machine.page).0,
    )
    .expect("token index read")
}

/// Whether `machine` serves the page to a visitor at `now`: the read every
/// public route serves the page from.
fn serves_page(machine: &Fixture, now: u64) -> bool {
    load_public_booking_page_listing(&machine.vault, machine.page, now)
        .expect("read the page's publication")
        .is_some()
}

/// The publication claims `machine` holds for the page.
fn publication_claims(machine: &Fixture) -> Vec<EntityId> {
    machine
        .vault
        .claims_for_subject(&machine.page)
        .expect("claims of the page")
        .into_iter()
        .filter(|id| {
            machine
                .vault
                .get_claim(id)
                .expect("claim read")
                .is_some_and(|claim| claim.predicate == BOOKING_PUBLIC_PAGE_PREDICATE)
        })
        .collect()
}

fn assert_refused(error: &MemoryError, reason: &str) {
    assert_eq!(error.code, MEMORY_CODE_INVALID_STATE, "{error:?}");
    assert_eq!(error.reason_codes, vec![reason.to_owned()], "{error:?}");
}

/// Whether `error` offers the owner act that makes this device the home.
fn offers_the_home_pick(error: &MemoryError) -> bool {
    error.suggestions.iter().any(|suggestion| {
        suggestion.starts_with("Make this device the booking home")
            && suggestion.contains("vault.consolidation.home.pick")
    })
}

#[test]
fn a_publish_on_a_device_that_is_not_the_booking_home_is_refused_and_writes_no_page() {
    let (seed, clock, owner) = seed();
    let (home, peer, home_id) = home_and_peer(seed, &clock);

    let refused = write_publication(&peer, owner, true)
        .expect_err("a publish on a device whose election names another home is refused");
    assert_refused(&refused, NOT_BOOKING_HOME);
    assert!(
        refused
            .suggestions
            .iter()
            .any(|suggestion| suggestion.contains(&format!("node {home_id}"))),
        "the refusal names the booking home: {refused:?}"
    );
    assert!(offers_the_home_pick(&refused), "{refused:?}");
    assert_eq!(publication_claims(&peer), Vec::<EntityId>::new());
    assert_eq!(resolved_page(&peer), None);

    publish(&home, owner, true);
    assert_eq!(publication_claims(&home).len(), 1);
    assert_eq!(resolved_page(&home), Some(home.page));
}

#[test]
fn a_publish_with_no_booking_home_is_refused_and_offers_to_make_this_device_the_home() {
    let (machine, _clock, owner) = seed();
    DreamerRunnerStore::new(&machine.vault)
        .elect_home_node(&[], NOW)
        .expect("FIXTURE: the election over no candidate");
    assert_eq!(
        DreamerRunnerStore::new(&machine.vault)
            .home_node_designation()
            .expect("designation read"),
        None,
        "FIXTURE: no election names a home"
    );

    let refused = write_publication(&machine, owner, true)
        .expect_err("a publish with no booking home is refused");
    assert_refused(&refused, NO_BOOKING_HOME);
    assert!(offers_the_home_pick(&refused), "{refused:?}");
    assert_eq!(publication_claims(&machine), Vec::<EntityId>::new());
    assert_eq!(resolved_page(&machine), None);

    let node_id = load_or_mint_client_id(&machine.vault).expect("FIXTURE: the node id");
    elect_home(&machine, node_id);
    publish(&machine, owner, true);
    assert_eq!(resolved_page(&machine), Some(machine.page));
}

#[test]
fn a_revision_confirm_or_retract_on_a_device_that_is_not_the_booking_home_is_refused() {
    let (seed, clock, owner) = seed();
    let live = publish(&seed, owner, true);
    let pending =
        write_publication(&seed, owner, false).expect("FIXTURE: the owner's revision write");
    assert_eq!(
        pending.approval, "proposed",
        "FIXTURE: a revision of a publication waits for its confirm"
    );
    let (home, peer, _home_id) = home_and_peer(seed, &clock);
    let memory = peer.vault.memory(owner, EdgeActorClass::Human);

    let confirm = memory
        .confirm_booking_publication(&pending.claim_short_id, NOW)
        .expect_err("a confirm off the booking home is refused");
    assert_refused(&confirm, NOT_BOOKING_HOME);
    let retract = memory
        .claim_retract(&live)
        .expect_err("a retract off the booking home is refused");
    assert_refused(&retract, NOT_BOOKING_HOME);
    let revision = write_publication(&peer, owner, true)
        .expect_err("a revision off the booking home is refused");
    assert_refused(&revision, NOT_BOOKING_HOME);

    home.vault
        .memory(owner, EdgeActorClass::Human)
        .confirm_booking_publication(&pending.claim_short_id, NOW)
        .expect("the booking home confirms the same revision");
}

#[test]
fn a_publish_on_the_former_home_of_a_move_is_refused_and_the_new_home_publishes() {
    let (seed, clock, owner) = seed();
    let (old_home, new_home) = seed.into_machines(|| config(&clock));
    drop_node_local_booking_rows(&new_home.vault).expect("FIXTURE: the new home's own rows");
    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"),
        "FIXTURE: every booking section applied"
    );

    let refused = write_publication(&old_home, owner, true)
        .expect_err("a publish on a home whose rows a move froze is refused");
    assert_refused(&refused, BOOKING_HOME_MOVING);
    assert_eq!(resolved_page(&old_home), None);

    publish(&new_home, owner, true);
    assert_eq!(resolved_page(&new_home), Some(new_home.page));
}

#[test]
fn a_former_home_serves_no_page_after_a_home_move_and_the_new_home_retract_ends_it() {
    let (seed, clock, owner) = seed();
    let (old_home, new_home) = seed.into_machines(|| config(&clock));
    drop_node_local_booking_rows(&new_home.vault).expect("FIXTURE: the new home's own rows");
    let live = publish(&old_home, owner, true);
    assert!(
        serves_page(&old_home, NOW + 20),
        "FIXTURE: the old home serves the page"
    );
    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"),
        "FIXTURE: every booking section applied"
    );
    assert!(
        serves_page(&new_home, NOW + 30),
        "FIXTURE: the new home serves the carried page"
    );

    assert!(
        !serves_page(&old_home, NOW + 30),
        "the former home serves no page once the move froze its booking rows"
    );
    new_home
        .vault
        .memory(owner, EdgeActorClass::Human)
        .claim_retract(&live)
        .expect("the new home retracts the page");
    assert!(
        !serves_page(&new_home, NOW + 40),
        "the owner's retract ends the page on the new home"
    );
    assert!(
        !serves_page(&old_home, NOW + 40),
        "and the former home serves it no more than before"
    );
}

/// The owner's publication input of the page on `machine`, published, with
/// `owner_display` as its one changed field: a revision of the page.
fn revised_publication_input(machine: &Fixture, owner_display: &str) -> ClaimInput {
    let mut input = publication_input(machine, true);
    input.value["owner_display"] = serde_json::json!(owner_display);
    input
}

#[test]
fn a_move_carried_revision_without_its_confirmation_is_refused_and_the_page_publishes_again() {
    let (seed, clock, owner) = seed();
    let (old_home, new_home) = seed.into_machines(|| config(&clock));
    drop_node_local_booking_rows(&new_home.vault).expect("FIXTURE: the new home's own rows");
    publish(&old_home, owner, true);
    let pending = old_home
        .vault
        .memory(owner, EdgeActorClass::Human)
        .claim_upsert(&revised_publication_input(&old_home, "Page owner, revised"))
        .expect("FIXTURE: the owner's revision write");
    assert_eq!(
        pending.approval, "proposed",
        "FIXTURE: a revision of a publication waits for its confirm"
    );
    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"),
        "FIXTURE: every booking section applied"
    );
    let memory = new_home.vault.memory(owner, EdgeActorClass::Human);

    let refused = memory
        .confirm_booking_publication(&pending.claim_short_id, NOW)
        .expect_err("a confirm of a revision whose confirmation stayed on the former home");
    assert_refused(&refused, REVISION_NOT_PENDING);
    assert!(
        refused
            .suggestions
            .iter()
            .any(|suggestion| suggestion.starts_with("Retract the revision")
                && suggestion.contains(&pending.claim_short_id)),
        "the refusal names the revision to retract: {refused:?}"
    );

    memory
        .claim_retract(&pending.claim_short_id)
        .expect("the new home retracts the carried revision");
    let again = memory
        .claim_upsert(&revised_publication_input(
            &new_home,
            "Page owner, published again",
        ))
        .expect("the owner publishes the page again on the new home");
    if again.approval == "proposed" {
        memory
            .confirm_booking_publication(&again.claim_short_id, NOW)
            .expect("the new home confirms the page published again");
    }
    assert!(
        serves_page(&new_home, NOW + 30),
        "the page published again on the new home is served there"
    );
}

#[test]
fn ordinary_sync_ships_no_booking_page_publication_claim() {
    let (machine, _clock, owner) = seed();
    publish(&machine, owner, true);
    assert_eq!(
        publication_claims(&machine).len(),
        1,
        "FIXTURE: the home holds its publication"
    );
    // The control: an ordinary owner claim learned in the same month window.
    let mut ordinary = publication_input(&machine, true);
    ordinary.predicate = ORDINARY_PREDICATE.to_owned();
    ordinary.subject_ref = owner.to_hex();
    ordinary.value = serde_json::json!("morning calls");
    ordinary.valid_to = None;
    machine
        .vault
        .memory(owner, EdgeActorClass::Human)
        .claim_upsert(&ordinary)
        .expect("FIXTURE: the owner's ordinary claim");

    let key = WindowKey::new(NOW_WINDOW);
    let doc = oneiron::sync::schema::create_window_doc("home", &key);
    window::reverse_rematerialize(&machine.vault, &doc, &key).expect("the window export");
    let mut predicates = Vec::new();
    doc.get_map("entities").for_each(|key, _value| {
        if let Ok(id) = EntityId::from_hex(key)
            && let Some(claim) = machine.vault.get_claim(&id).expect("claim read")
        {
            predicates.push(claim.predicate);
        }
    });
    assert!(
        predicates
            .iter()
            .any(|predicate| predicate == ORDINARY_PREDICATE),
        "the export ships the owner's ordinary claim: {predicates:?}"
    );
    assert!(
        !predicates
            .iter()
            .any(|predicate| predicate == BOOKING_PUBLIC_PAGE_PREDICATE),
        "the export ships no publication claim: {predicates:?}"
    );
}
