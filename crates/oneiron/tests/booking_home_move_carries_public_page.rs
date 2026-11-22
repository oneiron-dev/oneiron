//! A home move carries the booking pages' publications (FIX
//! [BK-HOME-MOVE-PUBLIC-PAGE-INDEX-NOT-CARRIED]; lead ruling
//! BK-HOME-MOVE-CARRIES-BOOKINGS = A, 21 Nov 06:2x: "Money follows the home,
//! and a move must never silently strand a visitor's link or a deposit"). A
//! public link resolves its page through the token index first, and the
//! publication claim the index names reaches no other machine by sync: every
//! peer refuses it at the put choke point. The new home of a move held
//! neither, so every public route of the page answered "booking page" not
//! found, a visitor's cancel link of a booking the old home confirmed among
//! them, before its action token was read. Now:
//! - the new home resolves the page's token and reads its live publication,
//!   and the visitor's cancel of a booking the old home confirmed lands there;
//! - a page the owner unpublished before the move resolves on the new home to
//!   its current publication, which is not public: the move carries the
//!   current head, never the published one it superseded.
//!
//! The page's standing invite grant, which the owner's publication write
//! mints on the node it runs on, is node-local too (FIX
//! [BK-HOME-MOVE-PAGE-INVITE-GRANT-NOT-CARRIED]; Engine 21 Nov 15:30: "a move
//! must not quietly stop the page's invite emails"). The new home of a move
//! held none, so a booking it confirmed sent no invite ("this page carries no
//! live booking page invite grant"). Now:
//! - the new home holds the old home's live grant row, the one the invite
//!   dispatch reads, and it covers the invite of a booking the new home
//!   confirmed;
//! - a grant the owner revoked on the old home stays revoked on the new home,
//!   and a publish there finds it and mints no live one;
//! - a grant the owner revoked on the new home before the move stays revoked:
//!   the old home's live row never lands over it.
//!
//! The two machines are copies of one vault, as
//! `tests/booking_home_move_carries_deposit.rs` makes them, taken after the
//! booking's confirm and before the owner publishes the page: the new home
//! holds the booking's EVENT and claims, as sync leaves them, and no
//! publication claim, as a machine born by pairing and sync holds none. The
//! door `drop_node_local_booking_rows` empties its node-local booking rows,
//! the token index and the publication markers among them, and
//! `move_booking_home` freezes the old home and carries each booking section
//! the build registers.
//!
//! Red on main beff0851b5bf, where no section carries a publication: the new
//! home resolves no page for the token. The two invite grant tests that
//! follow the old home's grant are red on main 2c56ee80294, where no section
//! carries a grant: the new home holds none. The third is green there (the
//! new home keeps its own revoked row) and guards the revoke-wins rule.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test booking_home_move_carries_public_page`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

#[path = "booking_deposit_support/fixture.rs"]
mod fixture;

use std::sync::Arc;

use fixture::{Fixture, MONDAY, NOW, event_type, slot_of};
use oneiron::booking::{
    BOOKING_PUBLIC_PAGE_PREDICATE, BOOKING_PUBLIC_PAGE_SCHEMA_VERSION, BookingLandingContent,
    BookingPageInviteContext, BookingPagePublication, ConfirmReceipt, ConstraintFieldConfig,
    EventTypeCard, HoldLeaseSpec, PublicBookingAvailability, PublicBookingPageToken,
    PublishBookingPageGrantRequest, SessionKey, ThemeTokens, booking_config_hash,
    booking_page_invites_authorizes, load_public_booking_page_listing,
    mint_publish_page_invite_grant, resolve_public_booking_token,
};
use oneiron::calendar::CALENDAR_INVITE_VERB;
use oneiron::memory::ClaimInput;
use oneiron::outbound_grant::StandingOutboundGrant;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::booking_home_move::{drop_node_local_booking_rows, move_booking_home};
use oneiron::{EdgeActorClass, EntityId, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;

const DAY: u64 = 86_400;

/// A vault config whose store clock reads `clock`.
fn config(clock: &Arc<ManualClock>) -> VaultConfig {
    let mut config = VaultConfig::default();
    config.store_clock = clock.bundle();
    config
}

/// One machine with the booking fixture (no deposit), its clock at the
/// fixture's `NOW`, and its embedded owner, the one actor whose publication
/// write a vault with no authority root admits.
fn seed() -> (Fixture, Arc<ManualClock>, EntityId) {
    let clock = ManualClock::new(NOW);
    let machine = Fixture::open_in(tempfile::tempdir().expect("temp dir"), config(&clock), None);
    let owner = machine
        .vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    (machine, clock, owner)
}

/// The seed's two copies: the old home, and the new home with none of the
/// old home's node-local booking rows.
fn old_and_new_home(seed: Fixture, clock: &Arc<ManualClock>) -> (Fixture, Fixture) {
    let (old_home, new_home) = seed.into_machines(|| config(clock));
    drop_node_local_booking_rows(&new_home.vault).expect("FIXTURE: the new home's own rows");
    (old_home, new_home)
}

/// A hold and its confirm of the fixture Monday's 12:00 UTC slot.
fn confirmed_booking(machine: &Fixture, session: SessionKey) -> ConfirmReceipt {
    let slot = machine
        .offered_slots()
        .into_iter()
        .find(|slot| slot.start_utc == MONDAY + 12 * 3_600)
        .expect("FIXTURE: the slot is offered");
    let hold = machine
        .hold(session, slot_of(&slot), HoldLeaseSpec::Ordinary, NOW)
        .expect("FIXTURE: the hold");
    machine
        .confirm(&hold, session, NOW + 10)
        .expect("FIXTURE: the confirm")
}

/// The owner's own write of the page's publication on `machine`, `published`
/// or not; a later write supersedes the earlier one.
fn publish(machine: &Fixture, owner: EntityId, published: bool) {
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
    let input = ClaimInput {
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
    };
    let memory = machine.vault.memory(owner, EdgeActorClass::Human);
    let receipt = memory
        .claim_upsert(&input)
        .expect("FIXTURE: the owner's publication write");
    if receipt.approval == "proposed" {
        memory
            .confirm_booking_publication(&receipt.claim_short_id, NOW)
            .expect("FIXTURE: the owner confirms the publication");
    }
}

fn token_of(machine: &Fixture) -> String {
    PublicBookingPageToken::for_page(machine.page).0
}

/// The page's invite grant on `machine`, as a publish there answers it: a
/// page that holds a grant, live or revoked, is answered with it and nothing
/// is written; a page that holds none gets a fresh live one.
fn publish_page_invite_grant(machine: &Fixture, owner: EntityId) -> StandingOutboundGrant {
    mint_publish_page_invite_grant(
        &machine.vault,
        &PublishBookingPageGrantRequest {
            page_ref: machine.page,
            publisher_principal: owner,
            issued_at: NOW,
        },
    )
    .expect("the page's invite grant")
}

/// The grant `machine` stores under `grant`'s id, as the invite dispatch
/// reads it: the live row, else the first revoked one.
fn stored_grant(machine: &Fixture, grant: &StandingOutboundGrant) -> Option<StandingOutboundGrant> {
    machine
        .vault
        .get_standing_outbound_grant(&grant.id)
        .expect("read the page's invite grant")
}

/// The owner's revoke of `grant` on `machine`.
fn revoke(machine: &Fixture, owner: EntityId, grant: &StandingOutboundGrant) {
    let proof = machine
        .vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the owner's proof");
    machine
        .vault
        .revoke_consent_grant(&proof, &grant.grant_ref())
        .expect("FIXTURE: the owner revokes the page's invite grant");
}

/// Whether `machine` reads the page's live, published publication at `now`,
/// as the public routes read it after the token.
fn serves_page(machine: &Fixture, now: u64) -> bool {
    load_public_booking_page_listing(&machine.vault, machine.page, now)
        .expect("read the page's publication")
        .is_some()
}

#[test]
fn a_visitor_link_to_a_page_published_on_the_old_home_resolves_on_the_new_home() {
    let (seed, clock, owner) = seed();
    let booking = confirmed_booking(&seed, SessionKey::derive(b"page-move-cancel"));
    let (old_home, new_home) = old_and_new_home(seed, &clock);
    publish(&old_home, owner, true);
    assert_eq!(
        resolve_public_booking_token(&old_home.vault, &token_of(&old_home))
            .expect("read the token"),
        Some(old_home.page),
        "FIXTURE: the old home serves the page"
    );
    assert!(serves_page(&old_home, NOW + 20), "FIXTURE: published");
    assert_eq!(
        resolve_public_booking_token(&new_home.vault, &token_of(&new_home))
            .expect("read the token"),
        None,
        "FIXTURE: the new home holds no publication before the move"
    );

    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"),
        "every booking section applies"
    );

    assert_eq!(
        resolve_public_booking_token(&new_home.vault, &token_of(&new_home))
            .expect("read the token"),
        Some(new_home.page),
        "the page's token resolves on the new home"
    );
    assert!(
        serves_page(&new_home, NOW + 30),
        "the new home reads the page's live publication"
    );
    new_home
        .cancel(&booking.cancel_token, NOW + 40)
        .expect("the visitor's cancel link lands on the new home");
}

#[test]
fn a_page_unpublished_before_the_move_stays_unpublished_on_the_new_home() {
    let (seed, clock, owner) = seed();
    let (old_home, new_home) = old_and_new_home(seed, &clock);
    publish(&old_home, owner, true);
    publish(&old_home, owner, false);
    assert!(
        !serves_page(&old_home, NOW + 20),
        "FIXTURE: the owner unpublished the page"
    );

    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"),
        "every booking section applies"
    );

    assert_eq!(
        resolve_public_booking_token(&new_home.vault, &token_of(&new_home))
            .expect("read the token"),
        Some(new_home.page),
        "the token resolves on the new home to the page's current publication"
    );
    assert!(
        !serves_page(&new_home, NOW + 30),
        "the current publication is unpublished: the earlier published one is not carried"
    );
}

#[test]
fn a_live_page_invite_grant_on_the_old_home_covers_a_booking_confirmed_on_the_new_home() {
    let (seed, clock, owner) = seed();
    let (old_home, new_home) = old_and_new_home(seed, &clock);
    publish(&old_home, owner, true);
    let grant = publish_page_invite_grant(&old_home, owner);
    assert!(
        grant.is_active(),
        "FIXTURE: the owner's publication write minted a live invite grant"
    );
    assert_eq!(
        stored_grant(&new_home, &grant),
        None,
        "FIXTURE: the new home holds no invite grant before the move"
    );

    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"),
        "every booking section applies"
    );

    assert_eq!(
        stored_grant(&new_home, &grant),
        Some(grant.clone()),
        "the new home holds the old home's live grant row, not a mint of its own"
    );
    let booking = confirmed_booking(&new_home, SessionKey::derive(b"page-move-invite"));
    assert!(
        booking_page_invites_authorizes(
            &new_home.vault,
            &grant.scope,
            &BookingPageInviteContext {
                booking_ref: booking.calendar.event_ref,
                verb_kind: CALENDAR_INVITE_VERB,
                requested_recipient: "visitor@example.test",
            },
        )
        .expect("read the booking's binding"),
        "the carried grant covers the invite of a booking the new home confirmed"
    );
}

#[test]
fn a_page_invite_grant_the_owner_revoked_on_the_old_home_stays_revoked_on_the_new_home() {
    let (seed, clock, owner) = seed();
    let (old_home, new_home) = old_and_new_home(seed, &clock);
    publish(&old_home, owner, true);
    let grant = publish_page_invite_grant(&old_home, owner);
    revoke(&old_home, owner, &grant);
    assert!(
        !publish_page_invite_grant(&old_home, owner).is_active(),
        "FIXTURE: the old home keeps the revoke, and a publish there mints no live grant"
    );

    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"),
        "every booking section applies"
    );

    assert_eq!(
        stored_grant(&new_home, &grant).map(|stored| stored.is_active()),
        Some(false),
        "the grant the owner revoked on the old home is revoked on the new home"
    );
    assert!(
        !publish_page_invite_grant(&new_home, owner).is_active(),
        "a publish on the new home finds the revoked grant and mints no live one"
    );
}

#[test]
fn a_page_invite_grant_the_owner_revoked_on_the_new_home_stays_revoked_after_the_move() {
    let (seed, clock, owner) = seed();
    // Published before the copy: both machines hold the page's claim and its
    // live invite grant row.
    publish(&seed, owner, true);
    let (old_home, new_home) = old_and_new_home(seed, &clock);
    let grant = publish_page_invite_grant(&new_home, owner);
    revoke(&new_home, owner, &grant);
    assert!(
        publish_page_invite_grant(&old_home, owner).is_active(),
        "FIXTURE: the old home keeps the grant live"
    );

    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"),
        "every booking section applies"
    );

    assert_eq!(
        stored_grant(&new_home, &grant).map(|stored| stored.is_active()),
        Some(false),
        "a revoke on either node wins: the old home's live row never lands over this one"
    );
}
