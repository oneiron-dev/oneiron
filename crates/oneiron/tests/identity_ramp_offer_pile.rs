//! An identity-ramp graduation offer waits on the owner in the INBOX pile
//! (ARCH-0063 [INB-04] into [INB-03]: "approval surface = INB-03's pile",
//! ARCH-0063:356; INBOX-RESIDUE PR-1).
//!
//! The owner applied SendWithApproval to an agent's email identity, and the
//! agent's sends were approved untouched twelve times, each on its own task:
//! the scope earns its offer (`Vault::evaluate_graduation_offer`). The owner's
//! inbox lens then holds one ApprovalRequired row for it, `ramp:<offer id>`,
//! for the owner alone, at the newest review. The owner's "not now" takes it
//! out; a scope short of its streak makes none.
//!
//! The reviewed sends are persisted through the hidden door
//! `oneiron::test_doors::identity_ramp`, built only under
//! `--cfg oneiron_test_support`. `RUSTFLAGS="--cfg oneiron_test_support"
//! cargo test --locked -p oneiron --all-features --test
//! identity_ramp_offer_pile`.
#![cfg(oneiron_test_support)]

#[path = "identity_ramp/fixture.rs"]
mod fixture;

use fixture::{RAMP_ITEM_PREFIX, RampFixture};
use oneiron::agent_inbox_lens::{AgentInboxItemKind, AgentInboxParticipant};
use oneiron::channel_identity_autonomy::DEFAULT_GRADUATION_UNCHANGED_STREAK;

#[test]
fn an_earned_offer_waits_on_the_owner_in_the_inbox_pile() {
    let fixture = RampFixture::at_send_with_approval();
    let newest = fixture.earn_offer();
    let offer = fixture
        .vault
        .evaluate_graduation_offer(&fixture.scope, 0, u64::MAX)
        .expect("evaluate the scope")
        .expect("twelve untouched reviews earn the offer");
    assert_eq!(offer.unchanged_streak, DEFAULT_GRADUATION_UNCHANGED_STREAK);

    let rows = fixture.ramp_rows();
    assert_eq!(rows.len(), 1, "one pile row for the earned offer: {rows:?}");
    let row = &rows[0];
    assert_eq!(row.kind, AgentInboxItemKind::ApprovalRequired);
    assert_eq!(row.identity_ref, Some(fixture.scope.identity_ref));
    assert_eq!(row.actor_ref, fixture.scope.actor_ref);
    assert_eq!(
        row.participants,
        vec![AgentInboxParticipant {
            identity_ref: Some(fixture.owner_id),
            actor_ref: fixture.owner_id,
        }],
        "the row is the owner's to answer"
    );
    assert_eq!(row.thread_ref, None);
    assert_eq!(
        row.occurred_at, newest,
        "the row stands at the newest review"
    );
    let offer_id = row
        .item_id
        .strip_prefix(RAMP_ITEM_PREFIX)
        .expect("a ramp row");
    assert_eq!(row.payload_ref.as_deref(), Some(offer_id));
    assert_eq!(offer_id.len(), 32, "the offer id is a handle's hex");
}

#[test]
fn the_owners_not_now_takes_the_offer_out_of_the_pile() {
    let fixture = RampFixture::at_send_with_approval();
    fixture.earn_offer();
    assert_eq!(fixture.ramp_rows().len(), 1, "the offer waits in the pile");
    let offer = fixture
        .vault
        .evaluate_graduation_offer(&fixture.scope, 0, u64::MAX)
        .expect("evaluate the scope")
        .expect("the offer stands");

    fixture
        .vault
        .decline_channel_identity_graduation_offer(&offer, &fixture.owner)
        .expect("the owner's not now");

    assert!(
        fixture.ramp_rows().is_empty(),
        "a declined offer leaves the pile"
    );
    assert_eq!(
        fixture
            .vault
            .evaluate_graduation_offer(&fixture.scope, 0, u64::MAX)
            .expect("evaluate the scope"),
        None
    );
}

#[test]
fn a_scope_short_of_its_streak_makes_no_row() {
    let fixture = RampFixture::at_send_with_approval();
    fixture.reviews(DEFAULT_GRADUATION_UNCHANGED_STREAK - 1);
    assert_eq!(
        fixture
            .vault
            .evaluate_graduation_offer(&fixture.scope, 0, u64::MAX)
            .expect("evaluate the scope"),
        None,
        "eleven reviews earn nothing"
    );
    assert!(fixture.ramp_rows().is_empty());
}

#[test]
fn the_agents_own_slice_does_not_carry_the_offer() {
    let fixture = RampFixture::at_send_with_approval();
    fixture.earn_offer();
    assert_eq!(fixture.ramp_rows().len(), 1, "the owner's pile holds it");
    assert!(
        fixture.agent_slice_ramp_rows().is_empty(),
        "the agent never answers its own graduation"
    );
}
