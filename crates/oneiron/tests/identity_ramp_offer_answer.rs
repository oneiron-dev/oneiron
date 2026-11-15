//! The owner answers an identity-ramp graduation offer from its INBOX row
//! (ARCH-0063 [INB-04]; INBOX-RESIDUE PR-1), through the doors the verbs
//! `vault.channel_identities.graduation.offers` and `.answer` call.
//!
//! The offers door names each standing offer by the id its `ramp:` row
//! carries. Auto mints the owner's `mail.send` grant over the offer's own
//! envelope and moves the identity to AutonomousWithinEnvelope, so the
//! volume bound stays; not-now and manual_pinned hold the offer and leave
//! the rung. An offer that does not stand is refused and changes nothing.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test identity_ramp_offer_answer`.
#![cfg(oneiron_test_support)]

#[path = "identity_ramp/fixture.rs"]
mod fixture;

use fixture::{COUNTERPARTY_CLASS, MAX_ACTIONS, RampFixture, WINDOW_SECS};
use oneiron::channel_identity_autonomy::api::{
    self, ChannelIdentityGraduationAnswerReceipt, ChannelIdentityGraduationAnswerRequest,
};
use oneiron::channel_identity_autonomy::{
    ChannelIdentityAutonomyMode, ChannelIdentityAutonomyRequest, ChannelIdentityAutonomyRung,
    DEFAULT_GRADUATION_UNCHANGED_STREAK, RAMP_OFFER_ITEM_PREFIX,
};
use oneiron::consent_graduation::api::{GraduationAnswer, GraduationSnooze};

fn mode(fixture: &RampFixture) -> ChannelIdentityAutonomyMode {
    fixture
        .vault
        .resolve_channel_identity_autonomy_mode(
            &fixture.scope.identity_ref,
            &fixture.scope.relationship_context,
            u64::MAX,
        )
        .expect("the identity's mode")
}

fn answer(
    fixture: &RampFixture,
    offer: &str,
    answer: GraduationAnswer,
) -> oneiron::memory::MemoryResult<ChannelIdentityGraduationAnswerReceipt> {
    api::answer(
        &fixture.vault,
        &fixture.owner,
        ChannelIdentityGraduationAnswerRequest {
            offer: offer.to_owned(),
            answer,
        },
    )
}

fn standing_offer_id(fixture: &RampFixture) -> String {
    let offers = api::offers(&fixture.vault, &fixture.owner).expect("the owner's offers");
    assert_eq!(offers.len(), 1, "one standing offer: {offers:?}");
    offers[0].offer.clone()
}

#[test]
fn the_offers_door_names_the_pile_rows_offer() {
    let fixture = RampFixture::at_send_with_approval();
    fixture.earn_offer();
    let offers = api::offers(&fixture.vault, &fixture.owner).expect("the owner's offers");
    assert_eq!(offers.len(), 1);
    let offer = &offers[0];
    let rows = fixture.ramp_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].item_id,
        format!("{RAMP_OFFER_ITEM_PREFIX}{}", offer.offer)
    );
    assert_eq!(rows[0].payload_ref.as_deref(), Some(offer.offer.as_str()));
    assert_eq!(
        offer.offer,
        fixture.scope.offer_id().expect("the scope's offer id")
    );
    assert_eq!(offer.actor, fixture.scope.actor_ref.to_hex());
    assert_eq!(offer.identity, fixture.scope.identity_ref.to_hex());
    assert_eq!(
        offer.relationship_context,
        fixture.scope.relationship_context.as_str()
    );
    assert_eq!(offer.verb_class, "mail.send");
    assert_eq!(
        offer.counterparty_class.as_deref(),
        Some(COUNTERPARTY_CLASS)
    );
    assert_eq!(offer.unchanged_streak, DEFAULT_GRADUATION_UNCHANGED_STREAK);
    assert_eq!(
        offer.evidence_refs.len(),
        usize::try_from(DEFAULT_GRADUATION_UNCHANGED_STREAK).expect("streak fits")
    );
    assert_eq!(offer.max_actions, MAX_ACTIONS);
    assert_eq!(offer.window_secs, WINDOW_SECS);
}

#[test]
fn auto_moves_the_identity_to_sends_within_the_offers_envelope() {
    let fixture = RampFixture::at_send_with_approval();
    fixture.earn_offer();
    let before = mode(&fixture);
    assert_eq!(before.rung, ChannelIdentityAutonomyRung::SendWithApproval);
    let offer = standing_offer_id(&fixture);

    let receipt = answer(&fixture, &offer, GraduationAnswer::Auto).expect("the owner's auto");
    assert_eq!(receipt.offer, offer);
    assert_eq!(receipt.rung.as_deref(), Some("autonomous_within_envelope"));
    assert!(matches!(receipt.snooze, GraduationSnooze::None));

    let after = mode(&fixture);
    assert_eq!(
        after.rung,
        ChannelIdentityAutonomyRung::AutonomousWithinEnvelope
    );
    assert_eq!(after.read_grant_ref, before.read_grant_ref);
    assert!(after.action_grant_ref.is_some());
    assert_ne!(
        after.action_grant_ref, before.action_grant_ref,
        "auto mints the send grant beside the draft grant"
    );
    // The applied envelopes, read and action, still bind the new rung: the
    // volume bound the offer proposed is the one in force.
    let desired = ChannelIdentityAutonomyRequest {
        rung: ChannelIdentityAutonomyRung::AutonomousWithinEnvelope,
        ..fixture.request.clone()
    };
    fixture
        .vault
        .verify_channel_identity_autonomy(&desired, &fixture.owner)
        .expect("the graduated posture keeps the offer's envelope");

    assert!(
        api::offers(&fixture.vault, &fixture.owner)
            .expect("the owner's offers")
            .is_empty()
    );
    assert!(
        fixture.ramp_rows().is_empty(),
        "an answered offer leaves the pile"
    );
    assert!(
        answer(&fixture, &offer, GraduationAnswer::Auto).is_err(),
        "a second auto finds no standing offer"
    );
}

#[test]
fn not_now_holds_the_offer_and_keeps_the_rung() {
    let fixture = RampFixture::at_send_with_approval();
    fixture.earn_offer();
    let offer = standing_offer_id(&fixture);

    let receipt = answer(&fixture, &offer, GraduationAnswer::NotNow).expect("the owner's not now");
    assert_eq!(receipt.rung, None);
    assert!(
        matches!(receipt.snooze, GraduationSnooze::Snoozed { count: 1, .. }),
        "the first decline starts the ladder: {:?}",
        receipt.snooze
    );
    assert_eq!(
        mode(&fixture).rung,
        ChannelIdentityAutonomyRung::SendWithApproval
    );
    assert!(
        api::offers(&fixture.vault, &fixture.owner)
            .expect("the owner's offers")
            .is_empty()
    );
    assert!(fixture.ramp_rows().is_empty());
}

#[test]
fn manual_pinned_stops_the_offer() {
    let fixture = RampFixture::at_send_with_approval();
    fixture.earn_offer();
    let offer = standing_offer_id(&fixture);

    let receipt =
        answer(&fixture, &offer, GraduationAnswer::ManualPinned).expect("the owner's pin");
    assert_eq!(receipt.rung, None);
    assert!(matches!(receipt.snooze, GraduationSnooze::ManualPinned));
    assert_eq!(
        mode(&fixture).rung,
        ChannelIdentityAutonomyRung::SendWithApproval
    );
    assert!(fixture.ramp_rows().is_empty());
}

#[test]
fn an_answer_to_an_offer_that_does_not_stand_is_refused() {
    let fixture = RampFixture::at_send_with_approval();
    fixture.reviews(DEFAULT_GRADUATION_UNCHANGED_STREAK - 1);
    let unearned = fixture.scope.offer_id().expect("the scope's offer id");

    for reply in [
        GraduationAnswer::Auto,
        GraduationAnswer::NotNow,
        GraduationAnswer::ManualPinned,
    ] {
        assert!(
            answer(&fixture, &unearned, reply).is_err(),
            "an unearned offer takes no answer"
        );
        assert!(
            answer(&fixture, "not-an-offer", reply).is_err(),
            "an unknown id takes no answer"
        );
    }
    assert_eq!(
        mode(&fixture).rung,
        ChannelIdentityAutonomyRung::SendWithApproval
    );
}
