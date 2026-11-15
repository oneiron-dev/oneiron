//! ONE-1764 (ED-08) unit tests: the leak NEG battery that makes rung-1's
//! "structurally impossible" claim testable, the judged-outcome tally that
//! feeds a signature, the comm doors the transport rides, the dial's
//! three-source resolution, and the interview digest proving ED-00/ED-01 reuse.

use super::*;

// FIX [T0B-PUBLISHER-PARTY-PORT]: publisher party key removed (#4165): port to withholding, SignatureNotFound and delivery successors
#[cfg(any())]
use crate::comm::{count_contact_record_claim_entries, run_comm_projector};
use crate::settings::model_versioning::{
    DEFAULT_MODEL_STACK_CURRENT_ID, default_model_stack_registry,
};
use crate::vault::Vault;

/// The string that must never reach disk. Deliberately long, mixed-case and
/// punctuated — nothing about it fits any field's admitted shape.
const SENTINEL: &str = "CANARY free-text: user said 'my password is hunter2' <leak>";

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config())
}

/// A well-formed pattern hash: blake3 rendered lowercase hex, the shape ED-01's
/// Δ refs already carry.
fn hash(of: &str) -> String {
    crate::entity_id::bytes_to_hex_lower(blake3::hash(of.as_bytes()).as_bytes())
}

fn counts() -> [(CountKey, u32); 3] {
    [
        (CountKey::Judged, 9),
        (CountKey::Amended, 4),
        (CountKey::Rejected, 2),
    ]
}

fn signature() -> IssueSignature {
    IssueSignature::new(
        IssueCategory::SkillDefect,
        crate::test_util::entity(0x5B),
        7,
        &default_model_stack_registry(),
        DEFAULT_MODEL_STACK_CURRENT_ID,
        &counts(),
        &hash("cluster-a"),
    )
    .expect("well-formed signature")
}

/// A delivery lane's emit: the signature lands `Pending` under the lane's
/// logical send `send_ref`, the key its outcome is written back under.
fn emit_pending(vault: &Vault, sig: &IssueSignature, send_ref: &str) -> crate::EntityId {
    vault
        .try_with_write_txn_grouped(|wtxn| emit_issue_signature_in_txn(vault, wtxn, sig, send_ref))
        .expect("lane emit")
}

// ─── the leak NEG battery ───────────────────────────────────────────────

/// The constructor refuses free text at EVERY argument position that accepts a
/// string.
///
/// There are exactly two such positions — `model_id` and `content_hash`. The
/// other four are structurally incapable of carrying text: `category` and the
/// `counts` keys are closed enums, `artifact` is an [`EntityId`], `version`
/// and the count values are `u32`. That is the whole argument for rung-1 being
/// safe to default on, so it is asserted rather than assumed: this test fails
/// the moment someone widens a field to `String`.
#[test]
fn constructor_refuses_free_text_in_every_string_position() {
    let registry = default_model_stack_registry();
    let artifact = crate::test_util::entity(0x5B);
    let good_hash = hash("cluster-a");

    // model_id — an unregistered id is how a "model name" would smuggle text.
    let via_model = IssueSignature::new(
        IssueCategory::SkillDefect,
        artifact,
        7,
        &registry,
        SENTINEL,
        &counts(),
        &good_hash,
    );
    assert!(matches!(via_model, Err(PublisherError::UnknownModelStack)));

    // A well-formed id that simply is not registered is refused for the same
    // reason: shape is not membership.
    let via_unregistered = IssueSignature::new(
        IssueCategory::SkillDefect,
        artifact,
        7,
        &registry,
        "not-a-registered-stack",
        &counts(),
        &good_hash,
    );
    assert!(matches!(
        via_unregistered,
        Err(PublisherError::UnknownModelStack)
    ));

    // content_hash — free text, wrong length, and uppercase hex all refused.
    for offered in [
        SENTINEL,
        "",
        &good_hash[1..],
        &good_hash.to_ascii_uppercase(),
        &format!("{good_hash}0"),
    ] {
        let attempt = IssueSignature::new(
            IssueCategory::SkillDefect,
            artifact,
            7,
            &registry,
            DEFAULT_MODEL_STACK_CURRENT_ID,
            &counts(),
            offered,
        );
        assert!(
            matches!(attempt, Err(PublisherError::MalformedContentHash)),
            "content_hash {offered:?} must be refused"
        );
    }

    // counts — keys are closed, so the only smuggling shape left is repeating
    // one key to carry a second value under one name.
    let via_duplicate = IssueSignature::new(
        IssueCategory::SkillDefect,
        artifact,
        7,
        &registry,
        DEFAULT_MODEL_STACK_CURRENT_ID,
        &[(CountKey::Judged, 1), (CountKey::Judged, 2)],
        &good_hash,
    );
    assert!(matches!(
        via_duplicate,
        Err(PublisherError::DuplicateCountKey)
    ));
}

// ─── the dial ───────────────────────────────────────────────────────────

/// Dial off: computed, stored, withheld — and the withholding is durable, so a
/// skip can be audited after the fact rather than only observed in a return
/// value.
#[test]
fn dial_off_stores_and_withholds_without_minting_a_party() {
    let (_tmp, vault) = open_vault();
    set_publisher_enabled(&vault, false).expect("dial off");
    let ids = [
        emit_pending(&vault, &signature(), "test-lane-send-a"),
        emit_pending(&vault, &signature(), "test-lane-send-b"),
    ];
    for id in ids {
        assert_eq!(
            signature_send_state(&vault, id).expect("state"),
            SignatureSendState::Pending
        );
    }

    let outcome = send_signatures_if_enabled(&vault, &ids).expect("send");
    assert_eq!(outcome.handed_off, 0);
    assert_eq!(outcome.sent, 0);
    assert_eq!(outcome.withheld, 2);
    assert_eq!(outcome.local, 0);
    for id in ids {
        assert_eq!(
            signature_send_state(&vault, id).expect("state"),
            SignatureSendState::Withheld
        );
        // Withheld means WITHHELD, not dropped: the record is still readable.
        assert!(issue_signature(&vault, id).expect("read").is_some());
    }
    // No-mint is structural now: there is no shared party left to mint.
    // `SendOutcome` carries no party, and only a `Delivered` delivery names a
    // per-artifact publisher actor — so a withheld batch mints nothing.
}

/// Dial on: the send door hands lane signatures to the ordinary delivery path
/// without confirming anything, and each delivery confirms its own signature.
/// `Sent` comes only from the delivery's answer, never from the send door.
#[test]
fn dial_on_hands_off_and_delivery_confirms_sent() {
    let (_tmp, vault) = open_vault();
    set_publisher_enabled(&vault, true).expect("dial on");
    let lanes = ["test-lane-send-a", "test-lane-send-b"];
    let ids = [
        emit_pending(&vault, &signature(), lanes[0]),
        emit_pending(&vault, &signature(), lanes[1]),
    ];

    // The send door confirms nothing: handed-off signatures stay `Pending`.
    let outcome = send_signatures_if_enabled(&vault, &ids).expect("send");
    assert_eq!(outcome.handed_off, 2);
    assert_eq!(outcome.sent, 0);
    assert_eq!(outcome.withheld, 0);
    assert_eq!(outcome.local, 0);
    for id in ids {
        assert_eq!(
            signature_send_state(&vault, id).expect("state"),
            SignatureSendState::Pending
        );
    }

    // Each delivery confirms its own signature with its publisher actor.
    let actor = crate::test_util::entity(0x41);
    for (id, send_ref) in ids.iter().zip(lanes) {
        record_signature_delivery(
            &vault,
            *id,
            send_ref,
            SignatureDeliveryOutcome::Delivered,
            |_| {
                Ok(Some(PublisherActor {
                    actor,
                    identity: "test-publisher".to_owned(),
                }))
            },
        )
        .expect("deliver");
    }
    for id in ids {
        assert_eq!(
            signature_send_state(&vault, id).expect("state"),
            SignatureSendState::Sent
        );
    }

    // A replay of the outcome already written changes nothing — not even a
    // second look at the publisher.
    for (id, send_ref) in ids.iter().zip(lanes) {
        record_signature_delivery(
            &vault,
            *id,
            send_ref,
            SignatureDeliveryOutcome::Delivered,
            |_| panic!("a settled replay must not consult the publisher"),
        )
        .expect("replay");
    }
    for id in ids {
        assert_eq!(
            signature_send_state(&vault, id).expect("state"),
            SignatureSendState::Sent
        );
    }

    // A confirmed signature stays confirmed: a second batch counts it as sent.
    let again = send_signatures_if_enabled(&vault, &ids).expect("second batch");
    assert_eq!(again.handed_off, 0);
    assert_eq!(again.sent, 2);
    assert_eq!(again.withheld, 0);
    assert_eq!(again.local, 0);
}

/// The send door will not receipt a signature that does not exist — an id with
/// no row behind it is a caller bug, not an empty send.
#[test]
fn send_door_refuses_an_unknown_signature_id() {
    let (_tmp, vault) = open_vault();
    set_publisher_enabled(&vault, true).expect("dial on");
    let missing = crate::test_util::entity(0x5E);
    assert!(matches!(
        send_signatures_if_enabled(&vault, &[missing]),
        Err(PublisherError::SignatureNotFound)
    ));
    // And it refused BEFORE writing any state: no signature row, and the send
    // state still reads the no-lane default.
    assert!(issue_signature(&vault, missing).expect("read").is_none());
    assert_eq!(
        signature_send_state(&vault, missing).expect("state"),
        SignatureSendState::Local
    );
}

// ─── UP rung 3 — the interview digest ───────────────────────────────────

/// The reuse proof: the digest is an ordinary proposal-text artifact, so the
/// user's amendment is recorded by ED-00's window and measured by ED-01's Δ
/// lane. Nothing in `publisher.rs` computes an edit distance.
#[cfg(feature = "sync")]
#[test]
fn interview_digest_rides_the_ed00_and_ed01_doors() {
    use crate::edge::EdgeActorClass;
    use crate::edit_distance::delta::delta_from_recorded_ops;
    use crate::edit_distance::{ProposalArtifactRef, finalized_proposal_text, retained_proposal};

    let clock = crate::ports::ManualClock::new(50);
    let mut config = crate::test_util::embedding_test_config();
    config.store_clock = clock.bundle();
    let (_tmp, vault) = crate::test_util::open_test_vault_with(config);
    let topic = crate::test_util::entity(0x5B);
    let reviewer = {
        let id = crate::test_util::entity(0x5C);
        vault
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_PERSON,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                b"ed08 interview reviewer",
            )
            .expect("put reviewer");
        WriteActor::new(id, EdgeActorClass::Human)
    };

    let previous_id = vault.new_entity_id().unwrap();
    let (session, mut digest) =
        open_interview(&vault, &topic, &reviewer, "the agent's draft digest").expect("open");
    // The reviewer's peer binding claim and its audit mutation take the two
    // injected ids before the digest's own.
    assert_eq!(
        u128::from_be_bytes(*session.digest_artifact.as_bytes()),
        u128::from_be_bytes(*previous_id.as_bytes()) + 3,
    );
    assert_eq!(session.topic_ref, topic);
    assert_eq!(session.state, InterviewState::Drafting);
    assert_eq!(
        interview_session(&vault, session.digest_artifact).expect("stored"),
        Some(session)
    );

    let session = submit_interview_for_review(&vault, session).expect("submit");
    assert_eq!(session.state, InterviewState::UserReview);

    // The user edits the digest before it settles — through ED-00's door.
    digest
        .edit_as(&vault, &reviewer, |text| {
            text.insert(0, "actually, ")
                .map_err(|_| Error::InvariantViolation("test digest edit"))
        })
        .expect("user amendment");

    let settled = settle_interview_digest(&vault, session, digest).expect("settle");
    assert_eq!(settled, session.digest_artifact);
    assert_eq!(
        interview_session(&vault, settled)
            .expect("stored")
            .expect("some")
            .state,
        InterviewState::Settled
    );

    // The Δ receipt: ED-01 measures the window ED-00 recorded.
    let finalized = finalized_proposal_text(&vault, ProposalArtifactRef::new(settled))
        .expect("read finalized")
        .expect("finalize persisted the record");
    // 15021c26eee (#4114) keeps texts in the retained document behind refs:
    // the same final digest through the retained read.
    let retained = retained_proposal(&vault, finalized.artifact_ref)
        .expect("read retained")
        .expect("finalize retained the document");
    assert_eq!(
        retained.final_text().into_text().as_deref(),
        Some("actually, the agent's draft digest")
    );
    let delta = delta_from_recorded_ops(&retained).expect("delta from recorded ops");
    assert!(
        delta.d_norm > 0.0,
        "the user's amendment must produce a measurable Δ"
    );
    assert!(delta.ops_summary.ins > 0);
}
