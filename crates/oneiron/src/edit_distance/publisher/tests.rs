//! ONE-1764 (ED-08) unit tests: the leak NEG battery that makes rung-1's
//! "structurally impossible" claim testable, the judged-outcome tally that
//! feeds a signature, the comm doors the transport rides, the dial's
//! three-source resolution, and the interview digest proving ED-00/ED-01 reuse.

use super::*;

use crate::comm::{count_contact_record_claim_entries, run_comm_projector};
use crate::receipt::ReceiptKind;
use crate::settings::model_versioning::{
    DEFAULT_MODEL_STACK_CURRENT_ID, default_model_stack_registry,
};

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

fn judged_receipt(outcome: &str, seq: u8) -> ReceiptRecord {
    ReceiptRecord {
        receipt_id: format!("rcpt-{seq}"),
        receipt_kind: ReceiptKind::ProposalOutcome,
        occurred_at: u64::from(seq),
        actor: None,
        on_behalf_of: None,
        outcome: outcome.to_owned(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: Vec::new(),
        fields: std::collections::BTreeMap::new(),
    }
}

// ─── closed vocabularies ────────────────────────────────────────────────

/// The publisher's category vocabulary and the attribution judge's verdict
/// vocabulary are the SAME taxonomy under two type names. A new arm on either
/// side that the other does not learn about fails here, which is what keeps
/// the second type from becoming a fork.
#[test]
fn category_tracks_the_attribution_verdict_arm_for_arm() {
    let verdicts = [
        AttributionVerdict::SkillDefect,
        AttributionVerdict::ExecutionLapse,
        AttributionVerdict::Discovery,
    ];
    assert_eq!(verdicts.len(), IssueCategory::ALL.len());
    for verdict in verdicts {
        let category = IssueCategory::from_verdict(verdict);
        assert_eq!(category.as_str(), verdict.as_str());
        assert_eq!(IssueCategory::parse(category.as_str()), Some(category));
    }
}

/// Every closed vocabulary round-trips its own tokens and rejects a token this
/// engine never wrote — the property the on-disk rows depend on.
#[test]
fn closed_vocabularies_round_trip_and_refuse_strangers() {
    for arm in CountKey::ALL {
        assert_eq!(CountKey::parse(arm.as_str()), Some(arm));
    }
    for arm in SignatureSendState::ALL {
        assert_eq!(SignatureSendState::parse(arm.as_str()), Some(arm));
    }
    for arm in InterviewState::ALL {
        assert_eq!(InterviewState::parse(arm.as_str()), Some(arm));
    }
    assert_eq!(CountKey::parse(SENTINEL), None);
    assert_eq!(IssueCategory::parse(SENTINEL), None);
    assert_eq!(SignatureSendState::parse(SENTINEL), None);
    assert_eq!(InterviewState::parse(SENTINEL), None);
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

/// Serialization audit: the bytes that actually land in the vault contain none
/// of the sentinel. Belt-and-suspenders to the constructor battery above — the
/// door could be perfect and an encoder that stringified a caller-supplied
/// value would still leak.
#[test]
fn stored_signature_carries_no_sentinel_bytes() {
    let (_tmp, vault) = open_vault();
    let id = emit_issue_signature(&vault, signature()).expect("emit");

    let rtxn = vault.store.env.read_txn().expect("read txn");
    let raw = vault
        .store
        .vault_meta
        .get(&rtxn, &signature_key(id))
        .expect("read row")
        .expect("row present")
        .to_vec();
    drop(rtxn);

    assert!(!raw.is_empty());
    for needle in [SENTINEL, "hunter2", "CANARY", "password"] {
        assert!(
            !raw.windows(needle.len())
                .any(|window| window == needle.as_bytes()),
            "stored signature leaked {needle:?}"
        );
    }
    // The row is exactly the ratified field set and nothing else.
    let decoded = issue_signature(&vault, id)
        .expect("read back")
        .expect("some");
    assert_eq!(decoded, signature());
    assert_eq!(decoded.category(), IssueCategory::SkillDefect);
    assert_eq!(decoded.version(), 7);
    assert_eq!(decoded.model_id().as_str(), DEFAULT_MODEL_STACK_CURRENT_ID);
    assert_eq!(decoded.count(CountKey::Amended), Some(4));
    assert_eq!(decoded.counts().collect::<Vec<_>>(), counts().to_vec());
}

// ─── emission from a judged fixture ─────────────────────────────────────

/// The judged-cluster inlet: outcomes in, the closed count set out. Only
/// tallies cross — the edit mass behind them never enters the vocabulary.
#[test]
fn judged_outcomes_tally_into_the_closed_count_set() {
    let receipts = [
        judged_receipt(ProposalOutcome::ApprovedAmended.as_str(), 1),
        judged_receipt(ProposalOutcome::ApprovedAmended.as_str(), 2),
        judged_receipt(ProposalOutcome::Rejected.as_str(), 3),
        judged_receipt(ProposalOutcome::ApprovedUntouched.as_str(), 4),
        // Not a proposal outcome: skipped, never counted, never raised.
        judged_receipt("delivered", 5),
    ];
    assert_eq!(
        tally_judged_outcomes(&receipts),
        [
            (CountKey::Judged, 4),
            (CountKey::Amended, 2),
            (CountKey::Rejected, 1),
        ]
    );
    // ApprovedUntouched has no arm because it is the remainder, and the
    // remainder must stay derivable rather than separately asserted.
    let [(_, judged), (_, amended), (_, rejected)] = tally_judged_outcomes(&receipts);
    assert_eq!(judged - amended - rejected, 1);

    // An empty cluster tallies to zeroes, not to an error: a signature about a
    // cluster nobody judged yet is a legitimate thing to hold.
    assert_eq!(
        tally_judged_outcomes(&[]),
        [
            (CountKey::Judged, 0),
            (CountKey::Amended, 0),
            (CountKey::Rejected, 0),
        ]
    );
}

/// End to end on this base: judged receipts → tally → signature → stored row.
#[test]
fn signature_emits_from_a_judged_cluster_fixture() {
    let (_tmp, vault) = open_vault();
    let receipts = [
        judged_receipt(ProposalOutcome::ApprovedAmended.as_str(), 1),
        judged_receipt(ProposalOutcome::Rejected.as_str(), 2),
    ];
    let sig = IssueSignature::new(
        IssueCategory::from_verdict(AttributionVerdict::SkillDefect),
        crate::test_util::entity(0x5C),
        3,
        &default_model_stack_registry(),
        DEFAULT_MODEL_STACK_CURRENT_ID,
        &tally_judged_outcomes(&receipts),
        &hash("cluster-b"),
    )
    .expect("signature from judged fixture");

    let id = emit_issue_signature(&vault, sig.clone()).expect("emit");
    assert_eq!(issue_signature(&vault, id).expect("read"), Some(sig));
    assert_eq!(
        signature_send_state(&vault, id).expect("state"),
        SignatureSendState::Pending
    );
    // An id nobody emitted reads as absent, never as an empty signature.
    assert_eq!(
        issue_signature(&vault, crate::test_util::entity(0x5D)).expect("absent"),
        None
    );
}

// ─── the dial ───────────────────────────────────────────────────────────

/// Three sources, resolved explicit → install profile → compiled default. The
/// owner's explicit answer sits on top: an install profile that could override
/// it would make this a wall rather than a dial.
#[test]
fn dial_resolves_across_all_three_sources() {
    let (_tmp, vault) = open_vault();
    assert_eq!(
        publisher_enabled(&vault).expect("compiled default"),
        PUBLISHER_ENABLED_COMPILED_DEFAULT
    );

    set_publisher_install_default(&vault, true).expect("install profile");
    assert!(publisher_enabled(&vault).expect("profile wins over compiled"));

    set_publisher_enabled(&vault, false).expect("explicit off");
    assert!(
        !publisher_enabled(&vault).expect("explicit wins over profile"),
        "an install profile must not override the owner's own dial"
    );

    set_publisher_enabled(&vault, true).expect("explicit on");
    assert!(publisher_enabled(&vault).expect("explicit on"));

    set_publisher_install_default(&vault, false).expect("profile off");
    assert!(
        publisher_enabled(&vault).expect("explicit still wins"),
        "the explicit dial stays authoritative when the profile flips"
    );
}

/// Dial off: computed, stored, withheld — and the withholding is durable, so a
/// skip can be audited after the fact rather than only observed in a return
/// value.
#[test]
fn dial_off_stores_and_withholds_without_minting_a_party() {
    let (_tmp, vault) = open_vault();
    set_publisher_enabled(&vault, false).expect("dial off");
    let ids = [
        emit_issue_signature(&vault, signature()).expect("emit a"),
        emit_issue_signature(&vault, signature()).expect("emit b"),
    ];

    let outcome = send_signatures_if_enabled(&vault, &ids).expect("send");
    assert_eq!(outcome.sent, 0);
    assert_eq!(outcome.withheld, 2);
    assert_eq!(outcome.party, None);
    for id in ids {
        assert_eq!(
            signature_send_state(&vault, id).expect("state"),
            SignatureSendState::Withheld
        );
        // Withheld means WITHHELD, not dropped: the record is still readable.
        assert!(issue_signature(&vault, id).expect("read").is_some());
    }
    assert_eq!(
        count_contact_record_claim_entries(&vault, PUBLISHER_PARTY_KEY).expect("contact view"),
        0,
        "a withheld batch must not mint the publisher counterparty"
    );
}

/// Dial on: the counterparty resolves once for the batch, each signature rides
/// `comm.rs`'s send-receipt door, and one projector pass surfaces the thread.
#[test]
fn dial_on_sends_through_the_comm_doors_and_the_projector_shows_the_thread() {
    let (_tmp, vault) = open_vault();
    set_publisher_enabled(&vault, true).expect("dial on");
    let ids = [
        emit_issue_signature(&vault, signature()).expect("emit a"),
        emit_issue_signature(&vault, signature()).expect("emit b"),
    ];

    let outcome = send_signatures_if_enabled(&vault, &ids).expect("send");
    assert_eq!(outcome.sent, 2);
    assert_eq!(outcome.withheld, 0);
    let party = outcome.party.expect("party resolved");
    for id in ids {
        assert_eq!(
            signature_send_state(&vault, id).expect("state"),
            SignatureSendState::Sent
        );
    }

    // "Resolves or creates ONCE": a second resolution is the same entity, and a
    // second batch reuses it rather than minting a twin.
    assert_eq!(publisher_party(&vault).expect("re-resolve"), party);
    let again = send_signatures_if_enabled(&vault, &ids[..1]).expect("second batch");
    assert_eq!(again.party, Some(party));

    run_comm_projector(&vault).expect("projector pass");
    assert!(
        count_contact_record_claim_entries(&vault, PUBLISHER_PARTY_KEY).expect("contact view") > 0,
        "the projector must surface the publisher thread"
    );
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
    // And it refused BEFORE resolving a counterparty or writing any state.
    assert_eq!(
        signature_send_state(&vault, missing).expect("state"),
        SignatureSendState::Pending
    );
    assert_eq!(
        count_contact_record_claim_entries(&vault, PUBLISHER_PARTY_KEY).expect("contact view"),
        0
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
    use crate::edit_distance::{ProposalArtifactRef, finalized_proposal_text};

    let (_tmp, vault) = open_vault();
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

    let (session, mut digest) =
        open_interview(&vault, &topic, &reviewer, "the agent's draft digest").expect("open");
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
        .edit_as(&reviewer, |text| {
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
    assert_eq!(finalized.final_text, "actually, the agent's draft digest");
    let delta = delta_from_recorded_ops(&finalized);
    assert!(
        delta.d_norm > 0.0,
        "the user's amendment must produce a measurable Δ"
    );
    assert!(delta.ops_summary.ins > 0);
}

/// A digest nobody opened has no session — absent, never a default-shaped one.
#[test]
fn unknown_digest_has_no_interview_session() {
    let (_tmp, vault) = open_vault();
    assert_eq!(
        interview_session(&vault, crate::test_util::entity(0x5E)).expect("absent"),
        None
    );
}
