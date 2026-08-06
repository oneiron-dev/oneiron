// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1776 (CA-05) cross-module oracle for send hygiene.
//!
//! Everything here runs through the crate's PUBLIC API, and every claim
//! assertion compares against the CA-01-owned ENCODERS rather than a
//! hand-spelled MessagePack map — so a schema change breaks the codec's own
//! tests, not this file's guesses about it.
//!
//! Two vault fixtures, because "not sent" and "sent with these headers" need
//! opposite conditions:
//!
//! * [`oracle_vault`] is unseeded, so the claim write door is open and
//!   suppression writes land. Its dispatches never reach a connector, which is
//!   exactly what the suppression tests want to measure.
//! * [`sending_vault`] is seeded and granted, so an admitted send is observed
//!   ARRIVING at the connector with its frozen headers. The header tests need
//!   that: on a fail-closed vault an empty header map would be vacuously true.

mod common;

use common::entity as test_id;
use oneiron::campaign::claims::{
    BounceKind, CampaignMemberChannel, CampaignMemberDerivation, CampaignMemberState,
    CampaignMemberValue, CommBounceValue, CommDoNotContactValue, DO_NOT_CONTACT_SCOPE_ALL,
    PREDICATE_CAMPAIGN_MEMBER, PREDICATE_COMM_BOUNCE, PREDICATE_COMM_DO_NOT_CONTACT,
    encode_campaign_member_value, encode_comm_bounce_value, encode_do_not_contact_value,
};
use oneiron::campaign::send_hygiene::{
    LIST_UNSUBSCRIBE, LIST_UNSUBSCRIBE_POST, LIST_UNSUBSCRIBE_POST_ONE_CLICK,
    ListUnsubscribeTarget, StickySenderOutcome, SuppressionCause, SuppressionInput,
    apply_suppression, bind_sticky_sender, list_unsubscribe_headers,
};
use oneiron::identity_reputation::{
    BOUNCE_CONSTRAINED_THRESHOLD, BOUNCE_DEGRADED_THRESHOLD, COMPLAINT_CONSTRAINED_THRESHOLD,
    COMPLAINT_DEGRADED_THRESHOLD, CampaignEmailWebhookEvent, DEGRADED_REPUTATION_DAILY_CAP,
    EmailDeliveryDisposition, EmailReputationWebhookSignal, IdentityReputation,
    IdentityReputationSignal, IdentityReputationStatus, IdentityWarmupStage,
    WARMUP_WARMING_DAILY_CAP, project_campaign_email_webhook,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, GrantMintIntent,
    GrantMintIntentScope, OutboundDeliveryWindowDecision, OutboundDispatchActor,
    OutboundDispatchGate, OutboundDispatchRequest, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger, Result, TimeRange, Vault, VaultConfig,
};

const CHANNEL: &str = "email";
const OTHER_CHANNEL: &str = "telegram";
const VERB: &str = "send";
const COUNTERPARTY: &str = "mika@example.com";
const DENY_OPT_OUT: &str = "gate.deny.counterparty_opt_out";

const HTTPS_TARGET: &str = "https://example.com/u/opaque-123";
const MAILTO_TARGET: &str = "mailto:unsubscribe@example.com?subject=unsub";

const PERSON_SEED: u8 = 0x61;
const CAMPAIGN_SEED: u8 = 0x62;
const SENDER_SEED: u8 = 0x63;
const OTHER_SENDER_SEED: u8 = 0x64;
const EVIDENCE_SEED: u8 = 0x65;
const BASIS_SEED: u8 = 0x66;
const MEMBER_SEED: u8 = 0x67;
const QUERY_SEED: u8 = 0x68;
const SECOND_MEMBER_SEED: u8 = 0x69;
const THIRD_SENDER_SEED: u8 = 0x6A;
const SECOND_BASIS_SEED: u8 = 0x6B;
const PROPOSED_DNC_SEED: u8 = 0x6C;
const STALE_DNC_SEED: u8 = 0x6D;
const SEND_GRANT_SEED: u8 = 0x6F;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Records the hygiene headers each connector call was handed, in order.
#[derive(Default)]
struct HeaderSink {
    calls: Vec<Vec<(String, String)>>,
    fail: bool,
}

impl OutboundExecutionSink for HeaderSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls.push(
            request
                .hygiene_headers
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        );
        if self.fail {
            OutboundExecutionOutcome::failed("transport-not-started")
        } else {
            OutboundExecutionOutcome::delivered_to_channel("provider:message:one")
        }
    }
}

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// Unseeded keeps the claim write door open without a policy fixture, matching
/// the CA-01/CA-03 oracles.
fn oracle_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    put_person(&vault, test_id(PERSON_SEED));
    (dir, vault)
}

/// A vault whose sends actually REACH the transport: seeded policy plus a
/// standing `send` grant for the one actor the seeded manifest gives an Auto
/// ceiling. Constructed directly rather than through `test_id`, which refuses
/// production-pinned seeds.
fn sending_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), test_config()).unwrap();
    let actor = EntityId::from_bytes([0xE1; 16]).unwrap();
    put_person(&vault, actor);
    vault
        .mint_standing_outbound_grant(
            &test_id(SEND_GRANT_SEED),
            &GrantMintIntent {
                principal_ref: actor.to_hex(),
                origin_component_id: "tasks".to_owned(),
                origin_action_id: "create".to_owned(),
                origin_receipt_ref: None,
                scope: GrantMintIntentScope::VerbClass {
                    verb_class: VERB.to_owned(),
                },
            },
            1,
        )
        .unwrap();
    (dir, vault, actor)
}

fn put_person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"send hygiene oracle person",
        )
        .unwrap();
}

/// The cohort row every suppression test starts from: enrolled, one email
/// channel bound to a sticky sender, and a machine derivation whose survival is
/// the point of half the assertions below.
fn enrolled_member() -> CampaignMemberValue {
    CampaignMemberValue {
        campaign: test_id(CAMPAIGN_SEED),
        state: CampaignMemberState::Enrolled,
        channels: vec![CampaignMemberChannel {
            channel: CHANNEL.to_owned(),
            basis_evidence: test_id(BASIS_SEED),
            sender_ref: test_id(SENDER_SEED),
        }],
        derivation: Some(CampaignMemberDerivation {
            source_query: test_id(QUERY_SEED),
            evidence_hash: [0x7C; 32],
            epoch: 3,
        }),
    }
}

fn put_member(vault: &Vault, claim_seed: u8, value: &CampaignMemberValue, subject: EntityId) {
    vault
        .put_claim(
            &test_id(claim_seed),
            &ClaimBody::new(
                PREDICATE_CAMPAIGN_MEMBER,
                ClaimSubject::Entity(subject),
                encode_campaign_member_value(value),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .unwrap();
}

fn webhook(
    disposition: EmailDeliveryDisposition,
    aggregate: EmailReputationWebhookSignal,
) -> CampaignEmailWebhookEvent {
    CampaignEmailWebhookEvent {
        identity_ref: test_id(SENDER_SEED),
        person_ref: test_id(PERSON_SEED),
        campaign_ref: Some(test_id(CAMPAIGN_SEED)),
        channel: CHANNEL.to_owned(),
        evidence_ref: test_id(EVIDENCE_SEED),
        disposition,
        aggregate,
        observed_at: 50,
    }
}

/// Every LIVE claim on `subject` carrying `predicate`, as decoded bodies.
fn live_claims(vault: &Vault, subject: EntityId, predicate: &str) -> Vec<ClaimBody> {
    vault
        .claims_for_subject(&subject)
        .unwrap()
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).unwrap())
        .filter(|body| {
            body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active
        })
        .collect()
}

fn only_live_claim(vault: &Vault, subject: EntityId, predicate: &str) -> ClaimBody {
    let mut claims = live_claims(vault, subject, predicate);
    assert_eq!(
        claims.len(),
        1,
        "expected exactly one live {predicate} head, found {}",
        claims.len()
    );
    claims.pop().unwrap()
}

fn unsubscribe_target() -> ListUnsubscribeTarget {
    ListUnsubscribeTarget {
        mailto_uri: Some(MAILTO_TARGET.to_owned()),
        https_one_click_uri: HTTPS_TARGET.to_owned(),
    }
}

/// One direct-pipeline send, optionally carrying a frozen unsubscribe target.
fn dispatch(
    vault: &Vault,
    actor: EntityId,
    channel: &str,
    intent_ref: &str,
    unsubscribe: Option<ListUnsubscribeTarget>,
    sink: &mut HeaderSink,
) -> oneiron::OutboundDispatchResult {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(actor.to_hex(), VERB, channel, COUNTERPARTY)
            .content_ref("content:send-hygiene-oracle"),
        OutboundIntentTrigger::agent_immediate("session:send-hygiene-oracle"),
    );
    let mut request = OutboundDispatchRequest::new(
        format!("outbound:{intent_ref}"),
        intent_ref,
        intent,
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref(COUNTERPARTY);
    if let Some(target) = unsubscribe {
        request = request.campaign_unsubscribe(target);
    }
    vault.dispatch_outbound_intent(request, sink).unwrap()
}

fn denies(reason_codes: &[String]) -> bool {
    reason_codes.iter().any(|code| code == DENY_OPT_OUT)
}

// ---------------------------------------------------------------------------
// Leg 1 — hard bounce suppresses in one write turn
// ---------------------------------------------------------------------------

#[test]
fn hard_bounce_writes_bounce_and_suppression_same_turn() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    put_member(&vault, MEMBER_SEED, &enrolled_member(), person);

    let projection = project_campaign_email_webhook(
        &vault,
        IdentityReputation::new(IdentityWarmupStage::Established, 10),
        &webhook(
            EmailDeliveryDisposition::HardBounce,
            EmailReputationWebhookSignal::new(950, 0, 50, false, 50),
        ),
        1_000,
    )?;

    let receipt = projection.suppression.expect("a hard bounce suppresses");
    assert!(receipt.bounce_claim_ref.is_some());
    assert!(receipt.member_claim_ref.is_some());

    // The bounce FACT, carrying the observing sender and the moment.
    let bounce = only_live_claim(&vault, person, PREDICATE_COMM_BOUNCE);
    assert_eq!(
        bounce.value,
        encode_comm_bounce_value(&CommBounceValue {
            channel: CHANNEL.to_owned(),
            bounce: BounceKind::Hard,
            sender_ref: test_id(SENDER_SEED),
            occurred_at: 50,
        })
    );
    assert!(bounce.evidence.is_some(), "a bounce must cite its webhook");

    // The channel-scoped enforcement suppression.
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_COMM_DO_NOT_CONTACT).value,
        encode_do_not_contact_value(&CommDoNotContactValue {
            channel: Some(CHANNEL.to_owned()),
            scope: DO_NOT_CONTACT_SCOPE_ALL.to_owned(),
        })
    );

    // The membership, suppressed but otherwise INTACT: the channel rows (each
    // with its consent basis and sticky sender) and the derivation survive.
    // Suppression removes someone from a cohort; it does not erase how they got
    // there or what authorized contacting them.
    let expected = CampaignMemberValue {
        state: CampaignMemberState::Suppressed,
        ..enrolled_member()
    };
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER).value,
        encode_campaign_member_value(&expected)
    );
    Ok(())
}

/// The "same turn" half of the law, measured the only way it can be: make the
/// LAST leg fail and prove the earlier legs are not on disk.
///
/// Two live member heads for one campaign is a torn cohort the membership leg
/// rejects. If the three legs were three transactions, the bounce fact and the
/// suppression would have committed before that rejection — and the person
/// would be left permanently suppressed by a write turn that reported failure.
#[test]
fn hard_bounce_suppression_rolls_back_whole() {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    put_member(&vault, MEMBER_SEED, &enrolled_member(), person);
    put_member(&vault, SECOND_MEMBER_SEED, &enrolled_member(), person);

    let error = apply_suppression(
        &vault,
        SuppressionCause::HardBounce,
        &SuppressionInput {
            person_ref: person,
            campaign_ref: Some(test_id(CAMPAIGN_SEED)),
            channel: CHANNEL.to_owned(),
            sender_ref: Some(test_id(SENDER_SEED)),
            evidence_ref: test_id(EVIDENCE_SEED),
            occurred_at: 50,
        },
    );

    assert!(error.is_err(), "a torn cohort must reject the write turn");
    assert!(live_claims(&vault, person, PREDICATE_COMM_BOUNCE).is_empty());
    assert!(live_claims(&vault, person, PREDICATE_COMM_DO_NOT_CONTACT).is_empty());
}

// ---------------------------------------------------------------------------
// Leg 1b — soft bounce is health only
// ---------------------------------------------------------------------------

#[test]
fn soft_bounce_updates_health_without_permanent_suppression() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    put_member(&vault, MEMBER_SEED, &enrolled_member(), person);
    let baseline = IdentityReputation::new(IdentityWarmupStage::Established, 10);

    let projection = project_campaign_email_webhook(
        &vault,
        baseline.clone(),
        &webhook(
            EmailDeliveryDisposition::SoftBounce,
            EmailReputationWebhookSignal::new(950, 0, 50, false, 50),
        ),
        1_000,
    )?;

    // Health moved, and moved the clamp with it.
    assert!(projection.suppression.is_none());
    assert_eq!(projection.reputation.bounce_rate, 0.05);
    assert_eq!(
        projection.reputation.status(),
        IdentityReputationStatus::Degraded
    );
    assert_eq!(
        projection.clamp.effective_daily_cap,
        DEGRADED_REPUTATION_DAILY_CAP
    );
    assert_ne!(
        projection.reputation.claim_bodies(test_id(SENDER_SEED)),
        baseline.claim_bodies(test_id(SENDER_SEED))
    );

    // Nothing permanent: no suppression claim, and the cohort row is untouched.
    assert!(live_claims(&vault, person, PREDICATE_COMM_DO_NOT_CONTACT).is_empty());
    assert!(live_claims(&vault, person, PREDICATE_COMM_BOUNCE).is_empty());
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER).value,
        encode_campaign_member_value(&enrolled_member())
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Leg 3 — unsubscribe is honored before the handler returns
// ---------------------------------------------------------------------------

#[test]
fn unsubscribe_is_honored_before_handler_returns() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let actor = test_id(PERSON_SEED);
    let mut sink = HeaderSink::default();

    // Control: this send is not denied for opt-out before the unsubscribe.
    let control = dispatch(&vault, actor, CHANNEL, "intent:control", None, &mut sink);
    assert!(!denies(&control.gate_reason_codes));

    // The PERSON the gate resolves the counterparty to.
    let counterparty = oneiron::resolve_or_create_comm_party(&vault, COUNTERPARTY).unwrap();

    let receipt = apply_suppression(
        &vault,
        SuppressionCause::Unsubscribe,
        &SuppressionInput {
            person_ref: counterparty,
            campaign_ref: None,
            channel: CHANNEL.to_owned(),
            sender_ref: None,
            evidence_ref: test_id(EVIDENCE_SEED),
            occurred_at: 60,
        },
    )?;
    assert!(
        receipt.bounce_claim_ref.is_none(),
        "an unsubscribe is not a bounce"
    );
    assert!(
        receipt.member_claim_ref.is_none(),
        "an inbound signal naming no campaign supersedes no membership; the \
         campaign-independent suppression is what refuses the send"
    );
    // The enforcement claim cites the inbound evidence it derives from, so the
    // suppression and its reason landed together rather than the claim landing
    // alone.
    let head = vault.get_claim(&receipt.do_not_contact_claim_ref)?.unwrap();
    assert!(head.evidence.is_some());
    assert_eq!(head.lifecycle, ClaimLifecycleStatus::Active);

    // No projector ran, no timer fired, no queue was drained between the call
    // above and the send below. The very next attempt is refused.
    let denied = dispatch(&vault, actor, CHANNEL, "intent:unsub", None, &mut sink);
    assert_eq!(denied.gate_outcome, "deny");
    assert!(denies(&denied.gate_reason_codes));
    assert!(sink.calls.is_empty());

    // Staleness never un-suppresses: a head whose validity window closed long
    // ago, and a head that was never approved, both still refuse the send.
    clear_do_not_contact(&vault, counterparty, 70);
    write_raw_do_not_contact(
        &vault,
        STALE_DNC_SEED,
        counterparty,
        ClaimApprovalStatus::Approved,
        Some(5),
    )?;
    let stale = dispatch(&vault, actor, CHANNEL, "intent:stale", None, &mut sink);
    assert!(denies(&stale.gate_reason_codes));

    clear_do_not_contact(&vault, counterparty, 71);
    write_raw_do_not_contact(
        &vault,
        PROPOSED_DNC_SEED,
        counterparty,
        ClaimApprovalStatus::Proposed,
        None,
    )?;
    let proposed = dispatch(&vault, actor, CHANNEL, "intent:proposed", None, &mut sink);
    assert!(denies(&proposed.gate_reason_codes));

    // Only an authorized lifecycle stamp clears it. Nothing else in this test
    // touched the head, and nothing else could have.
    clear_do_not_contact(&vault, counterparty, 80);
    let cleared = dispatch(&vault, actor, CHANNEL, "intent:cleared", None, &mut sink);
    assert!(!denies(&cleared.gate_reason_codes));
    Ok(())
}

/// A `comm.do_not_contact` head written straight through the claim door, so the
/// approval state and the validity window can be posed independently of the
/// suppression writer.
fn write_raw_do_not_contact(
    vault: &Vault,
    seed: u8,
    subject: EntityId,
    approval: ClaimApprovalStatus,
    valid_to: Option<u64>,
) -> Result<()> {
    let mut body = ClaimBody::new(
        PREDICATE_COMM_DO_NOT_CONTACT,
        ClaimSubject::Entity(subject),
        encode_do_not_contact_value(&CommDoNotContactValue {
            channel: Some(CHANNEL.to_owned()),
            scope: DO_NOT_CONTACT_SCOPE_ALL.to_owned(),
        }),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    );
    body.valid_to = valid_to;
    vault.put_claim(&test_id(seed), &body, TimeRange { start: 1, end: 1 }, 1)
}

/// Retracts every live suppression head on `subject` — the authorized clear.
fn clear_do_not_contact(vault: &Vault, subject: EntityId, now: u64) {
    for id in vault.claims_for_subject(&subject).unwrap() {
        let Some(body) = vault.get_claim(&id).unwrap() else {
            continue;
        };
        if body.predicate == PREDICATE_COMM_DO_NOT_CONTACT
            && body.lifecycle == ClaimLifecycleStatus::Active
        {
            vault.retract_claim(&id, now).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Leg 2 — List-Unsubscribe at the payload-assembly seam
// ---------------------------------------------------------------------------

#[test]
fn campaign_email_payload_contains_rfc8058_headers() {
    let (_dir, vault, actor) = sending_vault();
    let mut sink = HeaderSink::default();

    dispatch(
        &vault,
        actor,
        CHANNEL,
        "intent:email",
        Some(unsubscribe_target()),
        &mut sink,
    );
    assert_eq!(
        sink.calls,
        vec![vec![
            (
                LIST_UNSUBSCRIBE.to_owned(),
                format!("<{HTTPS_TARGET}>, <{MAILTO_TARGET}>"),
            ),
            (
                LIST_UNSUBSCRIBE_POST.to_owned(),
                LIST_UNSUBSCRIBE_POST_ONE_CLICK.to_owned(),
            ),
        ]],
        "an email campaign send carries exactly the two RFC 8058 headers"
    );

    // Same frozen target, non-email channel: no headers at all. The unsubscribe
    // header set is an email surface, not a general send decoration.
    let mut other = HeaderSink::default();
    dispatch(
        &vault,
        actor,
        OTHER_CHANNEL,
        "intent:telegram",
        Some(unsubscribe_target()),
        &mut other,
    );
    assert_eq!(other.calls, vec![Vec::new()]);
}

#[test]
fn retry_reuses_identical_unsubscribe_headers() {
    let (_dir, vault, actor) = sending_vault();

    // First attempt fails at the transport, leaving the intent replayable.
    let mut first = HeaderSink {
        fail: true,
        ..HeaderSink::default()
    };
    dispatch(
        &vault,
        actor,
        CHANNEL,
        "intent:retry",
        Some(unsubscribe_target()),
        &mut first,
    );
    assert_eq!(first.calls.len(), 1);
    assert_eq!(
        first.calls[0].len(),
        2,
        "the attempt under comparison must actually carry the headers"
    );

    // The replay re-freezes the same intent. That the ledger ACCEPTS it is
    // itself the determinism proof: the chokepoint rejects a new-effect replay
    // whose payload bytes differ, and the headers are part of those bytes.
    let mut second = HeaderSink::default();
    dispatch(
        &vault,
        actor,
        CHANNEL,
        "intent:retry",
        Some(unsubscribe_target()),
        &mut second,
    );

    assert_eq!(
        second.calls, first.calls,
        "a retry must reproduce header names, values, and ordering byte for byte"
    );
}

#[test]
fn unsubscribe_headers_are_deterministic_and_framed() -> Result<()> {
    let target = unsubscribe_target();
    assert_eq!(
        list_unsubscribe_headers(&target)?,
        list_unsubscribe_headers(&target)?
    );

    // The mailto is optional; the one-click HTTPS target is not.
    let https_only = ListUnsubscribeTarget {
        mailto_uri: None,
        https_one_click_uri: HTTPS_TARGET.to_owned(),
    };
    assert_eq!(
        list_unsubscribe_headers(&https_only)?.get(LIST_UNSUBSCRIBE),
        Some(&format!("<{HTTPS_TARGET}>"))
    );

    // A target that could rewrite the header around its own framing is refused
    // rather than emitted.
    for hostile in [
        "http://example.com/u",
        "https://example.com/u>, <mailto:evil@example.com",
        "https://example.com/u\r\nBcc: evil@example.com",
    ] {
        assert!(
            list_unsubscribe_headers(&ListUnsubscribeTarget {
                mailto_uri: None,
                https_one_click_uri: hostile.to_owned(),
            })
            .is_err(),
            "{hostile} must not reach a header"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Leg 4 — sender health and sticky sender
// ---------------------------------------------------------------------------

#[test]
fn sender_health_uses_existing_boundary_constants() -> Result<()> {
    // The four live thresholds, unretuned.
    assert_eq!(BOUNCE_CONSTRAINED_THRESHOLD, 0.02);
    assert_eq!(BOUNCE_DEGRADED_THRESHOLD, 0.05);
    assert_eq!(COMPLAINT_CONSTRAINED_THRESHOLD, 0.002);
    assert_eq!(COMPLAINT_DEGRADED_THRESHOLD, 0.005);

    // Exactly ON each boundary, which is where a `>` typo hides.
    assert_eq!(
        status_for(EmailReputationWebhookSignal::new(980, 0, 20, false, 20))?,
        IdentityReputationStatus::Constrained
    );
    assert_eq!(
        status_for(EmailReputationWebhookSignal::new(950, 0, 50, false, 20))?,
        IdentityReputationStatus::Degraded
    );
    assert_eq!(
        status_for(EmailReputationWebhookSignal::new(1_000, 2, 0, false, 20))?,
        IdentityReputationStatus::Constrained
    );
    assert_eq!(
        status_for(EmailReputationWebhookSignal::new(1_000, 5, 0, false, 20))?,
        IdentityReputationStatus::Degraded
    );

    // ARCH-0059's 0.3% complaint bench is REPRESENTED by the constrained tier,
    // not by a fifth constant.
    assert_eq!(
        status_for(EmailReputationWebhookSignal::new(1_000, 3, 0, false, 20))?,
        IdentityReputationStatus::Constrained
    );
    Ok(())
}

fn status_for(signal: EmailReputationWebhookSignal) -> Result<IdentityReputationStatus> {
    let mut reputation = IdentityReputation::new(IdentityWarmupStage::Established, 10);
    reputation.apply_adapter_signal(IdentityReputationSignal::EmailWebhook(signal))?;
    Ok(reputation.status())
}

#[test]
fn degraded_identity_clamps_and_rest_reenters_warmup() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let identity = test_id(SENDER_SEED);
    put_member(
        &vault,
        MEMBER_SEED,
        &enrolled_member(),
        test_id(PERSON_SEED),
    );

    // Degraded: the existing clamp cuts the cap and asks for a rotation ruling.
    let projection = project_campaign_email_webhook(
        &vault,
        IdentityReputation::new(IdentityWarmupStage::Established, 10),
        &webhook(
            EmailDeliveryDisposition::Complaint,
            EmailReputationWebhookSignal::new(1_000, 5, 0, false, 20),
        ),
        1_000,
    )?;
    assert_eq!(
        projection.clamp.effective_daily_cap,
        DEGRADED_REPUTATION_DAILY_CAP
    );
    assert!(projection.clamp.rotate_proposal_required);
    assert!(
        projection.suppression.is_none(),
        "a complaint is a reputation fact, not a permanent suppression"
    );

    // No parallel health state machine: the projection's clamp IS the existing
    // per-identity clamp, not a second computation that can disagree with it.
    assert_eq!(
        projection.clamp,
        projection.reputation.clamp_send_rate(identity, 1_000)
    );

    // Rest: the warm-up stage ladder is what cuts to zero and what re-ramps.
    let mut rested = projection.reputation;
    rested.apply_adapter_signal(IdentityReputationSignal::WarmupStage {
        stage: IdentityWarmupStage::Paused,
        observed_at: 30,
    })?;
    assert_eq!(
        rested.clamp_send_rate(identity, 1_000).effective_daily_cap,
        0
    );

    rested.apply_adapter_signal(IdentityReputationSignal::WarmupStage {
        stage: IdentityWarmupStage::Warming,
        observed_at: 40,
    })?;
    // Re-ramping does not clear a degraded reputation: the health cap still
    // binds until the counters themselves recover.
    assert_eq!(
        rested.clamp_send_rate(identity, 1_000).effective_daily_cap,
        DEGRADED_REPUTATION_DAILY_CAP
    );

    rested.apply_adapter_signal(IdentityReputationSignal::EmailWebhook(
        EmailReputationWebhookSignal::new(1_000, 0, 0, false, 50),
    ))?;
    assert_eq!(
        rested.clamp_send_rate(identity, 1_000).effective_daily_cap,
        WARMUP_WARMING_DAILY_CAP
    );
    Ok(())
}

#[test]
fn sticky_sender_is_reused_for_followups() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    let campaign = test_id(CAMPAIGN_SEED);
    put_member(&vault, MEMBER_SEED, &enrolled_member(), person);

    // A healthier sender is proposed for a channel that already has one. The
    // stored binding wins: re-picking per touch is the deliverability problem,
    // not the fix.
    assert_eq!(
        bind_sticky_sender(
            &vault,
            person,
            campaign,
            CHANNEL,
            test_id(OTHER_SENDER_SEED),
            true,
            test_id(BASIS_SEED),
            70,
        )?,
        StickySenderOutcome::Reused {
            sender_ref: test_id(SENDER_SEED)
        }
    );
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER).value,
        encode_campaign_member_value(&enrolled_member()),
        "a reuse writes nothing"
    );

    // First touch on a NEW channel binds, and leaves the existing row alone.
    assert_eq!(
        bind_sticky_sender(
            &vault,
            person,
            campaign,
            OTHER_CHANNEL,
            test_id(THIRD_SENDER_SEED),
            true,
            test_id(SECOND_BASIS_SEED),
            80,
        )?,
        StickySenderOutcome::Bound {
            sender_ref: test_id(THIRD_SENDER_SEED)
        }
    );
    let mut expected = enrolled_member();
    expected.channels.push(CampaignMemberChannel {
        channel: OTHER_CHANNEL.to_owned(),
        basis_evidence: test_id(SECOND_BASIS_SEED),
        sender_ref: test_id(THIRD_SENDER_SEED),
    });
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER).value,
        encode_campaign_member_value(&expected)
    );

    // And the freshly bound row is sticky too.
    assert_eq!(
        bind_sticky_sender(
            &vault,
            person,
            campaign,
            OTHER_CHANNEL,
            test_id(OTHER_SENDER_SEED),
            true,
            test_id(SECOND_BASIS_SEED),
            90,
        )?,
        StickySenderOutcome::Reused {
            sender_ref: test_id(THIRD_SENDER_SEED)
        }
    );
    Ok(())
}

#[test]
fn dead_sticky_sender_requires_visible_restart() -> Result<()> {
    let (_dir, vault) = oracle_vault();
    let person = test_id(PERSON_SEED);
    put_member(&vault, MEMBER_SEED, &enrolled_member(), person);

    assert_eq!(
        bind_sticky_sender(
            &vault,
            person,
            test_id(CAMPAIGN_SEED),
            CHANNEL,
            test_id(OTHER_SENDER_SEED),
            false,
            test_id(BASIS_SEED),
            70,
        )?,
        StickySenderOutcome::RestartRequired {
            previous_sender_ref: test_id(SENDER_SEED),
            proposed_sender_ref: test_id(OTHER_SENDER_SEED),
        }
    );
    // A dead mailbox is a result a human reads, not a rotation that already
    // happened: the stored binding is exactly as it was.
    assert_eq!(
        only_live_claim(&vault, person, PREDICATE_CAMPAIGN_MEMBER).value,
        encode_campaign_member_value(&enrolled_member())
    );
    Ok(())
}
