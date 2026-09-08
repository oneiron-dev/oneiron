//! Opt-out posture, override receipts, and the posture dial.

use super::*;

/// The manifest every ONE-1752 opt-out fixture below evaluates against: one
/// scoped grant for `sender` on `line`, plus whatever posture entry the caller
/// wants.
fn opt_out_posture_manifest(posture: Option<&str>) -> Vec<u8> {
    let mut entries = vec![external_effect_scoped_grant_entry(
        "sender",
        "send",
        Value::Map(vec![
            (
                Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                Value::from("line"),
            ),
            (
                Value::from(EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY),
                Value::from(ExternalEffectPolicyRisk::Normal.as_str()),
            ),
        ]),
        None,
    )];
    if let Some(posture) = posture {
        entries.push((
            Value::from(POLICY_COMM_OPT_OUT_POSTURE_KEY),
            Value::from(posture),
        ));
    }
    encode_policy_manifest(entries)
}

/// An opted-out contact for `counterparty`, written through the redirected
/// contact writers so the claim heads — not a hand-placed row — are the truth
/// the gate hydrates.
fn opted_out_contact(
    vault: &crate::Vault,
    identity: EntityId,
    contact_id: EntityId,
    counterparty: &str,
    reason: CounterpartyOptOutReason,
) -> Result<()> {
    let contact = CounterpartyContactRecord::user_introduction(identity, counterparty, 10)?;
    vault.create_counterparty_contact(&contact_id, &contact)?;
    vault.opt_out_counterparty_contact(&contact_id, reason, 20)?;
    Ok(())
}

/// A bound human, the only actor class that may rule on a send override.
fn owner_actor(vault: &crate::Vault, seed: u8) -> Result<WriteActor> {
    let owner = test_id(seed);
    vault.put_entity(
        &owner,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    Ok(WriteActor::new(owner, EdgeActorClass::Human))
}

/// ARCH-0057 §3.1, end to end on the full hydration path: an opted-out
/// counterparty HOLDS the send for the owner, the owner rules with
/// `mint_send_override`, and the resubmitted send is allowed and says so.
///
/// The owner-facing deny is never emitted.
#[test]
fn gate_opt_out_escalates_never_denies_owner() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xE5), &opt_out_posture_manifest(None))?;
    let policy = resolve(&vault)?;
    assert_eq!(policy.comm_opt_out_posture(), CommOptOutPosture::Escalate);

    opted_out_contact(
        &vault,
        test_id(0xE6),
        test_id(0xE7),
        "kenji@example.com",
        CounterpartyOptOutReason::Stop,
    )?;

    // No channel identity: the shipping constructors leave it None, so this is
    // the real hydration path (party-channel index plus mandatory full scan).
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.counterparty = Some("kenji@example.com".to_owned());
    effect.send_ref = Some("intent:kenji:1".to_owned());

    let (_decision_id, held, _charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(held.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&held),
        vec!["gate.pending.counterparty_opt_out"]
    );
    assert!(
        !gate_reason_strs(&held).contains(&GateReasonCode::DenyCounterpartyOptOut.as_str()),
        "the owner path must never see the deny"
    );
    assert_eq!(
        held.receipt_reasons(),
        &[
            "counterparty_opt_out_stop",
            "counterparty_first_touch_user_introduction"
        ]
    );

    // The decision is recorded as the pending owner ask the dispatch path holds
    // on. (`outbound::tests` pins the Held/Pending dispatch outcome itself.)
    let decisions = vault.store.gate_decisions(10)?;
    let held_record = decisions
        .iter()
        .find(|record| record.reason_codes == vec!["gate.pending.counterparty_opt_out"])
        .expect("the pending opt-out decision is recorded");
    assert_eq!(held_record.outcome, "pending");

    // The owner rules. The channel is minted mixed-case and padded on purpose:
    // mint and hydration share one normalizer, so it still covers `line`.
    let owner = owner_actor(&vault, 0xE8)?;
    crate::comm::mint_send_override(
        &vault,
        "kenji@example.com",
        Some(" LINE "),
        crate::comm::SendOverrideScope::Standing,
        None,
        owner,
        30,
        None,
    )
    .expect("the owner may rule on a send override");

    // The caller resubmits the SAME send.
    let (_decision_id, allowed, _charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(allowed.outcome(), GateOutcome::Allow);
    assert!(
        allowed
            .receipt_reasons()
            .contains(&"comm_send_override_standing"),
        "the allow must name the override that decided it: {:?}",
        allowed.receipt_reasons()
    );
    // The override authorized a send; it cleared nothing.
    let contact = vault
        .get_counterparty_contact(&test_id(0xE7))?
        .expect("contact row");
    assert!(contact.is_opted_out());
    Ok(())
}

/// The receipt names exactly ONE override source — never both, and never one
/// when no override decided the send.
#[test]
fn override_receipt_is_source_specific() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xEA), &opt_out_posture_manifest(None))?;
    let policy = resolve(&vault)?;
    opted_out_contact(
        &vault,
        test_id(0xEB),
        test_id(0xEC),
        "mika@example.com",
        CounterpartyOptOutReason::Unsubscribe,
    )?;

    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.counterparty = Some("mika@example.com".to_owned());
    effect.send_ref = Some("intent:mika:1".to_owned());

    let owner = owner_actor(&vault, 0xED)?;
    crate::comm::mint_send_override(
        &vault,
        "mika@example.com",
        Some("line"),
        crate::comm::SendOverrideScope::OneShot,
        Some("intent:mika:1"),
        owner,
        30,
        Some(u64::MAX),
    )
    .expect("the owner may rule on a send override");
    let (_decision_id, one_shot, _charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(one_shot.outcome(), GateOutcome::Allow);
    assert_eq!(
        override_tokens(&one_shot),
        vec!["comm_send_override_one_shot"]
    );
    // The chained sources are RETAINED, not replaced.
    assert!(
        one_shot
            .receipt_reasons()
            .contains(&"counterparty_opt_out_unsubscribe")
    );
    assert!(
        one_shot
            .receipt_reasons()
            .contains(&"counterparty_first_touch_user_introduction")
    );

    // A standing head now also covers this send. Standing wins, and the receipt
    // still names exactly one source.
    crate::comm::mint_send_override(
        &vault,
        "mika@example.com",
        None,
        crate::comm::SendOverrideScope::Standing,
        None,
        owner,
        31,
        None,
    )
    .expect("the owner may rule on a send override");
    let (_decision_id, standing, _charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(
        override_tokens(&standing),
        vec!["comm_send_override_standing"]
    );

    // A posture-`allow_with_receipt` send with no override at all carries
    // neither token.
    let (_other_tmp, other_vault) = temp_vault();
    put_policy_manifest_bytes(
        &other_vault,
        test_id(0xEE),
        &opt_out_posture_manifest(Some("allow_with_receipt")),
    )?;
    let other_policy = resolve(&other_vault)?;
    opted_out_contact(
        &other_vault,
        test_id(0xEB),
        test_id(0xEC),
        "mika@example.com",
        CounterpartyOptOutReason::Unsubscribe,
    )?;
    let (_decision_id, plain, _charge) = other_vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&other_vault.store, wtxn, &effect, &other_policy, true)
    })?;
    assert_eq!(plain.outcome(), GateOutcome::Allow);
    assert!(override_tokens(&plain).is_empty());
    assert!(
        plain
            .receipt_reasons()
            .contains(&"counterparty_opt_out_unsubscribe"),
        "allow_with_receipt keeps the opt-out trail: {:?}",
        plain.receipt_reasons()
    );
    Ok(())
}

/// The override tokens one decision carries, in receipt order.
fn override_tokens(decision: &GateDecision) -> Vec<&'static str> {
    decision
        .receipt_reasons()
        .iter()
        .copied()
        .filter(|reason| reason.starts_with("comm_send_override_"))
        .collect()
}

/// The DEC-0005 posture dial: default, effect, composition, and parse failure.
#[test]
fn posture_dial_allow_with_receipt() -> Result<()> {
    // Absent everywhere resolves to the restrictive pole.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xF0), &opt_out_posture_manifest(None))?;
    assert_eq!(
        resolve(&vault)?.comm_opt_out_posture(),
        CommOptOutPosture::Escalate
    );

    // One pack saying `allow_with_receipt` sends immediately, keeping the trail.
    let (_allow_tmp, allow_vault) = temp_vault();
    put_policy_manifest_bytes(
        &allow_vault,
        test_id(0xF1),
        &opt_out_posture_manifest(Some("allow_with_receipt")),
    )?;
    let allow_policy = resolve(&allow_vault)?;
    assert_eq!(
        allow_policy.comm_opt_out_posture(),
        CommOptOutPosture::AllowWithReceipt
    );
    opted_out_contact(
        &allow_vault,
        test_id(0xF2),
        test_id(0xF3),
        "kenji@example.com",
        CounterpartyOptOutReason::BlockOrFriendRemoval,
    )?;
    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.counterparty = Some("kenji@example.com".to_owned());
    let (_decision_id, decision, _charge) = allow_vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&allow_vault.store, wtxn, &effect, &allow_policy, true)
    })?;
    assert_eq!(decision.outcome(), GateOutcome::Allow);
    assert_eq!(
        decision.receipt_reasons(),
        &[
            "counterparty_opt_out_block_or_friend_removal",
            "counterparty_first_touch_user_introduction"
        ]
    );

    // An unrecognized token fails the manifest closed, in the same class as an
    // invalid `on_budget_exhausted` token.
    let (_bad_tmp, bad_vault) = temp_vault();
    put_policy_manifest_bytes(
        &bad_vault,
        test_id(0xF4),
        &opt_out_posture_manifest(Some("allow")),
    )?;
    let bad_policy = resolve(&bad_vault)?;
    assert!(bad_policy.diagnostics().malformed_manifest_seen);
    assert!(bad_policy.is_fail_closed());
    assert_eq!(
        bad_policy.comm_opt_out_posture(),
        CommOptOutPosture::Escalate
    );

    // Composition is restrictive: one `escalate` pack wins over an
    // `allow_with_receipt` one.
    let (_mixed_tmp, mixed_vault) = temp_vault();
    put_policy_manifest_bytes(
        &mixed_vault,
        test_id(0xF5),
        &opt_out_posture_manifest(Some("allow_with_receipt")),
    )?;
    put_policy_manifest_bytes(
        &mixed_vault,
        test_id(0xF6),
        &opt_out_posture_manifest(Some("escalate")),
    )?;
    let mixed_policy = resolve(&mixed_vault)?;
    assert!(!mixed_policy.diagnostics().malformed_manifest_seen);
    assert_eq!(
        mixed_policy.comm_opt_out_posture(),
        CommOptOutPosture::Escalate
    );
    Ok(())
}

/// The posture is frontier state: flipping it moves `read_frontier_hash`, so
/// every consent binding taken under the old posture — a standing outbound
/// grant's included — stops matching.
#[test]
fn posture_flip_moves_frontier_hash() -> Result<()> {
    let (_escalate_tmp, escalate_vault) = temp_vault();
    put_policy_manifest_bytes(
        &escalate_vault,
        test_id(0xF7),
        &opt_out_posture_manifest(Some("escalate")),
    )?;
    let escalate_policy = resolve(&escalate_vault)?;

    let (_allow_tmp, allow_vault) = temp_vault();
    put_policy_manifest_bytes(
        &allow_vault,
        test_id(0xF7),
        &opt_out_posture_manifest(Some("allow_with_receipt")),
    )?;
    let allow_policy = resolve(&allow_vault)?;

    assert_ne!(
        escalate_policy.read_frontier_hash()?,
        allow_policy.read_frontier_hash()?
    );

    // The binding a standing outbound grant is minted under is that same
    // frontier, so a grant minted under one posture is not active under the
    // other.
    let intent = GrantMintIntent {
        principal_ref: "sender".to_owned(),
        origin_component_id: "ask-1".to_owned(),
        origin_action_id: "escalate_always_this_verb_class".to_owned(),
        origin_receipt_ref: Some("gate:ask-1".to_owned()),
        scope: GrantMintIntentScope::VerbClass {
            verb_class: "send".to_owned(),
        },
    };
    let (escalate_handle, escalate_frontier) =
        standing_outbound_grant_binding_parts(&intent, &escalate_policy)?;
    let (allow_handle, allow_frontier) =
        standing_outbound_grant_binding_parts(&intent, &allow_policy)?;
    assert_eq!(
        escalate_handle, allow_handle,
        "the grant itself is identical; only the policy floor moved"
    );
    assert_ne!(escalate_frontier, allow_frontier);
    Ok(())
}

/// ONE-1868's fold is untouched: ONE-1752 changed what the folded bit DOES, not
/// which sources set it.
#[test]
fn dnc_and_132_fold_unchanged() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0xB0), &opt_out_posture_manifest(None))?;
    let policy = resolve(&vault)?;

    let mut effect = external_effect_gate_input("sender", "send", "line");
    effect.counterparty = Some("kenji@example.com".to_owned());

    // Control: nothing suppresses this send.
    let (_decision_id, control, _charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(control.outcome(), GateOutcome::Allow);

    // Leg 1 — the type-132 full-scan fallback. This contact's identity resolves
    // to no ChannelIdentity row, so the party-channel index never learned it and
    // only the mandatory scan can find it.
    opted_out_contact(
        &vault,
        test_id(0xB1),
        test_id(0xB2),
        "kenji@example.com",
        CounterpartyOptOutReason::Stop,
    )?;
    let (_decision_id, folded, _charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(folded.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&folded),
        vec!["gate.pending.counterparty_opt_out"]
    );

    // A SECOND contact for the same party that is not opted out cannot clear the
    // first: the aggregate is restrictive.
    let clean =
        CounterpartyContactRecord::user_introduction(test_id(0xB3), "kenji@example.com", 10)?;
    vault.create_counterparty_contact(&test_id(0xB4), &clean)?;
    let (_decision_id, still_folded, _charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &effect, &policy, true)
    })?;
    assert_eq!(still_folded.outcome(), GateOutcome::Pending);

    // Leg 2 — CA-01's `comm.do_not_contact`, on a party with no contact row at
    // all, and a caller-asserted bit that hydration may never clear.
    let mut other = external_effect_gate_input("sender", "send", "line");
    other.counterparty = Some("mika@example.com".to_owned());
    let party = crate::comm::resolve_or_create_comm_party(&vault, "mika@example.com")
        .map_err(|_| Error::InvalidClaimBody("comm party"))?;
    let mut dnc = ClaimBody::new(
        crate::campaign::claims::PREDICATE_COMM_DO_NOT_CONTACT,
        ClaimSubject::Entity(party),
        Value::Map(vec![(
            Value::from("scope"),
            Value::from(crate::campaign::claims::DO_NOT_CONTACT_SCOPE_ALL),
        )]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    dnc.valid_from = Some(1);
    vault.put_claim(&test_id(0xB5), &dnc, TimeRange { start: 1, end: 1 }, 1)?;
    let (_decision_id, dnc_folded, _charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &other, &policy, true)
    })?;
    assert_eq!(dnc_folded.outcome(), GateOutcome::Pending);
    assert_eq!(
        gate_reason_strs(&dnc_folded),
        vec!["gate.pending.counterparty_opt_out"]
    );
    assert_eq!(
        dnc_folded.receipt_reasons(),
        &["counterparty_opt_out_do_not_contact"]
    );

    // A caller-asserted bit for a party with no head at all still stands.
    let mut prehydrated = external_effect_gate_input("sender", "send", "line");
    prehydrated.counterparty = Some("nobody@example.com".to_owned());
    prehydrated.counterparty_opted_out = true;
    let (_decision_id, kept, _charge) = vault.with_write_txn(|wtxn| {
        check_external_effect_policy(&vault.store, wtxn, &prehydrated, &policy, true)
    })?;
    assert_eq!(kept.outcome(), GateOutcome::Pending);
    Ok(())
}
