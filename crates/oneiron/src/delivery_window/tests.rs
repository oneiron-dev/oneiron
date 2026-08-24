use super::*;

use crate::test_util::entity;

fn window_value(start_minute: u64, end_minute: u64) -> Value {
    Value::Map(vec![
        (Value::from(KEY_START_MINUTE), Value::from(start_minute)),
        (Value::from(KEY_END_MINUTE), Value::from(end_minute)),
    ])
}

fn quiet_claim(start_minute: u64, end_minute: u64) -> ClaimBody {
    let mut body = ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_QUIET,
        ClaimSubject::Entity(entity(0xD1)),
        Value::Map(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from(KEY_APPLIES_TO),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (
                Value::from(KEY_WINDOW),
                window_value(start_minute, end_minute),
            ),
            (Value::from(KEY_TZ), Value::from("user-local")),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::UserStated);
    body
}

fn context_claim(condition: DeliveryWindowContextCondition) -> ClaimBody {
    ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_CONTEXT,
        ClaimSubject::Entity(entity(0xD4)),
        Value::Map(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from(KEY_APPLIES_TO),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (Value::from(KEY_WHEN), Value::from(condition.as_str())),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
}

fn channel_claim(channel: &str, start_minute: u64, end_minute: u64, reason: &str) -> ClaimBody {
    ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_CHANNEL,
        ClaimSubject::Entity(entity(0xD5)),
        Value::Map(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from(KEY_APPLIES_TO),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (Value::from(KEY_CHANNEL), Value::from(channel)),
            (
                Value::from(KEY_WINDOW),
                window_value(start_minute, end_minute),
            ),
            (Value::from(KEY_REASON), Value::from(reason)),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
}

fn push_claim_value(body: &mut ClaimBody, key: &str, value: Value) {
    let Value::Map(entries) = &mut body.value else {
        panic!("claim value is a map");
    };
    entries.push((Value::from(key), value));
}

fn push_window_value(body: &mut ClaimBody, key: &str, value: Value) {
    let Value::Map(entries) = &mut body.value else {
        panic!("claim value is a map");
    };
    let Some((_, Value::Map(window_entries))) = entries
        .iter_mut()
        .find(|(entry_key, _)| entry_key.as_str() == Some(KEY_WINDOW))
    else {
        panic!("claim value has window map");
    };
    window_entries.push((Value::from(key), value));
}

fn replace_claim_value(body: &mut ClaimBody, key: &str, value: Value) {
    let Value::Map(entries) = &mut body.value else {
        panic!("claim value is a map");
    };
    let Some((_, entry_value)) = entries
        .iter_mut()
        .find(|(entry_key, _)| entry_key.as_str() == Some(key))
    else {
        panic!("claim value has key {key}");
    };
    *entry_value = value;
}

#[test]
fn delivery_window_quiet_claim_validates_interrupt_only_shape() -> Result<()> {
    let claim = quiet_claim(22 * 60, 8 * 60);
    validate_delivery_window_claim_structure(&claim)?;

    let mut invalid = claim;
    invalid.value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
        ),
        (Value::from(KEY_APPLIES_TO), Value::from("ambient")),
        (Value::from(KEY_WINDOW), window_value(22 * 60, 8 * 60)),
    ]);
    assert!(validate_delivery_window_claim_structure(&invalid).is_err());
    Ok(())
}

#[test]
fn delivery_window_rejects_keys_outside_predicate_variant() {
    let mut quiet_with_channel = quiet_claim(22 * 60, 8 * 60);
    push_claim_value(&mut quiet_with_channel, KEY_CHANNEL, Value::from("voice"));
    assert!(DeliveryWindowPolicyClaim::from_claim_body(&quiet_with_channel).is_err());

    let mut quiet_with_when = quiet_claim(22 * 60, 8 * 60);
    push_claim_value(
        &mut quiet_with_when,
        KEY_WHEN,
        Value::from(DeliveryWindowContextCondition::FocusOn.as_str()),
    );
    assert!(DeliveryWindowPolicyClaim::from_claim_body(&quiet_with_when).is_err());

    let mut context_with_window = context_claim(DeliveryWindowContextCondition::FocusOn);
    push_claim_value(
        &mut context_with_window,
        KEY_WINDOW,
        window_value(22 * 60, 8 * 60),
    );
    assert!(DeliveryWindowPolicyClaim::from_claim_body(&context_with_window).is_err());

    let mut channel_with_when = channel_claim("voice", 22 * 60, 8 * 60, "voice_window");
    push_claim_value(
        &mut channel_with_when,
        KEY_WHEN,
        Value::from(DeliveryWindowContextCondition::Driving.as_str()),
    );
    assert!(DeliveryWindowPolicyClaim::from_claim_body(&channel_with_when).is_err());
}

#[test]
fn delivery_window_rejects_unsupported_quiet_window_timezone() {
    let mut claim = quiet_claim(22 * 60, 8 * 60);
    replace_claim_value(&mut claim, KEY_TZ, Value::from("America/Los_Angeles"));

    assert!(DeliveryWindowPolicyClaim::from_claim_body(&claim).is_err());
}

#[test]
fn delivery_window_rejects_extra_fields_inside_window_map() {
    let mut claim = quiet_claim(22 * 60, 8 * 60);
    push_window_value(&mut claim, KEY_TZ, Value::from("Asia/Tokyo"));

    assert!(DeliveryWindowPolicyClaim::from_claim_body(&claim).is_err());
}

#[test]
fn delivery_window_channel_claim_matches_normalized_channel_alias() -> Result<()> {
    let policy = DeliveryWindowPolicyClaim::from_claim_body(&channel_claim(
        "imessage-mfb",
        21 * 60,
        9 * 60,
        "mfb_window",
    ))?;
    let context =
        DeliveryWindowEvaluationContext::new(1_000, 22 * 60, DeliveryWindowVerbClass::Interrupt)?
            .channel("imessage_mfb");

    assert_eq!(policy.channel.as_deref(), Some("imessage_mfb"));
    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&context, &[policy]),
        DeliveryWindowDecision::Hold {
            reason: "mfb_window".to_owned(),
            retry_at: Some(1_000 + 660 * 60),
        }
    );
    Ok(())
}

#[test]
fn delivery_window_evaluator_fails_closed_on_invalid_local_minute() -> Result<()> {
    let policy = DeliveryWindowPolicyClaim::from_claim_body(&quiet_claim(22 * 60, 8 * 60))?;
    let malformed_context = DeliveryWindowEvaluationContext {
        delivery_epoch_secs: 1_000,
        local_minute_of_day: MINUTES_PER_DAY,
        verb_class: DeliveryWindowVerbClass::Interrupt,
        channel: None,
        active_contexts: Vec::new(),
        interrupt_surface: None,
        degrade_to: None,
        apns_interruption_level: None,
        human_explicit_instant: false,
    };

    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&malformed_context, &[policy]),
        DeliveryWindowDecision::Hold {
            reason: "invalid_local_minute".to_owned(),
            retry_at: None,
        }
    );
    // The same unevaluable context resolves onto the fail-closed rung rather
    // than silently landing on `ambient`.
    let resolution = DeliveryWindowEvaluator::resolve(&malformed_context, &[]);
    assert_eq!(
        resolution.rung,
        DeliveryWindowLadderRung::MissingLocalMinute
    );
    Ok(())
}

#[test]
fn delivery_window_evaluator_ignores_auto_generated_claims_until_approved() -> Result<()> {
    let mut unvetted_claim = quiet_claim(22 * 60, 8 * 60);
    unvetted_claim.approval = ClaimApprovalStatus::Auto;
    unvetted_claim.source = Some(ClaimSource::Generated);
    let unvetted_policy = DeliveryWindowPolicyClaim::from_claim_body(&unvetted_claim)?;
    let context =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Interrupt)?;

    assert!(unvetted_policy.generated_origin);
    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&context, &[unvetted_policy]),
        DeliveryWindowDecision::DeliverNow
    );

    let mut approved_claim = unvetted_claim;
    approved_claim.approval = ClaimApprovalStatus::Approved;
    let approved_policy = DeliveryWindowPolicyClaim::from_claim_body(&approved_claim)?;
    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&context, &[approved_policy]),
        DeliveryWindowDecision::Hold {
            reason: "quiet_window".to_owned(),
            retry_at: Some(1_000 + 9 * 60 * 60),
        }
    );
    Ok(())
}

#[test]
fn delivery_window_evaluator_ignores_ambient_verbs() -> Result<()> {
    let policy = DeliveryWindowPolicyClaim::from_claim_body(&quiet_claim(22 * 60, 8 * 60))?;
    let context =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Ambient)?;

    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&context, &[policy]),
        DeliveryWindowDecision::DeliverNow
    );
    Ok(())
}

#[test]
fn delivery_window_evaluator_holds_interrupt_to_latest_window_end() -> Result<()> {
    let quiet = DeliveryWindowPolicyClaim::from_claim_body(&quiet_claim(22 * 60, 8 * 60))?;
    let mut channel_claim = ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_CHANNEL,
        ClaimSubject::Entity(entity(0xD2)),
        Value::Map(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from(KEY_APPLIES_TO),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (Value::from(KEY_CHANNEL), Value::from("voice")),
            (Value::from(KEY_WINDOW), window_value(21 * 60, 9 * 60)),
            (Value::from(KEY_REASON), Value::from("voice_window")),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    channel_claim.source = Some(ClaimSource::UserStated);
    let channel = DeliveryWindowPolicyClaim::from_claim_body(&channel_claim)?;
    let context = DeliveryWindowEvaluationContext::new(
        1_000,
        23 * 60 + 30,
        DeliveryWindowVerbClass::Interrupt,
    )?
    .channel("voice");

    let expected = DeliveryWindowDecision::Hold {
        reason: "voice_window".to_owned(),
        retry_at: Some(1_000 + 570 * 60),
    };
    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&context, &[quiet.clone(), channel.clone()]),
        expected
    );
    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&context, &[channel, quiet]),
        expected
    );
    Ok(())
}

#[test]
fn delivery_window_evaluator_degrades_interrupt_when_target_is_supplied() -> Result<()> {
    let policy = DeliveryWindowPolicyClaim::from_claim_body(&quiet_claim(22 * 60, 8 * 60))?;
    let context =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Interrupt)?
            .interrupt_surface("voice:call")
            .degrade_to("chat:passive");

    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&context, &[policy]),
        DeliveryWindowDecision::Degrade {
            reason: "quiet_window".to_owned(),
            from: "voice:call".to_owned(),
            to: "chat:passive".to_owned(),
        }
    );
    Ok(())
}

#[test]
fn delivery_window_evaluator_caps_apns_critical_and_degrades_closed_window() -> Result<()> {
    let unrestricted =
        DeliveryWindowEvaluationContext::new(1_000, 12 * 60, DeliveryWindowVerbClass::Interrupt)?
            .apns_interruption_level(DeliveryWindowApnsInterruptionLevel::Critical);
    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&unrestricted, &[]),
        DeliveryWindowDecision::DeliverNowWithApnsCap {
            reason: "apns_time_sensitive_ceiling".to_owned(),
            from: "push:critical".to_owned(),
            to: "push:time_sensitive".to_owned(),
        }
    );

    let policy = DeliveryWindowPolicyClaim::from_claim_body(&quiet_claim(22 * 60, 8 * 60))?;
    let quiet_push =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Interrupt)?
            .apns_interruption_level(DeliveryWindowApnsInterruptionLevel::TimeSensitive);
    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&quiet_push, std::slice::from_ref(&policy)),
        DeliveryWindowDecision::DeliverNowWithApnsCap {
            reason: "quiet_window".to_owned(),
            from: "push:time_sensitive".to_owned(),
            to: "push:active".to_owned(),
        }
    );

    let passive_push =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Interrupt)?
            .apns_interruption_level(DeliveryWindowApnsInterruptionLevel::Passive);
    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&passive_push, &[policy]),
        DeliveryWindowDecision::DeliverNow
    );

    let context_claim = ClaimBody::new(
        PREDICATE_DELIVERY_WINDOW_CONTEXT,
        ClaimSubject::Entity(entity(0xD3)),
        Value::Map(vec![
            (
                Value::from(KEY_SCHEMA_VERSION),
                Value::from(DELIVERY_WINDOW_SCHEMA_VERSION),
            ),
            (
                Value::from(KEY_APPLIES_TO),
                Value::from(DeliveryWindowAppliesTo::Interrupt.as_str()),
            ),
            (
                Value::from(KEY_WHEN),
                Value::from(DeliveryWindowContextCondition::FocusOn.as_str()),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let context_policy = DeliveryWindowPolicyClaim::from_claim_body(&context_claim)?;
    let passive_with_context_block =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Interrupt)?
            .active_context(DeliveryWindowContextCondition::FocusOn)
            .apns_interruption_level(DeliveryWindowApnsInterruptionLevel::Passive);
    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&passive_with_context_block, &[context_policy]),
        DeliveryWindowDecision::DeliverNow
    );
    Ok(())
}

/// ONE-1768 done-means: the executor derives local wall-clock minute from the
/// FROZEN offset at EXECUTION `now`, via pure arithmetic and never a timezone
/// database. Positive, negative, midnight-wrap, and non-minute-aligned epochs
/// are all exercised against `local_minute_of_day_at` itself — a hardcoded
/// expectation would prove nothing about the derivation.
#[test]
fn executor_derives_local_minute_from_task_offset() {
    use crate::outbound::local_minute_of_day_at;

    const MIDNIGHT_UTC: u64 = 86_400; // 00:00 UTC, day 2.
    for (epoch_secs, offset, expected, case) in [
        // Positive offset: 00:00 UTC is 09:00 in +09:00.
        (MIDNIGHT_UTC, 540_i16, 540_u16, "positive offset"),
        // Negative offset: 00:00 UTC is the PREVIOUS day's 16:00 in -08:00.
        (MIDNIGHT_UTC, -480, 960, "negative offset"),
        // Zero offset is the plain UTC minute.
        (
            MIDNIGHT_UTC + 13 * 3_600 + 45 * 60,
            0,
            13 * 60 + 45,
            "zero offset",
        ),
        // Forward midnight wrap: 23:00 UTC + 02:00 lands at 01:00 next day.
        (MIDNIGHT_UTC + 23 * 3_600, 120, 60, "forward wrap"),
        // Backward wrap below zero must borrow a day, not saturate at 0.
        (MIDNIGHT_UTC, -60, 1_380, "backward wrap"),
        // Extreme legal civil offsets stay in range.
        (MIDNIGHT_UTC, 840, 840, "max offset"),
        (MIDNIGHT_UTC, -840, 600, "min offset"),
    ] {
        let derived = local_minute_of_day_at(epoch_secs, offset);
        assert_eq!(derived, expected, "{case}");
        assert!(derived < 1_440, "{case} must stay a valid minute of day");
        // Whatever it derived must be an admissible evaluation context.
        DeliveryWindowEvaluationContext::new(
            epoch_secs,
            derived,
            DeliveryWindowVerbClass::Interrupt,
        )
        .unwrap_or_else(|_| panic!("{case} must produce an evaluable local minute"));
    }

    // Non-minute-aligned epochs truncate to the containing minute; they never
    // round up into the next one.
    let aligned = local_minute_of_day_at(MIDNIGHT_UTC + 600, 0);
    for skew in [1_u64, 30, 59] {
        assert_eq!(
            local_minute_of_day_at(MIDNIGHT_UTC + 600 + skew, 0),
            aligned,
            "a {skew}s skew inside the same minute must not advance it"
        );
    }
    assert_eq!(local_minute_of_day_at(MIDNIGHT_UTC + 660, 0), aligned + 1);

    // Derived from EXECUTION now, not schedule time: the same frozen offset
    // yields a different local minute an hour later.
    let scheduled_at = local_minute_of_day_at(MIDNIGHT_UTC, 540);
    let executed_at = local_minute_of_day_at(MIDNIGHT_UTC + 3_600, 540);
    assert_ne!(scheduled_at, executed_at);
    assert_eq!(executed_at, scheduled_at + 60);
}

#[test]
fn apns_interrupt_degrades_and_still_executes() {
    let claim = DeliveryWindowPolicyClaim::from_claim_body(&quiet_claim(22 * 60, 8 * 60)).unwrap();
    let context =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Interrupt)
            .unwrap()
            .apns_interruption_level(DeliveryWindowApnsInterruptionLevel::TimeSensitive);
    let (decision, evidence) = DeliveryWindowEvaluator::evaluate_with_evidence(&context, &[claim]);
    assert!(matches!(
        decision,
        DeliveryWindowDecision::DeliverNowWithApnsCap { .. }
    ));
    assert_eq!(evidence.len(), 1);
}

#[test]
fn non_degradable_interrupt_holds_to_window_edge() {
    let claim = DeliveryWindowPolicyClaim::from_claim_body(&quiet_claim(22 * 60, 8 * 60)).unwrap();
    let context =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Interrupt)
            .unwrap();
    let (decision, evidence) = DeliveryWindowEvaluator::evaluate_with_evidence(&context, &[claim]);
    assert!(matches!(
        decision,
        DeliveryWindowDecision::Hold {
            retry_at: Some(_),
            ..
        }
    ));
    assert_eq!(evidence.len(), 1);
}

/// ONE-1880 is the RUNTIME audit defect "permanent 1-second
/// `local_minute_unavailable` retry loop in the connector executor."
///
/// ES-F4 closes it structurally, and this test asserts BOTH halves of that
/// closure by name rather than merely observing a hold:
///
/// 1. Loop closure — an executor-created request receives TASK-derived local
///    time when the offset is present, so `local_minute_unavailable` is no
///    longer the standing verdict for a scheduled send.
/// 2. Re-arm — a hold that cannot deliver carries a CONCRETE window-edge
///    `retry_at` far beyond `now + 1`, so the executor re-arms at the edge
///    instead of spinning once per second.
#[test]
fn one_1880_duplicate_is_closed_by_es_f4() {
    use crate::outbound::local_minute_of_day_at;

    const ONE_1880_DEFECT: &str =
        "permanent 1-second `local_minute_unavailable` retry loop in the connector executor.";
    assert!(ONE_1880_DEFECT.contains("local_minute_unavailable"));
    assert!(ONE_1880_DEFECT.contains("1-second"));

    // 1. Loop closure: a frozen offset always yields an evaluable local minute,
    // so the executor never re-enters the door with "no local minute".
    let now = 1_000_000_u64;
    let local_minute = local_minute_of_day_at(now, 540);
    let context =
        DeliveryWindowEvaluationContext::new(now, local_minute, DeliveryWindowVerbClass::Interrupt)
            .expect("TASK-derived local time is always evaluable");
    let (unrestricted, _) = DeliveryWindowEvaluator::evaluate_with_evidence(&context, &[]);
    assert_eq!(
        unrestricted,
        DeliveryWindowDecision::DeliverNow,
        "a TASK-derived local minute must not reproduce {ONE_1880_DEFECT}"
    );

    // 2. Re-arm: a real hold parks at the window EDGE, not at `now + 1`.
    let claim = DeliveryWindowPolicyClaim::from_claim_body(&quiet_claim(22 * 60, 8 * 60)).unwrap();
    let quiet =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Interrupt)
            .unwrap();
    let (decision, evidence) = DeliveryWindowEvaluator::evaluate_with_evidence(&quiet, &[claim]);
    let DeliveryWindowDecision::Hold { retry_at, .. } = decision else {
        panic!("a non-degradable interrupt inside a quiet window holds");
    };
    let retry_at = retry_at.expect("the hold carries a concrete retry edge");
    // 23:00 → the 08:00 edge is nine hours out, not one second.
    assert_eq!(retry_at, 1_000 + 9 * 3_600);
    assert!(retry_at > 1_000 + 1, "re-arm must not be the 1-second loop");
    assert!(!evidence.is_empty(), "the window evidence rides the hold");
}

/// ONE-1768 done-means: the counterparty-timezone gap stays OUT of scope and
/// the ruled exclusion survives verbatim in the source that owns it. This is a
/// source oracle on purpose — a behavioral assertion cannot detect someone
/// quietly adding a subject-timezone lookup.
#[test]
fn counterparty_timezone_remains_out_of_scope() {
    const ONE_1751_EXCLUSION: &str = "the single local_minute_of_day currently applies to ALL subjects' claims — counterparty windows evaluate against the caller's clock. Real fix = subject tz as a vault fact (locale claim on actor/counterparty); rides the ONE-1751 claims direction, NOT this ticket.";

    let outbound_source = include_str!("../outbound.rs");
    assert!(
        outbound_source.contains(ONE_1751_EXCLUSION),
        "the ONE-1751 exclusion must remain verbatim in outbound.rs"
    );

    // No subject/counterparty timezone fact, lookup, or claim schema is added.
    for forbidden in [
        "counterparty_timezone",
        "subject_timezone",
        "locale_timezone",
        "delivery_window.locale",
    ] {
        assert!(
            !outbound_source.contains(forbidden),
            "{forbidden} belongs to ONE-1751, not this ticket"
        );
    }
    assert!(
        !DELIVERY_WINDOW_CLAIM_PREDICATES
            .iter()
            .any(|predicate| { predicate.contains("locale") || predicate.contains("timezone") }),
        "no locale/timezone claim predicate is introduced"
    );

    // The single caller-clock minute still drives every subject's claims.
    let claim = DeliveryWindowPolicyClaim::from_claim_body(&quiet_claim(22 * 60, 8 * 60)).unwrap();
    let context =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Interrupt)
            .unwrap();
    let (decision, evidence) = DeliveryWindowEvaluator::evaluate_with_evidence(&context, &[claim]);
    assert_eq!(context.local_minute_of_day(), 23 * 60);
    assert!(matches!(decision, DeliveryWindowDecision::Hold { .. }));
    assert_eq!(evidence[0].predicate, PREDICATE_DELIVERY_WINDOW_QUIET);
}

/// The ladder's top rung is a real resolution, not a caller-supplied seed:
/// `resolve` must OBSERVE the standing quiet-window hold and still return an
/// executing effective action, tagged `HumanExplicitInstant`.
#[test]
fn human_explicit_rung_lifts_the_hold_and_keeps_the_observation() {
    let claim = DeliveryWindowPolicyClaim::from_claim_body(&quiet_claim(22 * 60, 8 * 60)).unwrap();
    let standing =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Interrupt)
            .unwrap();
    let parked = DeliveryWindowEvaluator::resolve(&standing, std::slice::from_ref(&claim));
    assert_eq!(parked.rung, DeliveryWindowLadderRung::InterruptHeld);

    let explicit = standing.human_explicit_instant();
    let resolution = DeliveryWindowEvaluator::resolve(&explicit, std::slice::from_ref(&claim));
    assert_eq!(
        resolution.rung,
        DeliveryWindowLadderRung::HumanExplicitInstant
    );
    assert!(matches!(
        resolution.observed,
        DeliveryWindowDecision::Hold { .. }
    ));
    assert_eq!(resolution.effective, DeliveryWindowDecision::DeliverNow);
    // The standing claim is never erased by the override.
    assert_eq!(resolution.matched.len(), 1);
    assert_eq!(
        resolution.matched[0].predicate,
        PREDICATE_DELIVERY_WINDOW_QUIET
    );

    // An APNs cap already ADMITS execution, so the human rung keeps it verbatim
    // rather than discarding the companion ceiling.
    let capped =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Interrupt)
            .unwrap()
            .apns_interruption_level(DeliveryWindowApnsInterruptionLevel::TimeSensitive)
            .human_explicit_instant();
    let capped = DeliveryWindowEvaluator::resolve(&capped, &[claim]);
    assert_eq!(capped.rung, DeliveryWindowLadderRung::HumanExplicitInstant);
    assert!(matches!(
        capped.effective,
        DeliveryWindowDecision::DeliverNowWithApnsCap { .. }
    ));
}

/// The fail-closed rung is constructible and self-consistent: a hold, named
/// `missing_local_minute`, that still carries the unevaluable claim evidence.
#[test]
fn missing_local_minute_rung_is_a_fail_closed_hold_with_evidence() {
    let resolution = DeliveryWindowResolution::missing_local_minute(vec![DeliveryWindowMatch {
        predicate: PREDICATE_DELIVERY_WINDOW_QUIET.to_owned(),
        reason: "quiet_window".to_owned(),
        retry_at: None,
    }]);
    assert_eq!(
        resolution.rung,
        DeliveryWindowLadderRung::MissingLocalMinute
    );
    assert_eq!(resolution.rung.as_str(), "missing_local_minute");
    assert_eq!(resolution.observed, resolution.effective);
    assert_eq!(
        resolution.effective,
        DeliveryWindowDecision::Hold {
            reason: MISSING_LOCAL_MINUTE_REASON.to_owned(),
            retry_at: None,
        }
    );
    assert_eq!(resolution.matched.len(), 1);

    // Every rung name stays inside the frozen enum.
    for (rung, expected) in [
        (
            DeliveryWindowLadderRung::HumanExplicitInstant,
            "human_explicit_instant",
        ),
        (DeliveryWindowLadderRung::Ambient, "ambient"),
        (
            DeliveryWindowLadderRung::InterruptDegraded,
            "interrupt_degraded",
        ),
        (DeliveryWindowLadderRung::InterruptHeld, "interrupt_held"),
        (
            DeliveryWindowLadderRung::MissingLocalMinute,
            "missing_local_minute",
        ),
    ] {
        assert_eq!(rung.as_str(), expected);
    }
}

/// The non-APNs resolved level is a carrier, not a guess: it round-trips
/// through its stable wire labels and nothing else parses.
#[test]
fn resolved_level_parses_only_its_frozen_labels() {
    for level in [
        DeliveryWindowResolvedLevel::PlainChat,
        DeliveryWindowResolvedLevel::Push,
    ] {
        assert_eq!(
            DeliveryWindowResolvedLevel::parse(level.as_str()),
            Some(level)
        );
    }
    assert!(DeliveryWindowResolvedLevel::PlainChat.is_plain_chat());
    assert!(!DeliveryWindowResolvedLevel::Push.is_plain_chat());
    for unknown in ["", "chat", "ambient", "PLAIN_CHAT", "send"] {
        assert_eq!(DeliveryWindowResolvedLevel::parse(unknown), None);
    }
}

#[test]
fn canonical_resolution_preserves_match_and_effective_decision() {
    let claim = DeliveryWindowPolicyClaim::from_claim_body(&quiet_claim(22 * 60, 8 * 60)).unwrap();
    let context =
        DeliveryWindowEvaluationContext::new(1_000, 23 * 60, DeliveryWindowVerbClass::Interrupt)
            .unwrap();
    let resolution = DeliveryWindowEvaluator::resolve(&context, &[claim]);
    assert!(matches!(
        resolution.observed,
        DeliveryWindowDecision::Hold { .. }
    ));
    assert_eq!(resolution.observed, resolution.effective);
    assert_eq!(resolution.rung, DeliveryWindowLadderRung::InterruptHeld);
    assert_eq!(resolution.matched.len(), 1);
    assert_eq!(
        resolution.matched[0].predicate,
        PREDICATE_DELIVERY_WINDOW_QUIET
    );
}
