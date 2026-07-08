use super::*;
use crate::types::EntityId;

fn entity(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity")
}

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
    };

    assert_eq!(
        DeliveryWindowEvaluator::evaluate(&malformed_context, &[policy]),
        DeliveryWindowDecision::Hold {
            reason: "invalid_local_minute".to_owned(),
            retry_at: None,
        }
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
        DeliveryWindowDecision::Degrade {
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
        DeliveryWindowDecision::Hold {
            reason: "context_window".to_owned(),
            retry_at: None,
        }
    );
    Ok(())
}
