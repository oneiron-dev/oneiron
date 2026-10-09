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
    )
    .unwrap();
    body.source = Some(ClaimSource::UserStated);
    body
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
    )?;
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
