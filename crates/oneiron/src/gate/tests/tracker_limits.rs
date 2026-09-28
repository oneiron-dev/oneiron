//! Policy rows bound the server's revision-provenance lifecycle.
use super::*;

fn limits(events: u64, bytes: u64) -> Value {
    Value::Map(vec![
        (Value::from("max_events"), Value::from(events)),
        (Value::from("max_bytes"), Value::from(bytes)),
    ])
}
fn row(events: u64, bytes: u64, holder: Option<(EntityId, u64, u64)>) -> (Value, Value) {
    let mut fields = vec![(Value::from("vault"), limits(events, bytes))];
    if let Some((id, events, bytes)) = holder {
        fields.push((
            Value::from("holders"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("holder_ref"), Value::from(id.to_hex())),
                (Value::from("max_events"), Value::from(events)),
                (Value::from("max_bytes"), Value::from(bytes)),
            ])]),
        ));
    }
    (Value::from("livequery_tracker_limits"), Value::Map(fields))
}
#[test]
fn policy_tracker_defaults_holder_cannot_widen_parent_and_trusted_packs_restrict() -> Result<()> {
    let (_dir, vault) = temp_vault();
    assert_eq!(
        vault.policy_livequery_tracker_limits(None)?,
        crate::gate::LiveQueryTrackerLimits::default()
    );
    let holder = test_id(0x46);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x30),
        &encode_policy_manifest(vec![row(500, 32_000, Some((holder, 700, 4_000)))]),
    )?;
    assert_eq!(
        vault
            .policy_livequery_tracker_limits(Some(&holder.to_hex()))?
            .max_events,
        500
    );
    assert_eq!(
        vault
            .policy_livequery_tracker_limits(Some(&holder.to_hex()))?
            .max_bytes,
        4_000
    );
    assert_eq!(
        vault
            .policy_livequery_tracker_limits(Some(&test_id(0x48).to_hex()))?
            .max_bytes,
        32_000
    );
    put_policy_manifest_bytes(
        &vault,
        test_id(0x31),
        &encode_policy_manifest(vec![row(300, 16_000, None)]),
    )?;
    let narrowed = vault.policy_livequery_tracker_limits(Some(&holder.to_hex()))?;
    assert_eq!(narrowed.max_events, 300);
    assert_eq!(narrowed.max_bytes, 4_000);
    assert_eq!(
        vault.policy_livequery_tracker_limits(None)?.max_bytes,
        16_000
    );
    Ok(())
}
#[test]
fn malformed_tracker_policy_refuses_instead_of_falling_back_to_defaults() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let bad = Value::Map(vec![(Value::from("vault"), limits(0, 16_000))]);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x30),
        &encode_policy_manifest(vec![(Value::from("livequery_tracker_limits"), bad)]),
    )?;
    assert!(vault.policy_livequery_tracker_limits(None).is_err());
    Ok(())
}
