//! Manifest-backed voice serving limits: precedence, narrowing, and fail closure.
use super::*;
use crate::gate::voice_serving::{KEY, VoiceServingRows};

fn serving(vault_limit: u64, holder: Option<(EntityId, u64)>) -> Value {
    let mut value = VoiceServingRows::seeded();
    let Value::Map(entries) = &mut value else {
        unreachable!()
    };
    let (_, vault) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("vault"))
        .unwrap();
    let Value::Map(fields) = vault else {
        unreachable!()
    };
    fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("max_text_bytes"))
        .unwrap()
        .1 = Value::from(vault_limit);
    if let Some((id, limit)) = holder {
        let mut limits = vault.clone();
        let Value::Map(fields) = &mut limits else {
            unreachable!()
        };
        fields
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("max_text_bytes"))
            .unwrap()
            .1 = Value::from(limit);
        entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("holders"))
            .unwrap()
            .1 = Value::Array(vec![Value::Map(vec![
            (Value::from("holder"), Value::from(id.to_hex())),
            (Value::from("limits"), limits),
        ])]);
    }
    value
}

fn put(vault: &crate::Vault, seed: u8, row: Value) -> Result<()> {
    put_policy_manifest_bytes(
        vault,
        test_id(seed),
        &encode_policy_manifest(vec![(Value::from(KEY), row)]),
    )
}

#[test]
fn rows_restrict_by_vault_then_authenticated_holder_and_change_frontier() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let holder = test_id(0x44);
    put(&vault, 0x30, serving(8192, None))?;
    let initial = resolve(&vault)?;
    let hash = initial.read_frontier_hash()?;
    assert_eq!(initial.voice_serving_limits(None)?.max_text_bytes, 8192);
    put(&vault, 0x31, serving(4096, Some((holder, 1024))))?;
    let resolved = resolve(&vault)?;
    assert_ne!(hash, resolved.read_frontier_hash()?);
    assert_eq!(resolved.voice_serving_limits(None)?.max_text_bytes, 4096);
    assert_eq!(
        resolved.voice_serving_limits(Some(holder))?.max_text_bytes,
        1024
    );
    assert_eq!(
        resolved
            .voice_serving_limits(Some(test_id(0x45)))?
            .max_text_bytes,
        4096
    );
    Ok(())
}

#[test]
fn widening_holder_and_invalid_precedence_fail_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let holder = test_id(0x44);
    put(&vault, 0x30, serving(4096, Some((holder, 8192))))?;
    let policy = resolve(&vault)?;
    assert!(policy.voice_serving_limits(Some(holder)).is_err());
    let mut invalid = serving(4096, None);
    let Value::Map(entries) = &mut invalid else {
        unreachable!()
    };
    entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("precedence"))
        .unwrap()
        .1 = Value::from("last_wins");
    put(&vault, 0x31, invalid)?;
    let policy = resolve(&vault)?;
    assert!(policy.diagnostics().malformed_manifest_seen);
    assert!(policy.voice_serving_limits(None).is_err());
    Ok(())
}
