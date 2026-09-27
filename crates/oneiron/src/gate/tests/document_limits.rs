//! Document admission is declared vault policy, not a ZIP parser preference.

use super::*;
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use oneiron_docedit::edit_roundtrip::limits::DocumentLimits;

fn row(entry: u64, package: u64) -> (Value, Value) {
    (
        Value::from(POLICY_DOCUMENT_LIMITS_KEY),
        Value::Map(vec![
            (Value::from("entry_bytes"), Value::from(entry)),
            (Value::from("package_bytes"), Value::from(package)),
        ]),
    )
}

#[test]
fn seeded_default_and_trusted_holder_override_are_resolved() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    put_policy_manifest_bytes(
        &vault,
        default_policy_manifest_id()?,
        &default_policy_manifest(),
    )?;
    let default = resolve(&vault)?;
    assert_eq!(
        default.document_limits(),
        Some(DocumentLimits::new(256 * 1024 * 1024, 1024 * 1024 * 1024).unwrap())
    );
    let before = default.read_frontier_hash()?;
    // A trusted authored row replaces the seeded fallback, including an
    // explicit holder widen; a second trusted row can only narrow the result.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x64),
        &encode_policy_manifest(vec![row(2 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024)]),
    )?;
    let wider = resolve(&vault)?;
    assert_eq!(
        wider.document_limits(),
        DocumentLimits::new(2 * 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024)
    );
    assert_ne!(before, wider.read_frontier_hash()?);
    put_policy_manifest_bytes(
        &vault,
        test_id(0x65),
        &encode_policy_manifest(vec![row(1024, 2048)]),
    )?;
    assert_eq!(
        resolve(&vault)?.document_limits(),
        DocumentLimits::new(1024, 2048)
    );
    Ok(())
}

#[test]
fn malformed_and_untrusted_rows_never_widen() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    put_policy_manifest_bytes(
        &vault,
        default_policy_manifest_id()?,
        &default_policy_manifest(),
    )?;
    let invalid = encode_policy_manifest(vec![row(0, 100)]);
    assert!(decode_policy_manifest(&invalid).is_none());
    assert!(decode_policy_manifest(&encode_policy_manifest(vec![row(100, u64::MAX)])).is_none());
    let duplicate = encode_policy_manifest(vec![row(100, 200), row(101, 201)]);
    assert!(decode_policy_manifest(&duplicate).is_none());
    // A peer row with no trusted-origin stamp can only lower admission.
    let untrusted = encode_policy_manifest(vec![row(4, 8)]);
    let id = test_id(0x66);
    let payload = entity_record(ENTITY_TYPE_POLICY_MANIFEST, test_time(1), 1, &untrusted);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        vault.store.type_index.put(
            wtxn,
            &crate::store::Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id),
            &[],
        )?;
        Ok(())
    })?;
    assert_eq!(
        resolve(&vault)?.document_limits(),
        DocumentLimits::new(4, 8)
    );
    Ok(())
}
