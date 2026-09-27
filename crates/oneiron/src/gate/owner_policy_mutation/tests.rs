use super::*;
use crate::store::GateDecisionId;
use crate::{TimeRange, VaultConfig};

fn setup() -> Result<(tempfile::TempDir, Vault, AuthenticatedOwner)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let person = crate::EntityId::from_bytes([0x71; 16])?;
    vault.put_entity(
        &person,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"policy owner",
    )?;
    let owner = vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())?;
    Ok((dir, vault, owner))
}

fn apply(vault: &Vault, owner: &AuthenticatedOwner, change: &PolicyRowChange) -> Result<()> {
    vault.with_write_txn(|txn| apply_owner_policy_row_change_in_txn(vault, owner, txn, change, 2))
}

fn manifest(vault: &Vault) -> Result<Value> {
    let txn = vault.store.env.read_txn()?;
    let id = default_policy_manifest_id()?;
    let raw = vault
        .store
        .entities
        .get(&txn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    rmpv::decode::read_value(&mut &raw[ENTITY_METADATA_HEADER_LEN..])
        .map_err(|_| Error::CorruptedIndex("default policy manifest body"))
}

fn rows(value: &Value) -> &Vec<Value> {
    let Value::Map(entries) = value else {
        panic!("manifest map")
    };
    let Value::Array(rows) = field(entries, POLICY_OWNER_POLICY_ROWS_KEY)
        .unwrap()
        .unwrap()
    else {
        panic!("rows array")
    };
    rows
}

#[test]
fn add_edit_remove_exact_scoped_rows_preserves_other_fields() -> Result<()> {
    let (_dir, vault, owner) = setup()?;
    let before = manifest(&vault)?;
    let add = |scope: PolicyRowScope| PolicyRowChange::Add {
        row_ref: "boundary".to_owned(),
        text: "No unsolicited messages".to_owned(),
        action: PolicyRowAction::Block,
        scope,
    };
    for scope in [PolicyRowScope::Vault, PolicyRowScope::World("w1".into())] {
        apply(&vault, &owner, &add(scope))?;
    }
    let updated = manifest(&vault)?;
    assert_eq!(rows(&updated).len(), 2);
    let Value::Map(fields) = &updated else {
        panic!("manifest map")
    };
    assert_eq!(
        field(fields, POLICY_OWNER_POLICY_ENABLED_KEY)?,
        Some(&Value::Boolean(true))
    );
    let Value::Map(before_fields) = &before else {
        panic!("manifest map")
    };
    for (key, value) in before_fields {
        if key.as_str() != Some(POLICY_OWNER_POLICY_ENABLED_KEY)
            && key.as_str() != Some(POLICY_OWNER_POLICY_ROWS_KEY)
        {
            assert_eq!(field(fields, key.as_str().unwrap())?, Some(value));
        }
    }
    let edit = PolicyRowChange::Edit {
        row_ref: "boundary".into(),
        text: "Updated".into(),
        action: PolicyRowAction::Warn,
        scope: PolicyRowScope::World("w1".into()),
    };
    apply(&vault, &owner, &edit)?;
    let updated = manifest(&vault)?;
    assert_eq!(rows(&updated).len(), 2);
    let Value::Map(world) = &rows(&updated)[1] else {
        panic!("row map")
    };
    assert_eq!(
        field(world, POLICY_ROW_TEXT_KEY)?,
        Some(&Value::from("Updated"))
    );
    assert_eq!(
        field(world, POLICY_ROW_ACTION_KEY)?,
        Some(&Value::from("warn"))
    );
    assert!(apply(&vault, &owner, &add(PolicyRowScope::World("w1".into()))).is_err());
    assert!(
        apply(
            &vault,
            &owner,
            &PolicyRowChange::Remove {
                row_ref: "boundary".into(),
                scope: PolicyRowScope::World("w2".into()),
            }
        )
        .is_err()
    );
    apply(
        &vault,
        &owner,
        &PolicyRowChange::Remove {
            row_ref: "boundary".into(),
            scope: PolicyRowScope::Vault,
        },
    )?;
    assert_eq!(rows(&manifest(&vault)?).len(), 1);
    Ok(())
}

#[test]
fn malformed_or_untrusted_manifest_cannot_be_reauthored_by_mutation() -> Result<()> {
    let (_dir, vault, owner) = setup()?;
    let add = PolicyRowChange::Add {
        row_ref: "boundary".into(),
        text: "Stop".into(),
        action: PolicyRowAction::Block,
        scope: PolicyRowScope::Vault,
    };
    let mut malformed = manifest(&vault)?;
    let Value::Map(fields) = &mut malformed else {
        panic!("manifest map")
    };
    let index = fields
        .iter()
        .position(|(key, _)| key.as_str() == Some(POLICY_OWNER_POLICY_ROWS_KEY))
        .unwrap();
    fields[index].1 = Value::Array(vec![Value::Map(vec![(
        Value::from("unknown"),
        Value::from(1),
    )])]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &malformed)
        .map_err(|_| Error::InvariantViolation("test manifest encode"))?;
    vault.with_write_txn(|txn| {
        vault.write_owner_policy_manifest_in_txn(
            &owner,
            txn,
            default_policy_manifest_id()?,
            bytes,
            2,
        )
    })?;
    let before = manifest(&vault)?;
    assert!(apply(&vault, &owner, &add).is_err());
    assert_eq!(manifest(&vault)?, before);
    vault
        .batch()
        .put_replicated(
            &default_policy_manifest_id()?,
            ENTITY_TYPE_POLICY_MANIFEST,
            TimeRange { start: 3, end: 3 },
            3,
            &super::super::default_policy_manifest(),
        )
        .commit()?;
    let before = manifest(&vault)?;
    assert!(apply(&vault, &owner, &add).is_err());
    assert_eq!(manifest(&vault)?, before);
    Ok(())
}
