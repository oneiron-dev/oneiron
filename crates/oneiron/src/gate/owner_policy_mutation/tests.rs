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

#[test]
fn combined_scope_row_remains_editable_and_does_not_block_unrelated_rows() -> Result<()> {
    let (_dir, vault, owner) = setup()?;
    let mut current = manifest(&vault)?;
    let Value::Map(entries) = &mut current else {
        unreachable!()
    };
    let Value::Array(existing_rows) = &mut entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(POLICY_OWNER_POLICY_ROWS_KEY))
        .expect("owner rows")
        .1
    else {
        unreachable!()
    };
    let combined = PolicyRowScope::WorldProject {
        world: "w1".into(),
        project: "p1".into(),
    };
    existing_rows.push(row_value(
        "combined",
        &combined,
        "Keep it private",
        PolicyRowAction::Block,
        None,
    ));
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &current)
        .map_err(|_| Error::InvariantViolation("fixture encode"))?;
    vault.with_write_txn(|txn| {
        vault.write_owner_policy_manifest_in_txn(
            &owner,
            txn,
            default_policy_manifest_id()?,
            encoded,
            2,
        )
    })?;
    apply(
        &vault,
        &owner,
        &PolicyRowChange::Add {
            row_ref: "unrelated".into(),
            text: "Also private".into(),
            action: PolicyRowAction::Warn,
            scope: PolicyRowScope::Vault,
        },
    )?;
    apply(
        &vault,
        &owner,
        &PolicyRowChange::Edit {
            row_ref: "combined".into(),
            text: "Stricter text".into(),
            action: PolicyRowAction::Block,
            scope: combined.clone(),
        },
    )?;
    assert_eq!(rows(&manifest(&vault)?).len(), 2);
    apply(
        &vault,
        &owner,
        &PolicyRowChange::Remove {
            row_ref: "combined".into(),
            scope: combined,
        },
    )?;
    assert_eq!(rows(&manifest(&vault)?).len(), 1);
    Ok(())
}

#[test]
fn optional_why_is_stamped_and_draft_never_displaces_owner_reason() -> Result<()> {
    let (_dir, vault, owner) = setup()?;
    let scope = PolicyRowScope::Vault;
    apply(
        &vault,
        &owner,
        &PolicyRowChange::Add {
            row_ref: "plain".into(),
            text: "text".into(),
            action: PolicyRowAction::Warn,
            scope: scope.clone(),
        },
    )?;
    let snapshot = manifest(&vault)?;
    let Value::Map(plain) = &rows(&snapshot)[0] else {
        unreachable!()
    };
    assert!(field(plain, "why")?.is_none());
    apply(
        &vault,
        &owner,
        &PolicyRowChange::DraftWhy {
            row_ref: "plain".into(),
            scope: scope.clone(),
            why: "Suggested reason".into(),
        },
    )?;
    let snapshot = manifest(&vault)?;
    let Value::Map(drafted) = &rows(&snapshot)[0] else {
        unreachable!()
    };
    assert_eq!(field(drafted, "why_source")?, Some(&Value::from("drafted")));
    apply(
        &vault,
        &owner,
        &PolicyRowChange::EditWithWhy {
            row_ref: "plain".into(),
            text: "text".into(),
            action: PolicyRowAction::Block,
            scope: scope.clone(),
            why: "Owner's explicit reason".into(),
        },
    )?;
    assert!(
        apply(
            &vault,
            &owner,
            &PolicyRowChange::DraftWhy {
                row_ref: "plain".into(),
                scope: scope.clone(),
                why: "Replacement draft".into(),
            }
        )
        .is_err()
    );
    let snapshot = manifest(&vault)?;
    let Value::Map(owner_reason) = &rows(&snapshot)[0] else {
        unreachable!()
    };
    assert_eq!(
        field(owner_reason, "why")?,
        Some(&Value::from("Owner's explicit reason"))
    );
    assert_eq!(
        field(owner_reason, "why_source")?,
        Some(&Value::from("owner"))
    );
    apply(
        &vault,
        &owner,
        &PolicyRowChange::AddWithWhy {
            row_ref: "direct".into(),
            text: "text".into(),
            action: PolicyRowAction::Warn,
            scope,
            why: "Written during add".into(),
        },
    )?;
    assert_eq!(rows(&manifest(&vault)?).len(), 2);
    Ok(())
}
