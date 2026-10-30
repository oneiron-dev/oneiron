//! The owner's post-meeting check-in grace as a policy value (FIX 9647): the
//! vault-scope `calendar_outcome_grace_seconds` row, else the shipped 1,800
//! seconds. The owner edits the row in the trusted default policy manifest
//! through the authenticated manifest writer, so each change is a new version
//! of that manifest with its own gate decision receipt.

use rmpv::Value;

use super::{body_in_txn, decode_fields, encode_fields, invalid, record};
use crate::consent::AuthenticatedOwner;
use crate::gate::policy_values::{PolicyEvaluationScope, PolicyValue, PolicyValueKey};
use crate::{EdgeActorClass, Error, Result, Vault, WriteActor};

const KEY: PolicyValueKey = PolicyValueKey::CalendarOutcomeGraceSeconds;

/// The row an owner's edit adds when the manifest names no vault-scope grace.
const OWNER_ROW_REF: &str = "owner.calendar_outcome_grace_seconds";

/// The shipped vault-scope grace, read from the seeded data.
fn shipped_grace_seconds() -> u64 {
    let defaults: serde_json::Value =
        serde_json::from_str(include_str!("../policy_value_defaults.json"))
            .expect("valid shipped policy defaults");
    defaults
        .as_array()
        .expect("shipped policy rows")
        .iter()
        .find(|row| row["key"] == KEY.as_str() && row["scope"]["level"] == "vault")
        .and_then(|row| row["value"].as_u64())
        .expect("shipped calendar outcome grace row")
}

impl crate::gate::resolution::PolicyManifestResolution {
    /// How long after a meeting's scheduled end its outcome check-in falls
    /// due, in seconds: the vault's row, else the shipped one. A fail-closed
    /// manifest reads the shipped row, since a check-in grants nothing.
    pub(crate) fn calendar_outcome_grace_seconds(&self) -> u64 {
        match self
            .resolved_policy_value(
                KEY,
                &PolicyEvaluationScope::default(),
                PolicyValue::CalendarOutcomeGraceSeconds(shipped_grace_seconds()),
            )
            .value
        {
            PolicyValue::CalendarOutcomeGraceSeconds(seconds) => seconds,
            _ => unreachable!("typed policy key"),
        }
    }
}

fn is_vault_grace_row(entries: &[(Value, Value)]) -> bool {
    let named = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    named("key").and_then(Value::as_str) == Some(KEY.as_str())
        && matches!(
            named("scope"),
            Some(Value::Map(scope)) if scope.len() == 1
                && scope[0].0.as_str() == Some("level")
                && scope[0].1.as_str() == Some("vault")
        )
}

/// Sets the manifest's vault-scope grace row, adding one when it names none.
fn set_vault_grace_row(fields: &mut Vec<(Value, Value)>, grace_secs: u64) -> Result<()> {
    let index = match fields
        .iter()
        .position(|(key, _)| key.as_str() == Some("policy_values"))
    {
        Some(index) => index,
        None => {
            fields.push((Value::from("policy_values"), Value::Array(Vec::new())));
            fields.len() - 1
        }
    };
    let Value::Array(rows) = &mut fields[index].1 else {
        return Err(invalid("malformed policy_values"));
    };
    let existing = rows.iter_mut().find_map(|row| match row {
        Value::Map(entries) if is_vault_grace_row(entries) => Some(entries),
        _ => None,
    });
    match existing {
        Some(entries) => {
            for (key, value) in entries.iter_mut() {
                if key.as_str() == Some("value") {
                    *value = Value::from(grace_secs);
                }
            }
        }
        None => rows.push(Value::Map(vec![
            (Value::from("row_ref"), Value::from(OWNER_ROW_REF)),
            (Value::from("key"), Value::from(KEY.as_str())),
            (Value::from("value"), Value::from(grace_secs)),
            (
                Value::from("scope"),
                Value::Map(vec![(Value::from("level"), Value::from("vault"))]),
            ),
        ])),
    }
    Ok(())
}

/// The grace the vault resolves, under the owner's current proof.
pub fn calendar_outcome_grace_as_owner(vault: &Vault, owner: &AuthenticatedOwner) -> Result<u64> {
    let txn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    Ok(crate::gate::resolve_policy_manifest(&vault.store, &txn)?.calendar_outcome_grace_seconds())
}

/// Sets the vault-scope grace row. Owner revalidation, the manifest write and
/// its receipt share one writer; the result is the grace the vault resolves
/// once the write lands.
pub fn set_calendar_outcome_grace_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    grace_secs: u64,
) -> Result<u64> {
    let grace = vault.with_write_txn_grouped(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let id = crate::gate::default_policy_manifest_id()?;
        let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
        if !crate::gate::manifest_authenticity::manifest_is_trusted(&vault.store, txn, &id, &body)?
        {
            return Err(invalid(
                "the calendar outcome grace requires an owner-trusted manifest",
            ));
        }
        let mut fields = decode_fields(&body)?;
        set_vault_grace_row(&mut fields, grace_secs)?;
        vault.write_owner_policy_manifest_in_txn(
            owner,
            txn,
            id,
            encode_fields(fields)?,
            crate::unix_seconds_now(),
        )?;
        let body = body_in_txn(vault, txn, id)?.ok_or(Error::EntityNotFound)?;
        record(
            vault,
            txn,
            WriteActor::new(actor, EdgeActorClass::Human),
            id,
            &body,
            (
                "allow",
                vec!["gate.allow.owner_calendar_outcome_grace".to_owned()],
            ),
        )?;
        Ok(crate::gate::resolve_policy_manifest(&vault.store, txn)?
            .calendar_outcome_grace_seconds())
    })?;
    // A floor this commit moved is judged again at once (FIX 5505).
    vault.apply_pending_rebinds_after_commit();
    Ok(grace)
}
