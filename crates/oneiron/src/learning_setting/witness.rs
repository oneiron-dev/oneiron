//! Native records of the owner PUT acts behind numeric seed and pin rows.

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use super::{SettingRow, SettingScope};
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

/// A historical PUT act, not a second authority for the setting's value.
const PREDICATE: &str = "vault.learning_setting.put";

/// The caller verifies the owner in this same writer before recording the act.
pub(super) fn put_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    owner: &WriteActor,
    scope: &SettingScope,
    row: &SettingRow,
) -> Result<EntityId> {
    let scope_tag = match scope {
        SettingScope::Vault => "vault",
        SettingScope::Goal(_) => "goal",
        SettingScope::Project(_) => "project",
        SettingScope::Type(_) => "type",
    };
    let candidate = ClaimCandidate::new(
        PREDICATE,
        ClaimSubject::Entity(owner.entity_ref()),
        Value::Map(vec![
            (Value::from("key"), Value::from(row.key.as_str())),
            (Value::from("mode"), Value::from(row.mode.as_str())),
            (Value::from("scope_tag"), Value::from(scope_tag)),
        ]),
        1.0,
    );
    let envelope = WriteEnvelope::new(
        *owner,
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from(PREDICATE))?,
        ClaimApprovalStatus::Approved,
    );
    let body = candidate.into_claim_body(
        &envelope,
        crate::claim::substrate_facet_id(owner.entity_ref())?,
    )?;
    let id = vault.store.clock.entity_id()?;
    // The owner already decided this act. The typed door retains the normal
    // structural and source-trust checks without a second consent ladder.
    vault.put_reserved_claim_in_txn(
        txn,
        &id,
        &body,
        TimeRange {
            start: row.at,
            end: row.at,
        },
        row.at,
    )?;
    Ok(id)
}

pub(super) fn source_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    witness: Option<EntityId>,
) -> Result<Option<Vec<EntityId>>> {
    let Some(id) = witness else { return Ok(None) };
    Ok(vault
        .get_claim_in_txn(txn, &id)?
        .filter(|body| {
            body.predicate == PREDICATE && body.lifecycle == ClaimLifecycleStatus::Active
        })
        .map(|_| vec![id]))
}
