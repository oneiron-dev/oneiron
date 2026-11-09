//! Native records of the PUT acts behind numeric seed and pin rows: the
//! owner's, and a holder's of `engine.controls`.

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use super::{SettingRow, SettingScope};
use crate::Vault;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
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
    let candidate = ClaimCandidate::new(
        PREDICATE,
        ClaimSubject::Entity(owner.entity_ref()),
        act_value(scope, row),
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

/// What a PUT act's witness names: the key, the mode and the scope's kind.
fn act_value(scope: &SettingScope, row: &SettingRow) -> Value {
    let scope_tag = match scope {
        SettingScope::Vault => "vault",
        SettingScope::Goal(_) => "goal",
        SettingScope::Project(_) => "project",
        SettingScope::Type(_) => "type",
    };
    Value::Map(vec![
        (Value::from("key"), Value::from(row.key.as_str())),
        (Value::from("mode"), Value::from(row.mode.as_str())),
        (Value::from("scope_tag"), Value::from(scope_tag)),
    ])
}

/// The PUT act of a holder of `engine.controls` (untangle 6.6b): the
/// engine observed an act its one check admitted in this writer, so the
/// witness is `Observed` and `Auto`, about the holder. It is never the
/// owner's own word (`UserStated`), and the engine-control receipt beside it
/// names the holder, the class and the value.
pub(super) fn holder_put_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    holder: EntityId,
    scope: &SettingScope,
    row: &SettingRow,
) -> Result<EntityId> {
    let mut body = ClaimBody::new(
        PREDICATE,
        ClaimSubject::Entity(holder),
        act_value(scope, row),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.valid_from = Some(row.at);
    body.source = Some(ClaimSource::Observed);
    let id = vault.store.clock.entity_id()?;
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
