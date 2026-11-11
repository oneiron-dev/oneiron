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
    Value::Map(act_entries(scope, row))
}

/// [`act_value`]'s entries.
fn act_entries(scope: &SettingScope, row: &SettingRow) -> Vec<(Value, Value)> {
    let scope_tag = match scope {
        SettingScope::Vault => "vault",
        SettingScope::Goal(_) => "goal",
        SettingScope::Project(_) => "project",
        SettingScope::Type(_) => "type",
    };
    vec![
        (Value::from("key"), Value::from(row.key.as_str())),
        (Value::from("mode"), Value::from(row.mode.as_str())),
        (Value::from("scope_tag"), Value::from(scope_tag)),
    ]
}

/// The PUT act of a holder of `engine.controls` (untangle 6.6b): the
/// engine observed an act its one check admitted in this writer, so the
/// witness is `Observed` and `Auto`. It is never the owner's own word
/// (`UserStated`). The setting is the vault owner's, so the witness is about
/// the owner and lives on the owner's substrate facet, as the owner's own
/// PUT does; a holder such as the Coach is no PERSON and has no facet. It
/// names no holder (review of #6918, round 2): the claim is the owner's, on
/// the owner's facet, so a hard erase of the holder would never reach an id
/// written here. The setting row and the engine-control receipt beside it
/// name the holder, and each has an actor scrub.
pub(super) fn holder_put_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    scope: &SettingScope,
    row: &SettingRow,
) -> Result<EntityId> {
    let owner = crate::policy_model::owners_in_txn(vault, &*txn)?
        .first()
        .copied()
        .ok_or_else(|| crate::error::Error::InvalidConfig("this vault has no owner".into()))?;
    let mut body = ClaimBody::new(
        PREDICATE,
        ClaimSubject::Entity(owner),
        act_value(scope, row),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.scope_facet = crate::claim::substrate_facet_id(owner)?;
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
