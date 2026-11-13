//! Frozen execution and actual-use facts on an attempt's pack receipt.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::receipt::task_type_ref::TypeRef;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

const ATTEMPT_ATTRIBUTION: SideTable<[u8; 16], PackAttributionFields, Named> =
    SideTable::new(&side_table::ATTEMPT_PACK_ATTRIBUTION);

/// Whether a masked copy of a `ATTEMPT_PACK_ATTRIBUTION` row still decodes as its typed value,
/// for the historical lift sweep (FIX 2680).
pub(crate) fn attempt_pack_attribution_accepts_masked(bytes: &[u8]) -> bool {
    crate::side_table::decodes::<PackAttributionFields, Named>(bytes)
}

#[doc(hidden)]
pub(crate) use oneiron_verb_wire::receipt::pack_attribution::reference;
#[doc(hidden)]
pub use oneiron_verb_wire::receipt::pack_attribution::{
    ContributionCheck, CreditOptions, PackAttributionFields, PackLearningContext,
    SkillContribution, UsedProvenanceEdge,
};

pub(crate) fn put_attempt_pack_attribution_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
    fields: &PackAttributionFields,
) -> Result<()> {
    fields.validate()?;
    // Bind the receipt's two type stamps at the producer write, not at completion.
    if let Some(record) =
        crate::attempt_queue::AttemptQueue::from_store(store).get_in_txn(txn, id)?
        && let Some(type_ref) = crate::agent_dispatch::attempt_task_type_ref(&record)
        && TypeRef::from(&type_ref) != fields.type_ref
    {
        return Err(Error::InvalidClaimBody(
            "attempt type disagrees with attribution stamp",
        ));
    }
    let key = *id.as_bytes();
    if let Some(previous) = ATTEMPT_ATTRIBUTION.get(store, txn, &key)?
        && !fields.extends(&previous)
    {
        return Err(Error::InvalidClaimBody(
            "pack attribution is immutable and use lists are append-only",
        ));
    }
    ATTEMPT_ATTRIBUTION.put(store, txn, &key, fields)
}

/// Records `judge` as the unknown judge of attempt `id`'s live attribution
/// row (FIX 1877), the one change its execution context takes, through the
/// attribution door. Its one caller holds `id`'s live lease in `txn`.
/// Returns whether the judge was recorded now: a row with a judge already
/// keeps it, and no row records nothing.
pub(crate) fn finalize_attempt_pack_judge_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
    judge: &str,
) -> Result<bool> {
    let Some(mut fields) = ATTEMPT_ATTRIBUTION.get(store, txn, id.as_bytes())? else {
        return Ok(false);
    };
    if fields.judge.is_some() {
        return Ok(false);
    }
    fields.judge = Some(judge.to_owned());
    put_attempt_pack_attribution_in_txn(store, txn, id, &fields)?;
    Ok(true)
}

/// The live attribution row of attempt `id`, before its close takes it.
pub(crate) fn attempt_pack_attribution_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
) -> Result<Option<PackAttributionFields>> {
    ATTEMPT_ATTRIBUTION.get(store, txn, id.as_bytes())
}

pub(crate) fn has_attempt_pack_attribution_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: AttemptId,
) -> Result<bool> {
    ATTEMPT_ATTRIBUTION.contains(store, txn, id.as_bytes())
}

pub(crate) fn take_attempt_pack_attribution_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: AttemptId,
) -> Result<PackAttributionFields> {
    let key = *id.as_bytes();
    let fields = ATTEMPT_ATTRIBUTION
        .get(store, txn, &key)?
        .ok_or(Error::InvalidClaimBody(
            "an attributable attempt requires typeRef and execution context before closing",
        ))?;
    fields.validate()?;
    ATTEMPT_ATTRIBUTION.delete(store, txn, &key)?;
    Ok(fields)
}

/// Re-keys the project of every live attempt attribution naming erased
/// `entity` to one fresh opaque scope (FIX 11934), as the project's erase
/// re-keys the frozen receipt copy (`learning::erase_receipt_scope_in_txn`):
/// a run still in flight stays apart from the vault's and no longer names
/// the project. A row naming it that no longer decodes is deleted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_attempt_attribution_scope_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let named = entity.to_hex();
    let rows = ATTEMPT_ATTRIBUTION
        .iter_raw_from(&vault.store, wtxn, &[])?
        .collect::<Result<Vec<_>>>()?;
    let mut scope = None;
    for (key, value) in rows {
        if !value
            .windows(named.len())
            .any(|window| window == named.as_bytes())
        {
            continue;
        }
        let Ok(key) = <[u8; 16]>::try_from(key.as_slice()) else {
            continue;
        };
        match ATTEMPT_ATTRIBUTION.decode_value(&value) {
            Ok(mut fields) if fields.project == Some(*entity) => {
                let erased = match scope {
                    Some(erased) => erased,
                    None => {
                        let minted = vault.store.clock.entity_id()?;
                        scope = Some(minted);
                        minted
                    }
                };
                fields.project = Some(erased);
                ATTEMPT_ATTRIBUTION.put(&vault.store, wtxn, &key, &fields)?;
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    %error,
                    "a live attempt attribution that no longer decodes is deleted"
                );
                // FIX 12085: the deleted row's lifted custody goes with it.
                let place = format!("side:{}", ATTEMPT_ATTRIBUTION.decl().name);
                let origin = crate::batch::secret_scan::side_row_origin(
                    &place,
                    &ATTEMPT_ATTRIBUTION.key_bytes(&key),
                )?;
                crate::secret_custody::revoke_side_row_custody_in_txn(vault, wtxn, &origin, None)?;
                ATTEMPT_ATTRIBUTION.delete(&vault.store, wtxn, &key)?;
            }
        }
    }
    Ok(())
}
