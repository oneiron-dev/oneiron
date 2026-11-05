//! Scope of the projector's original-head-bound scoped touch source.

use super::{MachineHistoryScope, SCOPE_RECORD, Scope, ScopeAxis, SensitivityCeiling};
use crate::claim::{ClaimBody, ClaimRecordScope};
use crate::comm::ScopedTouchRecord;
use crate::ports::EntityStoreRead;
use crate::store::ManifestDbs;
use crate::{EntityId, Result};

pub(crate) enum ScopedCommRead {
    Ordinary,
    Unavailable,
    Claim {
        original: EntityId,
        raw: Vec<u8>,
        body: ClaimBody,
        record: Scope,
    },
}

pub(super) fn birth_position_in_txn(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    source: &ScopedTouchRecord,
) -> Result<Option<(Scope, EntityId)>> {
    // A consumed rewrite follows its already accepted native source stamp.
    // The source id binds every immutable field even after its head closes.
    if SCOPE_RECORD.get(store, txn, &id)?.is_none() && !source.origin_matches_in_txn(store, txn)? {
        return Ok(None);
    }
    let mut scope = source.position();
    scope.verbs = ScopeAxis::Bottom;
    Ok(Some((scope, source.facet())))
}

pub(crate) fn read_scoped_comm_in_txn(
    store: &(impl ManifestDbs + MachineHistoryScope),
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    data: &[u8],
) -> Result<ScopedCommRead> {
    let Some(source) = ScopedTouchRecord::decode(id, data)? else {
        return Ok(ScopedCommRead::Ordinary);
    };
    let Some(mut frozen) =
        super::stored_scope(store, txn, id, crate::registry::ENTITY_TYPE_COMM_RECORD)?
    else {
        return Ok(ScopedCommRead::Unavailable);
    };
    let original = source.original_head();
    if crate::vault::live_entity_row_in_txn(store, txn, &original)?.live_type()
        != Some(crate::registry::ENTITY_TYPE_CLAIM)
    {
        return Ok(ScopedCommRead::Unavailable);
    }
    let Some(row) = store.port_entity_record(txn, &original)? else {
        return Ok(ScopedCommRead::Unavailable);
    };
    let Ok(body) = crate::claim::decode_claim_body(&row.body, true) else {
        return Ok(ScopedCommRead::Unavailable);
    };
    let current = match store.machine_history_scope(txn, &body)? {
        Some(Some(current)) => current,
        Some(None) => return Ok(ScopedCommRead::Unavailable),
        None => body.record_scope("read"),
    };
    frozen.verbs = super::singleton("read".to_owned());
    let record = required_positions(&frozen, &current);
    Ok(ScopedCommRead::Claim {
        original,
        raw: row.encode(),
        body,
        record,
    })
}

pub(super) fn disclosure_in_txn(
    store: &(impl ManifestDbs + MachineHistoryScope),
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    data: &[u8],
) -> Result<Option<Scope>> {
    match read_scoped_comm_in_txn(store, txn, id, data)? {
        ScopedCommRead::Claim { record, .. } => Ok(Some(record)),
        ScopedCommRead::Unavailable | ScopedCommRead::Ordinary => Ok(None),
    }
}

// Records state what must be readable, not what a capability permits. A
// reader must cover both positions, including the higher classification.
fn required_positions(frozen: &Scope, current: &Scope) -> Scope {
    Scope {
        worlds: required_axis(&frozen.worlds, &current.worlds),
        facets: required_axis(&frozen.facets, &current.facets),
        bands: required_axis(&frozen.bands, &current.bands),
        audience: required_axis(&frozen.audience, &current.audience),
        verbs: required_axis(&frozen.verbs, &current.verbs),
        sensitivity: match (frozen.sensitivity, current.sensitivity) {
            (SensitivityCeiling::AtMost(a), SensitivityCeiling::AtMost(b)) => {
                SensitivityCeiling::AtMost(a.max(b))
            }
            (SensitivityCeiling::Bottom, _) | (_, SensitivityCeiling::Bottom) => {
                SensitivityCeiling::Bottom
            }
        },
    }
}

fn required_axis<T: Ord + Clone>(frozen: &ScopeAxis<T>, current: &ScopeAxis<T>) -> ScopeAxis<T> {
    match (frozen, current) {
        (ScopeAxis::Bottom, _) | (_, ScopeAxis::Bottom) => ScopeAxis::Bottom,
        (ScopeAxis::Some(values), _) if values.is_empty() => ScopeAxis::Bottom,
        (_, ScopeAxis::Some(values)) if values.is_empty() => ScopeAxis::Bottom,
        (ScopeAxis::All, _) | (_, ScopeAxis::All) => ScopeAxis::All,
        (ScopeAxis::Some(a), ScopeAxis::Some(b)) => a.iter().chain(b).cloned().collect(),
    }
}
