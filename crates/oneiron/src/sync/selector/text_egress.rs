//! The text fence at sync egress and peer document admission (facet rule C):
//! an ASSET_TEXT written from source ASSETs is selected only while every one
//! of them is a live row the same selection reads, judged on its stored row
//! wherever a window carries it. A source this window does not carry is not
//! thereby unread, and it is never sent along.

use std::collections::HashMap;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{FederationDirectionScope, Scope};
use crate::registry::ENTITY_TYPE_ASSET_TEXT;

use super::codec::SyncSelector;
use super::scope::{
    CoreferenceExportContext, FacetScope, entity_selector_decision, facet_filter,
    settled_position_selected,
};

/// Whether `id` may be selected beside its sources: any row but an ASSET_TEXT
/// (stored, or as `carried` says), a text bound to no source, or a text each
/// of whose sources passes `selected` on its stored header and body.
pub(super) fn text_backed(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    carried: Option<&[u8]>,
    mut selected: impl FnMut(&EntityId, &[u8]) -> Result<bool>,
) -> Result<bool> {
    let text = Some(ENTITY_TYPE_ASSET_TEXT);
    if carried.and_then(|raw| raw.first().copied()) != text
        && crate::batch::stored_entity_type(&vault.store, rtxn, id)? != text
    {
        return Ok(true);
    }
    let admitted = crate::federation::record_scope::asset_text::sources_admitted_in(
        &vault.store,
        rtxn,
        id,
        |source, row| selected(source, &row.encode()),
    )?;
    Ok(admitted.unwrap_or(true))
}

/// Whether the stored source `source`, with header and body `raw`, is read
/// under `authority` by a selector at `position`: causally admitted, at a
/// record position the grant reads and the selector selects, in a selected
/// facet, and past every per-row selector rule.
pub(super) fn source_selected(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    (source, raw): (&EntityId, &[u8]),
    authority: &Scope,
    selector: &SyncSelector,
    position: &FederationDirectionScope,
    facet_scope: &HashMap<EntityId, FacetScope>,
) -> Result<bool> {
    if !crate::authority::row_causal_admitted(vault, rtxn, source, raw)? {
        return Ok(false);
    }
    let Some(record) =
        crate::federation::record_scope::scope_for_blob(&vault.store, rtxn, *source, raw)?
    else {
        return Ok(false);
    };
    Ok(authority.admits("read", &record, &Scope::top())
        && settled_position_selected(source, raw, &record, position)?
        && facet_filter(position).is_none_or(|facets| !record.facets.meet(facets).is_bottom())
        && entity_selector_decision(
            vault,
            (source, raw),
            &record,
            selector,
            facet_scope,
            position,
            &CoreferenceExportContext::default(),
        )
        .is_some())
}

/// The document plane uses the same source fence as ledger selection, with
/// the destination's withheld worlds instead of an unknown-machine default.
pub(in crate::sync) fn document_sources_readable_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    flagged: &std::collections::BTreeSet<EntityId>,
) -> Result<bool> {
    text_backed(vault, txn, &id, None, |source, raw| {
        crate::settings::device_only_withholds_raw(&vault.store, txn, flagged, source, Some(raw))
            .map(|withheld| !withheld)
    })
}
