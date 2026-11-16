//! Complete authenticated machine-claim history required beside a selected row.

use std::collections::HashMap;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::Result;
use crate::federation::{FederationGrantScope, Position, Scope, decode_federation_grant_body};
use crate::{EntityId, Vault};

use super::authorize::{
    MemberAccess, authorize_selector_export_in_txn, live_federation_grant_in, member_access,
    member_reads_row,
};
use super::codec::SyncSelector;
use super::text_egress::source_selected;

/// The rows a machine CLAIM's authenticated history needs beside it in an
/// export, read from stored truth: its birth event, each transition event of
/// the chain's union and every handoff of its chain. `None` when that history
/// does not resolve whole (a missing or malformed row, a cycle in the chain).
/// The home's history pages serve the same rows (FIX 3820).
pub(in crate::sync) fn machine_history_controls(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<Vec<EntityId>>> {
    // The rows' one chain reader walks every packet back to genesis, so the
    // events and handoffs below are the whole history, not the tip's delta.
    let Ok(rows) = crate::claim::history_projection::machine_history_rows(&vault.store, rtxn, id)
    else {
        return Ok(None);
    };
    let mut required = vec![rows.birth.event_id()?];
    for event in &rows.events {
        required.push(crate::claim::transition::machine_claim_transition_event_id(
            event,
        )?);
    }
    for handoff in &rows.chain {
        let hash = handoff
            .content_hash()
            .map_err(|_| crate::Error::InvalidClaimBody("machine handoff hash"))?;
        required.push(EntityId::from_bytes(
            hash[..16]
                .try_into()
                .map_err(|_| crate::Error::InvalidClaimBody("machine handoff id"))?,
        )?);
    }
    Ok(Some(required))
}

/// How a selector's window export judges each control of a machine CLAIM's
/// history before it ships the target (RULING SECREAD-HOME-MACHINE-HISTORY =
/// A). The export ships a target only when it keeps every control
/// (`authorize/filter.rs`, the incomplete-target check); the home's history
/// pages (FIX 3820) serve a history only when this gate carries every control
/// of it, so the page refuses what the export refuses.
pub(in crate::sync) struct HistoryControlGate<'v, 's> {
    selector: &'s SyncSelector,
    member: MemberAccess<'v>,
    authority: Scope,
    position: Position,
}

impl<'v, 's> HistoryControlGate<'v, 's> {
    /// The gate for `selector`, read in `rtxn`; `None` when the selector no
    /// longer stands (its grant, pact or expiry refuses it): such a selector
    /// carries no row.
    ///
    /// # Errors
    ///
    /// Storage errors, and a grant row that does not decode.
    pub(in crate::sync) fn in_txn(
        vault: &'v Vault,
        rtxn: &heed::RoTxn<'_>,
        grant_scope: FederationGrantScope,
        selector: &'s SyncSelector,
    ) -> Result<Option<Self>> {
        let Ok(position) = authorize_selector_export_in_txn(
            vault,
            rtxn,
            grant_scope,
            selector,
            vault.now_recorded_at(),
        ) else {
            return Ok(None);
        };
        let raw = live_federation_grant_in(vault, rtxn, &selector.grant_id)?;
        let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        let member = member_access(vault, rtxn, &grant)?;
        Ok(Some(Self {
            selector,
            member,
            authority: grant.authority_scope,
            position,
        }))
    }

    /// Whether the export would carry the control `raw` of `id`: no legal use
    /// limit keeps it as storage only, no source audience binds it (its own
    /// bytes or its lineage), it passes the grant member's row gate
    /// ([`member_reads_row`]: the conversation home and the relationship
    /// labels) and the grant's selection ([`source_selected`]), as the export
    /// judges each row it ships (`authorize/filter.rs`). A control is not a
    /// facet seed of the window, so the selection judges its own recorded
    /// facets, as it judges a text's source.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(in crate::sync) fn carries(
        &self,
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        // A use-limited row is storage only: the export withholds it and no
        // ordinary reader sees it, the owner included (FIX 5226).
        if crate::store::legal_hold::use_limit_in_txn(&vault.store, rtxn, id)?.is_some() {
            return Ok(false);
        }
        // A selector is a restricted lane: a row bound to a source audience,
        // by its own bytes or by the rows its words came from, never rides it.
        if crate::source_audience::row_obligation(raw).is_present()
            || crate::source_audience::withheld_from_replication_in(
                vault,
                rtxn,
                id,
                crate::source_audience::ReplicationScope::Restricted,
            )?
        {
            return Ok(false);
        }
        Ok(member_reads_row(vault, rtxn, &self.member, id, raw)?
            && source_selected(
                vault,
                rtxn,
                (id, raw),
                &self.authority,
                self.selector,
                self.position.as_scope(),
                &HashMap::new(),
            )?)
    }
}
