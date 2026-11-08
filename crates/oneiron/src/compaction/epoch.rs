//! Epoch summaries: the body codec ([`codec`]), each epoch's lineage
//! ([`lineage`]), the transactional mint ([`mint`]), and the fences an epoch
//! summary's sources put on its export and disclosure.

use crate::ports::{EdgeDirection, EdgeStoreRead, EntityRecord, EntityStoreRead};

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_SUMMARY;
use crate::store::{ManifestDbs, Store};

use super::stored_epoch::{StoredEpoch, stored_epoch_in};

mod codec;
mod lineage;
mod mint;

pub(super) use codec::{
    AT_ACTOR, AT_CONVERSATION, AT_EPOCH, AT_LEVEL, AT_SESSION, AT_TURN_END, AT_TURN_START, AT_V,
    KEY_EPOCH_TEXT,
};
pub use codec::{
    EPOCH_SUMMARY_BODY_KEYS, EPOCH_SUMMARY_BODY_VERSION, EPOCH_SUMMARY_LEVEL, EpochSummaryBody,
    decode_epoch_summary_body, encode_epoch_summary_body,
};
pub(crate) use lineage::{EpochScope, PriorEpoch};
pub(super) use lineage::{prior_epoch_in_txn, validate_epoch_boundary, validate_window_span};
pub(crate) use mint::EpochMint;
pub(super) use mint::{
    mint_epoch_summary_admitted_writer, mint_epoch_summary_guarded, mint_epoch_summary_in_overlay,
    mint_epoch_summary_with,
};

/// Walks every record an epoch summary's words came from: its `DerivedFrom`
/// targets, and theirs through any nested epoch summary, each record once.
///
/// A summary's own birth scope is its run's position and cannot stand for
/// what it was written from, so a reader that is not the owner takes an
/// epoch summary only while `admit` takes each record reached here (nested
/// summaries included). The walk refuses as soon as one is refused or a source no
/// longer resolves, or a summary's pointer does ([`stored_epoch_in`]).
/// `Ok(None)` when `body` is not an epoch summary.
pub(crate) fn epoch_sources_admitted_in(
    dbs: &impl ManifestDbs,
    rtxn: &heed::RoTxn<'_>,
    summary: &EntityId,
    body: &[u8],
    mut admit: impl FnMut(&EntityId, &EntityRecord) -> Result<bool>,
) -> Result<Option<bool>> {
    match stored_epoch_in(dbs, rtxn, summary, body)? {
        StoredEpoch::No => return Ok(None),
        StoredEpoch::Unresolved => return Ok(Some(false)),
        StoredEpoch::Yes => {}
    }
    let mut seen = std::collections::BTreeSet::from([*summary]);
    let mut pending = vec![*summary];
    while let Some(next) = pending.pop() {
        for edge in dbs.port_edges(
            rtxn,
            &next,
            EdgeDirection::Out,
            Some(EdgeKind::DerivedFrom),
            None,
        )? {
            let source = edge?.target;
            if !seen.insert(source) {
                continue;
            }
            let Some(row) = dbs.port_entity_record(rtxn, &source)? else {
                return Ok(Some(false));
            };
            if !admit(&source, &row)? {
                return Ok(Some(false));
            }
            if row.entity_type == ENTITY_TYPE_SUMMARY {
                match stored_epoch_in(dbs, rtxn, &source, &row.body)? {
                    StoredEpoch::No => {}
                    StoredEpoch::Yes => pending.push(source),
                    StoredEpoch::Unresolved => return Ok(Some(false)),
                }
            }
        }
    }
    Ok(Some(true))
}

/// Where a run's epoch summary is born: the run credential's world and
/// facet, as the run's other records are. `None` is a vault-wide run's:
/// base reality, and the vault's default facet (ARCH-0022: with no active
/// mask, the vault's default facet stamps a record).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EpochPlacement {
    pub(crate) world: Option<EntityId>,
    pub(crate) facet: Option<EntityId>,
}

impl EpochPlacement {
    /// Settles the minted summary's birth stamp in its mint transaction.
    pub(crate) fn settle_in(
        self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        summary: EntityId,
    ) -> Result<()> {
        let world = self
            .world
            .unwrap_or_else(oneiron_contracts::claim::base_world_id);
        let facet = match self.facet {
            Some(facet) => facet,
            None => crate::claim::default_facet_in(store, txn)?,
        };
        store
            .scope_stamps
            .settle_epoch_birth(store, txn, summary, world, facet)
    }
}

/// Whether row `id` may leave through an export door, as the epoch fence
/// judges it: an epoch summary leaves only while it is not withdrawn and the
/// door would carry every record its words came from, through nested epochs
/// (`carries` judges one source's row; an erased or withdrawn source carries
/// nothing). The fence never exports those sources along with it. Every
/// other row passes.
pub(crate) fn epoch_exportable_in(
    store: &impl ManifestDbs,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
    mut carries: impl FnMut(&EntityId, &EntityRecord) -> Result<bool>,
) -> Result<bool> {
    if entity_type != ENTITY_TYPE_SUMMARY {
        return Ok(true);
    }
    let withdrawn = |id: &EntityId| -> Result<bool> {
        let state = crate::ports::TombstoneStoreRead::port_deletion_state(store, rtxn, id)?;
        Ok(state.deleted || state.stale)
    };
    match epoch_sources_admitted_in(store, rtxn, id, body, |source, row| {
        Ok(!withdrawn(source)? && carries(source, row)?)
    })? {
        None => Ok(true),
        Some(false) => Ok(false),
        Some(true) => Ok(!withdrawn(id)?),
    }
}

/// Whether a reader who is not the owner may be shown row `id`, as the epoch
/// fence judges it: by the export door's rule, with `admits` judging one
/// source's row for that reader. An epoch summary shows only while neither
/// it nor any record its words came from (through nested epochs) is
/// withdrawn, and the reader may see each of those records. Every other row
/// passes.
pub(crate) fn epoch_disclosable_in(
    store: &impl ManifestDbs,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
    admits: impl FnMut(&EntityId, &EntityRecord) -> Result<bool>,
) -> Result<bool> {
    epoch_exportable_in(store, rtxn, id, entity_type, body, admits)
}
