//! Core half of `origin::publication::publication_codec`: its store-layer items live in `oneiron_store::origin::publication::publication_codec` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::publication::publication_codec::*;

use super::publication_types::{
    ORIGIN_PUBLICATION_CLAIM_ID_DOMAIN, ORIGIN_PUBLICATION_COMMIT_ID_DOMAIN,
    ORIGIN_PUBLICATION_ID_DOMAIN, ORIGIN_PUBLICATION_INTENT_PREDICATE,
    ORIGIN_PUBLICATION_MAX_FAILURE_BYTES, ORIGIN_PUBLICATION_PREDICATE,
    ORIGIN_PUBLICATION_SCHEMA_VERSION, ORIGIN_PUBLICATION_VALUE_KEYS, OriginActor,
    OriginKeepRefKind, OriginPublicationRecord, OriginPublicationRequest, OriginPublicationStatus,
};
use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::git_wire::{GIT_WIRE_KEEP_REF_PREFIX, GitOid, GitRefName};
use crate::origin::lfs::LfsOid;
use crate::side_table::{self, Named, Raw, SideKey, SideTable};
use crate::store::code_snapshot::entity_id_from_hash_material;
use crate::temporal::TimeRange;
use crate::write_envelope::claim_body::{ClaimBody, ClaimSubject};
use oneiron_contracts::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use rmpv::Value;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Keys, tables and rows
// ---------------------------------------------------------------------------

/// Durable journal row for one origin ref-publication attempt. Key: publication id.
pub(super) const PUBLICATIONS: SideTable<EntityId, OriginPublicationRow, Named> =
    SideTable::new(&side_table::ORIGIN_PUBLICATION_RECORD);

/// The owner of `(repo, ref, expected, new)`, independent of provenance (value = owning
/// publication id): in flight while Prepared, and for good once Published, since the move is then
/// consumed. Key: repo id "\x00" ref_name "\x00" expected_old_oid "\x00" new_oid.
pub(super) const CAS_INTENT: SideTable<CasIntentKey, EntityId, Raw> =
    SideTable::new(&side_table::ORIGIN_CAS_INTENT);

/// Present once every Published row has its CAS row. Key: ().
pub(super) const CAS_BACKFILL: SideTable<(), (), Raw> =
    SideTable::new(&side_table::ORIGIN_CAS_BACKFILL);

/// The publication currently advertised for one repository's ref name (value = publication id).
/// Key: repo id "\x00" ref_name.
pub(super) const VISIBLE_REF: SideTable<VisibleRefKey, EntityId, Raw> =
    SideTable::new(&side_table::ORIGIN_VISIBLE_REF);

/// One logical owner's reservation of a physical git keep-ref (value = u64be learned_at)... the
/// value is actually u64 LE, unchanged from the pre-side-table row. Key: repo id "\x00" oid
/// "\x00" kind "\x00" owner_key.
pub(super) const KEEP_OWNER: SideTable<KeepOwnerKey, [u8; 8], Raw> =
    SideTable::new(&side_table::ORIGIN_KEEP_OWNER);

/// Erasing `actor` from the publication journal (FIX 3520): each publication
/// it made keeps its row, its move, its objects, its state and its times, and
/// names no one. The ref, its CAS row and its keep-ref owners stay as they
/// are and nothing is retried; a replay of the publication is refused, as no
/// actor matches it. One-way, in the erase's own transaction. An id whose
/// entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a journal row that cannot be read.
pub(crate) fn erase_publication_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if let Some(raw) = vault.get_raw_in(wtxn, actor)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
        && !matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        )
    {
        return Ok(());
    }
    let erased = Some(*actor.as_bytes());
    let mut rows = Vec::new();
    for (id, mut row) in PUBLICATIONS.scan(&vault.store, wtxn)? {
        if row.actor_id == erased {
            row.actor_id = None;
            rows.push((id, row));
        }
    }
    for (id, row) in rows {
        PUBLICATIONS.put(&vault.store, wtxn, &id, &row)?;
    }
    Ok(())
}
