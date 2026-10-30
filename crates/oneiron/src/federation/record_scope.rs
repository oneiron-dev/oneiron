//! Birth-facet-bound record-position stamps and scoped read/delete/export doors.
//!
//! Unstamped rows are never selected. Debug is an explicit read-only view, not
//! a wildcard selector. A body edit inherits its birth scope; a facet move
//! requires a new record, never a restamp of the same id. A NOTE's world
//! alone is read from its live `InWorld` edges at every read (`note_world`).
use super::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
    ports::{EdgeDirection, EdgeStoreRead},
    store::{ManifestDbs, Store},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

mod asset_body;
pub(crate) mod asset_text;
mod delete;
mod export;
pub(crate) mod note_world;
mod read;
// FIX 7608 slice 4: the masked copy a scoped export carries of a marked repo row.
mod secret_projection;
mod stamping;
#[cfg(test)]
mod tests;

pub(crate) use self::stamping::{
    has_stored_position, restrict_stamp_in_txn, room_rows_placed, settle_epoch_birth,
    settle_source_birth, stage_session_position, stamp_blob_project, stamp_import_audience_birth,
    stamp_leader_project, stamp_put, stamp_task_birth, stamp_task_fact,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeView {
    Normal,
    Debug,
}
#[derive(Debug, Clone, PartialEq)]
pub struct ScopedRecord {
    pub id: EntityId,
    /// Full entity metadata header and body; `Vault::get` returns only the body.
    pub bytes: Vec<u8>,
    pub scope: Option<Scope>,
    /// Only a Debug result may reveal a row suppressed by the normal selector.
    pub suppressed: bool,
    /// The row's birth as the export carries it, each ref the export does not
    /// carry withheld (Q26 = B); a scoped read carries none.
    pub birth: Option<crate::provenance::birth::RowBirth>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stamp {
    version: u8,
    kind: u8,
    birth_facet: [u8; 16],
    scope: Scope,
}
/// One entity's birth-position stamp, keyed by entity id.
const SCOPE_RECORD: SideTable<EntityId, Stamp, LegacyJson> =
    SideTable::new(&side_table::SCOPE_RECORD);
/// The vault's record-scope revision, bumped on every stamp change.
const SCOPE_RECORD_REVISION: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::SCOPE_RECORD_REVISION);

pub(crate) fn read_scope_revision(store: &impl ManifestDbs, txn: &heed::RoTxn<'_>) -> Result<u64> {
    match SCOPE_RECORD_REVISION.get(store, txn, &())? {
        None => Ok(0),
        Some(bytes) => {
            Ok(u64::from_le_bytes(bytes.as_slice().try_into().map_err(
                |_| Error::CorruptedIndex("record scope revision"),
            )?))
        }
    }
}

fn bump_scope_revision(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    let next = read_scope_revision(store, txn)?
        .checked_add(1)
        .ok_or(Error::IndexOverflow("record scope revision"))?;
    SCOPE_RECORD_REVISION.put(store, txn, &(), &next.to_le_bytes().to_vec())?;
    Ok(())
}

/// Settle a TASK that carries no birth stamp in base reality, as the upgrade
/// sweep does once: a TASK put before birth positions (#1401) was written by
/// a vault-wide writer. A stamp never travels with its TASK, so one a peer
/// replicates later stays unstamped, and a device-local world keeps it until
/// its world is known (DEC-0005).
pub(crate) fn backfill_task_base(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    data: &[u8],
) -> Result<()> {
    if SCOPE_RECORD.get(store, txn, &id)?.is_some() {
        return Ok(());
    }
    stamp_put(
        store,
        txn,
        id,
        crate::registry::ENTITY_TYPE_TASK,
        data,
        RowPut::Birth,
    )
}

/// Retire an id's scope sidecar in the same transaction that erases its body.
/// A later same-id write never inherits the deleted record's birth position.
pub(crate) fn retire_stamp(store: &Store, txn: &mut heed::RwTxn<'_>, id: EntityId) -> Result<()> {
    SCOPE_RECORD.delete(store, txn, &id)?;
    bump_scope_revision(store, txn)
}
fn singleton<T: Ord>(v: T) -> ScopeAxis<T> {
    ScopeAxis::Some(BTreeSet::from([v]))
}
/// What a put is to the row it writes: [`stamp_put`] mints a first position
/// for a row stored with none only at its local birth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RowPut {
    /// A local put of a row not stored before it, or a sweep that settles a
    /// stored row's first position.
    Birth,
    /// A local put of a row stored before it: a row stored with no position,
    /// as a replicated row is, keeps none (FIX 11925).
    LocalReput,
    /// A peer's replicated row.
    Replicated,
}
/// The world and facet a narrowed writer's TASKs are born at (ARCH-0067 §5:
/// a peer hears "my tasks" only where it may read them). An axis left `None`
/// keeps the default birth: base reality, under the record's own substrate
/// facet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BirthPosition {
    pub world: Option<EntityId>,
    pub facet: Option<EntityId>,
}
impl BirthPosition {
    /// The world a CLAIM born here names; base reality is a CLAIM with none.
    pub(crate) fn claim_world(self) -> Option<EntityId> {
        self.world
            .filter(|world| *world != crate::claim::base_world_id())
    }
}
pub(crate) fn default_stamp(kind: u8, facet: EntityId) -> Scope {
    Scope {
        worlds: singleton(ScopeId(crate::claim::base_world_id())),
        facets: singleton(ScopeId(facet)),
        bands: singleton(kind),
        audience: singleton(ScopeId(crate::claim::default_project_id())),
        // The record itself is not a capability. The operation is bound at evaluation.
        verbs: ScopeAxis::Bottom,
        sensitivity: SensitivityCeiling::AtMost(Sensitivity::Sensitive),
    }
}
fn carries_birth_stamp(kind: u8) -> bool {
    matches!(
        kind,
        crate::registry::ENTITY_TYPE_NOTE | crate::registry::ENTITY_TYPE_ASSET
    )
}
/// The facet a NOTE or ASSET was born under: the target of its one stored
/// `FacetOf` edge.
pub(crate) fn birth_facet(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<EntityId>> {
    let Some(row) = store
        .port_edges(
            txn,
            &id,
            EdgeDirection::Out,
            Some(crate::edge::EdgeKind::FacetOf),
            None,
        )?
        .next()
    else {
        return Ok(None);
    };
    Ok(Some(row?.target))
}

/// The position the row `id` of `kind`, with body `data`, is born at, read
/// on `store`, and the facet it is born under: a CLAIM's from its body, a
/// FACET at itself, a NOTE or ASSET under its one `FacetOf` target, an
/// ASSET_TEXT under its sources' facet, any other record under its own
/// substrate facet. A FACET or RELATIONSHIP keeps the sensitivity its body
/// declares. `None` for a NOTE or ASSET whose `FacetOf` is not written: no
/// position is inferred.
fn derived_position(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<Option<(Scope, EntityId)>> {
    let (mut scope, facet) = if kind == crate::registry::ENTITY_TYPE_CLAIM {
        let body = crate::claim::decode_claim_body(data, true)?;
        (body.record_scope("read"), body.scope_facet)
    } else if kind == crate::registry::ENTITY_TYPE_FACET {
        (default_stamp(kind, id), id)
    } else if carries_birth_stamp(kind) {
        let Some(facet) = birth_facet(store, txn, id)? else {
            return Ok(None);
        };
        let birth = default_stamp(kind, facet);
        let scope = note_world::note_position(store, txn, id, kind, birth);
        (scope, facet)
    } else if kind == crate::registry::ENTITY_TYPE_ASSET_TEXT {
        // A text born from its sources sits under their facet; one born
        // unplaced keeps its own (`asset_text`). A stamp added later is
        // refused by `stamp_put` as a restamp.
        let facet = asset_text::text_facet(store, txn, id)?;
        (default_stamp(kind, facet), facet)
    } else {
        let facet = crate::claim::substrate_facet_id(id)?;
        (default_stamp(kind, facet), facet)
    };
    // A locally authored RELATIONSHIP may declare its sensitivity just as a
    // FACET does. The resulting digest-bound record position, not a raw body
    // string read at export time, is the portable disclosure ceiling. Replayed
    // opaque rows remain unstamped and cannot become public here.
    if matches!(
        kind,
        crate::registry::ENTITY_TYPE_FACET | crate::registry::ENTITY_TYPE_RELATIONSHIP
    ) && let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut &data[..])
    {
        let bands: Vec<_> = entries
            .iter()
            .filter(|(k, _)| k.as_str() == Some("sensitivity"))
            .collect();
        if let [(_, value)] = bands.as_slice() {
            scope.sensitivity = SensitivityCeiling::AtMost(match value.as_str() {
                Some("public") => Sensitivity::Public,
                Some("private") => Sensitivity::Private,
                Some("sensitive") => Sensitivity::Sensitive,
                Some("restricted") => Sensitivity::Restricted,
                _ => {
                    return Err(Error::InvalidClaimBody(
                        "invalid facet or relationship sensitivity",
                    ));
                }
            });
        } else if !bands.is_empty() {
            return Err(Error::InvalidClaimBody(
                "duplicate facet or relationship sensitivity",
            ));
        }
    }
    scope.verbs = ScopeAxis::Bottom;
    Ok(Some((scope, facet)))
}

/// A TURN/MESSAGE body never proposes an audience: only
/// `stamp_leader_project` settles a non-default one, at the record's birth.
/// A BLOB_ARTIFACT's likewise: only `stamp_blob_project` settles one, in
/// the transaction that binds the blob to its project.
/// A SUMMARY body never proposes a world or facet: only `settle_epoch_birth`
/// settles them. An ASSET body never proposes a sensitivity either: a raise
/// (a secret-bearing ASSET marked Restricted, OF-560) leaves its stamp at a
/// band at least as sensitive as the default. A later content put recomputes
/// the default and keeps that settled position.
fn settled_at_birth(kind: u8, prior: &Scope, proposed: &Scope) -> bool {
    match kind {
        crate::registry::ENTITY_TYPE_ASSET => {
            proposed.sensitivity.is_narrowing_of(prior.sensitivity)
                && Scope {
                    sensitivity: proposed.sensitivity,
                    ..prior.clone()
                } == *proposed
        }
        crate::registry::ENTITY_TYPE_TURN
        | crate::registry::ENTITY_TYPE_MESSAGE
        | crate::registry::ENTITY_TYPE_BLOB_ARTIFACT => {
            Scope {
                audience: proposed.audience.clone(),
                ..prior.clone()
            } == *proposed
        }
        crate::registry::ENTITY_TYPE_SUMMARY => {
            Scope {
                worlds: proposed.worlds.clone(),
                facets: proposed.facets.clone(),
                ..prior.clone()
            } == *proposed
        }
        // A confirmed name keeps the facet `settle_source_birth` gave it:
        // every kind with a declared identity key (FIX 11382).
        kind if !crate::ingest::identity_fields_for_kind(kind).is_empty() => {
            Scope {
                facets: proposed.facets.clone(),
                ..prior.clone()
            } == *proposed
        }
        _ => false,
    }
}
/// A TASK body never proposes a position either: only `stamp_task_birth`
/// settles its writer's world and facet, at the record's birth. A later
/// content put recomputes the default and keeps that settled position.
fn writer_settled(prior: &Stamp, proposed: &Scope) -> bool {
    prior.kind == crate::registry::ENTITY_TYPE_TASK
        && matches!(&prior.scope.worlds, ScopeAxis::Some(worlds) if worlds.len() == 1)
        && EntityId::from_bytes(prior.birth_facet)
            .is_ok_and(|facet| prior.scope.facets == singleton(ScopeId(facet)))
        && Scope {
            worlds: proposed.worlds.clone(),
            facets: proposed.facets.clone(),
            ..prior.scope.clone()
        } == *proposed
}
fn stored_scope(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
) -> Result<Option<Scope>> {
    let Some(stamp) = SCOPE_RECORD.get(store, txn, &id)? else {
        return Ok(None);
    };
    if stamp.version != 2 || stamp.kind != kind {
        return Ok(None);
    }
    let facet = if kind == crate::registry::ENTITY_TYPE_CLAIM {
        // CLAIM carries its immutable facet in its body; `stamp_put` and the
        // promoted-replay door compare that body to this birth stamp.
        EntityId::from_bytes(stamp.birth_facet).ok()
    } else if kind == crate::registry::ENTITY_TYPE_FACET {
        Some(id)
    } else if carries_birth_stamp(kind) {
        birth_facet(store, txn, id)?
    } else if kind == crate::registry::ENTITY_TYPE_TASK {
        // A TASK is born under its writer's facet (`stamp_task_birth`) or its
        // own substrate facet; the stamp's one facet names which.
        EntityId::from_bytes(stamp.birth_facet)
            .ok()
            .filter(|facet| stamp.scope.facets == singleton(ScopeId(*facet)))
    } else if kind == crate::registry::ENTITY_TYPE_ASSET_TEXT {
        Some(asset_text::text_facet(store, txn, id)?)
    } else {
        Some(crate::claim::substrate_facet_id(id)?)
    };
    if facet.is_none_or(|facet| stamp.birth_facet != *facet.as_bytes()) {
        return Ok(None);
    }
    let scope = note_world::note_position(store, txn, id, kind, stamp.scope);
    Ok(Some(scope))
}
/// The world the stored row `id` of `kind`, with body `data`, sits in: what
/// every read that checks a world asks. A CLAIM, key pad or key wrap names its own; a
/// TASK and its authority facts sit where `stamp_task_birth` settled them,
/// and a SUMMARY
/// where `settle_epoch_birth` settled it, whatever its body reads now; an
/// epoch SUMMARY, in whatever form it is stored (`stored_epoch_in`), sits
/// where its birth stamp says; a NOTE where its live `InWorld` edges place
/// it (`note_world`); every other record, and any
/// other SUMMARY, is base reality (`Some(None)`). `None` where the row cannot
/// prove its world (an erased CLAIM, a TASK or epoch SUMMARY whose stamp is
/// gone or was never settled, a NOTE in no single world), which a read
/// narrowed on worlds keeps out.
pub(crate) fn record_world_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<Option<Option<EntityId>>> {
    if kind == crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(crate::claim::decode_claim_body(data, true)
            .ok()
            .map(|body| body.world));
    }
    // A live pad rides its world's windows (`sync::types::entity_world`).
    if kind == crate::registry::ENTITY_TYPE_WORLD_KEY_PAD {
        return Ok(crate::world_keys::pad_world_in_body(data).ok().map(Some));
    }
    // So do a world's key wraps; its settings entries are base reality.
    if kind == crate::registry::ENTITY_TYPE_AUTHORITY_LOG {
        return Ok(crate::authority::decode_authority_log_entry_body(data)
            .ok()
            .map(|entry| match entry.op {
                crate::authority::AuthorityOp::WorldKeyWraps(record) => Some(record.key.world),
                _ => None,
            }));
    }
    if kind == crate::registry::ENTITY_TYPE_NOTE {
        return Ok(note_world::note_worlds_in(store, txn, id).world());
    }
    let summary = kind == crate::registry::ENTITY_TYPE_SUMMARY;
    if kind != crate::registry::ENTITY_TYPE_TASK && !summary {
        return Ok(Some(None));
    }
    let worlds = stored_scope(store, txn, id, kind)?.map(|scope| scope.worlds);
    let stamped = match worlds {
        Some(ScopeAxis::Some(worlds)) if worlds.len() == 1 => worlds
            .first()
            .map(|world| Some(world.0).filter(|world| *world != crate::claim::base_world_id())),
        _ => None,
    };
    // An epoch summary is one whatever form its body takes, and a pointer no
    // head stands for may be one (Astra 1384e).
    if summary
        && stamped.flatten().is_none()
        && !crate::compaction::stored_epoch_in(store, txn, &id, data)?.may_be()
    {
        return Ok(Some(None));
    }
    Ok(stamped)
}
impl Vault {
    /// The world the live row `id` sits in, read on one snapshot as
    /// [`record_world_in`] reads it: `Some(None)` for base reality. `None`
    /// where no live row stands under `id` (none, or a deleted shell) or the
    /// row cannot prove its world.
    ///
    /// Read under no reader's scope: for dependency and invalidation sets
    /// only, never served to a caller. A caller that needs a row's world
    /// reads it through a [`crate::claim::ScopedRead`].
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn record_world(&self, id: &EntityId) -> Result<Option<Option<EntityId>>> {
        let txn = self.store.env.read_txn()?;
        match crate::vault::live_entity_row_in_txn(&self.store, &txn, id)? {
            crate::vault::LiveEntityRow::Live { entity_type, body } => {
                record_world_in(&self.store, &txn, *id, entity_type, &body)
            }
            crate::vault::LiveEntityRow::Absent | crate::vault::LiveEntityRow::DeletedShell => {
                Ok(None)
            }
        }
    }
}
/// Whether the TASK or authority-fact row `id`, with header and body `raw`,
/// sits by its birth stamp inside the worlds and facets `credential` grants.
/// An axis the credential leaves whole holds every position, so a credential
/// that narrows neither excludes no TASK. Under one that does, a row that
/// cannot prove its position is not inside, so no count names a denial of it
/// (ARCH-0067 §5, DEC-0005).
pub(crate) fn task_inside_credential(
    store: &(impl ManifestDbs + MachineHistoryScope),
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
    credential: &Scope,
) -> Result<bool> {
    let whole = |axis: &ScopeAxis<ScopeId>| matches!(axis, ScopeAxis::All);
    if whole(&credential.worlds) && whole(&credential.facets) {
        return Ok(true);
    }
    Ok(
        scope_for_blob(store, txn, id, raw)?.is_some_and(|position| {
            (whole(&credential.worlds) || !position.worlds.meet(&credential.worlds).is_bottom())
                && (whole(&credential.facets)
                    || !position.facets.meet(&credential.facets).is_bottom())
        }),
    )
}
/// A promoted edit may change content but cannot re-position the same id.
/// Read this in the author admission snapshot, before importing peer ops.
#[cfg(feature = "sync")]
pub(crate) fn validate_edit_birth_scope(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<()> {
    let stamp = SCOPE_RECORD
        .get(store, txn, &id)?
        .ok_or(Error::InvalidClaimBody("unstamped promoted edit"))?;
    if stamp.version != 2 || stamp.kind != kind || stored_scope(store, txn, id, kind)?.is_none() {
        return Err(Error::InvalidClaimBody("record scope restamp refused"));
    }
    if kind == crate::registry::ENTITY_TYPE_CLAIM {
        let body = crate::claim::decode_claim_body(data, true)?;
        let mut proposed = body.record_scope("read");
        proposed.verbs = ScopeAxis::Bottom;
        if proposed != stamp.scope || stamp.birth_facet != *body.scope_facet.as_bytes() {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
    }
    if matches!(
        kind,
        crate::registry::ENTITY_TYPE_FACET | crate::registry::ENTITY_TYPE_RELATIONSHIP
    ) {
        let proposed = match rmpv::decode::read_value(&mut &data[..]) {
            Ok(rmpv::Value::Map(entries)) => {
                let bands: Vec<_> = entries
                    .iter()
                    .filter(|(key, _)| key.as_str() == Some("sensitivity"))
                    .collect();
                match bands.as_slice() {
                    [] => Sensitivity::Sensitive,
                    [(_, value)] => match value.as_str() {
                        Some("public") => Sensitivity::Public,
                        Some("private") => Sensitivity::Private,
                        Some("sensitive") => Sensitivity::Sensitive,
                        Some("restricted") => Sensitivity::Restricted,
                        _ => return Err(Error::InvalidClaimBody("invalid facet sensitivity")),
                    },
                    _ => return Err(Error::InvalidClaimBody("duplicate facet sensitivity")),
                }
            }
            _ => Sensitivity::Sensitive,
        };
        if stamp.scope.sensitivity != SensitivityCeiling::AtMost(proposed) {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
    }
    Ok(())
}

/// Derive only an intrinsic current stamp or a birth-facet-bound persisted stamp.
/// A text document pointer changes representation, not birth authority.
/// The birth stamp is body-independent, so there is nothing to restamp.
pub(crate) fn restamp_document_pointer(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kind: u8,
    _original: &[u8],
    _pointer: &[u8],
) -> Result<()> {
    let _ = stored_scope(store, txn, id, kind)?;
    Ok(())
}
/// This is the sync-export seam; arbitrary remote opaque rows remain unstamped.
pub(crate) fn scope_for_blob(
    store: &(impl ManifestDbs + MachineHistoryScope),
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
) -> Result<Option<Scope>> {
    let h = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("record header"))?;
    let data = &raw[ENTITY_METADATA_HEADER_LEN..];
    if h.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
        let Ok(body) = crate::claim::decode_claim_body(data, true) else {
            return Ok(None);
        };
        if let Some(effective) = store.machine_history_scope(txn, &body)? {
            return Ok(effective);
        }
        return Ok(Some(body.record_scope("read")));
    }
    if carries_birth_stamp(h.entity_type) {
        return Ok(birth_facet(store, txn, id)?.map(|facet| {
            let birth = default_stamp(h.entity_type, facet);
            let mut scope = note_world::note_position(store, txn, id, h.entity_type, birth);
            scope.verbs = singleton("read".to_owned());
            scope
        }));
    }
    let mut scope = stored_scope(store, txn, id, h.entity_type)?;
    if let Some(scope) = scope.as_mut() {
        scope.verbs = singleton("read".to_owned());
    }
    Ok(scope)
}
/// Control bytes inherit the CURRENT projected claim's effective audience,
/// including signed sensitivity demotion. Immutable birth scope can never be
/// used to disclose an older, less restricted copy after narrowing.
/// Signed MACHINE history resolves against the base vault's authority fold.
pub(crate) trait MachineHistoryScope {
    /// `None` for an ordinary claim; `Some(None)` withholds a history control.
    fn machine_history_scope(
        &self,
        txn: &heed::RoTxn<'_>,
        body: &ClaimBody,
    ) -> Result<Option<Option<Scope>>>;
}

impl MachineHistoryScope for Store {
    fn machine_history_scope(
        &self,
        txn: &heed::RoTxn<'_>,
        body: &ClaimBody,
    ) -> Result<Option<Option<Scope>>> {
        machine_history_disclosure_scope(self, txn, body)
    }
}

/// A session overlay never stages signed history; its controls stay withheld.
impl MachineHistoryScope for crate::store::SessionStoreView<'_> {
    fn machine_history_scope(
        &self,
        _txn: &heed::RoTxn<'_>,
        body: &ClaimBody,
    ) -> Result<Option<Option<Scope>>> {
        Ok(crate::claim::history_store::machine_history_kind(&body.predicate).map(|_| None))
    }
}

/// A read target answers as the store it reads: a room's union as its view
/// does, base as the vault does.
impl MachineHistoryScope for crate::store::StoreRead<'_> {
    fn machine_history_scope(
        &self,
        txn: &heed::RoTxn<'_>,
        body: &ClaimBody,
    ) -> Result<Option<Option<Scope>>> {
        if self.is_union() {
            Ok(crate::claim::history_store::machine_history_kind(&body.predicate).map(|_| None))
        } else {
            machine_history_disclosure_scope(self.base(), txn, body)
        }
    }
}

fn machine_history_disclosure_scope(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Result<Option<Option<Scope>>> {
    if crate::claim::history_store::machine_history_kind(&body.predicate).is_none() {
        return Ok(None);
    }
    let ClaimSubject::Entity(target) = body.subject else {
        return Ok(Some(None));
    };
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
        store,
        store.privacy_posture,
        txn,
    )?;
    match crate::claim::history_projection::resolved_machine_history(store, txn, &fold, target) {
        Ok(projection) => {
            let mut effective =
                crate::claim::history_projection::project_machine_claim(&projection)
                    .record_scope("read");
            if projection.stale {
                effective.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Restricted);
            }
            Ok(Some(Some(effective)))
        }
        Err(Error::Claim(crate::error::ClaimError::MachineClaimHistoryIncomplete))
        | Err(Error::Claim(crate::error::ClaimError::InvalidMachineClaimProof)) => Ok(Some(None)),
        Err(other) => Err(other),
    }
}

/// The position the scoped read and export doors select the stored row of
/// `id` at, from its body `data` of `kind`: a history control's current
/// effective audience, or the row's birth stamp; `None` where neither door
/// selects it. `store` is the content the row is read on: base, or a room's
/// union, whose rows carry the positions their writes staged and whose
/// history controls stay withheld (WILL L11-01).
pub(crate) fn disclosure_scope_for_stored_row(
    store: &(impl ManifestDbs + MachineHistoryScope),
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<Option<Scope>> {
    if kind == crate::registry::ENTITY_TYPE_CLAIM {
        let body = crate::claim::decode_claim_body(data, true)?;
        if let Some(scope) = store.machine_history_scope(txn, &body)? {
            return Ok(scope);
        }
    }
    stored_scope(store, txn, id, kind)
}

fn admits(scope: &Scope, selector: &Scope, slip: &Scope, channel: &Scope, verb: &str) -> bool {
    let mut record = scope.clone();
    record.verbs = singleton(verb.to_owned());
    record.is_narrowing_of(selector) && slip.admits(verb, &record, channel)
}
impl Vault {
    /// The epoch fence at a scoped door: an epoch summary passes only while
    /// this door, under `door` (selector, slip, channel) and `verb`, passes
    /// every record its words came from.
    fn epoch_fence_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        raw: &[u8],
        [selector, slip, channel]: [&Scope; 3],
        verb: &str,
    ) -> Result<bool> {
        let h = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("record header"))?;
        crate::compaction::epoch_exportable_in(
            &self.store,
            txn,
            &id,
            h.entity_type,
            &raw[ENTITY_METADATA_HEADER_LEN..],
            |source, row| {
                let door = [selector, slip, channel];
                Ok(disclosure_scope_for_stored_row(
                    &self.store,
                    txn,
                    *source,
                    row.entity_type,
                    &row.body,
                )?
                .is_some_and(|scope| {
                    note_world::admits_at(
                        &self.store,
                        txn,
                        *source,
                        row.entity_type,
                        &scope,
                        door,
                        verb,
                    )
                }) && crate::authority::row_causal_admitted(self, txn, source, &row.encode())?)
            },
        )
    }
    /// The text fence at a scoped door (facet rule C): an ASSET_TEXT passes
    /// only while this door, under `door` (selector, slip, channel) and
    /// `verb`, passes every source ASSET it was written from, live and
    /// causally admitted, and none of them is `withheld` here.
    fn text_fence_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        raw: &[u8],
        [selector, slip, channel]: [&Scope; 3],
        verb: &str,
        mut withheld: impl FnMut(&EntityId) -> Result<bool>,
    ) -> Result<bool> {
        if raw.first() != Some(&crate::registry::ENTITY_TYPE_ASSET_TEXT) {
            return Ok(true);
        }
        let admitted = asset_text::sources_admitted_in(&self.store, txn, &id, |source, row| {
            Ok(!withheld(source)?
                && disclosure_scope_for_stored_row(
                    &self.store,
                    txn,
                    *source,
                    row.entity_type,
                    &row.body,
                )?
                .is_some_and(|scope| admits(&scope, selector, slip, channel, verb))
                && crate::authority::row_causal_admitted(self, txn, source, &row.encode())?)
        })?;
        Ok(admitted.unwrap_or(true))
    }
}
