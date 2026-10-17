//! Birth-facet-bound record-position stamps and scoped read/delete/export doors.
//!
//! Unstamped rows are never selected. Debug is an explicit read-only view, not
//! a wildcard selector. A body edit inherits its birth scope; a facet move
//! requires a new record, never a restamp of the same id.
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

pub(crate) mod asset_text;
mod export;
#[cfg(test)]
mod tests;

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
        false,
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
pub(crate) fn stamp_put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
    replicated: bool,
) -> Result<()> {
    bump_scope_revision(store, txn)?;
    let prior = SCOPE_RECORD.get(store, txn, &id)?;
    let (mut scope, facet) = if kind == crate::registry::ENTITY_TYPE_CLAIM {
        let body = crate::claim::decode_claim_body(data, true)?;
        (body.record_scope("read"), body.scope_facet)
    } else if kind == crate::registry::ENTITY_TYPE_FACET {
        (default_stamp(kind, id), id)
    } else if carries_birth_stamp(kind) {
        let Some(facet) = birth_facet(store, txn, id)? else {
            if prior.is_some() {
                return Err(Error::InvalidClaimBody("birth facet restamp refused"));
            }
            // A birth without its same-transaction FacetOf is not stamped.
            return Ok(());
        };
        (default_stamp(kind, facet), facet)
    } else if kind == crate::registry::ENTITY_TYPE_ASSET_TEXT {
        // A text born from its sources sits under their facet; one born
        // unplaced keeps its own (`asset_text`). A stamp added later is
        // refused below as a restamp.
        let facet = asset_text::text_facet(store, txn, id)?;
        (default_stamp(kind, facet), facet)
    } else {
        let facet = crate::claim::substrate_facet_id(id)?;
        (default_stamp(kind, facet), facet)
    };
    // A locally authored RELATIONSHIP may declare its sensitivity just as a
    // FACET does. The resulting digest-bound record position, not a raw body
    // string read at export time, is the portable disclosure ceiling. Replayed
    // opaque rows above remain unstamped and cannot become public here.
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
    if let Some(prior) = prior {
        // Content is mutable. The type, facet and authority position are NOT.
        // A changed facet/sensitivity/world/audience is a fork with a new id.
        let kept = prior.birth_facet == *facet.as_bytes()
            && (prior.scope == scope || settled_at_birth(kind, &prior.scope, &scope));
        if prior.version != 2 || prior.kind != kind || !(kept || writer_settled(&prior, &scope)) {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
        return Ok(());
    }
    if replicated && kind != crate::registry::ENTITY_TYPE_CLAIM {
        // A peer cannot mint a birth position for an opaque row merely by
        // picking its ID and bytes. Only an existing stamped row inherits.
        return Ok(());
    }
    let stamp = Stamp {
        version: 2,
        kind,
        birth_facet: *facet.as_bytes(),
        scope,
    };
    SCOPE_RECORD.put(store, txn, &id, &stamp)?;
    Ok(())
}
/// A TURN/MESSAGE body never proposes an audience: only
/// `stamp_leader_project` settles a non-default one, at the record's birth.
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
        crate::registry::ENTITY_TYPE_TURN | crate::registry::ENTITY_TYPE_MESSAGE => {
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
        _ => false,
    }
}
/// Settles an epoch SUMMARY's birth position in its mint transaction: born
/// in `world` under `facet`, where its run's records are born, never the
/// generic SUMMARY position. Only the default stamp `stamp_put` just wrote
/// may be settled; its structural anchor and every other axis stay.
pub(crate) fn settle_epoch_birth(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    world: EntityId,
    facet: EntityId,
) -> Result<()> {
    let kind = crate::registry::ENTITY_TYPE_SUMMARY;
    let anchor = crate::claim::substrate_facet_id(id)?;
    let birth = default_stamp(kind, anchor);
    let prior = SCOPE_RECORD
        .get(store, txn, &id)?
        .ok_or(Error::InvalidClaimBody("unstamped epoch summary"))?;
    if prior.version != 2
        || prior.kind != kind
        || prior.birth_facet != *anchor.as_bytes()
        || prior.scope != birth
    {
        return Err(Error::InvalidClaimBody("record scope restamp refused"));
    }
    let mut scope = birth;
    scope.worlds = singleton(ScopeId(world));
    scope.facets = singleton(ScopeId(facet));
    bump_scope_revision(store, txn)?;
    SCOPE_RECORD.put(
        store,
        txn,
        &id,
        &Stamp {
            version: 2,
            kind,
            birth_facet: *anchor.as_bytes(),
            scope,
        },
    )?;
    Ok(())
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
/// Raises a stamped record's sensitivity to at least `band`, in the
/// transaction that stored it (OF-560: a file the write door kept with keys
/// in it is Restricted). Every other axis stays. An unstamped record stays
/// unstamped, and a stamp already as strict stays as it is.
pub(crate) fn restrict_stamp_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    band: Sensitivity,
) -> Result<()> {
    let Some(mut stamp) = SCOPE_RECORD.get(store, txn, &id)? else {
        return Ok(());
    };
    if matches!(stamp.scope.sensitivity, SensitivityCeiling::AtMost(at) if at >= band) {
        return Ok(());
    }
    stamp.scope.sensitivity = SensitivityCeiling::AtMost(band);
    bump_scope_revision(store, txn)?;
    SCOPE_RECORD.put(store, txn, &id, &stamp)
}
/// Settle a locally minted TASK at its writer's world and facet, in the
/// transaction that put its first body. The writer's facet is provenance:
/// the mask that spoke stamps the record (ARCH-0022 "Every record carries a
/// facet").
///
/// The birth position is immutable (see `stamp_put`): like
/// `stamp_leader_project`, this door only moves the record's own default
/// birth stamp, or confirms the position it already carries. Any other prior
/// position is refused. Opaque replicated rows cannot call it and remain
/// unstamped.
pub(crate) fn stamp_task_birth(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    position: BirthPosition,
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("task birth scope header"))?;
    let kind = header.entity_type;
    if kind != crate::registry::ENTITY_TYPE_TASK {
        return Err(Error::InvalidEntityType(kind));
    }
    let substrate = crate::claim::substrate_facet_id(id)?;
    let facet = position.facet.unwrap_or(substrate);
    let mut scope = default_stamp(kind, facet);
    if let Some(world) = position.world {
        scope.worlds = singleton(ScopeId(world));
    }
    if let Some(prior) = SCOPE_RECORD.get(store, txn, &id)? {
        let settled = prior.birth_facet == *facet.as_bytes() && prior.scope == scope;
        let birth = prior.birth_facet == *substrate.as_bytes()
            && prior.scope == default_stamp(kind, substrate);
        if prior.version != 2 || prior.kind != kind || !(settled || birth) {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
        if settled {
            return Ok(());
        }
    }
    bump_scope_revision(store, txn)?;
    SCOPE_RECORD.put(
        store,
        txn,
        &id,
        &Stamp {
            version: 2,
            kind,
            birth_facet: *facet.as_bytes(),
            scope,
        },
    )?;
    Ok(())
}
/// An authority fact about one TASK is born at that TASK's settled position,
/// so a reader outside the TASK's world reads none of the facts about it. A
/// TASK at its default birth, or with no stamp, leaves the fact at its own.
pub(crate) fn stamp_task_fact(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    fact: EntityId,
    task: EntityId,
) -> Result<()> {
    let Some(stamp) = SCOPE_RECORD.get(store, txn, &task)? else {
        return Ok(());
    };
    if stamp.version != 2 || stamp.kind != crate::registry::ENTITY_TYPE_TASK {
        return Ok(());
    }
    let world = match &stamp.scope.worlds {
        ScopeAxis::Some(worlds) if worlds.len() == 1 => worlds.first().map(|world| world.0),
        _ => None,
    };
    let substrate = crate::claim::substrate_facet_id(task)?;
    let position = BirthPosition {
        world: world.filter(|world| *world != crate::claim::base_world_id()),
        facet: EntityId::from_bytes(stamp.birth_facet)
            .ok()
            .filter(|facet| *facet != substrate),
    };
    if position == BirthPosition::default() {
        return Ok(());
    }
    stamp_task_birth(store, txn, fact, position)
}
/// Restamp a locally authenticated leader-chat TURN/MESSAGE at the ordinary
/// record-position scope door, after the typed write's full batch succeeds.
/// Opaque replicated rows cannot call this door and remain unstamped.
///
/// The birth position is immutable (see `stamp_put`): this door only moves
/// the record's own default birth stamp to the leader's project, or confirms
/// the leader stamp it already carries. Any other prior position is refused.
pub(crate) fn stamp_leader_project(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    project: EntityId,
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("leader chat scope header"))?;
    let kind = header.entity_type;
    if !matches!(
        kind,
        crate::registry::ENTITY_TYPE_TURN | crate::registry::ENTITY_TYPE_MESSAGE
    ) {
        return Err(Error::InvalidEntityType(kind));
    }
    let facet = crate::claim::substrate_facet_id(id)?;
    let birth = default_stamp(kind, facet);
    let mut scope = birth.clone();
    scope.audience = singleton(ScopeId(project));
    if let Some(prior) = SCOPE_RECORD.get(store, txn, &id)? {
        if prior.version != 2
            || prior.kind != kind
            || prior.birth_facet != *facet.as_bytes()
            || (prior.scope != birth && prior.scope != scope)
        {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
        if prior.scope == scope {
            return Ok(());
        }
    }
    bump_scope_revision(store, txn)?;
    SCOPE_RECORD.put(
        store,
        txn,
        &id,
        &Stamp {
            version: 2,
            kind,
            birth_facet: *facet.as_bytes(),
            scope,
        },
    )?;
    Ok(())
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
    Ok(Some(stamp.scope))
}
/// The world the stored row `id` of `kind`, with body `data`, sits in: what
/// every read that checks a world asks. A CLAIM names its own; a TASK and its
/// authority facts sit where `stamp_task_birth` settled them, and a SUMMARY
/// where `settle_epoch_birth` settled it, whatever its body reads now; an
/// epoch SUMMARY, in whatever form it is stored (`stored_epoch_in`), sits
/// where its birth stamp says; every other record, and any
/// other SUMMARY, is base reality (`Some(None)`). `None` where the row cannot
/// prove its world (an erased CLAIM, a TASK or epoch SUMMARY whose stamp is
/// gone or was never settled), which a read narrowed on worlds keeps out.
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
#[cfg(feature = "sync")]
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
            let mut scope = default_stamp(h.entity_type, facet);
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
/// selects it.
pub(crate) fn disclosure_scope_for_stored_row(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<Option<Scope>> {
    if kind == crate::registry::ENTITY_TYPE_CLAIM {
        let body = crate::claim::decode_claim_body(data, true)?;
        if let Some(scope) = machine_history_disclosure_scope(store, txn, &body)? {
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
    /// Read the current positive stamp. Missing or stale stamps are not inferred.
    pub fn record_scope(&self, id: &EntityId) -> Result<Option<Scope>> {
        let txn = self.store.env.read_txn()?;
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, id)?
        else {
            return Ok(None);
        };
        let h = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("record header"))?;
        disclosure_scope_for_stored_row(
            &self.store,
            &txn,
            *id,
            h.entity_type,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )
    }
    /// Scoped reads bind a selector, the authenticated slip's Scope and channel.
    /// Debug additionally requires an explicit `debug` class on that slip.
    /// A SECRET_CUSTODY row is never a scoped record, in either view: its body
    /// carries the value, which only its binding door reads. Nor is an LFS
    /// chunk that no published object holds yet.
    pub fn records_in_scope(
        &self,
        selector: &Scope,
        slip: &Scope,
        channel: &Scope,
        view: ScopeView,
    ) -> Result<Vec<ScopedRecord>> {
        if view == ScopeView::Debug {
            let mut root = Scope::top();
            root.verbs = singleton("debug".to_owned());
            if !slip.admits("debug", &root, channel) {
                return Err(Error::InvalidClaimBody(
                    "unattenuated debug capability required",
                ));
            }
        }
        let txn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, &txn)? {
            let (id, raw) = row?;
            let h =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("record header"))?;
            if h.entity_type == crate::registry::ENTITY_TYPE_SECRET_CUSTODY
                || crate::origin::lfs::unpublished_lfs_chunk_in_txn(
                    &self.store,
                    &txn,
                    &id,
                    h.entity_type,
                )?
            {
                continue;
            }
            let scope = disclosure_scope_for_stored_row(
                &self.store,
                &txn,
                id,
                h.entity_type,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )?;
            let fences_pass = |door: [&Scope; 3]| -> Result<bool> {
                Ok(
                    crate::authority::row_causal_admitted(self, &txn, &id, &raw)?
                        && self.epoch_fence_in(&txn, id, &raw, door, "read")?
                        && self.text_fence_in(&txn, id, &raw, door, "read", |_| Ok(false))?,
                )
            };
            let withdrawn = !crate::ports::raw_readable_in_txn(&self.store, &txn, &id, &raw)?;
            let allowed = !withdrawn
                && scope
                    .as_ref()
                    .is_some_and(|scope| admits(scope, selector, slip, channel, "read"))
                && fences_pass([selector, slip, channel])?;
            if !allowed && view == ScopeView::Normal {
                continue;
            }
            // Debug reveals what the selector suppressed, never words that
            // are withdrawn or that a fence refuses: such a row keeps only
            // its header.
            let words = allowed || (!withdrawn && fences_pass([&Scope::top(), slip, channel])?);
            let mut bytes = raw;
            if !words {
                bytes.truncate(ENTITY_METADATA_HEADER_LEN);
            }
            out.push(ScopedRecord {
                id,
                bytes,
                scope,
                suppressed: !allowed,
                birth: None,
            });
        }
        Ok(out)
    }
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
                Ok(disclosure_scope_for_stored_row(
                    &self.store,
                    txn,
                    *source,
                    row.entity_type,
                    &row.body,
                )?
                .is_some_and(|scope| admits(&scope, selector, slip, channel, verb))
                    && crate::authority::row_causal_admitted(self, txn, source, &row.encode())?)
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
    /// Selection and delete share one write transaction; no row can change between them.
    pub fn delete_records_in_scope(
        &self,
        selector: &Scope,
        slip: &Scope,
        channel: &Scope,
    ) -> Result<Vec<EntityId>> {
        self.with_write_txn_grouped(|txn| {
            let mut ids = Vec::new();
            for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, txn)? {
                let (id, raw) = row?;
                let h = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("record header"))?;
                if let Some(scope) = stored_scope(&self.store, txn, id, h.entity_type)?
                    && admits(&scope, selector, slip, channel, "delete")
                {
                    ids.push(id);
                }
            }
            let mut batch = self.batch_in();
            for id in &ids {
                batch = batch.delete(id);
            }
            batch.apply(txn)?;
            for id in &ids {
                retire_stamp(&self.store, txn, *id)?;
            }
            Ok(ids)
        })
    }
}
