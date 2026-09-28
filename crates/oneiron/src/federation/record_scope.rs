//! Birth-facet-bound record-position stamps and scoped read/delete/export doors.
//!
//! Unstamped rows are never selected. Debug is an explicit read-only view, not
//! a wildcard selector. A body edit inherits its birth scope; a facet move
//! requires a new record, never a restamp of the same id.
use super::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
    store::{ManifestDbs, Store},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stamp {
    version: u8,
    kind: u8,
    birth_facet: [u8; 16],
    scope: Scope,
}
const RECORD_SCOPE_REVISION_KEY: &[u8] = b"scope:record:revision:v1";

pub(crate) fn read_scope_revision(store: &impl ManifestDbs, txn: &heed::RoTxn<'_>) -> Result<u64> {
    match store.vault_meta().get(txn, RECORD_SCOPE_REVISION_KEY)? {
        None => Ok(0),
        Some(bytes) => {
            Ok(u64::from_le_bytes(bytes.as_ref().try_into().map_err(
                |_| Error::CorruptedIndex("record scope revision"),
            )?))
        }
    }
}

fn bump_scope_revision(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    let next = read_scope_revision(store, txn)?
        .checked_add(1)
        .ok_or(Error::IndexOverflow("record scope revision"))?;
    store
        .vault_meta
        .put(txn, RECORD_SCOPE_REVISION_KEY, &next.to_le_bytes())?;
    Ok(())
}

fn key(id: EntityId) -> Vec<u8> {
    let mut key = b"scope:record:v2:".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}
/// Retire an id's scope sidecar in the same transaction that erases its body.
/// A later same-id write never inherits the deleted record's birth position.
pub(crate) fn retire_stamp(store: &Store, txn: &mut heed::RwTxn<'_>, id: EntityId) -> Result<()> {
    store.vault_meta.delete(txn, &key(id))?;
    bump_scope_revision(store, txn)
}
fn singleton<T: Ord>(v: T) -> ScopeAxis<T> {
    ScopeAxis::Some(BTreeSet::from([v]))
}
fn default_stamp(kind: u8, facet: EntityId) -> Scope {
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
    let prefix = crate::vault::edge_kind_prefix(&id, crate::edge::EdgeKind::FacetOf);
    let Some(row) = store.edges_out().prefix_iter(txn, &prefix)?.next() else {
        return Ok(None);
    };
    let (key, value) = row?;
    Ok(Some(crate::vault::parse_edge_record(&key, &value)?.target))
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
    let prior = store
        .vault_meta
        .get(txn, &key(id))?
        .map(|bytes| {
            serde_json::from_slice::<Stamp>(&bytes)
                .map_err(|_| Error::CorruptedIndex("record scope stamp"))
        })
        .transpose()?;
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
    } else {
        let facet = crate::claim::substrate_facet_id(id);
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
        if prior.version != 2
            || prior.kind != kind
            || prior.birth_facet != *facet.as_bytes()
            || prior.scope != scope
        {
            return Err(Error::InvalidClaimBody("record scope restamp refused"));
        }
        return Ok(());
    }
    if replicated
        && kind != crate::registry::ENTITY_TYPE_CLAIM
        && !(kind == crate::registry::ENTITY_TYPE_FACET
            && crate::companion::is_identity_facet_body(data))
    {
        // A peer cannot mint a birth position for an opaque row merely by
        // picking its ID and bytes. Only an existing stamped row inherits.
        return Ok(());
    }
    let bytes = serde_json::to_vec(&Stamp {
        version: 2,
        kind,
        birth_facet: *facet.as_bytes(),
        scope,
    })
    .map_err(|_| Error::InvariantViolation("scope stamp encode"))?;
    store.vault_meta.put(txn, &key(id), &bytes)?;
    Ok(())
}
fn stored_scope(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
) -> Result<Option<Scope>> {
    let Some(bytes) = store.vault_meta().get(txn, &key(id))? else {
        return Ok(None);
    };
    let stamp: Stamp =
        serde_json::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("record scope stamp"))?;
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
    } else {
        Some(crate::claim::substrate_facet_id(id))
    };
    if facet.is_none_or(|facet| stamp.birth_facet != *facet.as_bytes()) {
        return Ok(None);
    }
    Ok(Some(stamp.scope))
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
    let raw = store
        .vault_meta
        .get(txn, &key(id))?
        .ok_or(Error::InvalidClaimBody("unstamped promoted edit"))?;
    let stamp: Stamp =
        serde_json::from_slice(&raw).map_err(|_| Error::CorruptedIndex("record scope stamp"))?;
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
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    raw: &[u8],
) -> Result<Option<Scope>> {
    let h = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("record header"))?;
    let data = &raw[ENTITY_METADATA_HEADER_LEN..];
    if h.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(crate::claim::decode_claim_body(data, true)
            .ok()
            .map(|body| body.record_scope("read")));
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
fn admits(scope: &Scope, selector: &Scope, slip: &Scope, channel: &Scope, verb: &str) -> bool {
    let mut record = scope.clone();
    record.verbs = singleton(verb.to_owned());
    record.is_narrowing_of(selector) && slip.admits(verb, &record, channel)
}
impl Vault {
    /// Read the current positive stamp. Missing or stale stamps are not inferred.
    pub fn record_scope(&self, id: &EntityId) -> Result<Option<Scope>> {
        let txn = self.store.env.read_txn()?;
        let Some(raw) = self.store.entities.get(&txn, id.as_bytes())? else {
            return Ok(None);
        };
        let h = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("record header"))?;
        stored_scope(&self.store, &txn, *id, h.entity_type)
    }
    /// Scoped reads bind a selector, the authenticated slip's Scope and channel.
    /// Debug additionally requires an explicit `debug` class on that slip.
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
        for row in self.store.entities.iter(&txn)? {
            let (key, raw) = row?;
            let id = EntityId::from_bytes(
                key.as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("record id"))?,
            )?;
            let h =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("record header"))?;
            let scope = stored_scope(&self.store, &txn, id, h.entity_type)?;
            let allowed = scope
                .as_ref()
                .is_some_and(|scope| admits(scope, selector, slip, channel, "read"))
                && crate::authority::row_causal_admitted(self, &txn, &raw)?;
            if allowed || view == ScopeView::Debug {
                out.push(ScopedRecord {
                    id,
                    bytes: raw.into_owned(),
                    scope,
                    suppressed: !allowed,
                });
            }
        }
        Ok(out)
    }
    /// Export never has a debug mode and requires the export verb class.
    pub fn export_records_in_scope(
        &self,
        selector: &Scope,
        slip: &Scope,
        channel: &Scope,
    ) -> Result<Vec<ScopedRecord>> {
        let txn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for row in self.store.entities.iter(&txn)? {
            let (key, raw) = row?;
            let id = EntityId::from_bytes(
                key.as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("record id"))?,
            )?;
            let h =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("record header"))?;
            if let Some(scope) = stored_scope(&self.store, &txn, id, h.entity_type)?
                && admits(&scope, selector, slip, channel, "export")
                && crate::authority::row_causal_admitted(self, &txn, &raw)?
            {
                out.push(ScopedRecord {
                    id,
                    bytes: raw.into_owned(),
                    scope: Some(scope),
                    suppressed: false,
                });
            }
        }
        Ok(out)
    }
    /// Selection and delete share one write transaction; no row can change between them.
    pub fn delete_records_in_scope(
        &self,
        selector: &Scope,
        slip: &Scope,
        channel: &Scope,
    ) -> Result<Vec<EntityId>> {
        self.with_write_txn(|txn| {
            let mut ids = Vec::new();
            for row in self.store.entities.iter(txn)? {
                let (key, raw) = row?;
                let id = EntityId::from_bytes(
                    key.as_ref()
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("record id"))?,
                )?;
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
