//! Digest-bound record-position stamps and scoped read/delete/export doors.
//!
//! Unstamped rows are never selected. Debug is an explicit read-only view, not
//! a wildcard selector. Replication does not invent a stamp for opaque peer bytes.
use super::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{
    EntityId, Vault,
    error::{Error, Result},
    store::Store,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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
    digest: [u8; 32],
    scope: Scope,
}
/// One entity's digest-bound record-position stamp, keyed by entity id.
const SCOPE_RECORD: SideTable<EntityId, Stamp, LegacyJson> =
    SideTable::new(&side_table::SCOPE_RECORD);
fn digest(kind: u8, data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("oneiron/record-scope/v1");
    h.update(&[kind]);
    h.update(data);
    *h.finalize().as_bytes()
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
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<EntityId>> {
    let prefix = crate::vault::edge_kind_prefix(&id, crate::edge::EdgeKind::FacetOf);
    let Some(row) = store.edges_out.prefix_iter(txn, &prefix)?.next() else {
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
    let mut scope = if kind == crate::registry::ENTITY_TYPE_CLAIM {
        let body = crate::claim::decode_claim_body(data, true)?;
        body.record_scope("read")
    } else if replicated
        && !(kind == crate::registry::ENTITY_TYPE_FACET
            && crate::companion::is_identity_facet_body(data))
    {
        // Same bytes may retain their locally authored stamp. A changed opaque
        // replay must not inherit one from an earlier row at the same id.
        if stored_scope(store, txn, id, kind, data)?.is_none() {
            SCOPE_RECORD.delete(store, txn, &id)?;
        }
        return Ok(());
    } else if kind == crate::registry::ENTITY_TYPE_FACET {
        default_stamp(kind, id)
    } else if carries_birth_stamp(kind) {
        let Some(facet) = birth_facet(store, txn, id)? else {
            SCOPE_RECORD.delete(store, txn, &id)?;
            return Ok(());
        };
        default_stamp(kind, facet)
    } else {
        default_stamp(kind, crate::claim::substrate_facet_id(id))
    };
    if kind == crate::registry::ENTITY_TYPE_FACET
        && let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut &data[..])
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
                _ => return Err(Error::InvalidClaimBody("invalid facet sensitivity")),
            });
        } else if !bands.is_empty() {
            return Err(Error::InvalidClaimBody("duplicate facet sensitivity"));
        }
    }
    scope.verbs = ScopeAxis::Bottom;
    let stamp = Stamp {
        version: 1,
        digest: digest(kind, data),
        scope,
    };
    SCOPE_RECORD.put(store, txn, &id, &stamp)?;
    Ok(())
}
fn stored_scope(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<Option<Scope>> {
    let Some(stamp) = SCOPE_RECORD.get(store, txn, &id)? else {
        return Ok(None);
    };
    if stamp.version != 1 || stamp.digest != digest(kind, data) {
        return Ok(None);
    }
    Ok(Some(stamp.scope))
}
/// Derive only an intrinsic current stamp or a digest-matched persisted stamp.
/// This is the sync-export seam; arbitrary remote opaque rows remain unstamped.
pub(crate) fn scope_for_blob(
    store: &Store,
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
    let mut scope = stored_scope(store, txn, id, h.entity_type, data)?;
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
        stored_scope(
            &self.store,
            &txn,
            *id,
            h.entity_type,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )
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
            let scope = stored_scope(
                &self.store,
                &txn,
                id,
                h.entity_type,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )?;
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
            if let Some(scope) = stored_scope(
                &self.store,
                &txn,
                id,
                h.entity_type,
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )? && admits(&scope, selector, slip, channel, "export")
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
                if let Some(scope) = stored_scope(
                    &self.store,
                    txn,
                    id,
                    h.entity_type,
                    &raw[ENTITY_METADATA_HEADER_LEN..],
                )? && admits(&scope, selector, slip, channel, "delete")
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
                SCOPE_RECORD.delete(&self.store, txn, id)?;
            }
            Ok(ids)
        })
    }
}
