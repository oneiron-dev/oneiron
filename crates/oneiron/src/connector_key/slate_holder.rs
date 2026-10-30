//! ARCH-0072 self-update on a per-grant key (FIX 987): "Any holder may narrow
//! its own Grant, and the owner narrows at the registry."
//!
//! A per-grant key has no slate of its own: its calls meet its catalog
//! connector's owner-stamped slate, shared by every other grant of that
//! connector. Its holder narrows only its own state, kept beside the key as
//! one overlay ([`KeySlateNarrows`]); the catalog's accepted slate stays the
//! one base, never copied and never changed by a holder. Every effective
//! setting a call on the key meets is the base met with this overlay, so a
//! narrow only tightens.
//!
//! The holder is never submitted: it is the principal of the live scoped
//! grant the key's typed capability names, read in the narrowing writer and
//! compared with the authenticated caller. A key with no actor binding is no
//! licence for the owner or another actor to narrow it. A narrow needs no
//! stamp, is receipted on the key's own log and marked with its holder, so it
//! never reads as an owner tap. The owner's stamp on a row reverses that row's
//! narrows, and his facet ruling the facet narrows, in the stamping writer;
//! his other rows leave them in force. A retired key's overlay is its own
//! and names no other grant's key.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::record::{ConnectorKeyRecord, ScopedCapabilityProvenance, invalid_body};
use super::slate::{
    ConnectorGrantSlate, SlateCapability, SlateDisposition, SlateFacetNarrow, SlateHolderNarrow,
};
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

/// One per-grant key's own narrows of the slate its calls meet. Key: the key's id.
const HOLDER_NARROWS: SideTable<EntityId, KeySlateNarrows, Named> =
    SideTable::new(&side_table::CONNECTOR_SLATE_HOLDER_NARROW);

/// A per-grant key's holder narrows: rows by row key (a tool name or the
/// elicitation row's key) and the facet set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeySlateNarrows {
    pub(crate) rows: BTreeMap<String, SlateHolderNarrow>,
    pub(crate) facets: Option<SlateFacetNarrow>,
}

/// What a key's calls meet after a holder's narrow: the slate they meet,
/// each row's effective setting, the facets they reach and the narrows in
/// force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorKeySlateNarrowed {
    pub key_id: EntityId,
    /// The slate the key's calls meet: its own, else its catalog's.
    pub slate_id: EntityId,
    /// That slate's revision.
    pub slate_revision: u64,
    /// Each row's effective setting on this key, by row key.
    pub settings: BTreeMap<String, SlateDisposition>,
    /// The facets the key reaches; `None` is every facet.
    pub facets: Option<BTreeSet<EntityId>>,
    /// The holder narrows in force on this key, by row key.
    pub narrows: BTreeMap<String, SlateHolderNarrow>,
    /// The live grant a per-grant key's holder holds; `None` for a key with
    /// its own slate.
    pub grant_id: Option<EntityId>,
}

/// The live holder of per-grant key `key`: the principal of the live scoped
/// grant its typed capability names, on that capability's own server. `None`
/// for a key with a catalog, a capability that does not parse, or a grant
/// that is gone, no longer live or another server's.
fn derived_key_holder_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &ConnectorKeyRecord,
) -> Result<Option<(EntityId, EntityId)>> {
    if key.catalog.is_some() {
        return Ok(None);
    }
    let Some(capability) = ScopedCapabilityProvenance::parse_owner_capability_key(&key.connector)
    else {
        return Ok(None);
    };
    let grant_id = capability.grant_id();
    let Some(grant) = crate::outbound_grant::standing_outbound_grant_in_txn(store, txn, &grant_id)?
    else {
        return Ok(None);
    };
    let floor = crate::gate::resolve_policy_manifest(store, txn)?.read_frontier_hash()?;
    if !grant.is_active_under_policy(&floor)
        || grant
            .scope
            .scoped_mcp_grant()
            .is_none_or(|scope| scope.server != capability.server())
    {
        return Ok(None);
    }
    Ok(EntityId::from_hex(&grant.principal_ref)
        .ok()
        .map(|holder| (holder, grant_id)))
}

/// `base`, the setting the governing slate gives row `row_key`, tightened by
/// key `key_id`'s holder narrow of that row. A key with its own slate keeps
/// its narrows on that slate.
pub(super) fn narrowed_setting_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    key: &ConnectorKeyRecord,
    row_key: &str,
    base: SlateDisposition,
) -> Result<SlateDisposition> {
    if key.slate_ref.is_some() {
        return Ok(base);
    }
    let narrow = HOLDER_NARROWS
        .get(store, txn, key_id)?
        .and_then(|narrows| narrows.rows.get(row_key).map(|row| row.disposition));
    Ok(narrow.map_or(base, |narrow| narrow.max(base)))
}

/// Key `key_id`'s holder narrows over `HOLDER_NARROWS` (FIX 9230): the whole
/// overlay — rows by row key plus the facet narrow — for the per-grant-key
/// overlays in the consent, slate and reach views. `None` is no overlay
/// stored. Keyed by the per-grant key's id, as the table is.
pub(crate) fn narrowed_settings_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
) -> Result<Option<KeySlateNarrows>> {
    HOLDER_NARROWS.get(store, txn, key_id)
}

/// The owner's ruling on slate `slate_id`, in his stamping writer: each
/// per-grant key whose calls meet that slate drops its narrows of the rows
/// he ruled on, and its facet narrow when he ruled on the facets. Its other
/// narrows stay in force.
pub(super) fn clear_ruled_narrows_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    slate_id: EntityId,
    ruled_rows: &BTreeSet<&str>,
    facet_ruling: bool,
) -> Result<()> {
    for (key_id, mut narrows) in HOLDER_NARROWS.scan(store, txn)? {
        let Some(key) = super::txn::read_connector_key_in_txn(store, txn, &key_id)? else {
            continue;
        };
        if key.slate_ref.is_some()
            || super::lifecycle::derived_key_catalog_slate_in_txn(store, txn, &key)?
                != Some(slate_id)
        {
            continue;
        }
        let before = narrows.clone();
        narrows
            .rows
            .retain(|row_key, _| !ruled_rows.contains(row_key.as_str()));
        if facet_ruling {
            narrows.facets = None;
        }
        if narrows == before {
            continue;
        }
        if narrows == KeySlateNarrows::default() {
            HOLDER_NARROWS.delete(store, txn, &key_id)?;
        } else {
            HOLDER_NARROWS.put(store, txn, &key_id, &narrows)?;
        }
    }
    Ok(())
}

/// The key's view after a narrow: `slate` (with id `slate_id`) met with
/// `narrows`, the key's overlay (none for a key with its own slate).
fn narrowed_view(
    key_id: EntityId,
    slate_id: EntityId,
    slate: &ConnectorGrantSlate,
    narrows: &KeySlateNarrows,
    grant_id: Option<EntityId>,
) -> ConnectorKeySlateNarrowed {
    let settings = slate
        .rows()
        .iter()
        .map(|row| {
            let key = row.draft.tool.clone();
            let base = row.effective_disposition();
            let narrowed = narrows
                .rows
                .get(&key)
                .map_or(base, |narrow| narrow.disposition.max(base));
            (key, narrowed)
        })
        .collect();
    let mut in_force: BTreeMap<String, SlateHolderNarrow> = slate
        .rows()
        .iter()
        .filter_map(|row| Some((row.draft.tool.clone(), row.holder_narrow.clone()?)))
        .collect();
    in_force.extend(narrows.rows.clone());
    ConnectorKeySlateNarrowed {
        key_id,
        slate_id,
        slate_revision: slate.revision(),
        settings,
        facets: met_facets(slate, narrows),
        narrows: in_force,
        grant_id,
    }
}

/// The facets `slate` reaches, met with the key's own facet narrow.
fn met_facets(
    slate: &ConnectorGrantSlate,
    narrows: &KeySlateNarrows,
) -> Option<BTreeSet<EntityId>> {
    match (slate.effective_facets(), narrows.facets.as_ref()) {
        (base, None) => base,
        (None, Some(narrow)) => Some(narrow.facets.clone()),
        (Some(base), Some(narrow)) => Some(base.intersection(&narrow.facets).copied().collect()),
    }
}

impl Vault {
    /// ARCH-0072 self-update through the holder's own door (FIX 987): the
    /// holder of key `key_id`, the authenticated `caller`, tightens rows or
    /// the facet set of what the key's calls meet, with no stamp. A key with
    /// its own slate and actor binding narrows that slate
    /// ([`Self::narrow_connector_slate`]). A per-grant key narrows only its
    /// own overlay, never its catalog's shared slate: its holder is the live
    /// principal of the grant its capability names. `expected_revision` is
    /// the revision of the slate the holder reviewed; a slate that moved
    /// since refuses ([`Error::ConcurrentWrite`]). Narrowing never widens.
    ///
    /// # Errors
    /// A caller that is not the key's live holder, a row the slate does not
    /// name, a setting or facet set that does not tighten, a moved slate,
    /// storage errors.
    pub fn narrow_connector_key_slate(
        &self,
        key_id: &EntityId,
        caller: EntityId,
        expected_revision: u64,
        narrows: &BTreeMap<String, SlateDisposition>,
        facets: Option<BTreeSet<EntityId>>,
    ) -> Result<ConnectorKeySlateNarrowed> {
        if narrows.is_empty() && facets.is_none() {
            return Err(invalid_body("slate narrow names no row or facet"));
        }
        let at = crate::unix_seconds_now();
        let own = {
            let txn = self.store.env.read_txn()?;
            let key = super::txn::read_connector_key_in_txn(&self.store, &txn, key_id)?
                .ok_or(Error::EntityNotFound)?;
            match key.slate_ref {
                Some(slate_id) => {
                    let slate = super::slate::read_slate_in_store_txn(&self.store, &txn, slate_id)?
                        .ok_or_else(|| invalid_body("connector slate missing"))?;
                    if slate.revision() != expected_revision {
                        return Err(Error::ConcurrentWrite("connector slate revision"));
                    }
                    Some(slate_id)
                }
                None => None,
            }
        };
        if let Some(slate_id) = own {
            let slate = self.narrow_connector_slate(key_id, caller, narrows, facets, at)?;
            return Ok(narrowed_view(
                *key_id,
                slate_id,
                &slate,
                &KeySlateNarrows::default(),
                None,
            ));
        }
        self.with_write_txn_grouped(|txn| {
            let record = super::txn::read_connector_key_in_txn(&self.store, txn, key_id)?
                .ok_or(Error::EntityNotFound)?;
            let Some((holder, grant_id)) = derived_key_holder_in_txn(&self.store, txn, &record)?
            else {
                return Err(invalid_body("only the key's live holder narrows its slate"));
            };
            if holder != caller {
                return Err(invalid_body("only the key's live holder narrows its slate"));
            }
            let slate_id =
                super::lifecycle::derived_key_catalog_slate_in_txn(&self.store, txn, &record)?
                    .ok_or_else(|| invalid_body("connector slate missing"))?;
            let slate = super::slate::read_slate_in_store_txn(&self.store, txn, slate_id)?
                .ok_or_else(|| invalid_body("connector slate missing"))?;
            if slate.revision() != expected_revision {
                return Err(Error::ConcurrentWrite("connector slate revision"));
            }
            let mut overlay = HOLDER_NARROWS
                .get(&self.store, txn, key_id)?
                .unwrap_or_default();
            for (row_key, disposition) in narrows {
                let row = slate
                    .capability_row(SlateCapability::parse(row_key))
                    .ok_or_else(|| invalid_body("the slate names no such row"))?;
                let current = overlay
                    .rows
                    .get(row_key)
                    .map_or(row.effective_disposition(), |narrow| {
                        narrow.disposition.max(row.effective_disposition())
                    });
                if *disposition <= current {
                    return Err(invalid_body("a holder narrow must tighten the row"));
                }
                overlay.rows.insert(
                    row_key.clone(),
                    SlateHolderNarrow {
                        disposition: *disposition,
                        actor: holder.to_hex(),
                        at,
                    },
                );
            }
            if let Some(facets) = facets {
                if facets.is_empty()
                    || met_facets(&slate, &overlay)
                        .is_some_and(|current| !facets.is_subset(&current))
                {
                    return Err(invalid_body("a holder facet narrow must tighten the set"));
                }
                overlay.facets = Some(SlateFacetNarrow {
                    facets,
                    actor: holder.to_hex(),
                    at,
                });
            }
            HOLDER_NARROWS.put(&self.store, txn, key_id, &overlay)?;
            let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
            super::txn::append_connector_key_op_record(
                &self.store,
                txn,
                key_id,
                "gate.connector_key.slate_narrow",
                &record,
                policy.read_frontier_hash()?,
                at,
            )?;
            Ok(narrowed_view(
                *key_id,
                slate_id,
                &slate,
                &overlay,
                Some(grant_id),
            ))
        })
    }
}
