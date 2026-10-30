//! A catalog connector's route follows the pack install its slate is bound
//! to: an update carries or keeps it, and a removal, an erase or a restore
//! that takes the install out halts it.
use crate::Vault;
use crate::connector_key::qualification::ConnectorQualificationReceipt;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill_hub::pack_catalog::PackInstallReceipt;

use super::super::record::{ConnectorKeyRecord, ConnectorKeyStatus};
use super::super::slate::{ConnectorGrantSlate, SlatePackSource, read_connector_slate_in_txn};
use super::super::txn::{
    CATALOG_NAME_INDEX, append_connector_key_op_record, read_connector_key_in_txn,
    rewrite_connector_key_in_txn,
};

/// FIX 5941, Ask-first: a pack update (another source of the pack installed
/// over the one a catalog connector's slate names) halts that connector's
/// route as the pack's removal does. False keeps today's update: the key
/// stays Active and routes until the owner revises and requalifies it. An
/// update whose qualified declaration did not move carries the key to the
/// new install either way (FIX 6041).
const PACK_UPDATE_HALTS_CONNECTOR_ROUTES: bool = false;

impl Vault {
    /// A pack update installed `next` over the install (`source_ref` at
    /// `content_hash`) a catalog connector's slate names. A key whose
    /// declaration `next`'s own suite qualified unchanged (same revision,
    /// same resolved manifest) moves to `next` and keeps routing: its slate
    /// is rebound to `next` under the carried owner stamp, and `next`'s
    /// suite is its qualification (FIX 6041). Any other bound key halts as
    /// on removal only while [`PACK_UPDATE_HALTS_CONNECTOR_ROUTES`] holds.
    pub(crate) fn follow_updated_pack_connector_routes_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        source_ref: &str,
        content_hash: &str,
        next: &PackInstallReceipt,
        at: u64,
    ) -> Result<()> {
        for (id, record, slate_id, slate) in
            self.pack_bound_keys_in_txn(wtxn, source_ref, content_hash)?
        {
            let qualified = next.connector_qualification.as_ref().filter(|pack| {
                pack.source_hash == next.content_hash
                    && record.pending_manifest.is_none()
                    && record.protocol_revision.as_deref()
                        == Some(pack.qualification.protocol_revision.as_str())
                    && pack.qualification.qualified_at >= record.registered_at
                    && record
                        .retained_manifest
                        .as_ref()
                        .and_then(|manifest| manifest.hash().ok())
                        == Some(pack.qualification.manifest_hash)
            });
            if let Some(pack) = qualified {
                let next_slate = slate.rebound_to_pack(
                    slate_id,
                    SlatePackSource {
                        source_ref: next.source_id.clone(),
                        content_hash: next.content_hash.clone(),
                    },
                )?;
                let receipt = ConnectorQualificationReceipt {
                    manifest_hash: next_slate.manifest_hash(),
                    ..pack.qualification.clone()
                };
                let carried = self.carry_connector_slate_in_txn(
                    wtxn,
                    &id,
                    &record,
                    (&slate, next_slate, EntityId::now()),
                    Some(receipt),
                    "gate.connector_key.pack_update_carried",
                    at,
                )?;
                if carried.is_some() {
                    continue;
                }
            }
            if PACK_UPDATE_HALTS_CONNECTOR_ROUTES {
                self.halt_connector_key_route_in_txn(wtxn, &id, record, at)?;
            }
        }
        Ok(())
    }

    /// The install a catalog connector's slate is bound to left the install
    /// catalog, in the caller's transaction: the owner removed the pack
    /// (FIX 5941), its source was erased or a restore did not bring the
    /// install back (FIX 6034), or an update superseded it while
    /// [`PACK_UPDATE_HALTS_CONNECTOR_ROUTES`] holds. Every Active or
    /// Suspended catalog key whose slate names that exact source goes back
    /// to Pending, as a revision change leaves it: its route stops, its
    /// per-grant keys are held, and only a re-install that qualifies again
    /// through [`Self::qualify_connector_key`] brings it back; a resume
    /// does not (FIX 6035).
    pub(crate) fn halt_pack_connector_routes_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        source_ref: &str,
        content_hash: &str,
        at: u64,
    ) -> Result<()> {
        for (id, record, _, _) in self.pack_bound_keys_in_txn(wtxn, source_ref, content_hash)? {
            self.halt_connector_key_route_in_txn(wtxn, &id, record, at)?;
        }
        Ok(())
    }

    /// Every Active or Suspended catalog key whose slate names the pack
    /// install `source_ref` at `content_hash`, with its slate.
    fn pack_bound_keys_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        source_ref: &str,
        content_hash: &str,
    ) -> Result<Vec<(EntityId, ConnectorKeyRecord, EntityId, ConnectorGrantSlate)>> {
        let mut bound = Vec::new();
        for (_, id) in CATALOG_NAME_INDEX.scan(&self.store, wtxn)? {
            let Some(record) = read_connector_key_in_txn(&self.store, wtxn, &id)? else {
                continue;
            };
            let routable = matches!(
                record.status,
                ConnectorKeyStatus::Active | ConnectorKeyStatus::Suspended
            );
            if !routable || record.catalog.is_none() {
                continue;
            }
            let Some(slate_id) = record.slate_ref else {
                continue;
            };
            let Some(slate) = read_connector_slate_in_txn(self, wtxn, slate_id)? else {
                continue;
            };
            let names = slate
                .slate_manifest()
                .pack_source
                .as_ref()
                .is_some_and(|binding| {
                    binding.source_ref == source_ref && binding.content_hash == content_hash
                });
            if names {
                bound.push((id, record, slate_id, slate));
            }
        }
        Ok(bound)
    }

    /// Key `id` back to Pending, as a revision change leaves it: its route
    /// stops and its per-grant keys are held until it qualifies again.
    fn halt_connector_key_route_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: ConnectorKeyRecord,
        at: u64,
    ) -> Result<()> {
        let admission_epoch = record
            .admission_epoch
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("connector admission epoch"))?;
        let pending = ConnectorKeyRecord {
            status: ConnectorKeyStatus::Pending,
            status_changed_at: Some(at),
            suspended_reason: None,
            admission_epoch,
            qualification_receipt: None,
            staged_slate_ref: None,
            ..record
        };
        pending.validate()?;
        rewrite_connector_key_in_txn(&self.store, wtxn, id, &pending)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, wtxn)?;
        append_connector_key_op_record(
            &self.store,
            wtxn,
            id,
            "gate.connector_key.pack_uninstalled",
            &pending,
            policy.read_frontier_hash()?,
            at,
        )?;
        self.sync_derived_keys_in_txn(wtxn, &pending, at)
    }
}
