//! Exact optional position operations of one successful own-device import.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Weak};

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, LoroValue};

use super::{ORIGIN_POSITIONS_MAP, bound_position, has_positions, holds_carrier};
use crate::authority::PeerMachine;
use crate::error::Result;
use crate::federation::record_scope::origin_positions::{self as facts, OriginPosition};
use crate::ports::EntityStoreRead;
use crate::sync::asset_body::session::LocalBodyLand;
use crate::sync::client::OwnDeviceImport;
use crate::sync::loro_support::map_for_each_value_bytes;
use crate::sync::manager::WindowManager;
use crate::sync::types::WindowKey;
use crate::sync::window::LoadedWindow;
use crate::{EntityId, Vault};

/// Optional position bytes that this exact payload inserted, prepared before
/// the live import. Only the successful import boundary may finish it; no
/// recovery pass, later replay or other value in the window borrows its key.
pub struct OwnDevicePositionImport {
    vault: PathBuf,
    window: WindowKey,
    proof: OwnDeviceImport,
    values: BTreeMap<String, Vec<u8>>,
}

/// A source position whose exact incoming bytes, current original key,
/// canonical incarnation and complete native facts the dedicated writer
/// checked in its own transaction. Only that writer constructs this value.
pub(crate) struct VerifiedOriginPosition<'a> {
    position: &'a OriginPosition,
}

impl VerifiedOriginPosition<'_> {
    pub(crate) fn position(&self) -> &OriginPosition {
        self.position
    }
}

pub(in crate::sync) fn prepare(
    vault: &Vault,
    proof: Option<&OwnDeviceImport>,
    window: &WindowKey,
    doc: &LoroDoc,
    payload: &[u8],
) -> Option<OwnDevicePositionImport> {
    let proof = proof?;
    if window.world().is_some() {
        return None;
    }
    let meta = LoroDoc::decode_import_blob_meta(payload, true).ok()?;
    let mut inserted = BTreeMap::new();
    let candidate = if meta.mode.is_snapshot() {
        let candidate = LoroDoc::from_snapshot(payload).ok()?;
        if has_positions(&candidate) {
            map_for_each_value_bytes(&candidate.get_map(ORIGIN_POSITIONS_MAP), |key, value| {
                if let Some(bytes) = value {
                    inserted.insert(key.to_owned(), bytes.to_vec());
                }
            });
        }
        candidate
    } else {
        if doc.oplog_vv().includes_vv(&meta.partial_end_vv) {
            return None;
        }
        let candidate = doc.fork();
        if candidate.import(payload).ok()?.pending.is_some() {
            return None;
        }
        let positions = ContainerID::new_root(ORIGIN_POSITIONS_MAP, ContainerType::Map);
        let sent = candidate.export_json_updates(&meta.partial_start_vv, &meta.partial_end_vv);
        for op in sent.changes.into_iter().flat_map(|change| change.ops) {
            if op.container == positions
                && let JsonOpContent::Map(MapOp::Insert {
                    key,
                    value: LoroValue::Binary(bytes),
                }) = op.content
            {
                // A payload can contain several writes to one key. Select
                // only the one that actually stands in its complete state.
                if bound_position(&candidate, &key)
                    .is_some_and(|(_, current)| current.as_slice() == bytes.as_slice())
                {
                    inserted.insert(key, bytes.to_vec());
                }
            }
        }
        candidate
    };
    inserted.retain(|key, bytes| {
        bound_position(&candidate, key).is_some_and(|(_, current)| current == *bytes)
    });
    if inserted.is_empty() {
        return None;
    }
    Some(OwnDevicePositionImport {
        vault: vault.store.env.path().to_path_buf(),
        window: window.clone(),
        proof: proof.clone(),
        values: inserted,
    })
}

/// Prepares only this own-device socket's admitted payload, never a
/// federation socket's bytes. `from` is the ORIGINAL connection proof, not
/// a machine id or a freshly fetched replacement key. Call `finish` only
/// after the real observed import returned success.
pub fn prepare_own_device_push_positions(
    vault: &Vault,
    from: PeerMachine,
    window: &WindowKey,
    doc: &LoroDoc,
    payload: &[u8],
) -> Option<OwnDevicePositionImport> {
    let proof = OwnDeviceImport::proven(vault, from)?;
    prepare(vault, Some(&proof), window, doc, payload)
}

/// Exact incoming values selected after replacement conflict resolution,
/// before reverse rematerialization can remove uninstalled position data.
/// Only the native replacement's final persistence writer may finish them.
pub(in crate::sync) struct ReplacementPositions {
    incoming: OwnDevicePositionImport,
}

impl OwnDevicePositionImport {
    /// Installs only exact values this successful payload supplied and the
    /// live document still holds. Missing facts, unknown births, a changed
    /// key or a peer-origin owner/source leaves ordinary row import alone.
    /// Result bodies are pinned before the writer and through its commit.
    pub fn finish(&self, vault: &Vault, doc: &LoroDoc) -> Result<()> {
        if self.vault != vault.store.env.path() {
            return Ok(());
        }
        let _bodies = vault.pin_all_result_bodies();
        vault.with_write_txn_grouped(|txn| {
            let positions = self.values.iter().filter_map(|(key, sent)| {
                let (position, current) = bound_position(doc, key)?;
                (current == *sent).then_some(position)
            });
            self.install_in_txn(vault, txn, positions).map(|_| ())
        })
    }

    pub(in crate::sync) fn select_replacement(
        mut self,
        doc: &LoroDoc,
    ) -> Option<ReplacementPositions> {
        self.values.retain(|key, sent| {
            bound_position(doc, key).is_some_and(|(_, current)| current == *sent)
        });
        (!self.values.is_empty()).then_some(ReplacementPositions { incoming: self })
    }

    /// Only the completed live importer may retain these selected values.
    /// Root scrubs can remove their map entries, never their carrier binding.
    pub(in crate::sync) fn select_deferred(
        mut self,
        window: &LoadedWindow,
        identity: Weak<LoadedWindow>,
    ) -> Option<DeferredPositions> {
        if self.window != window.key {
            return None;
        }
        self.values.retain(|key, sent| {
            OriginPosition::decode(sent).is_some_and(|position| {
                holds_carrier(&window.doc, key, &position)
                    && std::iter::once(&position.row)
                        .chain(position.sources.iter())
                        .all(|row| row.birth_digest.is_some())
                    && std::iter::once(&position.row)
                        .chain(position.sources.iter())
                        .any(|row| row.file_reference.is_some())
            })
        });
        (!self.values.is_empty()).then(|| DeferredPositions {
            incoming: self,
            window: identity,
            ready: BTreeSet::new(),
        })
    }

    fn install_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        positions: impl Iterator<Item = OriginPosition>,
    ) -> Result<Vec<EntityId>> {
        if self.vault != vault.store.env.path() || !self.proof.stands_in_txn(vault, txn)? {
            return Ok(Vec::new());
        }
        let mut settled = Vec::new();
        for position in positions {
            // Unknown birth is data, not an incarnation certificate.
            if std::iter::once(&position.row)
                .chain(position.sources.iter())
                .any(|row| row.birth_digest.is_none())
                || !facts::matches_in_txn(vault, txn, &position)?
            {
                continue;
            }
            let mut peer = false;
            for row in std::iter::once(&position.row).chain(position.sources.iter()) {
                let Some(raw) = vault.store.port_entity_raw(txn, &row.id)? else {
                    peer = true;
                    break;
                };
                let residence = crate::sync::residence::residence_window_for_blob(&raw)?;
                if (row.id == position.row.id && residence != self.window)
                    || crate::sync::ingest::peer_row_in_txn(
                        vault,
                        txn,
                        residence.as_str(),
                        &row.id,
                        &raw,
                    )?
                {
                    peer = true;
                    break;
                }
            }
            if !peer {
                facts::install_in_txn(
                    vault,
                    txn,
                    &VerifiedOriginPosition {
                        position: &position,
                    },
                )?;
                settled.push(position.row.id);
            }
        }
        Ok(settled)
    }
}

/// Selected facts of one completed live import, owned only by its socket's
/// body session. A weak window handle never holds up replacement or eviction.
/// Neither a remote Receipt nor a replay can construct a local-land effect.
pub(in crate::sync) struct DeferredPositions {
    incoming: OwnDevicePositionImport,
    window: Weak<LoadedWindow>,
    ready: BTreeSet<String>,
}

impl DeferredPositions {
    pub(in crate::sync) fn supersede_by(&mut self, newer: &Self) {
        if self.incoming.window == newer.incoming.window {
            if !Weak::ptr_eq(&self.window, &newer.window) {
                self.incoming.values.clear();
            } else {
                self.incoming
                    .values
                    .retain(|key, _| !newer.incoming.values.contains_key(key));
            }
        }
    }

    pub(in crate::sync) fn is_empty(&self) -> bool {
        self.incoming.values.is_empty()
    }

    pub(in crate::sync) fn body_landed(&mut self, landed: &LocalBodyLand) -> Result<()> {
        let reference = landed.reference()?;
        for (key, sent) in &self.incoming.values {
            if OriginPosition::decode(sent).is_some_and(|position| {
                std::iter::once(&position.row)
                    .chain(position.sources.iter())
                    .any(|row| row.file_reference.as_deref() == Some(reference.as_slice()))
            }) {
                self.ready.insert(key.clone());
            }
        }
        Ok(())
    }

    /// Retry through existing housekeeping after a related local body landed.
    /// A later native caption materialization need not coincide with that event.
    pub(in crate::sync) fn retry(&mut self, manager: &WindowManager) -> Result<()> {
        let Some(current) = manager
            .window(&self.incoming.window)
            .filter(|current| Weak::ptr_eq(&Arc::downgrade(current), &self.window))
        else {
            self.incoming.values.clear();
            return Ok(());
        };
        self.incoming.values.retain(|key, sent| {
            OriginPosition::decode(sent)
                .is_some_and(|position| holds_carrier(&current.doc, key, &position))
        });
        self.ready
            .retain(|key| self.incoming.values.contains_key(key));
        if self.ready.is_empty() {
            return Ok(());
        }
        let vault = manager.vault();
        let _bodies = vault.pin_all_result_bodies();
        let settled = vault.with_write_txn_grouped(|txn| {
            let positions = self.incoming.values.iter().filter_map(|(key, sent)| {
                if !self.ready.contains(key) {
                    return None;
                }
                let position = OriginPosition::decode(sent)?;
                holds_carrier(&current.doc, key, &position).then_some(position)
            });
            self.incoming.install_in_txn(vault, txn, positions)
        })?;
        for id in settled {
            let key = id.to_hex();
            self.incoming.values.remove(&key);
            self.ready.remove(&key);
        }
        Ok(())
    }
}

impl ReplacementPositions {
    /// Caller pins bodies before the parent writer. The optional savepoint
    /// joins that writer's commit or leaves no position/revision writes on
    /// error. Final carrier/reference checks do not need the root keys the
    /// unchanged canonical scrub deliberately removed.
    pub(in crate::sync) fn finish_in_txn(
        &self,
        vault: &Vault,
        parent: &mut heed::RwTxn<'_>,
        doc: &LoroDoc,
    ) -> Result<()> {
        let mut staged = vault.store.env.nested_write_txn(parent)?;
        let positions = self.incoming.values.iter().filter_map(|(key, sent)| {
            let position = OriginPosition::decode(sent)?;
            holds_carrier(doc, key, &position).then_some(position)
        });
        self.incoming
            .install_in_txn(vault, &mut staged, positions)?;
        staged.commit()?;
        Ok(())
    }
}
