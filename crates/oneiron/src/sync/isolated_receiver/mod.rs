//! Full-window materialization on a private candidate and a caller-owned root writer.
//!
//! The bootstrap receiver stages its original signed history and final request
//! authority before calling `stage_in_txn`. No live document, observer or event
//! is touched here. The outer root commit owns the returned effects.

mod retained;

use std::borrow::Cow;

use crate::sync::bridge::{self, EdgeImportEffects, EntityImportEffects, TombstoneEffects};
use crate::sync::client::OwnDeviceImport;
use crate::sync::custody::IsolatedCustody;
use crate::sync::document_pins::PinBatch;
use crate::sync::message_docs::{MessageDocumentBatch, MessageDocumentEffects};
use crate::sync::repo_manifests::{RepoManifestBatch, RepoManifestEffects};
use crate::sync::room_facts::RoomFactBatch;
use crate::sync::room_turns::RoomTurnBatch;
use crate::sync::row_birth::BirthBatch;
use crate::sync::types::WindowKey;
use crate::sync::withdrawn_cutoffs;
use crate::{EntityId, Result, Vault};
use loro::event::MapDelta;
use loro::{LoroDoc, LoroMap, LoroValue};

pub(in crate::sync) struct PreparedIsolatedWindow {
    base: LoroDoc,
    update: Vec<u8>,
    content: IsolatedContent,
}

struct IsolatedContent {
    key: WindowKey,
    candidate: LoroDoc,
    persist: Vec<u8>,
    lease_vault_id: u64,
    entities: MapDelta<'static>,
    edges: MapDelta<'static>,
    tombstones: MapDelta<'static>,
    births: BirthBatch,
    custody: Option<IsolatedCustody>,
    turns: Option<RoomTurnBatch>,
    facts: Option<RoomFactBatch>,
    messages: MessageDocumentBatch,
    pins: Option<PinBatch>,
    repos: Option<RepoManifestBatch>,
    notes: Option<crate::sync::note::State>,
}

impl PreparedIsolatedWindow {
    /// Decodes an update over an unobserved fork. Store authority is judged
    /// later on the supplied writer, after the bootstrap's history is staged.
    pub(in crate::sync) fn prepare(
        vault: &Vault,
        key: WindowKey,
        base: &LoroDoc,
        update: Vec<u8>,
        lease_vault_id: u64,
    ) -> Result<Self> {
        let decode_error = |source| {
            crate::Error::Sync(crate::error::SyncError::CrdtDecodeError {
                context: "isolated window candidate",
                source,
            })
        };
        let base = base.fork();
        let metadata = LoroDoc::decode_import_blob_meta(&update, true).map_err(decode_error)?;
        let candidate = if metadata.mode.is_snapshot() {
            LoroDoc::from_snapshot(&update).map_err(decode_error)?
        } else {
            let candidate = base.fork();
            let imported = candidate.import(&update).map_err(decode_error)?;
            if imported.pending.is_some() {
                return Err(crate::Error::InvalidConfig(
                    "window update has unresolved dependencies".into(),
                ));
            }
            candidate
        };
        let notes = retained::native_notes(&candidate)?;
        let entities = full_delta(root_map(&candidate, "entities"));
        let edges = full_delta(root_map(&candidate, "edges"));
        let tombstones = full_delta(root_map(&candidate, "tombstones"));
        let births = BirthBatch::prepare(
            &full_delta(root_map(&candidate, crate::sync::row_birth::ROW_BIRTHS_MAP)),
            key.as_str(),
        );
        let custody = IsolatedCustody::prepare(vault, &candidate, &key);
        let turns = key
            .world()
            .is_none()
            .then(|| {
                root_map(&candidate, crate::sync::room_turns::ROOM_TURNS_MAP).map(|map| {
                    RoomTurnBatch::prepare(
                        key.as_str(),
                        crate::sync::room_parts::rows(&map, |_| true),
                    )
                })
            })
            .flatten();
        let facts = key
            .world()
            .is_none()
            .then(|| {
                root_map(&candidate, crate::sync::room_facts::ROOM_FACTS_MAP).map(|map| {
                    let rows = crate::sync::room_parts::rows(&map, |_| true)
                        .into_iter()
                        .map(|(key, bytes)| (key, Some(bytes)))
                        .collect();
                    RoomFactBatch::prepare(&candidate, key.as_str(), rows)
                })
            })
            .flatten();
        let messages = MessageDocumentBatch::prepare(&candidate, &key);
        let pins = PinBatch::prepare_full(&candidate, &key);
        let repos = RepoManifestBatch::prepare_full(vault, &candidate, &key);
        let persist =
            crate::sync::window::persisted_window_pads(vault, &key, &update, Some(&candidate))
                .into_owned();
        Ok(Self {
            base,
            update,
            content: IsolatedContent {
                key,
                candidate,
                persist,
                lease_vault_id,
                entities,
                edges,
                tombstones,
                births,
                custody,
                turns,
                facts,
                messages,
                pins,
                repos,
                notes,
            },
        })
    }

    /// Stages all content and its window bytes in this root, after the caller
    /// staged and checked its original signed history and logged request.
    pub(in crate::sync) fn stage_in_txn(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        own_device: Option<&OwnDeviceImport>,
    ) -> Result<StagedIsolatedWindow> {
        let cutoffs = crate::sync::window::check_window_update_residence_in_txn(
            vault,
            txn,
            &self.base,
            &self.update,
            &self.content.key,
        )?;
        withdrawn_cutoffs::stage_withdrawn_cutoffs_in_txn(vault, &cutoffs, txn)?;
        withdrawn_cutoffs::stage_withdrawn_cutoff_map_in_txn(
            vault,
            &self.content.candidate,
            self.content.key.as_str(),
            txn,
        )?;
        let Self {
            base,
            update,
            content,
        } = self;
        let key = content.key.clone();
        let _import = crate::sync::manager::import_scope();
        crate::sync::ingest::with_own_device_import(
            vault,
            own_device,
            (&key, &base),
            &update,
            || content.stage_in_txn(vault, txn),
        )
    }
}

impl IsolatedContent {
    fn stage_in_txn(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<StagedIsolatedWindow> {
        let Self {
            key,
            candidate,
            persist,
            lease_vault_id,
            entities,
            edges,
            tombstones,
            births,
            custody,
            turns,
            facts,
            messages,
            pins,
            repos,
            notes,
        } = self;
        if let Some(custody) = &custody {
            custody.stage_in_txn(vault, &candidate, &key, txn)?;
        }
        births.stage_in_txn(vault, &candidate, txn)?;
        let entities = bridge::stage_isolated_entities_in_txn(
            &candidate,
            &entities,
            vault,
            key.as_str(),
            lease_vault_id,
            txn,
        )?;
        let healed = retained::stage_in_txn(vault, &candidate, &key, notes, txn)?;
        let edges = bridge::stage_isolated_edges_in_txn(
            &candidate,
            &edges,
            vault,
            key.as_str(),
            lease_vault_id,
            txn,
        )?;
        // Re-prepare custody against the same writer after its new edges.
        if let Some(custody) = &custody {
            custody.stage_in_txn(vault, &candidate, &key, txn)?;
        }
        if let Some(turns) = turns {
            turns.stage_in_txn(vault, key.as_str(), txn)?;
        }
        if let Some(facts) = facts {
            facts.stage_in_txn(vault, key.as_str(), txn)?;
        }
        let messages = messages.stage_in_txn(vault, txn)?;
        if let Some(pins) = pins {
            pins.stage_in_txn(vault, key.as_str(), txn)?;
        }
        let repos = repos
            .map(|repos| repos.stage_in_txn(vault, txn))
            .transpose()?;
        bridge::retry_in_txn(vault, txn)?;
        let tombstones =
            bridge::stage_tombstones_in_txn(vault, &candidate, &tombstones, key.as_str(), txn)?;
        bridge::persist_window_update_in_txn(vault, txn, key.as_str(), &persist)?;
        Ok(StagedIsolatedWindow {
            key,
            candidate,
            entities,
            edges,
            tombstones,
            messages,
            repos,
            healed,
        })
    }
}

/// Owned results of staging, not a durability receipt. Drop on root failure;
/// publish only from the real write door's after-commit callback.
pub(in crate::sync) struct StagedIsolatedWindow {
    key: WindowKey,
    candidate: LoroDoc,
    entities: EntityImportEffects,
    edges: EdgeImportEffects,
    tombstones: TombstoneEffects,
    messages: MessageDocumentEffects,
    repos: Option<RepoManifestEffects>,
    healed: Vec<EntityId>,
}

pub(in crate::sync) struct PublishedIsolatedWindow {
    pub(in crate::sync) key: WindowKey,
    pub(in crate::sync) candidate: LoroDoc,
    pub(in crate::sync) revisions: Vec<crate::vault::EntityRevisionChange>,
    pub(in crate::sync) affected: Vec<EntityId>,
}

impl StagedIsolatedWindow {
    pub(in crate::sync) fn publish_after_commit(self, vault: &Vault) -> PublishedIsolatedWindow {
        let Self {
            key,
            candidate,
            entities,
            edges,
            tombstones,
            messages,
            repos,
            mut healed,
        } = self;
        let revisions = entities.publish_after_commit(vault);
        healed.extend(edges.publish_after_commit(vault));
        healed.extend(tombstones.publish_after_commit(vault, key.as_str()));
        messages.publish_after_commit(vault);
        if let Some(repos) = repos {
            repos.publish_after_commit();
        }
        PublishedIsolatedWindow {
            key,
            candidate,
            revisions,
            affected: healed,
        }
    }
}

fn root_map(doc: &LoroDoc, name: &str) -> Option<LoroMap> {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(name))
        .then(|| doc.get_map(name))
}

fn full_delta(map: Option<LoroMap>) -> MapDelta<'static> {
    let mut delta = MapDelta {
        updated: Default::default(),
    };
    if let Some(map) = map {
        map.for_each(|key, value| {
            delta
                .updated
                .insert(Cow::Owned(key.to_owned()), Some(value));
        });
    }
    delta
}
