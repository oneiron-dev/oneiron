//! Custody-backed local embedders kept by this server, beside its incumbent slot.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError, Weak};

use oneiron::embed::{EmbeddingSpace, InputKind};
use oneiron::training_pack::{PinnedCheckpoint, TrainingEmbedderSource};
use oneiron::{EntityId, Error, ModelId, Result, Vault};

use super::SyncServer;
use super::media_embedding::MediaEmbedRefusal;
use crate::embedder::CheckpointEmbedder;

type RuntimeKey = (EntityId, [u8; 32]);
type LoadCell = Mutex<Weak<TrainedEmbedding>>;

/// A forward owns the actual runtime and its private files until it ends.
/// The cell points back weakly: it shares a concurrent load without a cycle.
pub(crate) struct TrainedEmbedding {
    run: EntityId,
    checkpoint: PinnedCheckpoint,
    pub(super) provider: Arc<CheckpointEmbedder>,
    _load: Arc<LoadCell>,
}

impl TrainedEmbedding {
    fn current(&self, vault: &Vault, active: bool) -> Result<()> {
        let current = vault.training_embedder_source(&self.run)?;
        if current.as_ref().is_some_and(|source| {
            source.checkpoint == self.checkpoint
                && (!active
                    || ((source.approved() || source.bound())
                        && source.space.as_ref().is_some_and(|space| {
                            space.dimensions == self.provider.dimensions()
                                && space.accepts.contains(&InputKind::Text)
                                && space.query_towers.contains(&InputKind::Text)
                        })))
        }) {
            return Ok(());
        }
        Err(Error::InvalidConfig(
            "trained embedder checkpoint is no longer current".into(),
        ))
    }

    /// A returned checkpoint may be evaluated before the separate swap choice.
    pub(crate) fn query(&self, vault: &Vault, text: &str) -> Result<Vec<f32>> {
        self.current(vault, false)?;
        self.provider.query(text)
    }

    pub(super) fn document(&self, vault: &Vault, text: &str) -> Result<Vec<f32>> {
        self.current(vault, true)?;
        self.provider.document(text)
    }

    pub(super) fn query_active(&self, vault: &Vault, text: &str) -> Result<Vec<f32>> {
        self.current(vault, true)?;
        self.provider.query(text)
    }
}

struct Retained {
    source: TrainingEmbedderSource,
    runtime: Arc<TrainedEmbedding>,
}

/// Weak eval ownership; strong ownership only while an actual staged or bound
/// source remains. Nothing replaces the configured slot or outlives the server.
#[derive(Default)]
pub(crate) struct TrainedEmbedders {
    loads: Mutex<BTreeMap<RuntimeKey, Weak<LoadCell>>>,
    retained: Mutex<BTreeMap<RuntimeKey, Retained>>,
}

impl SyncServer {
    fn load_training_embedder(
        &self,
        source: &TrainingEmbedderSource,
    ) -> Result<Arc<TrainedEmbedding>> {
        let key = (source.run, source.checkpoint.content_hash()?);
        let cell = {
            let mut loads = self
                .trained_embedders
                .loads
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            loads.retain(|_, cell| cell.strong_count() > 0);
            if let Some(cell) = loads.get(&key).and_then(Weak::upgrade) {
                cell
            } else {
                let cell = Arc::new(Mutex::new(Weak::new()));
                loads.insert(key, Arc::downgrade(&cell));
                cell
            }
        };
        // Only another load of these exact bytes waits here, never incumbent queries.
        let mut held = cell.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(runtime) = held.upgrade() {
            runtime.current(self.vault(), false)?;
            return Ok(runtime);
        }
        let slot = self.embedder_slot();
        let host = slot
            .as_ref()
            .map(|slot| slot.config().clone())
            .unwrap_or_default();
        let provider = CheckpointEmbedder::load(self.vault(), &source.checkpoint, &host)?;
        if provider.checkpoint_hash() != key.1 {
            return Err(Error::InvariantViolation(
                "trained embedder loaded another checkpoint",
            ));
        }
        let runtime = Arc::new(TrainedEmbedding {
            run: source.run,
            checkpoint: source.checkpoint.clone(),
            provider,
            _load: Arc::clone(&cell),
        });
        runtime.current(self.vault(), false)?;
        *held = Arc::downgrade(&runtime);
        Ok(runtime)
    }

    /// Exact checkpoint-authenticated E2 arm. A registry entry for a different
    /// deployment is neither required nor borrowed for these private weights.
    pub(crate) fn training_embedder_exact(
        &self,
        model: &ModelId,
        revision: &str,
    ) -> Result<Option<Arc<TrainedEmbedding>>> {
        for source in self.vault().training_embedder_sources()? {
            if source.checkpoint.model == *model
                && blake3::Hash::from(source.checkpoint.content_hash()?)
                    .to_hex()
                    .as_str()
                    == revision
            {
                return self.load_training_embedder(&source).map(Some);
            }
        }
        Ok(None)
    }

    /// One admitted backfill pass: load outside a writer, then declare through
    /// the source snapshot's same-writer comparison before ordinary moves run.
    pub(super) fn refresh_trained_embedders(
        &self,
    ) -> Vec<(
        String,
        std::result::Result<oneiron::embed::MediaEmbedReport, MediaEmbedRefusal>,
    )> {
        let sources = match self.vault().training_embedder_sources() {
            Ok(sources) => sources,
            Err(error) => return vec![(String::new(), Err(error.into()))],
        };
        {
            let mut retained = self
                .trained_embedders
                .retained
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            retained.retain(|_, held| {
                sources.iter().any(|source| {
                    (source.approved() || source.bound())
                        && source.run == held.source.run
                        && source.checkpoint == held.source.checkpoint
                        && source.pending == held.source.pending
                })
            });
        }
        let mut failures = Vec::new();
        for source in sources
            .into_iter()
            .filter(|source| source.approved() || source.bound())
        {
            let id = match source.space_id() {
                Ok(id) => id,
                Err(error) => {
                    failures.push((String::new(), Err(error.into())));
                    continue;
                }
            };
            let loaded = (|| -> Result<()> {
                let runtime = self.load_training_embedder(&source)?;
                let space = EmbeddingSpace {
                    id: id.clone(),
                    dimensions: runtime.provider.dimensions(),
                    accepts: BTreeSet::from([InputKind::Text]),
                    query_towers: BTreeSet::from([InputKind::Text]),
                    evidence: None,
                };
                if source.approved() {
                    self.vault()
                        .declare_training_embedder_space(&source, &space)?;
                }
                let Some(current) = self.vault().training_embedder_source(&source.run)? else {
                    return Ok(());
                };
                if current.checkpoint != source.checkpoint
                    || !(current.approved() || current.bound())
                {
                    return Ok(());
                }
                if current.space.as_ref() != Some(&space) {
                    return Err(Error::InvalidConfig(
                        "trained embedder space does not match its loaded checkpoint".into(),
                    ));
                }
                self.trained_embedders
                    .retained
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(
                        (source.run, source.checkpoint.content_hash()?),
                        Retained {
                            source: current,
                            runtime,
                        },
                    );
                Ok(())
            })();
            if let Err(error) = loaded {
                failures.push((id, Err(error.into())));
            }
        }
        failures
    }

    /// The actual active receipt and exact declaration, checked before a cached
    /// runtime may become a document or query provider.
    pub(super) fn trained_embedding_for_space(
        &self,
        space: &EmbeddingSpace,
    ) -> Result<Option<Arc<TrainedEmbedding>>> {
        for source in self.vault().training_embedder_sources()? {
            if source.space_id()? != space.id || !(source.approved() || source.bound()) {
                continue;
            }
            let runtime = self
                .trained_embedders
                .retained
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&(source.run, source.checkpoint.content_hash()?))
                .map(|held| Arc::clone(&held.runtime));
            let Some(runtime) = runtime else {
                return Err(Error::InvalidConfig(
                    "trained embedder checkpoint is not loaded on this host".into(),
                ));
            };
            runtime.current(self.vault(), true)?;
            if source.space.as_ref() != Some(space)
                || space.dimensions != runtime.provider.dimensions()
            {
                return Err(Error::InvalidConfig(
                    "trained embedder declaration changed".into(),
                ));
            }
            return Ok(Some(runtime));
        }
        Ok(None)
    }

    /// Serving is not loading: the actual bound role and live text slot must
    /// select this checkpoint's declared space and the runtime must still live.
    pub(crate) fn serves_training_checkpoint(&self, checkpoint: &PinnedCheckpoint) -> Result<bool> {
        let retained = self
            .trained_embedders
            .retained
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for held in retained.values() {
            if held.runtime.checkpoint != *checkpoint {
                continue;
            }
            let Some(source) = self.vault().training_embedder_source(&held.source.run)? else {
                continue;
            };
            if source.bound()
                && source.checkpoint == *checkpoint
                && source.slots.text.as_deref() == Some(source.space_id()?.as_str())
                && source
                    .space
                    .as_ref()
                    .is_some_and(|space| space.dimensions == held.runtime.provider.dimensions())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
