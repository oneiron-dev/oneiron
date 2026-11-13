//! The small local models of private worlds (DEC-0005 #private-world-vectors;
//! census L5-26): a world whose model order names a declared text space
//! `<org>/<name>@<commit>@device` embeds its rows into that space alone, with
//! that model, in this process.
//!
//! Each such space has one tower here. Its model loads on the first document
//! the media backfill hands it, which downloads the files on a machine that
//! never ran it. Only a machine the world may be read on holds the world's
//! rows (fix 2), so only such a machine ever sends the tower a document and
//! fetches its model. A machine that has the files already, because it
//! embedded the world's rows before, loads the model on its next pass, so a
//! restart does not leave the world's list without a query vector. A query
//! never loads a model: until the model serves, the world's rows are found by
//! keywords, names, links and time, as canon says of a world without one.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use oneiron::embed::{EmbeddingProvenance, EmbeddingSpace, InputKind, space_runs_on_device};

use super::SyncServer;
use super::media_embedding::MediaEmbedRefusal;
use crate::config::EmbedderConfig;
use crate::embedder::DeviceSpaceModel;

/// A text model that runs in this process for one device text space.
pub(crate) trait DeviceTextModel: Send + Sync {
    /// One query through the model's query tower.
    fn query(&self, text: &str) -> oneiron::Result<Vec<f32>>;
    /// One stored document through its document tower.
    fn document(&self, text: &str) -> oneiron::Result<Vec<f32>>;
    /// The device and runtime that compute its vectors.
    fn provenance(&self) -> EmbeddingProvenance;
}

impl DeviceTextModel for DeviceSpaceModel {
    fn query(&self, text: &str) -> oneiron::Result<Vec<f32>> {
        DeviceSpaceModel::query(self, text)
    }

    fn document(&self, text: &str) -> oneiron::Result<Vec<f32>> {
        DeviceSpaceModel::document(self, text)
    }

    fn provenance(&self) -> EmbeddingProvenance {
        DeviceSpaceModel::provenance(self)
    }
}

/// Where a tower's model comes from.
enum DeviceModelSource {
    /// The repository and commit the space's id names, run with these host
    /// settings.
    Hub(EmbedderConfig),
    /// A model placed in the tower ahead of any use, with nothing to load.
    #[cfg_attr(not(oneiron_test_support), allow(dead_code))]
    Installed,
}

/// One device text space's model on this server.
pub(crate) struct DeviceSpaceTower {
    space: EmbeddingSpace,
    source: DeviceModelSource,
    /// Held while the model loads, so two passes never load it twice; a
    /// query never takes it.
    loading: Mutex<()>,
    model: OnceLock<Arc<dyn DeviceTextModel>>,
}

impl DeviceSpaceTower {
    /// The declared space the tower embeds into.
    pub(crate) fn space(&self) -> &EmbeddingSpace {
        &self.space
    }

    /// The model, once loaded.
    pub(crate) fn loaded(&self) -> Option<Arc<dyn DeviceTextModel>> {
        self.model.get().cloned()
    }

    /// The model, loaded first when it is not. Blocking: a first load
    /// downloads its files. A load that fails is tried again by the next
    /// caller.
    pub(crate) fn load(&self) -> oneiron::Result<Arc<dyn DeviceTextModel>> {
        let _loading = self.loading.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(model) = self.loaded() {
            return Ok(model);
        }
        let DeviceModelSource::Hub(config) = &self.source else {
            return Err(oneiron::Error::InvariantViolation(
                "a device text space's installed model is gone",
            ));
        };
        // The load holds the model's width to the space's.
        let model: Arc<dyn DeviceTextModel> = DeviceSpaceModel::load(config)?;
        let _ = self.model.set(Arc::clone(&model));
        Ok(model)
    }

    /// Loads the model when its files are on this machine already, and does
    /// nothing otherwise: a machine that never embedded the space's rows
    /// fetches nothing here. Blocking.
    pub(crate) fn load_when_on_disk(&self) -> oneiron::Result<()> {
        match &self.source {
            DeviceModelSource::Hub(config)
                if self.loaded().is_none() && DeviceSpaceModel::on_disk(config) =>
            {
                self.load().map(drop)
            }
            _ => Ok(()),
        }
    }
}

/// The device text space towers this server keeps, by space id.
#[derive(Default)]
pub(crate) struct DeviceSpaceTowers {
    by_space: Mutex<BTreeMap<String, Arc<DeviceSpaceTower>>>,
}

impl SyncServer {
    /// The tower of declared space `space`, when its model runs on the
    /// device; `None` for a space on an `ai.embed` rung. A tower is made once
    /// per space, and again when the space's declaration changes. Nothing is
    /// loaded.
    pub(crate) fn device_space_tower(
        &self,
        space: &EmbeddingSpace,
    ) -> Result<Option<Arc<DeviceSpaceTower>>, MediaEmbedRefusal> {
        if !space_runs_on_device(&space.id) {
            return Ok(None);
        }
        let mut towers = self
            .device_space_towers
            .by_space
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(tower) = towers.get(&space.id)
            && tower.space == *space
        {
            return Ok(Some(Arc::clone(tower)));
        }
        let host = self
            .embedder_slot()
            .map(|slot| slot.config().clone())
            .unwrap_or_default();
        let config = DeviceSpaceModel::config_for(space, &host)?;
        let tower = Arc::new(DeviceSpaceTower {
            space: space.clone(),
            source: DeviceModelSource::Hub(config),
            loading: Mutex::new(()),
            model: OnceLock::new(),
        });
        towers.insert(space.id.clone(), Arc::clone(&tower));
        Ok(Some(tower))
    }

    /// Places `model` as declared space `space`'s device model, loaded, in
    /// place of the one its id names: a test's in-process model, so nothing
    /// is fetched.
    #[cfg(oneiron_test_support)]
    pub(crate) fn install_device_text_model(
        &self,
        space: EmbeddingSpace,
        model: Arc<dyn DeviceTextModel>,
    ) {
        let tower = DeviceSpaceTower {
            space: space.clone(),
            source: DeviceModelSource::Installed,
            loading: Mutex::new(()),
            model: OnceLock::new(),
        };
        let _ = tower.model.set(model);
        self.device_space_towers
            .by_space
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(space.id, Arc::new(tower));
    }

    /// Every space a world names as its own text space, by id; empty when
    /// they do not read, which is logged.
    pub(crate) fn world_text_spaces(&self) -> Vec<EmbeddingSpace> {
        self.vault.world_text_spaces().unwrap_or_else(|error| {
            tracing::debug!(%error, "the worlds' own text spaces did not read");
            Vec::new()
        })
    }

    /// The tower of each world text space whose model serves on this
    /// machine and which declares a text query tower: the lists a text query
    /// adds. A space that takes text documents but no text query adds none,
    /// as retrieval would refuse its seed for the whole request. Nothing is
    /// loaded.
    pub(crate) fn world_space_query_towers(&self) -> Vec<Arc<DeviceSpaceTower>> {
        self.world_text_spaces()
            .iter()
            .filter(|space| space.query_towers.contains(&InputKind::Text))
            .filter_map(|space| match self.device_space_tower(space) {
                Ok(tower) => tower.filter(|tower| tower.loaded().is_some()),
                Err(refusal) => {
                    tracing::debug!(space = %space.id, %refusal, "a world's text space adds no query list");
                    None
                }
            })
            .collect()
    }
}

/// `query`'s vector in each tower's space, through its loaded model: one
/// list per world text space, which recall searches beside the others
/// (ARCH-0004 MERGE-RULE = B). A model that fails, or answers a vector not
/// of its space's width or not finite, adds no list. Blocking.
pub(crate) fn world_space_query_vectors(
    towers: &[Arc<DeviceSpaceTower>],
    query: &str,
) -> Vec<(String, Vec<f32>)> {
    towers
        .iter()
        .filter_map(|tower| {
            let model = tower.loaded()?;
            match model.query(query) {
                Ok(vector)
                    if vector.len() == tower.space.dimensions
                        && vector.iter().all(|value| value.is_finite()) =>
                {
                    Some((tower.space.id.clone(), vector))
                }
                Ok(vector) => {
                    tracing::debug!(space = %tower.space.id, got = vector.len(), "a world's text space model answered no usable query vector");
                    None
                }
                Err(error) => {
                    tracing::debug!(space = %tower.space.id, %error, "a world's text space model did not embed the query");
                    None
                }
            }
        })
        .collect()
}

/// The stored input kinds a world text space's query list keeps: text.
pub(crate) const WORLD_SPACE_QUERY_KINDS: [InputKind; 1] = [InputKind::Text];
