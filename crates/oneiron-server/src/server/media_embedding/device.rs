//! A device text space's model in this process (DEC-0005
//! #private-world-vectors; census L5-26), alongside the ordinary rung
//! implementation: no `ai.embed` seat, no inference call, nothing leaves the
//! machine.
use super::super::device_embedding::DeviceSpaceTower;
use super::*;

impl SyncServer {
    /// The embedder for declared space `space_id` when its model runs on the
    /// device (`<org>/<name>@<commit>@device`): that model, in this process,
    /// loaded on the first document it embeds. `None` for a space on an
    /// `ai.embed` rung.
    pub(super) fn device_media_embedder(
        &self,
        space_id: &str,
    ) -> Result<Option<RuntimeMediaEmbedder>, MediaEmbedRefusal> {
        if !oneiron::embed::space_runs_on_device(space_id) {
            return Ok(None);
        }
        let space = self
            .vault
            .embedding_spaces()?
            .into_iter()
            .find(|space| space.id == space_id)
            .ok_or_else(|| MediaEmbedRefusal::Undeclared(space_id.to_owned()))?;
        let Some(tower) = self.device_space_tower(&space)? else {
            return Ok(None);
        };
        let model = space
            .id
            .rsplit_once('@')
            .and_then(|(pinned, _)| ModelId::new(pinned).ok())
            .ok_or_else(|| {
                oneiron::Error::InvalidConfig(format!(
                    "embedding space {} names no device model",
                    space.id
                ))
            })?;
        Ok(Some(RuntimeMediaEmbedder {
            space,
            model,
            locality: ModelLocality::OnDevice,
            inputs: BTreeSet::from([Modality::Text]),
            ai: self.ai.clone(),
            vault: Arc::clone(&self.vault),
            egress: None,
            names_width: AtomicBool::new(false),
            runtime: None,
            payer: None,
            trained: None,
            device: Some(tower),
        }))
    }
}

impl RuntimeMediaEmbedder {
    /// One text query through the device model's query tower, on a blocking
    /// thread. A model that is not loaded yet refuses: a query never loads
    /// one.
    pub(super) async fn embed_device_query(
        &self,
        tower: &DeviceSpaceTower,
        kind: InputKind,
        media_type: &str,
        bytes: Vec<u8>,
    ) -> Result<Vec<f32>, MediaEmbedRefusal> {
        if kind != InputKind::Text {
            return Err(MediaEmbedRefusal::NoInput {
                model: self.model.clone(),
                modality: media_part(kind, media_type, bytes)?.modality(),
            });
        }
        let text = String::from_utf8(bytes).map_err(|_| MediaEmbedRefusal::NotText)?;
        let model = tower
            .loaded()
            .ok_or_else(|| MediaEmbedRefusal::DeviceModelNotLoaded(self.space.id.clone()))?;
        let vector = tokio::task::spawn_blocking(move || model.query(&text))
            .await
            .map_err(|error| {
                MediaEmbedRefusal::Vault(oneiron::Error::InvalidConfig(error.to_string()))
            })??;
        self.device_vector(vector)
    }

    /// One stored text document through the device model's document tower,
    /// loading the model first when it is not (a first load downloads its
    /// files). Blocking.
    pub(super) fn embed_device_input(
        &self,
        tower: &DeviceSpaceTower,
        input: &MediaEmbeddingInput<'_>,
        release: Option<(
            &(dyn Fn(&[oneiron::EntityId]) -> oneiron::Result<()> + Sync),
            &[oneiron::EntityId],
        )>,
    ) -> Result<(Vec<f32>, EmbeddingProvenance), MediaEmbedRefusal> {
        if input.kind != InputKind::Text || !self.space.accepts.contains(&input.kind) {
            return Err(MediaEmbedRefusal::NoInput {
                model: self.model.clone(),
                modality: media_part(input.kind, input.media_type, input.bytes.to_vec())?
                    .modality(),
            });
        }
        let text = std::str::from_utf8(input.bytes).map_err(|_| MediaEmbedRefusal::NotText)?;
        let model = tower.load()?;
        if let Some((release, rows)) = release {
            release(rows)?;
        }
        let vector = self.device_vector(model.document(text)?)?;
        Ok((vector, model.provenance()))
    }

    /// Loads a device text space's model when its files are on this machine
    /// already, from a pass that embedded the space's rows before, so a
    /// query finds the model serving after a restart; nothing for any other
    /// embedder. Blocking.
    pub(crate) fn load_device_model_on_disk(&self) -> Result<(), MediaEmbedRefusal> {
        if let Some(device) = &self.device {
            device.load_when_on_disk()?;
        }
        Ok(())
    }

    /// `vector` when it is one finite vector of the space's width.
    fn device_vector(&self, vector: Vec<f32>) -> Result<Vec<f32>, MediaEmbedRefusal> {
        if vector.len() != self.space.dimensions {
            return Err(MediaEmbedRefusal::Width {
                space: self.space.id.clone(),
                expected: self.space.dimensions,
                got: vector.len(),
            });
        }
        if vector.iter().any(|value| !value.is_finite()) {
            return Err(MediaEmbedRefusal::Malformed);
        }
        Ok(vector)
    }
}
