//! Checkpoint-only media towers, alongside the ordinary rung implementation.
use super::*;

impl EgressPredicate for MediaEgress {
    fn decide(&self, _input: &PendingEmbeddingInput) -> EgressDecision {
        EgressDecision::NoVerdict
    }

    fn decide_media(&self, _input: &MediaEmbeddingInput<'_>) -> EgressDecision {
        EgressDecision::Allow
    }
}

impl SyncServer {
    pub(super) fn trained_media_embedder(
        &self,
        space_id: &str,
    ) -> Result<Option<RuntimeMediaEmbedder>, MediaEmbedRefusal> {
        let declared = self
            .vault
            .embedding_spaces()?
            .into_iter()
            .find(|space| space.id == space_id);
        if let Some(space) = &declared
            && let Some(trained) = self.trained_embedding_for_space(space)?
        {
            return Ok(Some(RuntimeMediaEmbedder {
                space: space.clone(),
                model: ModelId::new(trained.provider.model_id())
                    .map_err(|_| MediaEmbedRefusal::Unmapped(space.id.clone()))?,
                locality: ModelLocality::OnDevice,
                inputs: BTreeSet::from([Modality::Text]),
                ai: self.ai.clone(),
                vault: Arc::clone(&self.vault),
                egress: None,
                names_width: AtomicBool::new(false),
                runtime: None,
                payer: None,
                trained: Some(trained),
            }));
        }
        Ok(None)
    }
}

impl RuntimeMediaEmbedder {
    pub(super) async fn embed_trained_query(
        &self,
        trained: &Arc<super::super::trained_embedding::TrainedEmbedding>,
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
        let trained = Arc::clone(trained);
        let vault = Arc::clone(&self.vault);
        tokio::task::spawn_blocking(move || trained.query_active(&vault, &text))
            .await
            .map_err(|error| {
                MediaEmbedRefusal::Vault(oneiron::Error::InvalidConfig(error.to_string()))
            })?
            .map_err(MediaEmbedRefusal::Vault)
    }

    pub(super) fn embed_trained_input(
        &self,
        trained: &Arc<super::super::trained_embedding::TrainedEmbedding>,
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
        if let Some((release, rows)) = release {
            release(rows)?;
        }
        let text = std::str::from_utf8(input.bytes).map_err(|_| MediaEmbedRefusal::NotText)?;
        let vector = trained.document(&self.vault, text)?;
        Ok((vector, trained.provider.provenance()))
    }
}

/// The part an input of `kind` sends.
pub(super) fn media_part(
    kind: InputKind,
    media_type: &str,
    bytes: Vec<u8>,
) -> Result<MediaPart, MediaEmbedRefusal> {
    let media_type = media_type.to_owned();
    Ok(match kind {
        InputKind::Image => MediaPart::Image { media_type, bytes },
        InputKind::Audio => MediaPart::Audio { media_type, bytes },
        InputKind::Text => MediaPart::Text {
            text: String::from_utf8(bytes).map_err(|_| MediaEmbedRefusal::NotText)?,
        },
    })
}
