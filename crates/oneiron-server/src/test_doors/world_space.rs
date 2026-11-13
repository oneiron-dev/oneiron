//! Doors for `tests/world_space_recall_seed.rs` (census L5-26 PR 2; DEC-0005
//! #private-world-vectors): a world's own device text space on a server, its
//! model an in-process function in place of the one the space's id names, so
//! nothing is fetched.

use std::sync::Arc;

use oneiron::embed::{
    EmbedderLocality, EmbeddingDevice, EmbeddingProvenance, MediaEmbedReport, MediaEmbedder,
};

use crate::server::{DeviceTextModel, SyncServer};

/// The runtime mark a door's device model stamps on the vectors it computes.
pub const DOOR_DEVICE_RUNTIME: &str = "world-space-door-model";

/// A test's text model: both towers answer `embed(text)`.
pub type DeviceTextFn = Arc<dyn Fn(&str) -> Vec<f32> + Send + Sync>;

struct FnDeviceModel(DeviceTextFn);

impl DeviceTextModel for FnDeviceModel {
    fn query(&self, text: &str) -> oneiron::Result<Vec<f32>> {
        Ok((self.0)(text))
    }

    fn document(&self, text: &str) -> oneiron::Result<Vec<f32>> {
        Ok((self.0)(text))
    }

    fn provenance(&self) -> EmbeddingProvenance {
        EmbeddingProvenance::new(EmbeddingDevice::Cpu, DOOR_DEVICE_RUNTIME)
    }
}

/// Places `embed` as declared space `space_id`'s device model on `server`,
/// loaded, in place of the model the space's id names.
///
/// # Errors
///
/// [`oneiron::Error::InvalidConfig`] for a space not declared on the
/// server's vault; storage errors.
pub fn install_device_text_model(
    server: &SyncServer,
    space_id: &str,
    embed: DeviceTextFn,
) -> oneiron::Result<()> {
    let space = server
        .vault()
        .embedding_spaces()?
        .into_iter()
        .find(|space| space.id == space_id)
        .ok_or_else(|| {
            oneiron::Error::InvalidConfig(format!("embedding space {space_id} is not declared"))
        })?;
    server.install_device_text_model(space, Arc::new(FnDeviceModel(embed)));
    Ok(())
}

/// The locality of the embedder `server` resolves for declared space
/// `space_id`, or the text of its refusal. Nothing is loaded or fetched.
///
/// # Errors
///
/// The refusal's text.
pub fn media_embedder_locality(
    server: &SyncServer,
    space_id: &str,
) -> Result<EmbedderLocality, String> {
    server
        .media_embedder(space_id)
        .map(|embedder| embedder.locality())
        .map_err(|refusal| refusal.to_string())
}

/// One media backfill pass on `server` as its worker runs one, on a blocking
/// thread of the current multi-thread runtime: each space's report, or the
/// text of its refusal.
pub async fn media_backfill_pass(
    server: Arc<SyncServer>,
) -> Vec<(String, Result<MediaEmbedReport, String>)> {
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        server
            .backfill_media_pass_once(&runtime)
            .into_iter()
            .map(|(space, pass)| (space, pass.map_err(|refusal| refusal.to_string())))
            .collect()
    })
    .await
    .expect("the media backfill pass joins")
}
