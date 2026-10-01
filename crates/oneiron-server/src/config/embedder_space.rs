//! The local provider's space id and the files that fill it, settled as one.
//!
//! A vault pins the space id, and the local provider fills it from the
//! repository and commit it fetches, so the two must name the same weights. A
//! layer that names only the space selects that space's own files; one that
//! names only the files names the space they fill; names that disagree are
//! refused before anything opens. A mirror that keeps another repository's id
//! is a label, not proof it holds those weights.
//!
//! `model_dir` is the operator's own word for where the files are, and is not
//! checked against either name.

use super::embedder::{EmbedderConfig, EmbedderConfigOverride, EmbedderProvider};

/// Whether any layer named the space, and whether any named its files.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SpaceNaming {
    space: bool,
    files: bool,
}

impl SpaceNaming {
    pub(super) fn of(layers: [Option<&EmbedderConfigOverride>; 3]) -> Self {
        layers
            .into_iter()
            .flatten()
            .fold(Self::default(), |named, layer| Self {
                space: named.space || layer.model_id.is_some(),
                files: named.files || layer.repo.is_some() || layer.revision.is_some(),
            })
    }
}

/// Settles the resolved local section once every layer has applied.
pub(super) fn settle_local_space(
    embedder: &mut EmbedderConfig,
    named: SpaceNaming,
) -> anyhow::Result<()> {
    if embedder.provider != EmbedderProvider::Local || !named.files {
        return Ok(());
    }
    let files = format!("{}@{}", embedder.local.repo, embedder.local.revision);
    if !named.space {
        embedder.model_id = files;
        return Ok(());
    }
    if embedder.model_id != files {
        return Err(oneiron::Error::InvalidConfig(format!(
            "embedder.model_id is {}, but embedder.repo and embedder.revision name {files}; the files fill the space, so name one model (drop repo/revision to load the model_id's own files, or set model_id to {files})",
            embedder.model_id
        ))
        .into());
    }
    Ok(())
}
