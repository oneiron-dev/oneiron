//! `[embedding]`: the embedding spaces and kind slots a vault starts with
//! (OF-370; ARCH-0019 `#default-bindings`).
//!
//! File-only, like `[models]`. Each start declares every listed space the
//! vault does not hold yet, then binds every listed slot the vault binds to
//! nothing yet. The vault's own rows win after that: a space the owner door
//! changed, or a slot a version move swapped, is left as it is. A listed
//! space the vault holds at another width stops serve, since a new width is a
//! new space.
//!
//! ```toml
//! [[embedding.spaces]]
//! id = "google/embeddinggemma-2@914f7f89142e33e77833254d9c9b90c3cef7303b@own"
//! dimensions = 768
//! accepts = ["image", "audio"]
//! query_towers = ["text", "image", "audio"]
//! evidence = { floor = 0.3, strong = 0.5 }
//!
//! [embedding.slots]
//! image = "google/embeddinggemma-2@914f7f89142e33e77833254d9c9b90c3cef7303b@own"
//! audio = "google/embeddinggemma-2@914f7f89142e33e77833254d9c9b90c3cef7303b@own"
//! ```
//!
//! `one_space = "<id>"` in place of `[embedding.slots]` is the one-space
//! preset: every kind the space accepts, text included.

use std::collections::BTreeSet;

use oneiron::Vault;
use oneiron::embed::{EmbeddingSpace, InputKind};
use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EmbeddingConfig {
    /// Spaces declared at start when the vault holds none by that id.
    pub spaces: Vec<EmbeddingSpace>,
    /// Kind slots bound at start when the vault binds them to nothing.
    pub slots: EmbeddingSlotsConfig,
    /// The one-space preset's space, bound at start when the vault binds no
    /// slot yet.
    pub one_space: Option<String>,
}

/// Kind to declared space id. An unbound text slot reads the vault's own
/// text index.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct EmbeddingSlotsConfig {
    pub text: Option<String>,
    pub image: Option<String>,
    pub audio: Option<String>,
}

impl EmbeddingSlotsConfig {
    fn bindings(&self) -> impl Iterator<Item = (InputKind, &str)> {
        [
            (InputKind::Text, &self.text),
            (InputKind::Image, &self.image),
            (InputKind::Audio, &self.audio),
        ]
        .into_iter()
        .filter_map(|(kind, space)| Some((kind, space.as_deref()?)))
    }
}

impl EmbeddingConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        let mut ids = BTreeSet::new();
        for space in &self.spaces {
            space.validate()?;
            if !ids.insert(space.id.as_str()) {
                anyhow::bail!("[embedding] lists space {} twice", space.id);
            }
        }
        if self.one_space.is_some() && self.slots.bindings().next().is_some() {
            anyhow::bail!(
                "[embedding] one_space binds every slot; drop it or [embedding.slots], not both"
            );
        }
        Ok(())
    }

    /// Declares the listed spaces the vault does not hold, then binds the
    /// listed slots it binds to nothing. Runs before the listener binds.
    pub fn apply_to(&self, vault: &Vault) -> anyhow::Result<()> {
        let held = vault.embedding_spaces()?;
        for space in &self.spaces {
            match held.iter().find(|held| held.id == space.id) {
                Some(held) if held.dimensions != space.dimensions => anyhow::bail!(
                    "[embedding] lists space {} at width {}, but the vault holds it at width {}; a new width is a new space, so give it a new id",
                    space.id,
                    space.dimensions,
                    held.dimensions
                ),
                Some(_) => {}
                None => {
                    vault.declare_embedding_space(space.clone())?;
                    tracing::info!(space = %space.id, "embedding space declared from [embedding]");
                }
            }
        }
        let bound = vault.kind_slot_bindings()?;
        if let Some(space) = &self.one_space {
            if InputKind::ALL
                .iter()
                .all(|kind| bound.space_for(*kind).is_none())
            {
                vault.bind_one_space_for_all(space)?;
                tracing::info!(%space, "one-space preset bound from [embedding]");
            }
            return Ok(());
        }
        for (kind, space) in self.slots.bindings() {
            match bound.space_for(kind) {
                None => {
                    vault.bind_kind_slot(kind, space)?;
                    tracing::info!(?kind, %space, "kind slot bound from [embedding]");
                }
                Some(held) if held != space => tracing::info!(
                    ?kind,
                    listed = %space,
                    bound = %held,
                    "kind slot keeps the vault's binding over [embedding]"
                ),
                Some(_) => {}
            }
        }
        Ok(())
    }
}
