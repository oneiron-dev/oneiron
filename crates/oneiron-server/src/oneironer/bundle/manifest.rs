//! The manifest's common rows: the trunk, its config and tokenizer, the
//! label table and the optional heads. Their checks that need no setting
//! run as the manifest parses, for every reader: the label tables, each
//! artifact row's shape, each head's parameters and trunk binding, and the
//! platform rows. What a section pins is checked by the loader.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Deserialize;

use super::platform::{self, Platform};
use super::{Artifact, FORMAT_VERSION};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MentionHead {
    pub(crate) weights: Artifact,
    pub(crate) trunk_sha16: String,
    pub(crate) labels: Vec<String>,
    pub(crate) o_bias: f32,
    /// Labels that are not overt mentions (for example predicate anchors).
    pub(crate) ignored_labels: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CorefHead {
    pub(crate) weights: Artifact,
    pub(crate) trunk_sha16: String,
    pub(crate) repr_dim: usize,
    pub(crate) tau: f32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VadHead {
    pub(crate) weights: Artifact,
    pub(crate) trunk_sha16: String,
    pub(crate) hidden_size: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CharacterHead {
    /// The checkpoint's own training config.json, copied verbatim.
    pub(crate) config: Artifact,
    /// Must be this build's `ONEIRONER_DECODE_REVISION`, so a bundle never
    /// runs a decode other than the one it names.
    pub(crate) decode_revision: String,
}

/// The keys a checkpoint's training config holds for its character head.
/// The file's other keys are training settings and go unread.
#[derive(Deserialize)]
pub(crate) struct CharacterConfig {
    pub(crate) char_head: bool,
    pub(crate) char_dim: u32,
    pub(crate) char_vocab: BTreeMap<String, u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    /// 2: another format is refused before this parse.
    pub(crate) format_version: u32,
    pub(crate) trunk: Artifact,
    pub(crate) config: Artifact,
    pub(crate) tokenizer: Artifact,
    pub(crate) ner_labels: Vec<String>,
    pub(crate) mentions: Option<MentionHead>,
    pub(crate) coref: Option<CorefHead>,
    pub(crate) vad: Option<VadHead>,
    pub(crate) characters: Option<CharacterHead>,
    /// The runtime rows, required and possibly empty; each is checked on
    /// every OS, whether or not this machine runs it.
    pub(crate) platforms: Vec<Platform>,
}

impl Manifest {
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.format_version == FORMAT_VERSION,
            "unsupported local oneironer manifest version"
        );
        validate_labels(&self.ner_labels)?;
        let mut artifacts = vec![&self.trunk, &self.config, &self.tokenizer];
        artifacts.extend(self.mentions.as_ref().map(|head| &head.weights));
        artifacts.extend(self.coref.as_ref().map(|head| &head.weights));
        artifacts.extend(self.vad.as_ref().map(|head| &head.weights));
        artifacts.extend(self.characters.as_ref().map(|head| &head.config));
        for artifact in artifacts {
            artifact.validate()?;
        }
        let trunk = &self.trunk.sha256[..16];
        if let Some(head) = &self.mentions {
            anyhow::ensure!(
                head.trunk_sha16 == trunk,
                "mention head belongs to another trunk"
            );
            anyhow::ensure!(head.o_bias.is_finite(), "invalid mention O bias");
            validate_labels(&head.labels)?;
        }
        if let Some(head) = &self.coref {
            anyhow::ensure!(
                head.trunk_sha16 == trunk && head.repr_dim > 0 && head.tau.is_finite(),
                "invalid coreference head or trunk binding"
            );
            anyhow::ensure!(
                self.mentions.is_some(),
                "coreference requires a mention proposer"
            );
        }
        if let Some(head) = &self.vad {
            anyhow::ensure!(
                head.trunk_sha16 == trunk && head.hidden_size > 0,
                "invalid affect head or trunk binding"
            );
        }
        platform::validate_rows(&self.platforms)
    }

    /// The platform row named `name`.
    pub(crate) fn platform(&self, name: &str) -> Option<&Platform> {
        self.platforms.iter().find(|row| row.name() == name)
    }
}

/// The character vocabulary as the head reads it, and the embedding rows it
/// fills: ids run from 2 with no gap, 0 being padding and 1 an unknown
/// character, as the model project's loader requires.
pub(crate) fn character_vocab(
    vocab: BTreeMap<String, u32>,
) -> anyhow::Result<(HashMap<char, u32>, usize)> {
    let mut ids = BTreeSet::new();
    let mut table = HashMap::with_capacity(vocab.len());
    for (key, id) in vocab {
        let mut scalars = key.chars();
        let (Some(character), None) = (scalars.next(), scalars.next()) else {
            anyhow::bail!("oneironer character vocabulary keys must be single characters");
        };
        ids.insert(id);
        table.insert(character, id);
    }
    let rows = table.len() + 2;
    anyhow::ensure!(
        ids.len() == table.len()
            && ids.first() == Some(&2)
            && ids.last().map(|&last| last as usize + 1) == Some(rows),
        "oneironer character vocabulary ids must run from 2 with no gap"
    );
    Ok((table, rows))
}

fn validate_labels(labels: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(
        labels.first().map(String::as_str) == Some("O"),
        "local extraction BIO table must start with O"
    );
    let mut seen = BTreeSet::new();
    for label in labels {
        anyhow::ensure!(seen.insert(label), "duplicate extraction BIO label");
        if label == "O" {
            continue;
        }
        let Some((prefix, kind)) = label.split_once('-') else {
            anyhow::bail!("invalid extraction BIO label");
        };
        anyhow::ensure!(
            matches!(prefix, "B" | "I") && !kind.is_empty() && kind.len() <= 64,
            "invalid extraction BIO label"
        );
    }
    Ok(())
}
