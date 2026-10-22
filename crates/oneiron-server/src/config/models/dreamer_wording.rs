//! `[models.dreamer.wording]`: the host's wording of what the engine asks a
//! model in its own words today (FIX 8696). Each piece ships its default here,
//! word for word what the engine asked before, so nothing changes until the
//! owner writes one.
//!
//! * `confession_prompt` / `confession_prompt_file`: how a workflow step, an
//!   agent run and a Dreamer-lane TASK's realization are asked for their
//!   confession (OF-544). The engine still lists the objectives first and
//!   parses the answer; a wording that asks for no `oneiron-confession` block
//!   is answered with none, and none is recorded.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The confession instruction the engine asked with before it was host
/// wording, and the one a host without its own still asks with.
const DEFAULT_CONFESSION_INSTRUCTION: &str = "When your result is complete, end it with a line \
     that is exactly DONE, then one block fenced ```oneiron-confession holding \
     {\"objectives\":[{\"objective\":\"<the assigned objective, copied exactly>\",\
     \"met\":<true or false>,\"flaw\":<null or what is wrong>,\
     \"uncertainty\":<null or what you are unsure of>}]} with one row per assigned \
     objective, in order. Say plainly what you did not meet, any flaw and any doubt: a \
     confession never costs the score. Nothing follows the closing fence.";

/// `[models.dreamer.wording]` as written in the config file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DreamerWordingFile {
    confession_prompt: Option<String>,
    confession_prompt_file: Option<PathBuf>,
}

impl DreamerWordingFile {
    /// The wording this host asks with: each piece the owner wrote, else its
    /// shipped default. `base` is the config file's directory, against which
    /// a relative `*_file` path resolves.
    pub(super) fn resolve(self, base: Option<&Path>) -> anyhow::Result<DreamerWording> {
        let confession = super::levels::prompt_text(
            "models.dreamer.wording.confession_prompt",
            self.confession_prompt,
            self.confession_prompt_file,
            base,
        )?
        .unwrap_or_else(|| DEFAULT_CONFESSION_INSTRUCTION.to_owned());
        Ok(DreamerWording { confession })
    }
}

/// The host's wording of the engine's asks, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DreamerWording {
    confession: String,
}

impl DreamerWording {
    /// How a run is asked for its confession, after its objectives are
    /// listed.
    #[must_use]
    pub fn confession(&self) -> &str {
        &self.confession
    }
}

impl Default for DreamerWording {
    /// The shipped wording: a host with no `[models]` asks with it too.
    fn default() -> Self {
        Self {
            confession: DEFAULT_CONFESSION_INSTRUCTION.to_owned(),
        }
    }
}
