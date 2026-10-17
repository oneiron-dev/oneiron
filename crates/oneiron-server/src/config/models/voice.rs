//! `[models.voice]`: the server's own voice loop (OF-410). Off unless
//! `socket` names where it listens.

use std::path::{Path, PathBuf};

use oneiron::voice_cascade::media::VoiceRender;
use serde::Deserialize;

use super::levels;

/// Calls the voice loop's media queue holds by default.
const DEFAULT_QUEUE_CAPACITY: usize = 64;
/// A call's line for the host's own model calls by default.
const DEFAULT_CALL_BUDGET_UNITS: u64 = 64_000;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VoiceFile {
    socket: Option<PathBuf>,
    extraction_prompt: Option<String>,
    extraction_prompt_file: Option<PathBuf>,
    stock_voice: Option<String>,
    bank_voice: Option<String>,
    queue_capacity: Option<usize>,
    call_budget_units: Option<u64>,
}

/// The resolved `[models.voice]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceSettings {
    /// The loop's private socket: its parent is the owner-only runtime
    /// directory. `None`: no voice loop.
    pub socket: Option<PathBuf>,
    /// The TINY entity-label and salient-term prompt each partial is
    /// enriched with for speculative retrieval.
    pub extraction_prompt: Option<String>,
    /// The voice the assistant speaks in.
    pub render: Option<VoiceRender>,
    /// Calls the media queue holds. Past it, heard audio waits for the
    /// next cut and a sentence waits for room.
    pub queue_capacity: usize,
    /// Each call's line for the host's own model calls: partial
    /// enrichment and the sentence safeguard's model.
    pub call_budget_units: u64,
}

impl VoiceFile {
    pub(super) fn resolve(self, base: Option<&Path>) -> anyhow::Result<VoiceSettings> {
        let extraction_prompt = levels::prompt_text(
            "models.voice.extraction_prompt",
            self.extraction_prompt,
            self.extraction_prompt_file,
            base,
        )?;
        let render = match (self.stock_voice, self.bank_voice) {
            (Some(_), Some(_)) => {
                anyhow::bail!("models.voice: set `stock_voice` or `bank_voice`, not both")
            }
            (Some(name), None) => Some(VoiceRender::Stock(name)),
            (None, Some(voice_id)) => Some(VoiceRender::Bank {
                voice_id,
                include_generated: false,
                register: None,
            }),
            (None, None) => None,
        };
        if let Some(socket) = &self.socket {
            anyhow::ensure!(
                socket.is_absolute() && socket.file_name().is_some(),
                "models.voice.socket must be an absolute socket path"
            );
            anyhow::ensure!(
                extraction_prompt.is_some(),
                "models.voice.socket needs `extraction_prompt` or `extraction_prompt_file`"
            );
            anyhow::ensure!(
                render.is_some(),
                "models.voice.socket needs `stock_voice` or `bank_voice`"
            );
        }
        let queue_capacity = self.queue_capacity.unwrap_or(DEFAULT_QUEUE_CAPACITY);
        let call_budget_units = self.call_budget_units.unwrap_or(DEFAULT_CALL_BUDGET_UNITS);
        anyhow::ensure!(
            queue_capacity > 0 && call_budget_units > 0,
            "models.voice: queue_capacity and call_budget_units must be > 0"
        );
        Ok(VoiceSettings {
            socket: self.socket,
            extraction_prompt,
            render,
            queue_capacity,
            call_budget_units,
        })
    }
}
