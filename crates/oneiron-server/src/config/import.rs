//! The `[import]` section: whether a running `serve` imports the session logs
//! queued for it (`oneiron import claude-code <log> --queue`), where that
//! queue lives, the folder each source's queued logs must sit under, and the
//! folders a hook may hand transcripts over from.
//!
//! Off by default. Turning it on is the owner's standing act for every log
//! queued under those folders: `serve` lands each one as `oneiron import`
//! would, and nothing outside them. Listing a hook folder is the same act for
//! the transcripts under it, queued or imported directly.

use std::path::{Path, PathBuf};

use oneiron::ingest::history::HistorySource;
use serde::Deserialize;

/// Resolved import-queue settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImportConfig {
    /// Whether `serve` imports queued session logs. Off unless set.
    pub queue: bool,
    /// Queue directory. `None` means `<vault>.import-queue` beside the vault.
    pub queue_dir: Option<PathBuf>,
    /// The folder queued Claude Code logs must sit under. `None` means
    /// `~/.claude/projects`.
    pub claude_code_root: Option<PathBuf>,
    /// The folder queued Codex rollouts must sit under. `None` means
    /// `~/.codex/sessions`.
    pub codex_root: Option<PathBuf>,
    /// The folders a GitHub Copilot or Cursor hook's transcripts must sit
    /// under (`oneiron import hook-transcript`), each with everything below
    /// it. Empty unless set: no hook transcript is read.
    pub hook_transcript_roots: Vec<PathBuf>,
}

impl ImportConfig {
    /// The queue directory for `vault_path`.
    pub fn queue_dir_for(&self, vault_path: &Path) -> PathBuf {
        self.queue_dir.clone().unwrap_or_else(|| {
            let name = vault_path.file_name().map_or_else(
                || "vault".into(),
                |name| name.to_string_lossy().into_owned(),
            );
            vault_path.with_file_name(format!("{name}.import-queue"))
        })
    }

    /// The folder queued logs of `source` must sit under; `None` for a source
    /// that is an export, not a folder of session logs, and for hook
    /// transcripts, whose folder depends on the log ([`Self::root_for_path`]).
    pub fn root_for(&self, source: HistorySource) -> Option<PathBuf> {
        let (set, default) = match source {
            HistorySource::ClaudeCode => (&self.claude_code_root, "~/.claude/projects"),
            HistorySource::Codex => (&self.codex_root, "~/.codex/sessions"),
            HistorySource::Chatgpt | HistorySource::Claude | HistorySource::HookTranscript => {
                return None;
            }
        };
        Some(
            set.clone()
                .unwrap_or_else(|| super::lookup::expand_home(PathBuf::from(default))),
        )
    }

    /// The folder the log at `path` (absolute) must sit under to be read for
    /// `source`: the source's root, or the deepest hook folder that holds it.
    pub fn root_for_path(&self, source: HistorySource, path: &Path) -> Option<PathBuf> {
        if source != HistorySource::HookTranscript {
            return self.root_for(source);
        }
        self.hook_transcript_roots
            .iter()
            .filter(|root| path.starts_with(root))
            .max_by_key(|root| root.components().count())
            .cloned()
    }

    /// Every hook folder must be absolute, and with the queue on, its folder
    /// and both roots: the hooks queue from the session's folder and `serve`
    /// reads from its own, so a relative path would name two places.
    pub(super) fn validate(&self, vault_path: &Path) -> anyhow::Result<()> {
        for root in &self.hook_transcript_roots {
            anyhow::ensure!(
                root.is_absolute(),
                "every [import] hook_transcript_roots folder must be an absolute path (one is {})",
                root.display()
            );
        }
        if !self.queue {
            return Ok(());
        }
        let queue_dir = self.queue_dir_for(vault_path);
        anyhow::ensure!(
            queue_dir.is_absolute(),
            "import.queue_dir must be an absolute path (it is {})",
            queue_dir.display()
        );
        for source in [HistorySource::ClaudeCode, HistorySource::Codex] {
            if let Some(root) = self.root_for(source) {
                anyhow::ensure!(
                    root.is_absolute(),
                    "the {} root under [import] must be an absolute path (it is {}); \
                     set it, or set HOME for the default",
                    source.source_id(),
                    root.display()
                );
            }
        }
        Ok(())
    }

    pub(super) fn apply_override(&mut self, over: ImportConfigOverride) {
        if let Some(value) = over.queue {
            self.queue = value;
        }
        if let Some(value) = over.queue_dir {
            self.queue_dir = Some(super::lookup::expand_home(value));
        }
        if let Some(value) = over.claude_code_root {
            self.claude_code_root = Some(super::lookup::expand_home(value));
        }
        if let Some(value) = over.codex_root {
            self.codex_root = Some(super::lookup::expand_home(value));
        }
        if let Some(roots) = over.hook_transcript_roots {
            self.hook_transcript_roots =
                roots.into_iter().map(super::lookup::expand_home).collect();
        }
    }
}

/// The config file's `[import]` keys.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ImportConfigOverride {
    pub queue: Option<bool>,
    pub queue_dir: Option<PathBuf>,
    pub claude_code_root: Option<PathBuf>,
    pub codex_root: Option<PathBuf>,
    pub hook_transcript_roots: Option<Vec<PathBuf>>,
}
