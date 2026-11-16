//! Where a refused setting came from (FIX CONFIG-REFUSED-VALUE-NAMES-NO-FILE-LINE).
//!
//! A value refused after the parse names its key path and nothing of where
//! it was set, and serve merges four layers: the config file, the owner's
//! settings file, the environment and the flags. So a refusal is given the
//! layer it came from, as the context over the unchanged refusal (a typed
//! error under it still downcasts). For a file layer that is the file and
//! the line of the longest key path the refusal names that the file sets,
//! else the file alone. The environment and the flags are named as layers:
//! most refusals already name their variable and their flag.
//!
//! A refusal met as a layer is applied comes from that layer. One met when
//! the merged result is checked is located by merging the layers again over
//! the defaults, one more at a time: the first merge whose check meets the
//! same refusal names the layer it added last. No validator changes for it.

use std::path::{Path, PathBuf};

use super::super::diagnostics::locate_named_key;

/// Where one layer's values came from.
pub(super) enum LayerOrigin {
    /// The config file: `--config`, `ONEIRON_CONFIG` or the default path,
    /// and the text it was read from.
    ConfigFile { path: PathBuf, raw: String },
    /// The owner's settings file (`--settings-file`), and its text.
    SettingsFile { path: PathBuf, raw: String },
    /// The `ONEIRON_*` environment.
    Environment,
    /// The command line's flags.
    CommandLine,
}

impl LayerOrigin {
    /// `refusal`, under the place this layer set what it refuses.
    pub(super) fn attach(&self, refusal: anyhow::Error) -> anyhow::Error {
        let place = match self {
            Self::ConfigFile { path, raw } => file_place("config file", path, raw, &refusal),
            Self::SettingsFile { path, raw } => file_place("settings file", path, raw, &refusal),
            Self::Environment => "from the environment".to_owned(),
            Self::CommandLine => "from the command line".to_owned(),
        };
        refusal.context(place)
    }
}

/// `refusal`, met checking the merge of every layer, under the origin of the
/// layer that completes it: `refused_with(count)` is the refusal met checking
/// the merge of the first `count` layers, if any, and the first count whose
/// refusal reads the same names the layer at `count - 1`. The refusal as it
/// is when the defaults alone meet it, when that layer has no origin, or
/// when no merge meets it.
pub(super) fn locate_refusal(
    refusal: anyhow::Error,
    origins: &[Option<&LayerOrigin>],
    refused_with: impl Fn(usize) -> Option<anyhow::Error>,
) -> anyhow::Error {
    let refused = format!("{refusal:#}");
    let completes = (0..=origins.len())
        .find(|&count| refused_with(count).is_some_and(|met| format!("{met:#}") == refused));
    match completes
        .and_then(|count| count.checked_sub(1))
        .and_then(|last| origins[last])
    {
        Some(origin) => origin.attach(refusal),
        None => refusal,
    }
}

/// The place a file layer set what `refusal` names: the key and its line
/// when the file sets a key path the refusal names, else the file.
fn file_place(noun: &str, path: &Path, raw: &str, refusal: &anyhow::Error) -> String {
    match locate_named_key(raw, &format!("{refusal:#}")) {
        Some((key, line)) => format!("{key} is set in {noun} {} at line {line}", path.display()),
        None => format!("from {noun} {}", path.display()),
    }
}
