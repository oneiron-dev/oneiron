//! This machine's measured engine rows: where they live, how they are read
//! and written, and what keys them. Rows are written in this format only: a
//! file in any other is unreadable, and the engines are measured again.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Engine;
use super::calibration::{CALIBRATION_IDLE, Timing};
use crate::config::oneironer::OneironerRuntime;

/// This machine's measured rows, under its data directory.
const ROWS_FILE: &str = "engines.json";
/// The file macOS names its build in.
const MAC_VERSION_FILE: &str = "/System/Library/CoreServices/SystemVersion.plist";
/// The file Linux names its kernel release in.
const LINUX_RELEASE_FILE: &str = "/proc/sys/kernel/osrelease";
/// The longest OS build a row keeps; a longer string is not one.
const MAX_OS_BUILD_BYTES: usize = 64;

/// One engine measured on this machine against one bundle's reference.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Row {
    pub(crate) stack_sha16: String,
    pub(crate) reference_sha16: String,
    pub(crate) engine: String,
    /// The runtime that ran it (`candle`): another runtime runs other kernels.
    pub(crate) runtime: String,
    /// The bytes that runtime loaded, by hash.
    pub(crate) artifact_sha16: String,
    /// The server build that measured it: another build may run other kernels.
    pub(crate) build: String,
    /// The OS build it was measured on: an update may move a runtime's speed.
    pub(crate) os_build: String,
    /// Idle milliseconds before each timed case.
    pub(crate) idle_ms: u64,
    /// The longest live window, in tokens with specials, a reference case
    /// may need to be held; candle's is its `max_input_tokens`.
    pub(crate) max_window_tokens: usize,
    /// The `live_window_tokens` each case's window was cut to.
    pub(crate) live_window_tokens: u32,
    /// Whether every held reference answer cleared the bar; a row holding
    /// none clears nothing.
    pub(crate) clears: bool,
    /// Mean wall-clock milliseconds per reference case, each timed after the
    /// idle, after one warm-up call; `None` when the engine could not load
    /// the bundle or answer, which no rows file keeps.
    pub(crate) mean_ms: Option<f64>,
    /// The cases' median milliseconds, as `mean_ms` is timed.
    pub(crate) p50_ms: Option<f64>,
    /// The cases' 95th percentile milliseconds, as `mean_ms` is timed.
    pub(crate) p95_ms: Option<f64>,
    /// The reference cases held and timed.
    pub(crate) cases: usize,
    /// The reference cases whose window is longer than `max_window_tokens`:
    /// left out, never failed.
    pub(crate) skipped: usize,
    /// Unix seconds.
    pub(crate) measured_at: u64,
}

/// What a row is measured for: it is reused while every part holds, and
/// measured again once one moves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RowKey {
    stack_sha16: String,
    reference_sha16: String,
    engine: String,
    runtime: String,
    artifact_sha16: String,
    build: String,
    os_build: String,
    idle_ms: u64,
    window: WindowRules,
}

/// The window rules a row is measured under: which reference cases it
/// holds, and how each case's window is cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WindowRules {
    /// The longest window a held case may need, tokens with specials.
    pub(super) max_window_tokens: usize,
    /// The earlier text a live window keeps.
    pub(super) live_window_tokens: u32,
}

impl RowKey {
    /// `engine`'s key for the bundle `stack` and its reference, under this
    /// server build and OS build and these window rules.
    pub(super) fn new(
        stack: &str,
        reference: &str,
        engine: Engine,
        build: &str,
        os_build: &str,
        window: WindowRules,
    ) -> Self {
        let artifact = match engine.runtime {
            // A candle engine loads the bundle the stack names.
            OneironerRuntime::Candle => stack,
        };
        Self {
            stack_sha16: stack.to_owned(),
            reference_sha16: reference.to_owned(),
            engine: engine.id(),
            runtime: engine.runtime.as_str().to_owned(),
            artifact_sha16: artifact.to_owned(),
            build: build.to_owned(),
            os_build: os_build.to_owned(),
            idle_ms: u64::try_from(CALIBRATION_IDLE.as_millis()).unwrap_or(u64::MAX),
            window,
        }
    }

    /// The longest window a case the row holds may need.
    pub(super) fn max_window_tokens(&self) -> usize {
        self.window.max_window_tokens
    }
}

impl Row {
    /// A row for `key` holding `cases` and skipping `skipped`, with nothing
    /// timed and nothing cleared yet.
    pub(super) fn unmeasured(key: &RowKey, cases: usize, skipped: usize) -> Self {
        let key = key.clone();
        Self {
            stack_sha16: key.stack_sha16,
            reference_sha16: key.reference_sha16,
            engine: key.engine,
            runtime: key.runtime,
            artifact_sha16: key.artifact_sha16,
            build: key.build,
            os_build: key.os_build,
            idle_ms: key.idle_ms,
            max_window_tokens: key.window.max_window_tokens,
            live_window_tokens: key.window.live_window_tokens,
            clears: false,
            mean_ms: None,
            p50_ms: None,
            p95_ms: None,
            cases,
            skipped,
            measured_at: unix_now(),
        }
    }

    pub(super) fn is_for(&self, key: &RowKey) -> bool {
        self.stack_sha16 == key.stack_sha16
            && self.reference_sha16 == key.reference_sha16
            && self.engine == key.engine
            && self.runtime == key.runtime
            && self.artifact_sha16 == key.artifact_sha16
            && self.build == key.build
            && self.os_build == key.os_build
            && self.idle_ms == key.idle_ms
            && self.max_window_tokens == key.window.max_window_tokens
            && self.live_window_tokens == key.window.live_window_tokens
    }

    /// Its timing, when it clears the bar and was timed.
    pub(super) fn clearing(&self) -> Option<Timing> {
        if !self.clears {
            return None;
        }
        Some(Timing {
            mean_ms: self.mean_ms?,
            p50_ms: self.p50_ms?,
            p95_ms: self.p95_ms?,
        })
    }
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RowsFile {
    rows: Vec<Row>,
}

/// The server build a row is measured under.
pub(super) fn build_id() -> String {
    format!(
        "{}+{}-{}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        std::env::consts::OS
    )
}

/// The OS build this machine runs, as rows key it: macOS's build number, a
/// Linux kernel's release, else the OS name alone.
pub(super) fn os_build() -> String {
    let os = std::env::consts::OS;
    let named = match os {
        "macos" => mac_build(),
        "linux" => std::fs::read_to_string(LINUX_RELEASE_FILE)
            .ok()
            .map(|release| release.trim().to_owned()),
        _ => None,
    };
    let named = named.filter(|build| {
        !build.is_empty()
            && build.len() <= MAX_OS_BUILD_BYTES
            && build.bytes().all(|byte| byte.is_ascii_graphic())
    });
    named.map_or_else(|| os.to_owned(), |build| format!("{os} {build}"))
}

/// `ProductBuildVersion` in the system version file: the build an update
/// moves, which the release number alone does not name.
fn mac_build() -> Option<String> {
    let plist = std::fs::read_to_string(MAC_VERSION_FILE).ok()?;
    let (_, after) = plist.split_once("<key>ProductBuildVersion</key>")?;
    let (_, value) = after.split_once("<string>")?;
    let (build, _) = value.split_once("</string>")?;
    Some(build.trim().to_owned())
}

/// The rows file: `rows_location` when the caller names one, and then no
/// environment is read; else `<data>/oneiron/oneironer/engines.json`, the
/// data directory found the way the embedder's model root is:
/// `XDG_DATA_HOME`, then the home share tree. `None` when nothing is named
/// and neither names an absolute directory; rows are then measured and kept
/// for this process only.
///
/// A managed vault names its own, under its data directory: it reads no HOME
/// or XDG, and its rows never go under a shared model root or a bundle.
pub(super) fn rows_path(rows_location: Option<&Path>) -> Option<PathBuf> {
    if let Some(rows_location) = rows_location {
        return Some(rows_location.to_path_buf());
    }
    let absolute = |key: &str| {
        let path = PathBuf::from(std::env::var_os(key)?);
        path.is_absolute().then_some(path)
    };
    let data = absolute("XDG_DATA_HOME")
        .or_else(|| absolute("HOME").map(|home| home.join(".local").join("share")))?;
    Some(data.join("oneiron").join("oneironer").join(ROWS_FILE))
}

/// The rows file, empty when absent; an unreadable one is measured over.
pub(super) fn read_rows(path: &Path) -> Vec<Row> {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<RowsFile>(&bytes) {
            Ok(file) => file.rows,
            Err(_) => {
                tracing::warn!(path = %path.display(), "oneironer engine rows unreadable; measuring again");
                Vec::new()
            }
        },
        Err(_) => Vec::new(),
    }
}

/// Writes the rows whole, through a sibling file and a rename.
pub(super) fn write_rows(path: &Path, rows: &[Row]) {
    let written = (|| -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let staged = path.with_extension("json.tmp");
        std::fs::write(
            &staged,
            serde_json::to_vec_pretty(&RowsFile {
                rows: rows.to_vec(),
            })?,
        )?;
        std::fs::rename(&staged, path)?;
        Ok(())
    })();
    if let Err(error) = written {
        tracing::warn!(path = %path.display(), %error, "oneironer engine rows not saved; the next start measures again");
    }
}

pub(super) fn sha16(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))[..16].to_owned()
}

pub(super) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
