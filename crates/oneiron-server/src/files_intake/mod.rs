//! The host's intake of local folders (OF-554, FIX 6942): the confined walk,
//! the notes reader, a Files source's reader and the rescan an attached
//! folder runs. `oneiron import notes|folder`, `oneiron files`, the facade's
//! `vault.files.sources.*` doors and `oneiron serve`'s rescan worker all call
//! it; none keeps a traversal of its own, and an HTTP door never runs a CLI
//! command's code.

use serde::Serialize;

#[cfg(unix)]
pub(crate) mod confined;
mod files;
mod markdown;
mod reader;
mod source;
#[cfg(unix)]
mod worker;

#[cfg(unix)]
use confined::{walk_files, walk_notes};
pub(crate) use reader::{
    LinkCounts, NoteCounts, TitleCounts, choose_title, crossed_rows, earlier_titles, read_folder,
    resolve_links,
};
pub(crate) use source::{canonical_folder, files_attached, files_rescan, rescanned};
#[cfg(unix)]
pub(crate) use worker::spawn_rescans;

/// What an import passed over or crossed, and why; the rest of it landed.
#[derive(Serialize)]
#[serde(tag = "warning", rename_all = "snake_case")]
pub(crate) enum ImportWarning {
    /// Files with another name (a hard link), never read: that name can be
    /// outside the folder. Counted, not named, as a notes import's stdout
    /// names no note.
    HardLinked { files: usize },
    /// A folder past one of its `[limits]` rows: read and imported whole
    /// all the same, and the row asks whether everything is okay (OF-520).
    LimitCrossed {
        row: &'static str,
        limit: u64,
        observed: u64,
    },
}

/// Whether the open file has another name (a hard link). A walk passes over
/// such a file: the other name may be outside the folder it was given.
#[cfg(unix)]
pub(crate) fn hard_linked(metadata: &std::fs::Metadata) -> bool {
    std::os::unix::fs::MetadataExt::nlink(metadata) > 1
}

#[cfg(not(unix))]
pub(crate) fn hard_linked(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(not(unix))]
fn walk_notes(
    path: &std::path::Path,
    _visit: &mut dyn FnMut(&std::path::Path, std::fs::File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    anyhow::bail!("importing a folder ({}) needs a unix host", path.display())
}

#[cfg(not(unix))]
fn walk_files(
    path: &std::path::Path,
    _excluded: &dyn Fn(&std::path::Path) -> bool,
    _visit: &mut dyn FnMut(&std::path::Path, std::fs::File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "reading a Files source ({}) needs a unix host",
        path.display()
    )
}
