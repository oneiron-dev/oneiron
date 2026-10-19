//! The run's durable journal, `results.jsonl`: a header line with the run's
//! pins before any case, one complete line per finished case, and a
//! run-complete line once the manifest is in place. Each line is written
//! whole and synced before the run goes on, and every file a line names is
//! already in place (written aside, synced and renamed), so a run cut short
//! by a timeout or a kill keeps every case it finished. The final manifest
//! is folded from this file, not from memory.

use super::record::{
    Calibration, Candidate, Excluded, FileRef, Note, OfficeRef, Res, StepCase, text,
};
use crate::live::deck_export::StepOutcome;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::Path;

/// The journal's name inside the run directory.
pub(super) const JOURNAL: &str = "results.jsonl";
/// The journal's schema; `deck_gate.py` reads no other.
pub(super) const JOURNAL_SCHEMA: &str = "oneiron.deck-gate-journal/1";

/// The journal's first line: what the run is pinned to.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Header {
    pub(super) schema: String,
    pub(super) source: String,
    pub(super) projector: String,
    pub(super) profile: String,
    pub(super) case_manifest: FileRef,
    pub(super) office: OfficeRef,
}

/// One finished case: every engine result, candidate, calibration fixture,
/// exclusion and note it recorded, and its wall time from entry through its
/// last durable write.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct CaseLine {
    pub(super) id: String,
    /// Its results' outcome taken together, as a step's is.
    pub(super) outcome: StepOutcome,
    pub(super) elapsed_ms: u64,
    /// Why the run stopped inside this case, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<String>,
    pub(super) results: Vec<StepCase>,
    pub(super) candidates: Vec<Candidate>,
    pub(super) calibration: Vec<Calibration>,
    pub(super) excluded: Vec<Excluded>,
    pub(super) notes: Vec<Note>,
}

/// One journal line.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "line", rename_all = "snake_case")]
pub(super) enum Line {
    Header(Header),
    Case(CaseLine),
    /// Every case ran and the manifest folded from them is in place.
    Complete {
        manifest: FileRef,
        cases: usize,
    },
}

/// The open journal file; every append is synced before it returns.
pub(super) struct Journal {
    file: File,
}

impl Journal {
    /// A new journal in the run directory `dir`, holding `header`.
    pub(super) fn create(dir: &Path, header: Header) -> Res<Self> {
        let path = dir.join(JOURNAL);
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        sync_dir(dir)?;
        let mut journal = Self { file };
        journal.append(&Line::Header(header))?;
        Ok(journal)
    }

    /// Write one whole line and sync it.
    pub(super) fn append(&mut self, line: &Line) -> Res<()> {
        let mut bytes = serde_json::to_vec(line).map_err(text)?;
        bytes.push(b'\n');
        self.file
            .write_all(&bytes)
            .and_then(|()| self.file.sync_all())
            .map_err(|error| format!("{JOURNAL}: {error}"))
    }
}

/// The journal of the run in `dir`, read back: its header and every case
/// line, in order.
pub(super) fn fold(dir: &Path) -> Res<(Header, Vec<CaseLine>)> {
    let path = dir.join(JOURNAL);
    let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let body = String::from_utf8(bytes).map_err(|_| format!("{JOURNAL} is not UTF-8"))?;
    let mut lines = body.lines().enumerate();
    let header = match lines.next() {
        Some((_, first)) => match serde_json::from_str(first) {
            Ok(Line::Header(header)) if header.schema == JOURNAL_SCHEMA => header,
            _ => return Err(format!("{JOURNAL} does not open with its header")),
        },
        None => return Err(format!("{JOURNAL} is empty")),
    };
    let mut cases = Vec::new();
    for (at, line) in lines {
        match serde_json::from_str(line) {
            Ok(Line::Case(case)) => cases.push(case),
            Ok(_) => return Err(format!("{JOURNAL} line {} is out of place", at + 1)),
            Err(error) => return Err(format!("{JOURNAL} line {}: {error}", at + 1)),
        }
    }
    Ok((header, cases))
}

/// Write `bytes` at `path` whole or not at all: aside, synced, renamed into
/// place, and the directory synced.
pub(super) fn write_atomic(path: &Path, bytes: &[u8]) -> Res<()> {
    let shown = |error: std::io::Error| format!("{}: {error}", path.display());
    let mut name = path
        .file_name()
        .ok_or_else(|| format!("{} names no file", path.display()))?
        .to_os_string();
    name.push(".part");
    let aside = path.with_file_name(name);
    let mut file = File::create(&aside).map_err(shown)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(shown)?;
    drop(file);
    std::fs::rename(&aside, path).map_err(shown)?;
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => sync_dir(dir),
        _ => Ok(()),
    }
}

/// Sync a directory, so a file created or renamed in it stays named.
fn sync_dir(dir: &Path) -> Res<()> {
    File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| format!("{}: {error}", dir.display()))
}
