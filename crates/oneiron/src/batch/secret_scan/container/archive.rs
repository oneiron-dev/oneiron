//! Core half of `batch::secret_scan::container::archive`: its store-layer items live in `oneiron_store::batch::secret_scan::container::archive` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::secret_scan::container::archive::*;

use super::{Budget, Walked, encode_failed, hidden_member, over_budget, unreadable};
use crate::file_secret_marks::MemberStep;
use flate2::read::DeflateDecoder;
use std::io::{Cursor, Read, Write};
use zip::write::FileOptions;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter};

pub(super) fn members(
    bytes: &[u8],
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<()>,
) -> Walked<()> {
    let mut archive = open(bytes)?;
    let mut covered = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let (_, data, span) = read(&mut archive, index, budget)?;
        covered.push(span);
        each(step(index)?, &data, budget)?;
    }
    if budget.hidden {
        outside(bytes, covered, budget, each)?;
    }
    Ok(())
}

/// The bytes outside the central directory's entries (FIX 2470): each run
/// `covered` leaves, handed whole when it is a container the walk reads,
/// and each local entry in it decoded.
fn outside(
    bytes: &[u8],
    mut covered: Vec<(u64, u64)>,
    budget: &mut Budget,
    each: &mut dyn FnMut(MemberStep, &[u8], &mut Budget) -> Walked<()>,
) -> Walked<()> {
    let at = |offset: u64| usize::try_from(offset).map_or(bytes.len(), |at| at.min(bytes.len()));
    covered.sort_unstable();
    let mut runs = Vec::new();
    let mut end = 0;
    for (from, to) in covered {
        if at(from) > end {
            runs.push(end..at(from));
        }
        end = end.max(at(to));
    }
    runs.push(end..bytes.len());
    for run in runs {
        let run = &bytes[run];
        if run.is_empty() {
            continue;
        }
        if super::classify(run).is_some() && hidden_member(run) {
            each(OUTSIDE, run, budget)?;
        }
        for (local, head) in run.windows(LOCAL.len()).enumerate() {
            if head == LOCAL
                && let Some(data) = local_entry(&run[local..], budget)?
                && hidden_member(&data)
            {
                each(OUTSIDE, &data, budget)?;
            }
        }
    }
    Ok(())
}
