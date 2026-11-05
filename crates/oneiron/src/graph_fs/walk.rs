//! Core half of `graph_fs::walk`: its store-layer items live in `oneiron_store::graph_fs::walk` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::graph_fs::walk::*;

use super::coreutils_text::{LinePosition, join_graph_path, page_lines};
use super::model::{GRAPH_FS_MAX_SCAN_ROWS, GraphFsEntryKind, GraphFsPage, GraphFsResolver};
use super::paging::{CommandOutputBuilder, SealedPosition};
use crate::error::Result;
use oneiron_contracts::claim::ScopedReadReceipt;

/// The page a walk prints into, and what it read.
struct Walk {
    out: CommandOutputBuilder,
    total: usize,
    receipt: Option<ScopedReadReceipt>,
}

impl GraphFsResolver<'_, '_> {
    pub(super) fn find_walk(&self, path: &str, cursor: Option<&str>) -> Result<WalkOutput> {
        self.walk(path, true, WalkVerb::Find, &format!("find {path}"), cursor)
    }

    pub(super) fn grep_walk(
        &self,
        pattern: &str,
        path: &str,
        recursive: bool,
        cursor: Option<&str>,
    ) -> Result<WalkOutput> {
        let flag = if recursive { " -r" } else { "" };
        let listing = format!("grep{flag} {}:{pattern} {path}", pattern.len());
        self.walk(
            path,
            recursive,
            WalkVerb::Grep { pattern },
            &listing,
            cursor,
        )
    }

    /// Walks `root` as `find` does: the root, then each directory's entries
    /// in listing order, every page of the listing, a directory's own tree
    /// right after it. A page ends where its output or its scan limit cut it,
    /// and only then hands out a cursor, sealed to this walk.
    fn walk(
        &self,
        root: &str,
        recursive: bool,
        verb: WalkVerb<'_>,
        listing: &str,
        cursor: Option<&str>,
    ) -> Result<WalkOutput> {
        let scope = self.cursor_scope(listing);
        let mut at: WalkPosition = scope.open(cursor)?.unwrap_or_default();
        let mut walk = Walk {
            out: CommandOutputBuilder::new(self.options),
            total: 0,
            receipt: None,
        };
        let cut = self.walk_from(root, recursive, verb, &mut at, &mut walk)?;
        Ok(WalkOutput {
            bytes: walk.out.into_bytes(),
            next_cursor: cut.then(|| scope.seal(&at)),
            total: walk.total,
            receipt: walk.receipt,
        })
    }

    /// Walks on from `at`, leaving there where the next page resumes.
    /// Returns whether the page was cut before the walk ended.
    fn walk_from(
        &self,
        root: &str,
        recursive: bool,
        verb: WalkVerb<'_>,
        at: &mut WalkPosition,
        walk: &mut Walk,
    ) -> Result<bool> {
        let mut steps = 0;
        if !at.root_done {
            if !self.coreutils_path_visible(root)? {
                return Ok(false);
            }
            if let Visited::Cut(lines) = self.visit(verb, root, false, at.lines.take(), walk)? {
                at.lines = lines;
                return Ok(true);
            }
            if !recursive {
                return Ok(false);
            }
            at.root_done = true;
            at.frames.push(WalkFrame {
                name: String::new(),
                page: None,
                passed: 0,
            });
        }
        let mut dirs: Vec<String> = Vec::with_capacity(at.frames.len());
        for frame in &at.frames {
            let dir = match dirs.last() {
                Some(parent) => join_graph_path(parent, &frame.name),
                None => root.to_owned(),
            };
            dirs.push(dir);
        }
        let mut pages: Vec<Option<GraphFsPage>> = at.frames.iter().map(|_| None).collect();
        while let Some(depth) = at.frames.len().checked_sub(1) {
            if steps >= GRAPH_FS_MAX_SCAN_ROWS {
                return Ok(true);
            }
            let page = match pages[depth].take() {
                Some(page) => page,
                None => {
                    steps += 1;
                    let page = self.readdir(&dirs[depth], at.frames[depth].page.as_deref())?;
                    if let Some(read) = page.read_receipt() {
                        fold_receipt(&mut walk.receipt, read.clone());
                    }
                    page
                }
            };
            let entry = page
                .entries()
                .get(at.frames[depth].passed)
                .filter(|entry| entry.kind() != GraphFsEntryKind::Cursor)
                .cloned();
            let next_page = page.next_cursor().map(str::to_owned);
            pages[depth] = Some(page);
            // Lines to resume belong to the entry the walk stopped on, so to
            // the first one it reaches now.
            let lines = at.lines.take();
            let Some(entry) = entry else {
                // This page is walked: on to the listing's next page, or back up.
                if let Some(next_page) = next_page {
                    let frame = &mut at.frames[depth];
                    frame.page = Some(next_page);
                    frame.passed = 0;
                    pages[depth] = None;
                } else {
                    at.frames.pop();
                    pages.pop();
                    dirs.pop();
                }
                continue;
            };
            steps += 1;
            let child = join_graph_path(&dirs[depth], entry.name());
            let is_dir = entry.kind() == GraphFsEntryKind::Directory;
            if self.coreutils_path_visible(&child)? {
                if let Visited::Cut(lines) = self.visit(verb, &child, is_dir, lines, walk)? {
                    at.lines = lines;
                    return Ok(true);
                }
                if is_dir {
                    at.frames[depth].passed += 1;
                    at.frames.push(WalkFrame {
                        name: entry.name().to_owned(),
                        page: None,
                        passed: 0,
                    });
                    pages.push(None);
                    dirs.push(child);
                    continue;
                }
            }
            at.frames[depth].passed += 1;
        }
        Ok(false)
    }

    fn visit(
        &self,
        verb: WalkVerb<'_>,
        path: &str,
        is_dir: bool,
        lines: Option<LinePosition>,
        walk: &mut Walk,
    ) -> Result<Visited> {
        match verb {
            WalkVerb::Find => {
                let mut line = path.to_owned();
                line.push('\n');
                let from = lines.map_or(0, |lines| lines.printed);
                match walk.out.push_line(&line, from) {
                    None => {
                        walk.total += 1;
                        Ok(Visited::Done)
                    }
                    Some(printed) => Ok(Visited::Cut(Some(LinePosition { line: 0, printed }))),
                }
            }
            WalkVerb::Grep { .. } if is_dir => Ok(Visited::Done),
            WalkVerb::Grep { pattern } => {
                let read = self.read_file(path)?;
                if let Some(receipt) = read.receipt {
                    fold_receipt(&mut walk.receipt, receipt);
                }
                let Some(file) = read.value else {
                    return Ok(Visited::Done);
                };
                let (matched, next) = page_lines(
                    file.bytes(),
                    lines.unwrap_or_default(),
                    &mut walk.out,
                    usize::MAX,
                    |line| line.contains(pattern).then(|| format!("{path}:{line}\n")),
                );
                walk.total += matched;
                Ok(next.map_or(Visited::Done, |lines| Visited::Cut(Some(lines))))
            }
        }
    }
}
