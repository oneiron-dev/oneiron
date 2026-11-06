//! Line composition of disjoint same-file proposals (FIX 4360).
//!
//! Proposals in one batch may each change one file from one verified base
//! `B`. Each change is kept as its runs of changed base lines, so a later
//! proposal's runs are added to the bytes `S` the earlier ones staged,
//! giving `C`. Its whole file `P` never overwrites theirs. Owner staging
//! and reviewed-stack admission use this one helper.
//!
//! CALL A is unchanged: on the automatic driver path, two proposals that
//! replace one path still go to reconciliation before staging, even when a
//! text merge would be clean. Composition applies to owner staging and the
//! reviewed stack it lands.
//!
//! Composition only lets the checker see the combined file. It never says
//! the combined program is valid.
use std::ops::Range;

use similar::{Algorithm, DiffTag, capture_diff_slices};

use crate::code_document::CodeFileEdit;

/// One proposal's changed run: base lines `start..end` become
/// `replacement`. An insertion has `start == end`; a deletion replaces the
/// lines with no bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChangedRun {
    start: usize,
    end: usize,
    replacement: Vec<u8>,
}

impl ChangedRun {
    fn is_insertion(&self) -> bool {
        self.start == self.end
    }

    /// The conservative overlap rule between two proposals' runs. Nonempty
    /// base ranges overlap when their interiors meet, so adjacent ranges
    /// that share only an endpoint do not. Two insertions overlap at one
    /// gap. An insertion overlaps a range it lies in or on either boundary
    /// of. Identical changes overlap too, so no authored change is dropped.
    fn overlaps(&self, other: &Self) -> bool {
        match (self.is_insertion(), other.is_insertion()) {
            (true, true) => self.start == other.start,
            (true, false) => other.start <= self.start && self.start <= other.end,
            (false, true) => self.start <= other.start && other.start <= self.end,
            (false, false) => self.start < other.end && other.start < self.end,
        }
    }
}

/// What one more proposal composes to.
pub(crate) struct ComposedFile {
    /// The composed bytes `C`.
    pub(crate) bytes: Vec<u8>,
    /// Whether the one span the document writer lowers `S -> C` as
    /// (`CodeFileEdit::between`) meets an earlier proposal's changed text.
    pub(crate) covers_earlier: bool,
}

/// One path's proposals, composed from one base in batch order.
#[derive(Debug, Clone)]
pub(crate) struct LineComposition {
    base: Vec<u8>,
    /// The byte offset each base line starts at, then the base's length.
    line_starts: Vec<usize>,
    /// Every composed proposal's runs, in base order.
    runs: Vec<ChangedRun>,
}

impl LineComposition {
    /// The composition of one proposal's `postimage` over `base`. `None`
    /// when either is not UTF-8 text or the postimage changes nothing.
    pub(crate) fn new(base: &[u8], postimage: &[u8]) -> Option<Self> {
        std::str::from_utf8(base).ok()?;
        let mut line_starts = vec![0];
        line_starts.extend(
            base.iter()
                .enumerate()
                .filter(|(_, byte)| **byte == b'\n')
                .map(|(at, _)| at + 1),
        );
        if line_starts.last() != Some(&base.len()) {
            line_starts.push(base.len());
        }
        let mut composition = Self {
            base: base.to_vec(),
            line_starts,
            runs: Vec::new(),
        };
        composition.compose(base, postimage)?;
        Some(composition)
    }

    /// The verified base `B` every proposal of this path changes.
    pub(crate) fn base(&self) -> &[u8] {
        &self.base
    }

    /// The bytes every proposal composed so far gives.
    pub(crate) fn output(&self) -> Vec<u8> {
        self.render(&self.runs)
    }

    /// `compose(B, S, P) -> C`: adds the base-relative runs of `B -> P` to
    /// the runs already composed, when no run of `P` overlaps one of them
    /// and the previous output is exactly the staged bytes `S`. `C` copies
    /// the unchanged base lines and every run's replacement in base order.
    /// `None` refuses: `P` is not UTF-8 or changes nothing, a run overlaps,
    /// or `S` is not this composition's output. A refusal changes nothing.
    pub(crate) fn compose(&mut self, staged: &[u8], postimage: &[u8]) -> Option<ComposedFile> {
        std::str::from_utf8(postimage).ok()?;
        let added = self.changed_runs(postimage);
        if added.is_empty()
            || added
                .iter()
                .any(|run| self.runs.iter().any(|kept| kept.overlaps(run)))
        {
            return None;
        }
        if self.output() != staged {
            return None;
        }
        let mut runs = self.runs.clone();
        runs.extend(added);
        runs.sort_by_key(|run| (run.start, run.end));
        let bytes = self.render(&runs);
        let covers_earlier = self.covers_earlier(staged, &bytes);
        self.runs = runs;
        Some(ComposedFile {
            bytes,
            covers_earlier,
        })
    }

    fn line_count(&self) -> usize {
        self.line_starts.len() - 1
    }

    /// Base lines `from..to` as one byte span.
    fn base_span(&self, from: usize, to: usize) -> &[u8] {
        &self.base[self.line_starts[from]..self.line_starts[to]]
    }

    /// The runs `B -> postimage` changes, by a Myers diff of lines with
    /// their terminators kept. A run is one maximal changed stretch, not a
    /// display hunk with context lines.
    fn changed_runs(&self, postimage: &[u8]) -> Vec<ChangedRun> {
        let base: Vec<&[u8]> = (0..self.line_count())
            .map(|line| self.base_span(line, line + 1))
            .collect();
        let lines: Vec<&[u8]> = postimage.split_inclusive(|byte| *byte == b'\n').collect();
        let mut runs = Vec::new();
        let mut open: Option<ChangedRun> = None;
        for op in capture_diff_slices(Algorithm::Myers, &base, &lines) {
            let (tag, old, new) = op.as_tag_tuple();
            if tag == DiffTag::Equal {
                runs.extend(open.take());
                continue;
            }
            let run = open.get_or_insert_with(|| ChangedRun {
                start: old.start,
                end: old.start,
                replacement: Vec::new(),
            });
            run.end = old.end;
            for line in &lines[new] {
                run.replacement.extend_from_slice(line);
            }
        }
        runs.extend(open);
        runs
    }

    /// The base with `runs`, sorted and disjoint, applied in base order.
    fn render(&self, runs: &[ChangedRun]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.base.len());
        let mut at = 0;
        for run in runs {
            bytes.extend_from_slice(self.base_span(at, run.start));
            bytes.extend_from_slice(&run.replacement);
            at = run.end;
        }
        bytes.extend_from_slice(self.base_span(at, self.line_count()));
        bytes
    }

    /// Whether the span `CodeFileEdit::between(S, C)` meets the text an
    /// earlier proposal wrote into `S`. An earlier deletion left no text.
    fn covers_earlier(&self, staged: &[u8], composed: &[u8]) -> bool {
        if self.runs.is_empty() {
            return false;
        }
        let (Ok(staged), Ok(composed)) =
            (std::str::from_utf8(staged), std::str::from_utf8(composed))
        else {
            return true;
        };
        let span = CodeFileEdit::between("", staged, composed);
        self.scalar_regions()
            .iter()
            .any(|region| !region.is_empty() && region.start < span.end && span.start < region.end)
    }

    /// Each composed run's replacement as a Unicode scalar range of the
    /// output, the offsets a document edit counts in.
    fn scalar_regions(&self) -> Vec<Range<usize>> {
        let scalars = |bytes: &[u8]| bytes.iter().filter(|byte| (**byte & 0xC0) != 0x80).count();
        let mut regions = Vec::with_capacity(self.runs.len());
        let (mut offset, mut at) = (0, 0);
        for run in &self.runs {
            offset += scalars(self.base_span(at, run.start));
            let length = scalars(&run.replacement);
            regions.push(offset..offset + length);
            offset += length;
            at = run.end;
        }
        regions
    }
}
