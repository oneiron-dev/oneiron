//! Where [`super::mnemonic`] finds each recovery phrase in `text` (FIX 1099).

use std::ops::Range;

/// Where [`super::mnemonic`] finds each recovery phrase in `text`: one span
/// per accepted run, from its first word's start to its last word's end, the
/// separators between them included. It reads what [`super::mnemonic`] reads,
/// tracking each word's byte offset.
pub(crate) fn mnemonic_spans(text: &str) -> Vec<Range<usize>> {
    let mut scan = Scan::default();
    scan.feed(text);
    scan.finish();
    scan.spans
}

/// [`super::MnemonicStream`] with each word's byte offsets, collecting spans.
#[derive(Default)]
struct Scan {
    wrapped: Wrapped,
    group: Group,
    current: Current,
    spans: Vec<Range<usize>>,
}

impl Scan {
    fn feed(&mut self, text: &str) {
        for (at, ch) in text.char_indices() {
            if ch.is_ascii_alphabetic() {
                self.current.push_letter(ch, at);
                continue;
            }
            self.current.end_word();
            if super::segment_break(ch) {
                self.close_segment(matches!(ch, '\n' | '\r'));
            } else if !matches!(ch, ' ' | '\t') {
                self.current.filled = true;
            }
        }
    }

    fn finish(&mut self) {
        self.current.end_word();
        self.close_segment(false);
        self.group.finish(&mut self.spans);
    }

    fn close_segment(&mut self, line_break: bool) {
        let indices = std::mem::take(&mut self.current.indices);
        let end = std::mem::take(&mut self.current.end);
        let span = self.current.start.take().map(|start| start..end);
        let wraps = !self.current.impure && !self.current.filled;
        let pure = !self.current.impure;
        self.wrapped
            .close(&indices, span.clone(), wraps, line_break, &mut self.spans);
        self.group.close(indices, span, pure, &mut self.spans);
        self.current.impure = false;
        self.current.filled = false;
    }
}

/// The segment the scan reads now, with its words' offsets.
#[derive(Default)]
struct Current {
    indices: Vec<u16>,
    start: Option<usize>,
    end: usize,
    impure: bool,
    filled: bool,
    word: String,
    word_start: Option<usize>,
    word_end: usize,
}

impl Current {
    fn push_letter(&mut self, ch: char, at: usize) {
        if self.word.is_empty() {
            self.word_start = Some(at);
        }
        if self.word.len() <= super::MAX_LIST_WORD_LEN {
            self.word.push(ch);
        }
        self.word_end = at + ch.len_utf8();
    }

    fn end_word(&mut self) {
        if self.word.is_empty() {
            self.word_start = None;
            return;
        }
        let start = self.word_start.take();
        match super::list_word_index(&self.word) {
            // A segment past the longest run reads as any longer one does.
            Some(index) if self.indices.len() < super::MAX_RUN => {
                self.indices.push(index);
                if self.start.is_none() {
                    self.start = start;
                }
                self.end = self.word_end;
            }
            Some(_) => {}
            None => self.impure = true,
        }
        self.word.clear();
    }
}

/// A wrapped phrase's run so far, with its span.
#[derive(Default)]
struct Wrapped {
    words: Vec<u16>,
    lines: usize,
    start: Option<usize>,
    end: usize,
}

impl Wrapped {
    fn close(
        &mut self,
        words: &[u16],
        span: Option<Range<usize>>,
        wraps: bool,
        line_break: bool,
        out: &mut Vec<Range<usize>>,
    ) {
        if words.is_empty() && wraps && line_break {
            return;
        }
        if !wraps || words.is_empty() {
            self.finish(out);
            return;
        }
        let room = (super::MAX_RUN + 1).saturating_sub(self.words.len());
        self.words.extend(words.iter().take(room));
        if room > 0
            && let Some(span) = span
        {
            if self.start.is_none() {
                self.start = Some(span.start);
            }
            self.end = span.end;
        }
        self.lines += 1;
        if !line_break {
            self.finish(out);
        }
    }

    fn finish(&mut self, out: &mut Vec<Range<usize>>) {
        let words = std::mem::take(&mut self.words);
        let lines = std::mem::take(&mut self.lines);
        let start = self.start.take();
        let end = std::mem::take(&mut self.end);
        if lines <= 1 || !super::phrase(&words) {
            return;
        }
        if let Some(start) = start {
            out.push(start..end);
        }
    }
}

/// Consecutive pure segments, each with its span.
#[derive(Default)]
struct Group {
    segments: Vec<Seg>,
    multi_word: bool,
}

struct Seg {
    indices: Vec<u16>,
    start: usize,
    end: usize,
}

impl Group {
    fn close(
        &mut self,
        words: Vec<u16>,
        span: Option<Range<usize>>,
        pure: bool,
        out: &mut Vec<Range<usize>>,
    ) {
        if !pure {
            self.finish(out);
            return;
        }
        if words.is_empty() {
            return;
        }
        if super::phrase(&words) {
            if let Some(span) = span {
                out.push(span);
            }
            return;
        }
        self.multi_word |= words.len() > 1;
        // A run past the longest one a phrase spans reads as any longer one.
        if self.segments.len() <= super::MAX_RUN
            && let Some(span) = span
        {
            self.segments.push(Seg {
                indices: words,
                start: span.start,
                end: span.end,
            });
        }
    }

    fn finish(&mut self, out: &mut Vec<Range<usize>>) {
        let segments = std::mem::take(&mut self.segments);
        if std::mem::take(&mut self.multi_word) {
            return;
        }
        let count = segments.len();
        for (first, last) in [
            (0, count),
            (1, count),
            (0, count.saturating_sub(1)),
            (1, count.saturating_sub(1)),
        ] {
            let Some(window) = segments.get(first..last) else {
                continue;
            };
            if window.is_empty() || !window_phrase(window) {
                continue;
            }
            if let (Some(first), Some(last)) = (window.first(), window.last()) {
                out.push(first.start..last.end);
            }
            break;
        }
    }
}

fn window_phrase(window: &[Seg]) -> bool {
    let len: usize = window.iter().map(|seg| seg.indices.len()).sum();
    if !super::PHRASE_WORDS.contains(&len) {
        return false;
    }
    let flat: Vec<u16> = window
        .iter()
        .flat_map(|seg| seg.indices.iter().copied())
        .collect();
    super::phrase(&flat)
}
