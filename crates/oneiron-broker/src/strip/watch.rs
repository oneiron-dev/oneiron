//! The strip rule read as a reply streams (FIX 6103), moved out of the
//! strip module whole: [`KeyWatch`].

use zeroize::Zeroizing;

use super::{
    DEPTH, Decoding, MARKER, base64_forms, forms, is_base64_byte, is_url_byte, json_unescaped_from,
    mark, percent_decoded_from, run_end, run_marks, wrapped_base64_matches, write_marked,
};

/// How many bytes past the reach of a form a streamed reply's watch holds
/// back at most, waiting for a run or a wrapped stretch to end: a buffering
/// bound, never a refusal. A run or stretch still open past it is redacted
/// from there to its end, as a run encoded too deep is redacted whole by
/// [`strip`](super::strip), and the reply goes on.
const MAX_HELD_RUN: usize = 1 << 20;

/// Whether `run` holds an escape a reading decodes.
fn escaped(run: &[u8]) -> bool {
    memchr::memchr2(b'\\', b'%', run).is_some()
}

/// Whether `byte` can continue a run or a wrapped base64 stretch.
fn continues(key: &[u8], byte: u8) -> bool {
    is_url_byte(byte) || key.contains(&byte) || byte == b'\\' || byte.is_ascii_whitespace()
}

/// Whether the byte at `at` is marked.
fn is_marked(marked: &[u64], at: usize) -> bool {
    (marked[at / 64] >> (at % 64)) & 1 == 1
}

/// How many bytes at the end of a reading of an open run the bytes after it
/// may still change (FIX 6250): an unfinished escape, a surrogate pair's 12
/// bytes at the most, at each of the [`DEPTH`] decodings a reading is
/// through.
const UNSETTLED: usize = 12 * DEPTH;

/// Where a streamed reply's watch may cut a run with an escape, and how far
/// back a match still growing from the bytes after it could reach (FIX
/// 6250).
struct RunCuts {
    /// The run's length.
    len: usize,
    /// One bit per run byte: set where every reading of the run passes
    /// between two of its units, so the bytes from there read as the rest of
    /// each reading and every escape stays whole. The run's start is one.
    aligned: Vec<u64>,
    /// The first run byte a match that could still grow from the bytes
    /// after the run reaches, in any reading: a form ending past what the
    /// reading has settled, or a wrapped form starting in the last base64
    /// characters of its open stretch. The run's length for a run that has
    /// ended.
    reach: usize,
}

impl RunCuts {
    /// The last cut at or before `offset` into the run.
    fn at_or_before(&self, offset: usize) -> usize {
        (1..=offset)
            .rev()
            .find(|&at| is_marked(&self.aligned, at))
            .unwrap_or(0)
    }
}

/// Where, at or before `end`, the base64 characters of the stretch of
/// base64 and whitespace that reaches `end` begin that a wrapped form of
/// `reach` more characters could still start in: the last `reach` of them,
/// whitespace skipped. `end` when the stretch holds none.
fn stretch_start(text: &[u8], end: usize, reach: usize) -> usize {
    let mut hold = end;
    let mut counted = 0;
    let mut at = end;
    while counted < reach && at > 0 {
        let byte = text[at - 1];
        if is_base64_byte(byte) {
            counted += 1;
            hold = at - 1;
        } else if !byte.is_ascii_whitespace() {
            break;
        }
        at -= 1;
    }
    hold
}

/// The strip rule for a reply read as it streams (FIX 6103): what [`strip`](super::strip)
/// would replace, the raw and encoded forms and the wrapped base64 alike, is
/// replaced with [`MARKER`] at the matched bytes as the chunks pass, and the
/// reply goes on. A byte is released once no form, no reading of its run and
/// no wrapped match that could still grow from the bytes after it can reach
/// back over it, so the watch holds back the longest form's length less one,
/// the last base64 characters of an open wrapped stretch that a wrapped form
/// could still start in, and of an open run that holds an escape the bytes
/// from the first one a match in any of its readings could still reach
/// (FIX 6250). A run with an escape is cut only where every reading of it
/// passes between two of its units, so each escape stays whole and the bytes
/// held read on as the rest of each reading. A plain run (one with no escape
/// yet) is released up to the forms' reach: no reading of it can reach
/// further back. What it holds is bounded by [`MAX_HELD_RUN`]: only a wrapped
/// stretch whose whitespace pads a still-matching form past it is redacted
/// there.
pub(crate) struct KeyWatch<'k> {
    key: &'k [u8],
    forms: Vec<Zeroizing<Vec<u8>>>,
    wrapped: Vec<Zeroizing<Vec<u8>>>,
    /// The longest form's length less one.
    reach: usize,
    /// The longest wrapped form's length less one, in base64 characters.
    wrapped_reach: usize,
    /// Bytes read and not yet released. They start at a run's start, at a
    /// byte no run holds, or inside a plain run, as the whole body's reading
    /// would.
    held: Zeroizing<Vec<u8>>,
    /// The bytes before `held` ended inside a run or stretch the bound
    /// redacted: every byte that continues it is redacted too, so no part of
    /// a form it held passes.
    redacting: bool,
}

impl<'k> KeyWatch<'k> {
    pub(crate) fn new(key: &'k [u8]) -> Self {
        let forms = forms(key);
        let wrapped = base64_forms(key);
        let reach = forms.iter().map(|form| form.len()).max().unwrap_or(1) - 1;
        let wrapped_reach = wrapped
            .iter()
            .map(|form| form.len())
            .max()
            .unwrap_or(1)
            .saturating_sub(1);
        Self {
            key,
            forms,
            wrapped,
            reach,
            wrapped_reach,
            held: Zeroizing::new(Vec::new()),
            redacting: false,
        }
    }

    /// Takes the next chunk, and returns the bytes now released, redacted.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut data = Zeroizing::new(Vec::with_capacity(self.held.len() + chunk.len()));
        data.extend_from_slice(&self.held);
        data.extend_from_slice(chunk);
        self.take(&data, false)
    }

    /// Ends the reply, and returns the bytes still held, redacted.
    pub(crate) fn finish(&mut self) -> Zeroizing<Vec<u8>> {
        let held = std::mem::take(&mut self.held);
        self.take(&held, true)
    }

    /// Releases what it can of `data`, the held bytes and the next chunk, at
    /// the reply's `end` all of it, and holds the rest.
    fn take(&mut self, data: &[u8], end: bool) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(data.len() + MARKER.len()));
        let mut from = 0;
        if self.redacting {
            // Already one MARKER in the reply for the stretch these continue.
            while data
                .get(from)
                .is_some_and(|&byte| continues(self.key, byte))
            {
                from += 1;
            }
            if from == data.len() && !end {
                self.held = Zeroizing::new(Vec::new());
                return out;
            }
            self.redacting = false;
        }
        let text = &data[from..];
        let mut marked = vec![0_u64; text.len().div_ceil(64)];
        let runs = self.mark(text, &mut marked);
        let mut cleared = if end {
            text.len()
        } else {
            self.cleared(text, &runs, &marked)
        };
        if !end && text.len() - cleared > MAX_HELD_RUN + self.reach {
            mark(&mut marked, cleared, text.len());
            cleared = text.len();
            self.redacting = true;
        }
        write_marked(&text[..cleared], &marked, &mut out);
        self.held = Zeroizing::new(text[cleared..].to_vec());
        out
    }

    /// Marks every form in `text`, every reading of each run in it with an
    /// escape, and every wrapped match. Returns the runs, in order.
    fn mark(&self, text: &[u8], marked: &mut [u64]) -> Vec<(usize, usize)> {
        for form in &self.forms {
            for at in memchr::memmem::find_iter(text, form.as_slice()) {
                mark(marked, at, at + form.len());
            }
        }
        let mut runs = Vec::new();
        let mut at = 0;
        while at < text.len() {
            let stop = run_end(self.key, text, at);
            if stop == at {
                at += 1;
                continue;
            }
            runs.push((at, stop));
            let run = &text[at..stop];
            // An open run is read as it stands too: what its readings have
            // settled may be released (FIX 6250).
            if escaped(run) {
                let read = run_marks(&self.forms, &self.wrapped, run);
                for offset in (0..run.len()).filter(|&offset| is_marked(&read, offset)) {
                    mark(marked, at + offset, at + offset + 1);
                }
            }
            at = stop;
        }
        wrapped_base64_matches(&self.wrapped, text, |start, end| {
            mark(marked, start, end);
        });
        runs
    }

    /// How many of the first bytes of `text` can be released: none a form
    /// that could still grow could reach, in the bytes as sent or in any
    /// reading of an open run with an escape; none of the base64 characters
    /// at an open stretch's end a wrapped form could start in; never a run
    /// with an escape cut but where every reading of it passes between two
    /// units; and never a marked stretch cut in two.
    fn cleared(&self, text: &[u8], runs: &[(usize, usize)], marked: &[u64]) -> usize {
        let mut cleared = text.len().saturating_sub(self.reach);
        let mut cuts: Vec<Option<RunCuts>> = runs.iter().map(|_| None).collect();
        if let Some((last, &(start, stop))) = runs.iter().enumerate().next_back()
            && stop == text.len()
            && escaped(&text[start..stop])
        {
            let open = self.run_cuts(&text[start..stop], true);
            cleared = cleared.min(start + open.reach);
            cuts[last] = Some(open);
        }
        cleared = cleared.min(self.stretch_hold(text));
        loop {
            let mut moved = cleared;
            // A marked stretch is released whole or not at all.
            while moved > 0
                && moved < text.len()
                && is_marked(marked, moved - 1)
                && is_marked(marked, moved)
            {
                moved -= 1;
            }
            // A run with an escape is cut only where each of its readings
            // is cut between two units.
            if let Some((index, &(start, stop))) =
                runs.iter().enumerate().find(|&(_, &(start, stop))| {
                    start < moved && moved < stop && escaped(&text[start..stop])
                })
            {
                let run = cuts[index]
                    .get_or_insert_with(|| self.run_cuts(&text[start..stop], stop == text.len()));
                moved = start + run.at_or_before(moved - start);
            }
            if moved == cleared {
                return cleared;
            }
            cleared = moved;
        }
    }

    /// The cuts of `run`, a run with an escape, and for an `open` one, which
    /// the bytes after it may go on, the first byte a match still growing
    /// from them could reach in any of its readings.
    fn run_cuts(&self, run: &[u8], open: bool) -> RunCuts {
        let mut cuts = RunCuts {
            len: run.len(),
            aligned: vec![u64::MAX; run.len().div_ceil(64)],
            reach: run.len(),
        };
        self.walk(&mut cuts, run, None, 0, open);
        cuts
    }

    /// Reads `text`, a reading `depth` decodings deep whose bytes' sources
    /// start at `starts` in the run (the run itself when `None`), into
    /// `cuts`, then each reading it decodes to, as the strip's search reads
    /// them: depth first, each decoding that changes it. A reading no
    /// decoding goes past keeps only the cuts at its bytes' own starts, and
    /// an `open` run's reading bounds its reach.
    fn walk(
        &self,
        cuts: &mut RunCuts,
        text: &[u8],
        starts: Option<&[usize]>,
        depth: usize,
        open: bool,
    ) {
        if open {
            let settled = text.len().saturating_sub(UNSETTLED);
            let first = settled.saturating_sub(self.reach).min(stretch_start(
                text,
                settled,
                self.wrapped_reach,
            ));
            let source = match starts {
                Some(starts) => starts.get(first).copied().unwrap_or(cuts.len),
                None => first,
            };
            cuts.reach = cuts.reach.min(source);
        }
        let mut leaf = true;
        if depth < DEPTH {
            let decodings: [Decoding; 2] =
                [(b'\\', json_unescaped_from), (b'%', percent_decoded_from)];
            for (escape, decode) in decodings {
                if memchr::memchr(escape, text).is_none() {
                    continue;
                }
                let (decoded, from) = decode(text);
                if decoded.as_slice() == text {
                    continue;
                }
                leaf = false;
                let from: Vec<usize> = match starts {
                    Some(starts) => from.into_iter().map(|at| starts[at]).collect(),
                    None => from,
                };
                self.walk(cuts, &decoded, Some(&from), depth + 1, open);
            }
        }
        if leaf && let Some(starts) = starts {
            let mut own = vec![0_u64; cuts.aligned.len()];
            for &start in starts {
                mark(&mut own, start, start + 1);
            }
            for (word, own) in cuts.aligned.iter_mut().zip(own) {
                *word &= own;
            }
        }
    }

    /// Where the base64 characters that a wrapped form could still start in
    /// begin, at the end of a stretch of base64 and whitespace that reaches
    /// the end of `text`: the last `wrapped_reach` of them. The end
    /// of `text` when it holds none.
    fn stretch_hold(&self, text: &[u8]) -> usize {
        stretch_start(text, text.len(), self.wrapped_reach)
    }
}
