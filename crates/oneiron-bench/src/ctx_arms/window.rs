//! The live window, the harness-minted reference store, and the accounting
//! every (arm, strategy) cell reports.
//!
//! The harness owns the window. A strategy edits it only through [`Ctx`],
//! whose operations are gated by the strategy's declared [`Caps`] and each
//! charge the tokens a model would decode to perform the edit. References are
//! minted by the harness, never by the strategy: the strategy chooses which
//! spans leave, the substrate makes them restorable (OF-190, Sculptor).

use std::collections::BTreeMap;
use std::ops::Range;

/// The one fixed tokenizer stand-in. Named in every report header and never
/// changed between rounds.
pub(crate) const TOKENIZER: &str =
    "bytes4 = ceil(utf8 bytes / 4) per rendered span \"[[label]]\\n<text>\\n\"";

pub(crate) fn tokens(text: &str) -> u64 {
    (text.len() as u64).div_ceil(4)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpanKind {
    /// Stream turn `n`, appended by the environment.
    Turn(u32),
    /// Agent-written text appended to the tail.
    Note,
    /// A lossy stub with no restore path.
    Stub,
    /// A harness-minted pointer to reference `r`.
    RefStub(u32),
    /// The engine-rendered dynamic tail: a projection of typed state.
    Board,
}

#[derive(Clone, Debug)]
pub(crate) struct Span {
    id: u64,
    kind: SpanKind,
    text: String,
    tok: u64,
}

impl Span {
    fn new(id: u64, kind: SpanKind, text: String) -> Self {
        let label = match kind {
            SpanKind::Turn(n) => format!("t{n}"),
            SpanKind::Note => format!("note s{id}"),
            SpanKind::Stub => format!("stub s{id}"),
            SpanKind::RefStub(r) => format!("ref r{r}"),
            SpanKind::Board => "board".to_owned(),
        };
        let tok = tokens(&format!("[[{label}]]\n{text}\n"));
        Self {
            id,
            kind,
            text,
            tok,
        }
    }

    pub(crate) const fn id(&self) -> u64 {
        self.id
    }

    pub(crate) const fn kind(&self) -> SpanKind {
        self.kind
    }

    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    pub(crate) const fn tok(&self) -> u64 {
        self.tok
    }
}

/// The rendered window as an ordered span list. `cached` is the span count
/// the last model call prefilled; `dirty` is the first index touched by an
/// edit since then. A pure append never dirties anything.
#[derive(Default)]
pub(crate) struct Window {
    spans: Vec<Span>,
    total: u64,
    next_id: u64,
    cached: usize,
    dirty: Option<usize>,
}

impl Window {
    pub(crate) fn push(&mut self, kind: SpanKind, text: String) -> u64 {
        self.next_id += 1;
        let span = Span::new(self.next_id, kind, text);
        self.total += span.tok;
        self.spans.push(span);
        self.next_id
    }

    pub(crate) const fn total(&self) -> u64 {
        self.total
    }

    pub(crate) fn spans(&self) -> &[Span] {
        &self.spans
    }

    fn touch(&mut self, index: usize) {
        self.dirty = Some(self.dirty.map_or(index, |d| d.min(index)));
    }

    fn take(&mut self, range: Range<usize>) -> Vec<Span> {
        self.touch(range.start);
        let gone: Vec<Span> = self.spans.drain(range).collect();
        self.total -= gone.iter().map(|s| s.tok).sum::<u64>();
        gone
    }

    fn insert(&mut self, index: usize, kind: SpanKind, text: String) {
        self.touch(index);
        self.next_id += 1;
        let span = Span::new(self.next_id, kind, text);
        self.total += span.tok;
        self.spans.insert(index, span);
    }

    /// Replaces a span's text in place, keeping its id; returns the old text.
    fn set_text(&mut self, index: usize, text: String) -> String {
        self.touch(index);
        let old = &self.spans[index];
        let span = Span::new(old.id, old.kind, text);
        self.total = self.total - old.tok + span.tok;
        std::mem::replace(&mut self.spans[index], span).text
    }

    /// One model call: everything from the first edited cached position to
    /// the end of the window is re-prefilled (OF-263's missing component).
    /// Returns those tokens and re-arms the cache at the current window.
    pub(crate) fn checkpoint(&mut self) -> u64 {
        let reprefill = match self.dirty {
            Some(d) if d < self.cached => self.spans[d..].iter().map(|s| s.tok).sum(),
            _ => 0,
        };
        self.cached = self.spans.len();
        self.dirty = None;
        reprefill
    }
}

/// The typed index of one reference: what the engine knows without reading
/// the bytes back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RefMeta {
    pub(crate) id: u32,
    pub(crate) spans: usize,
    pub(crate) turns: Option<(u32, u32)>,
    pub(crate) tok: u64,
}

impl RefMeta {
    pub(crate) fn row(&self) -> String {
        let turns = self
            .turns
            .map_or_else(|| "-".to_owned(), |(a, b)| format!("{a}-{b}"));
        format!(
            "ref r{} spans={} turns={turns} tok={}",
            self.id, self.spans, self.tok
        )
    }
}

struct Stored {
    span_id: u64,
    text: String,
    digest: [u8; 32],
}

struct Reference {
    meta: RefMeta,
    spans: Vec<Stored>,
}

/// Harness-owned. A restore re-hashes every stored span against the digest
/// taken at mint and refuses on any mismatch.
#[derive(Default)]
pub(crate) struct RefStore {
    refs: Vec<Reference>,
}

fn digest(text: &str) -> [u8; 32] {
    *blake3::hash(text.as_bytes()).as_bytes()
}

impl RefStore {
    fn mint(&mut self, spans: &[Span]) -> u32 {
        let id = self.refs.len() as u32 + 1;
        let turns: Vec<u32> = spans
            .iter()
            .filter_map(|s| match s.kind {
                SpanKind::Turn(n) => Some(n),
                _ => None,
            })
            .collect();
        self.refs.push(Reference {
            meta: RefMeta {
                id,
                spans: spans.len(),
                turns: turns.first().zip(turns.last()).map(|(a, b)| (*a, *b)),
                tok: spans.iter().map(|s| s.tok).sum(),
            },
            spans: spans
                .iter()
                .map(|s| Stored {
                    span_id: s.id,
                    text: s.text.clone(),
                    digest: digest(&s.text),
                })
                .collect(),
        });
        id
    }

    pub(crate) fn metas(&self) -> impl Iterator<Item = &RefMeta> {
        self.refs.iter().map(|r| &r.meta)
    }

    pub(crate) fn meta(&self, id: u32) -> Option<&RefMeta> {
        self.refs
            .get((id as usize).checked_sub(1)?)
            .map(|r| &r.meta)
    }

    /// The span texts of reference `id`, byte-exact, or an error.
    pub(crate) fn restore(&self, id: u32) -> Result<Vec<(u64, &str)>, String> {
        let r = self
            .refs
            .get((id as usize).wrapping_sub(1))
            .ok_or_else(|| format!("no reference r{id}"))?;
        r.spans
            .iter()
            .map(|s| {
                if digest(&s.text) == s.digest {
                    Ok((s.span_id, s.text.as_str()))
                } else {
                    Err(format!("r{id} span s{} fails its digest", s.span_id))
                }
            })
            .collect()
    }

    /// References whose stored bytes contain `pattern`.
    pub(crate) fn grep(&self, pattern: &str) -> Vec<u32> {
        self.refs
            .iter()
            .filter(|r| r.spans.iter().any(|s| s.text.contains(pattern)))
            .map(|r| r.meta.id)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn corrupt(&mut self, id: u32) {
        if let Some(s) = self.refs[id as usize - 1].spans.first_mut() {
            s.text.push('!');
        }
    }
}

/// One span that left the window or was rewritten: the harness's own digest
/// of the bytes it held when it first left, and the reference (if any) that
/// claims to restore them.
pub(crate) struct Departure {
    digest: [u8; 32],
    via: Option<u32>,
}

/// What the harness records while a strategy edits.
#[derive(Default)]
pub(crate) struct Ledger {
    pub(crate) edit_tok: u64,
    pub(crate) departed: BTreeMap<u64, Departure>,
    pub(crate) violations: Vec<&'static str>,
}

impl Ledger {
    fn depart(&mut self, span: &Span, via: Option<u32>) {
        // The dynamic tail is a projection of typed state, not content.
        if span.kind != SpanKind::Board {
            self.departed.entry(span.id).or_insert(Departure {
                digest: digest(&span.text),
                via,
            });
        }
    }

    /// Restores every departed span through its reference and compares the
    /// bytes with the harness's own digest.
    pub(crate) fn audit(&self, refs: &RefStore) -> Audit {
        let mut restored: BTreeMap<u32, Option<BTreeMap<u64, [u8; 32]>>> = BTreeMap::new();
        let mut audit = Audit {
            departed: self.departed.len() as u64,
            ..Audit::default()
        };
        for (id, d) in &self.departed {
            let Some(r) = d.via else { continue };
            audit.with_ref += 1;
            let spans = restored.entry(r).or_insert_with(|| {
                refs.restore(r)
                    .ok()
                    .map(|v| v.into_iter().map(|(sid, t)| (sid, digest(t))).collect())
            });
            if spans.as_ref().and_then(|m| m.get(id)) == Some(&d.digest) {
                audit.exact += 1;
            }
        }
        audit
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Audit {
    /// Spans that left the window (or were rewritten) at least once.
    pub(crate) departed: u64,
    /// Of those, spans that left through a reference.
    pub(crate) with_ref: u64,
    /// Of those, spans the reference gives back byte-exactly.
    pub(crate) exact: u64,
}

impl Audit {
    /// A reference that cannot give its span back byte-exactly.
    pub(crate) const fn broken_reference(self) -> bool {
        self.exact < self.with_ref
    }
}

/// The operations a strategy declares it may use. Anything else is refused
/// and recorded as a violation, which invalidates the cell.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Caps {
    /// Delete whole spans with no restore path.
    pub(crate) drop: bool,
    /// Replace spans with a lossy stub it writes itself.
    pub(crate) fold_lossy: bool,
    /// Move spans into a harness-minted reference, and restore them.
    pub(crate) offload: bool,
    /// Rewrite or delete anything anywhere (the CLM free-file arm only).
    pub(crate) rewrite: bool,
    /// Keep an engine-rendered board as the dynamic tail.
    pub(crate) board: bool,
}

/// A strategy's handle on the window for one step.
pub(crate) struct Ctx<'a> {
    pub(crate) win: &'a mut Window,
    pub(crate) refs: &'a mut RefStore,
    pub(crate) led: &'a mut Ledger,
    pub(crate) caps: Caps,
    pub(crate) budget: u64,
    pub(crate) low_water: u64,
}

fn span_range_label(spans: &[Span]) -> String {
    match (spans.first(), spans.last()) {
        (Some(a), Some(b)) => format!("s{}..s{}", a.id, b.id),
        _ => "-".to_owned(),
    }
}

impl Ctx<'_> {
    pub(crate) const fn budget(&self) -> u64 {
        self.budget
    }

    /// The hysteresis floor eviction shrinks to once the budget is crossed.
    pub(crate) const fn low_water(&self) -> u64 {
        self.low_water
    }

    pub(crate) const fn tokens(&self) -> u64 {
        self.win.total()
    }

    pub(crate) fn spans(&self) -> &[Span] {
        self.win.spans()
    }

    pub(crate) fn index_of(&self, id: u64) -> Option<usize> {
        self.win.spans().iter().position(|s| s.id == id)
    }

    pub(crate) fn ref_metas(&self) -> Vec<RefMeta> {
        self.refs.metas().cloned().collect()
    }

    fn allow(&mut self, ok: bool, op: &'static str) -> bool {
        if !ok {
            self.led.violations.push(op);
        }
        ok
    }

    fn charge(&mut self, command: &str) {
        self.led.edit_tok += tokens(command);
    }

    /// Appends agent-written text. Always allowed: an agent can always
    /// append its own output.
    pub(crate) fn append_note(&mut self, text: String) -> u64 {
        self.charge(&text);
        self.win.push(SpanKind::Note, text)
    }

    /// Deletes whole spans; nothing restores them.
    pub(crate) fn drop_spans(&mut self, range: Range<usize>) {
        if !self.allow(self.caps.drop, "drop") || range.is_empty() {
            return;
        }
        self.charge(&format!(
            "drop {}",
            span_range_label(&self.spans()[range.clone()])
        ));
        for span in self.win.take(range) {
            self.led.depart(&span, None);
        }
    }

    /// Replaces spans with a stub the strategy wrote; nothing restores them.
    pub(crate) fn fold_lossy(&mut self, range: Range<usize>, stub: String) {
        if !self.allow(self.caps.fold_lossy, "fold_lossy") || range.is_empty() {
            return;
        }
        self.charge(&stub);
        let start = range.start;
        for span in self.win.take(range) {
            self.led.depart(&span, None);
        }
        self.win.insert(start, SpanKind::Stub, stub);
    }

    /// Moves spans into a harness-minted reference and leaves its stub in
    /// place. The strategy only names the spans.
    pub(crate) fn offload(&mut self, range: Range<usize>) -> Option<u32> {
        if !self.allow(self.caps.offload, "offload") || range.is_empty() {
            return None;
        }
        self.charge(&format!(
            "fold {}",
            span_range_label(&self.spans()[range.clone()])
        ));
        let start = range.start;
        let gone = self.win.take(range);
        let id = self.refs.mint(&gone);
        for span in &gone {
            self.led.depart(span, Some(id));
        }
        let stub = self.refs.meta(id).map(RefMeta::row).unwrap_or_default();
        self.win.insert(start, SpanKind::RefStub(id), stub);
        Some(id)
    }

    /// References whose bytes contain `pattern` (a search over its own
    /// offloaded spans).
    pub(crate) fn grep_refs(&self, pattern: &str) -> Vec<u32> {
        if self.caps.offload {
            self.refs.grep(pattern)
        } else {
            Vec::new()
        }
    }

    /// Rewrites lines of a span in place (`(line index, new line)`).
    pub(crate) fn patch_lines(&mut self, index: usize, patches: &[(usize, String)]) {
        if !self.allow(self.caps.rewrite, "patch_lines") {
            return;
        }
        let span = &self.win.spans()[index];
        let mut lines: Vec<String> = span.text.lines().map(str::to_owned).collect();
        let mut command = format!("patch s{}", span.id);
        for (at, line) in patches {
            command.push_str(&format!(" {at}:{line}"));
            if let Some(slot) = lines.get_mut(*at) {
                slot.clone_from(line);
            }
        }
        self.charge(&command);
        self.rewrite_span(index, lines.join("\n"));
    }

    /// Deletes the lines of a span `keep` rejects; an emptied span goes.
    pub(crate) fn retain_lines(&mut self, index: usize, label: &str, keep: impl Fn(&str) -> bool) {
        if !self.allow(self.caps.rewrite, "retain_lines") {
            return;
        }
        let span = &self.win.spans()[index];
        let kept: Vec<&str> = span.text.lines().filter(|l| keep(l)).collect();
        if kept.len() == span.text.lines().count() {
            return;
        }
        let text = kept.join("\n");
        self.charge(&format!("del s{} /{label}/", span.id));
        if text.is_empty() {
            for span in self.win.take(index..index + 1) {
                self.led.depart(&span, None);
            }
        } else {
            self.rewrite_span(index, text);
        }
    }

    /// Deletes whole spans under the rewrite capability.
    pub(crate) fn delete_spans(&mut self, range: Range<usize>) {
        if !self.allow(self.caps.rewrite, "delete_spans") || range.is_empty() {
            return;
        }
        self.charge(&format!(
            "delete {}",
            span_range_label(&self.spans()[range.clone()])
        ));
        for span in self.win.take(range) {
            self.led.depart(&span, None);
        }
    }

    fn rewrite_span(&mut self, index: usize, text: String) {
        let span = self.win.spans()[index].clone();
        self.led.depart(&span, None);
        self.win.set_text(index, text);
    }

    /// Charges the tokens of one typed verb call the agent emits.
    pub(crate) fn charge_verb(&mut self, verb: &str) {
        if self.allow(self.caps.board, "charge_verb") {
            self.charge(verb);
        }
    }

    /// Removes the dynamic tail so it can be re-rendered.
    pub(crate) fn clear_board(&mut self) {
        if !self.allow(self.caps.board, "clear_board") {
            return;
        }
        if let Some(i) = self
            .win
            .spans()
            .iter()
            .position(|s| s.kind == SpanKind::Board)
        {
            self.win.take(i..i + 1);
        }
    }

    /// Appends the engine-rendered board as the dynamic tail. The engine
    /// renders it from typed state, so no decode tokens are charged here.
    pub(crate) fn set_board(&mut self, text: String) {
        if self.allow(self.caps.board, "set_board") {
            self.clear_board();
            self.win.push(SpanKind::Board, text);
        }
    }
}
