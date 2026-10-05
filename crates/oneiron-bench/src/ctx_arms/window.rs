//! The live window, the harness-minted reference store, and the accounting
//! every (arm, strategy) cell reports.
//!
//! The harness owns the window. A strategy edits it only through [`Ctx`],
//! whose fields are private to this module: every operation is gated by the
//! strategy's declared [`Caps`], bounds-checked, and charged the tokens a
//! model would decode to perform it (the command naming its target plus any
//! text it writes). References are minted by the harness, never by the
//! strategy: the strategy chooses which spans leave, the substrate makes them
//! restorable (OF-190, Sculptor).

use std::collections::BTreeMap;
use std::ops::Range;

use super::arms::Grid;
use super::board;

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
    /// Bytes of the rendered `[[label]]\n` head.
    head: usize,
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
        let head = format!("[[{label}]]\n");
        let tok = tokens(&format!("{head}{text}\n"));
        Self {
            id,
            kind,
            text,
            tok,
            head: head.len(),
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

/// The first edited position since the last model call: a span index plus
/// the tokens of that span's rendered prefix the edit left unchanged.
#[derive(Clone, Copy, Debug)]
struct Dirty {
    index: usize,
    kept_tok: u64,
}

/// The rendered window as an ordered span list. `cached` is the span count
/// the last model call prefilled. A pure append never dirties anything.
#[derive(Default)]
pub(crate) struct Window {
    spans: Vec<Span>,
    total: u64,
    next_id: u64,
    cached: usize,
    dirty: Option<Dirty>,
}

impl Window {
    /// Appends at the tail (the environment's turn, or agent output).
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

    fn touch(&mut self, index: usize, kept_tok: u64) {
        self.dirty = Some(match self.dirty {
            Some(d) if d.index < index => d,
            Some(d) if d.index == index => Dirty {
                index,
                kept_tok: d.kept_tok.min(kept_tok),
            },
            _ => Dirty { index, kept_tok },
        });
    }

    fn take(&mut self, range: Range<usize>) -> Vec<Span> {
        self.touch(range.start, 0);
        let gone: Vec<Span> = self.spans.drain(range).collect();
        self.total -= gone.iter().map(|s| s.tok).sum::<u64>();
        gone
    }

    fn insert(&mut self, index: usize, kind: SpanKind, text: String) {
        self.touch(index, 0);
        self.next_id += 1;
        let span = Span::new(self.next_id, kind, text);
        self.total += span.tok;
        self.spans.insert(index, span);
    }

    /// Replaces a span's text in place, keeping its id. The rendered bytes
    /// before the first changed byte stay cached.
    fn set_text(&mut self, index: usize, text: String) {
        let old = &self.spans[index];
        let same = old
            .text
            .bytes()
            .zip(text.bytes())
            .take_while(|(a, b)| a == b)
            .count();
        let kept_tok = (old.head + same) as u64 / 4;
        let span = Span::new(old.id, old.kind, text);
        self.total = self.total - old.tok + span.tok;
        self.spans[index] = span;
        self.touch(index, kept_tok);
    }

    /// One model call: everything from the first changed cached position to
    /// the end of the rendered window is re-prefilled (OF-263's missing
    /// component). Returns those tokens and re-arms the cache.
    pub(crate) fn checkpoint(&mut self) -> u64 {
        let reprefill = match self.dirty {
            Some(d) if d.index < self.cached => self.spans[d.index..]
                .iter()
                .map(|s| s.tok)
                .sum::<u64>()
                .saturating_sub(d.kept_tok),
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
        let r = (id as usize)
            .checked_sub(1)
            .and_then(|i| self.refs.get(i))
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

/// What the harness records while a strategy edits.
#[derive(Default)]
pub(crate) struct Ledger {
    pub(crate) edit_tok: u64,
    /// Every version of every span that left the window or was rewritten,
    /// keyed by (span id, the harness's own digest of the bytes it held),
    /// with the reference (if any) that claims to restore it. Keying by
    /// version means a span rewritten and later offloaded is audited twice.
    departed: BTreeMap<(u64, [u8; 32]), Option<u32>>,
    pub(crate) violations: Vec<&'static str>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Audit {
    /// Span versions that left the window or were rewritten.
    pub(crate) departed: u64,
    /// Of those, versions that left through a reference.
    pub(crate) with_ref: u64,
    /// Of those, versions the reference gives back byte-exactly.
    pub(crate) exact: u64,
}

impl Audit {
    /// A reference that cannot give its span back byte-exactly.
    pub(crate) const fn broken_reference(self) -> bool {
        self.exact < self.with_ref
    }
}

impl Ledger {
    fn depart(&mut self, span: &Span, via: Option<u32>) {
        // The dynamic tail is a projection of typed state, not content, and
        // the harness never lets any operation but the re-render move it.
        if span.kind != SpanKind::Board {
            let slot = self
                .departed
                .entry((span.id, digest(&span.text)))
                .or_default();
            if slot.is_none() {
                *slot = via;
            }
        }
    }

    /// Restores every departed version through its reference and compares
    /// the bytes with the harness's own digest.
    pub(crate) fn audit(&self, refs: &RefStore) -> Audit {
        let mut restored: BTreeMap<u32, Option<BTreeMap<u64, [u8; 32]>>> = BTreeMap::new();
        let mut audit = Audit {
            departed: self.departed.len() as u64,
            ..Audit::default()
        };
        for (&(id, want), via) in &self.departed {
            let Some(r) = *via else { continue };
            audit.with_ref += 1;
            let spans = restored.entry(r).or_insert_with(|| {
                refs.restore(r)
                    .ok()
                    .map(|v| v.into_iter().map(|(sid, t)| (sid, digest(t))).collect())
            });
            if spans.as_ref().and_then(|m| m.get(&id)) == Some(&want) {
                audit.exact += 1;
            }
        }
        audit
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

/// A strategy's handle on the window for one step. Its fields are private:
/// the only way in is the gated, charged operations below.
pub(crate) struct Ctx<'a> {
    win: &'a mut Window,
    refs: &'a mut RefStore,
    led: &'a mut Ledger,
    caps: Caps,
    budget: u64,
    low_water: u64,
}

impl<'a> Ctx<'a> {
    pub(crate) const fn new(
        win: &'a mut Window,
        refs: &'a mut RefStore,
        led: &'a mut Ledger,
        caps: Caps,
        budget: u64,
        low_water: u64,
    ) -> Self {
        Self {
            win,
            refs,
            led,
            caps,
            budget,
            low_water,
        }
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

    /// Records a failure the strategy hit (an engine render error, an
    /// invalid policy choice); it invalidates the cell like a violation.
    pub(crate) fn fail(&mut self, why: &'static str) {
        self.led.violations.push(why);
    }

    fn allow(&mut self, ok: bool, op: &'static str) -> bool {
        if !ok {
            self.led.violations.push(op);
        }
        ok
    }

    /// A range an edit may touch: in bounds and clear of the board, which
    /// only the harness re-render moves. An empty range is a no-op.
    fn editable(&mut self, range: &Range<usize>, op: &'static str) -> bool {
        if range.is_empty() {
            return false;
        }
        let spans = self.win.spans();
        let ok = range.end <= spans.len()
            && spans[range.clone()]
                .iter()
                .all(|s| s.kind != SpanKind::Board);
        self.allow(ok, op)
    }

    fn charge(&mut self, command: &str) {
        self.led.edit_tok += tokens(command);
    }

    /// Names window positions the way a command would: each run of
    /// adjacent spans as `sA..sB`, runs joined by commas.
    fn label(&self, indices: impl IntoIterator<Item = usize>) -> String {
        let spans = self.win.spans();
        let mut runs: Vec<(usize, usize)> = Vec::new();
        for i in indices {
            match runs.last_mut() {
                Some(run) if run.1 + 1 == i => run.1 = i,
                _ => runs.push((i, i)),
            }
        }
        runs.iter()
            .map(|&(a, b)| {
                if a == b {
                    format!("s{}", spans[a].id)
                } else {
                    format!("s{}..s{}", spans[a].id, spans[b].id)
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Appends agent-written text. Always allowed: an agent can always
    /// append its own output.
    pub(crate) fn append_note(&mut self, text: String) -> u64 {
        self.charge(&text);
        self.win.push(SpanKind::Note, text)
    }

    /// Deletes whole spans; nothing restores them.
    pub(crate) fn drop_spans(&mut self, range: Range<usize>) {
        if !self.allow(self.caps.drop, "drop") || !self.editable(&range, "drop range") {
            return;
        }
        self.charge(&format!("drop {}", self.label(range.clone())));
        for span in self.win.take(range) {
            self.led.depart(&span, None);
        }
    }

    /// Replaces spans with a stub the strategy wrote; nothing restores them.
    pub(crate) fn fold_lossy(&mut self, range: Range<usize>, stub: String) {
        if !self.allow(self.caps.fold_lossy, "fold_lossy")
            || !self.editable(&range, "fold_lossy range")
        {
            return;
        }
        self.charge(&format!("fold {}\n{stub}", self.label(range.clone())));
        let start = range.start;
        for span in self.win.take(range) {
            self.led.depart(&span, None);
        }
        self.win.insert(start, SpanKind::Stub, stub);
    }

    /// Moves spans into a harness-minted reference and leaves its stub in
    /// place. The strategy only names the spans.
    pub(crate) fn offload(&mut self, range: Range<usize>) -> Option<u32> {
        if !self.allow(self.caps.offload, "offload") || !self.editable(&range, "offload range") {
            return None;
        }
        self.charge(&format!("fold {}", self.label(range.clone())));
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
        if !self.allow(self.caps.rewrite, "patch_lines")
            || !self.editable(&(index..index + 1), "patch range")
        {
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

    /// Deletes, in each listed span, the lines `keep` rejects: one regex
    /// command naming the selection by window runs (`del s1,s3..s9 /label/`).
    /// An emptied span goes.
    pub(crate) fn retain_lines(&mut self, ids: &[u64], label: &str, keep: impl Fn(&str) -> bool) {
        if !self.allow(self.caps.rewrite, "retain_lines") || ids.is_empty() {
            return;
        }
        let mut at: Vec<usize> = ids.iter().filter_map(|&id| self.index_of(id)).collect();
        at.sort_unstable();
        self.charge(&format!("del {} /{label}/", self.label(at)));
        for &id in ids {
            let Some(index) = self.index_of(id) else {
                continue;
            };
            if !self.editable(&(index..index + 1), "retain range") {
                continue;
            }
            let span = &self.win.spans()[index];
            let kept: Vec<&str> = span.text.lines().filter(|l| keep(l)).collect();
            if kept.len() == span.text.lines().count() {
                continue;
            }
            let text = kept.join("\n");
            if text.is_empty() {
                for span in self.win.take(index..index + 1) {
                    self.led.depart(&span, None);
                }
            } else {
                self.rewrite_span(index, text);
            }
        }
    }

    /// Deletes whole spans under the rewrite capability.
    pub(crate) fn delete_spans(&mut self, range: Range<usize>) {
        if !self.allow(self.caps.rewrite, "delete_spans") || !self.editable(&range, "delete range")
        {
            return;
        }
        self.charge(&format!("delete {}", self.label(range.clone())));
        for span in self.win.take(range) {
            self.led.depart(&span, None);
        }
    }

    /// A no-op rewrite changes nothing and costs no cache.
    fn rewrite_span(&mut self, index: usize, text: String) {
        if self.win.spans()[index].text == text {
            return;
        }
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

    /// Re-renders the dynamic tail. The harness renders it through the
    /// engine renderer from typed state only (the agent's grid and the
    /// reference store's index); the strategy supplies no text, so nothing
    /// is charged. Returns the tail's tokens.
    pub(crate) fn render_board(&mut self, sketch: Option<(&Grid, u32)>) -> u64 {
        if !self.allow(self.caps.board, "render_board") {
            return 0;
        }
        self.clear_board();
        let refs = self.ref_metas();
        match board::render(sketch, &refs) {
            Ok(text) => {
                self.win.push(SpanKind::Board, text);
                self.win.spans().last().map_or(0, |s| s.tok)
            }
            Err(_) => {
                self.fail("engine board render");
                0
            }
        }
    }
}
