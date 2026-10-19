//! The answers a driver holds (Rule 5, AB-002): the observations a later
//! one may edit, the one its caller last read whole, and the pages of long
//! answers a cursor reads on. A row answer searched in a desktop window
//! whose walk stayed cut holds what it searched for and where the walk
//! stopped, for its `walk_next` to search on.
//!
//! An observation is whole, or an ordered edit of a base the caller holds
//! whole, of the same scope, that neither it nor the base is partial: the
//! base the caller names, else the last observation it read whole. Reads
//! the caller never sees (a routine step's looks, a library check, a
//! batch's steps before its last) never move that base. Of the two valid
//! forms, the answer carries the one whose pages take fewer JSON bytes,
//! the whole one on a tie (AB-003). A base no longer held, of another
//! scope, or partial gives a whole observation, never a refusal.

use crate::observation::{ObservationBase, splice_of};
use crate::{
    BrowserError, FindInput, Observation, ObservationPage, ObserveInput, PartialTree, Row,
    WaitForInput,
};
use std::collections::VecDeque;

/// Observations a later one may edit, and answers of each kind held for
/// their later pages.
pub(crate) const HISTORY: usize = 8;
/// The most bytes of rows, as JSON, one observation answer carries (Rule 5:
/// a long outline goes on in pages, never cut). Half the 512 KiB past which
/// a code-mode answer crosses as a stored result, so a page crosses inline
/// with its receipt and manifest.
const OBSERVE_PAGE_BYTES: usize = 256 * 1024;

/// What an observation is read against.
#[derive(Clone, Debug)]
pub(crate) enum Base {
    /// Whole: an `open`, a window move, a longer walk, or a read that asked
    /// whole.
    Whole,
    /// The last observation the caller read whole, every page of it.
    Delivered,
    /// The base the caller named.
    Named(ObservationBase),
}

impl Base {
    /// An effect's base: the one its caller named, else the last observation
    /// it read whole.
    pub(crate) fn of(named: Option<ObservationBase>) -> Self {
        named.map_or(Self::Delivered, Self::Named)
    }

    /// An `observe`'s base, once its input holds together: whole when it
    /// asks so, else as an effect's.
    pub(crate) fn of_observe(input: &ObserveInput) -> Result<Self, BrowserError> {
        if input.cursor.is_some() && (input.full || input.base.is_some()) {
            return Err(BrowserError::Input(
                "observe reads a cursor, or reads whole or against a base, not both".to_owned(),
            ));
        }
        if input.full && input.base.is_some() {
            return Err(BrowserError::Input(
                "observe reads whole or against a base, not both".to_owned(),
            ));
        }
        Ok(if input.full {
            Self::Whole
        } else {
            Self::of(input.base.clone())
        })
    }
}

/// One read of the page or window, as an observation takes it.
pub(crate) struct Read {
    pub(crate) seq: u64,
    pub(crate) scope: String,
    pub(crate) url: String,
    pub(crate) title: String,
    pub(crate) rows: Vec<Row>,
    pub(crate) no_tree: bool,
    pub(crate) partial: Option<PartialTree>,
}

/// One observation's ordered rows, kept for a later one to edit.
#[derive(Clone)]
struct Snapshot {
    seq: u64,
    scope: String,
    rows: Vec<Row>,
    partial: bool,
}

/// The observations a later one may edit, and the answers held for their
/// later pages: the last [`HISTORY`] observations, the one the caller last
/// read whole, the last [`HISTORY`] paged observations and the last
/// [`HISTORY`] paged or cut row answers (`find`, `wait_for`).
#[derive(Default)]
pub(crate) struct Observations {
    history: VecDeque<Snapshot>,
    /// Kept apart from `history`, so reads the caller never sees cannot age
    /// it out.
    delivered: Option<Snapshot>,
    paged: VecDeque<Observation>,
    rows: VecDeque<Rows>,
    /// The number the last held row answer took.
    rows_seq: u64,
}

/// A held row answer: its number, its rows, and, when its window's walk
/// stayed cut, the search its `walk_next` goes on with.
struct Rows {
    answer: u64,
    rows: Vec<Row>,
    search: Option<Search>,
}

/// A row search of a desktop window whose walk stopped before the tree's
/// end (Rule 5): the window (as its observation's `url` names it), where the
/// walk stopped, and what it searched for. Its `walk_next` walks the window
/// again, longer, and searches the rows it reaches for the same.
#[derive(Clone)]
pub(crate) struct Search {
    pub(crate) url: String,
    pub(crate) cut: PartialTree,
    /// The rows sought: `targets`, else `role` and `name`, as a wait
    /// matches them.
    pub(crate) query: WaitForInput,
}

/// One page of a row answer: its rows, the cursor of its next page, and,
/// when its window's walk stayed cut, where (on every page) and the cursor
/// that searches on (on the last).
pub(crate) struct Found {
    pub(crate) rows: Vec<Row>,
    pub(crate) next: Option<String>,
    pub(crate) partial: Option<PartialTree>,
    pub(crate) walk_next: Option<String>,
}

impl Observations {
    /// The observation of `read`, whole or as an edit of `base`, the smaller
    /// on the wire; `read` is kept for a later observation to edit.
    pub(crate) fn observe(&mut self, read: Read, base: &Base) -> Observation {
        let partial = read.partial.is_some();
        let edit = self
            .base_of(base, &read.scope, partial)
            .map(|held| (held.seq, splice_of(&held.rows, &read.rows)));
        let whole = Observation {
            seq: read.seq,
            scope: read.scope.clone(),
            base_seq: None,
            url: read.url,
            title: read.title,
            full: true,
            splice: None,
            rows: read.rows.clone(),
            offset: None,
            receipt: None,
            library: Vec::new(),
            no_tree: read.no_tree,
            partial: read.partial,
            walk_next: None,
            rebound: None,
        };
        self.history.push_back(Snapshot {
            seq: read.seq,
            scope: read.scope,
            rows: read.rows,
            partial,
        });
        if self.history.len() > HISTORY {
            self.history.pop_front();
        }
        let Some((base_seq, (splice, rows))) = edit else {
            return whole;
        };
        let delta = Observation {
            seq: whole.seq,
            scope: whole.scope.clone(),
            base_seq: Some(base_seq),
            url: whole.url.clone(),
            title: whole.title.clone(),
            full: false,
            splice: Some(splice),
            rows,
            offset: None,
            receipt: None,
            library: Vec::new(),
            no_tree: whole.no_tree,
            partial: None,
            walk_next: None,
            rebound: None,
        };
        // AB-003: the two forms say the same; the answer takes the one
        // whose pages are fewer bytes, the whole one on a tie.
        if plan_bytes(&delta) < plan_bytes(&whole) {
            delta
        } else {
            whole
        }
    }

    /// The held observation `base` names, when an observation of `scope`
    /// may edit it: the same scope, and neither partial.
    fn base_of(&self, base: &Base, scope: &str, partial: bool) -> Option<&Snapshot> {
        let held = match base {
            Base::Whole => None,
            Base::Delivered => self.delivered.as_ref(),
            Base::Named(named) => self
                .held(named.seq)
                .filter(|held| held.scope == named.scope),
        }?;
        (!partial && !held.partial && held.scope == scope).then_some(held)
    }

    fn held(&self, seq: u64) -> Option<&Snapshot> {
        self.delivered
            .iter()
            .chain(&self.history)
            .find(|held| held.seq == seq)
    }

    /// The caller read observation `seq` whole: a later observation edits it
    /// unless the caller names another base. Every answer that gives the
    /// caller an observation's last rows delivers it: its last page, the
    /// unpaged rest a cursor reads, or a longer walk read unpaged.
    pub(crate) fn deliver(&mut self, seq: u64) {
        if self.delivered.as_ref().is_some_and(|held| held.seq == seq) {
            return;
        }
        self.delivered = self.history.iter().find(|held| held.seq == seq).cloned();
    }

    /// `observation` as its first page; the rest is held for its cursor. A
    /// partial observation is held even when it fits one page: its last
    /// page's `walk_next` walks on (Rule 5). An observation whose last page
    /// is read is the caller's.
    pub(crate) fn first(&mut self, mut observation: Observation) -> ObservationPage {
        let (mut page, next) = cut(&observation, 0);
        if next.is_none() {
            self.deliver(observation.seq);
            if observation.partial.is_none() {
                return ObservationPage::whole(observation);
            }
        }
        page.observation.receipt = observation.receipt.take();
        page.observation.library = std::mem::take(&mut observation.library);
        page.observation.rebound = observation.rebound.take();
        let seq = observation.seq;
        self.paged.retain(|held| held.seq != seq);
        self.paged.push_back(observation);
        if self.paged.len() > HISTORY {
            self.paged.pop_front();
        }
        page
    }

    /// The page of a held observation that `cursor` starts. Every page
    /// repeats the observation's scope, base and splice, with its offset.
    pub(crate) fn next(&mut self, cursor: &str) -> Result<ObservationPage, BrowserError> {
        let (held, from) = self.continued(cursor)?;
        let (page, next) = cut(held, from);
        let seq = held.seq;
        if next.is_none() {
            self.deliver(seq);
        }
        Ok(page)
    }

    /// The whole rest of a held observation from `cursor`, unpaged: the
    /// caller has then read it whole, so it is the caller's.
    pub(crate) fn rest(&mut self, cursor: &str) -> Result<Observation, BrowserError> {
        let (held, from) = self.continued(cursor)?;
        let rest = part(
            held,
            held.rows.get(from..).unwrap_or_default().to_vec(),
            Some(from),
            true,
        );
        self.deliver(rest.seq);
        Ok(rest)
    }

    /// The window and the cut of the held partial observation that `cursor`
    /// (its `walk_next`) walks on from.
    pub(crate) fn walk_of(&self, cursor: &str) -> Result<(String, PartialTree), BrowserError> {
        let seq = cursor
            .strip_prefix('w')
            .and_then(|seq| seq.parse::<u64>().ok())
            .ok_or_else(|| BrowserError::Input(format!("{cursor} is no walk cursor")))?;
        self.paged
            .iter()
            .find(|held| held.seq == seq)
            .and_then(|held| Some((held.url.clone(), held.partial.clone()?)))
            .ok_or_else(|| {
                BrowserError::Input(format!(
                    "observation {seq} is no longer held for a longer walk; observe again"
                ))
            })
    }

    /// A row answer's first page, and the cursor of the next when the rows
    /// go on; the rest is held for it.
    pub(crate) fn first_rows(&mut self, rows: Vec<Row>) -> (Vec<Row>, Option<String>) {
        let found = self.first_found(rows, None);
        (found.rows, found.next)
    }

    /// The page of a held row answer that `cursor` starts, and the cursor
    /// of the next when the rows go on.
    pub(crate) fn next_rows(
        &self,
        cursor: &str,
    ) -> Result<(Vec<Row>, Option<String>), BrowserError> {
        let found = self.next_found(cursor)?;
        Ok((found.rows, found.next))
    }

    /// A row answer's first page, with its `search` when its window's walk
    /// stayed cut: the rest, and the search, are held for their cursors. A
    /// cut answer is held even when it fits one page, so its last page's
    /// `walk_next` searches on (Rule 5).
    pub(crate) fn first_found(&mut self, rows: Vec<Row>, search: Option<Search>) -> Found {
        let (page, next) = page_of(&rows, 0);
        if next.is_none() && search.is_none() {
            return Found {
                rows: page,
                next: None,
                partial: None,
                walk_next: None,
            };
        }
        self.rows_seq += 1;
        let answer = self.rows_seq;
        let held = Rows {
            answer,
            rows,
            search,
        };
        let found = found_of(&held, page, next);
        self.rows.push_back(held);
        if self.rows.len() > HISTORY {
            self.rows.pop_front();
        }
        found
    }

    /// The page of a held row answer that `cursor` starts, the cursor of
    /// the next when the rows go on, and its cut, as its first page had it.
    pub(crate) fn next_found(&self, cursor: &str) -> Result<Found, BrowserError> {
        let parsed = cursor
            .strip_prefix('r')
            .and_then(|rest| rest.split_once('.'))
            .and_then(|(answer, at)| {
                Some((answer.parse::<u64>().ok()?, at.parse::<usize>().ok()?))
            });
        let Some((answer, at)) = parsed else {
            return Err(BrowserError::Input(format!("{cursor} is no row cursor")));
        };
        let held = self.held_rows(answer)?;
        let (page, next) = page_of(&held.rows, at);
        Ok(found_of(held, page, next))
    }

    /// The search a cut row answer's `walk_next`, `cursor`, goes on with.
    pub(crate) fn search_of(&self, cursor: &str) -> Result<Search, BrowserError> {
        let answer = cursor
            .strip_prefix("rw")
            .and_then(|answer| answer.parse::<u64>().ok())
            .ok_or_else(|| BrowserError::Input(format!("{cursor} is no search cursor")))?;
        self.held_rows(answer)?
            .search
            .clone()
            .ok_or_else(|| BrowserError::Input(format!("answer {answer} was not cut")))
    }

    fn held_rows(&self, answer: u64) -> Result<&Rows, BrowserError> {
        self.rows
            .iter()
            .find(|held| held.answer == answer)
            .ok_or_else(|| {
                BrowserError::Input(format!(
                    "answer {answer} is no longer held for its later pages; ask again"
                ))
            })
    }

    /// Forgets every observation and held answer, so the next observation is
    /// whole: a person drove the page, or the front tab moved.
    pub(crate) fn clear(&mut self) {
        self.history.clear();
        self.delivered = None;
        self.paged.clear();
        self.rows.clear();
    }

    /// The paged observation `cursor` reads on, and where its next page
    /// starts. A cursor whose observation has left the held ones refuses.
    fn continued(&self, cursor: &str) -> Result<(&Observation, usize), BrowserError> {
        let parsed = cursor
            .split_once('.')
            .and_then(|(seq, at)| Some((seq.parse::<u64>().ok()?, at.parse::<usize>().ok()?)));
        let Some((seq, from)) = parsed else {
            return Err(BrowserError::Input(format!(
                "{cursor} is no observation cursor"
            )));
        };
        let held = self
            .paged
            .iter()
            .find(|held| held.seq == seq)
            .ok_or_else(|| {
                BrowserError::Input(format!(
                    "observation {seq} is no longer held for its later pages; observe again"
                ))
            })?;
        Ok((held, from))
    }
}

/// `whole` with `rows` of its own: its scope, base and splice, `offset`
/// where the rows start among its own, and, when `last`, its `walk_next`
/// if it is partial. The receipt and library stay on the first page.
fn part(whole: &Observation, rows: Vec<Row>, offset: Option<usize>, last: bool) -> Observation {
    Observation {
        seq: whole.seq,
        scope: whole.scope.clone(),
        base_seq: whole.base_seq,
        url: whole.url.clone(),
        title: whole.title.clone(),
        full: whole.full,
        splice: whole.splice,
        rows,
        offset: offset.map(|at| at as u64),
        receipt: None,
        library: Vec::new(),
        no_tree: whole.no_tree,
        partial: whole.partial.clone(),
        walk_next: whole
            .partial
            .as_ref()
            .filter(|_| last)
            .map(|_| walk_cursor(whole.seq)),
        rebound: None,
    }
}

/// The page of `whole` its row `from` starts, and where the next starts
/// when its rows go on.
fn cut(whole: &Observation, from: usize) -> (ObservationPage, Option<usize>) {
    let (rows, next) = page_of(&whole.rows, from);
    let paged = from > 0 || next.is_some();
    let page = ObservationPage {
        observation: part(whole, rows, paged.then_some(from), next.is_none()),
        next: next.map(|at| cursor_of(whole.seq, at)),
    };
    (page, next)
}

/// The JSON bytes every page of `observation` takes, as its answer pages it.
fn plan_bytes(observation: &Observation) -> usize {
    let (mut bytes, mut from) = (0, 0);
    loop {
        let (page, next) = cut(observation, from);
        bytes += json_len(&page);
        match next {
            Some(at) => from = at,
            None => return bytes,
        }
    }
}

/// The cursor a `find` reads on from, when it names one: a cursor beside a
/// role or a name refuses.
pub(crate) fn find_cursor(input: &FindInput) -> Result<Option<&str>, BrowserError> {
    match input.cursor.as_deref() {
        Some(_) if input.role.is_some() || input.name.is_some() => Err(BrowserError::Input(
            "find reads a role and name or a cursor, not both".to_owned(),
        )),
        cursor => Ok(cursor),
    }
}

/// The cursor a `wait_for` reads on from, when it names one: a cursor
/// beside what to wait for refuses.
pub(crate) fn wait_cursor(input: &WaitForInput) -> Result<Option<&str>, BrowserError> {
    match input.cursor.as_deref() {
        Some(_)
            if !input.targets.is_empty()
                || input.role.is_some()
                || input.name.is_some()
                || input.timeout_ms.is_some() =>
        {
            Err(BrowserError::Input(
                "wait_for waits for rows or reads on from a cursor, not both".to_owned(),
            ))
        }
        cursor => Ok(cursor),
    }
}

/// Whether `cursor` is a partial observation's `walk_next`.
pub(crate) fn is_walk(cursor: &str) -> bool {
    cursor.starts_with('w')
}

/// Whether `cursor` is a cut row answer's `walk_next`.
pub(crate) fn is_search(cursor: &str) -> bool {
    cursor.starts_with("rw")
}

/// `page` of the held row answer `held`, whose next page starts at `next`
/// when the rows go on: every page carries the answer's cut, and the last
/// its `walk_next`.
fn found_of(held: &Rows, page: Vec<Row>, next: Option<usize>) -> Found {
    let partial = held.search.as_ref().map(|search| search.cut.clone());
    Found {
        rows: page,
        walk_next: partial
            .as_ref()
            .filter(|_| next.is_none())
            .map(|_| format!("rw{}", held.answer)),
        next: next.map(|at| rows_cursor(held.answer, at)),
        partial,
    }
}

/// A token for one session's handles and scopes, so a later session's
/// never read as this one's.
pub(crate) fn session_token() -> String {
    use std::hash::BuildHasher;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let short = std::collections::hash_map::RandomState::new().hash_one(now) & 0xffff_ffff;
    format!("{short:08x}")
}

/// The page of `rows` that starts at `from` and fits
/// [`OBSERVE_PAGE_BYTES`] as JSON, and where the next page starts, when one
/// does. A page takes at least one row, so every page moves on.
fn page_of(rows: &[Row], from: usize) -> (Vec<Row>, Option<usize>) {
    let mut bytes = 0;
    let mut page = Vec::new();
    let mut at = from.min(rows.len());
    while at < rows.len() {
        let len = json_len(&rows[at]);
        if !page.is_empty() && bytes + len > OBSERVE_PAGE_BYTES {
            return (page, Some(at));
        }
        bytes += len;
        page.push(rows[at].clone());
        at += 1;
    }
    (page, None)
}

/// One entry's bytes in a page's JSON, with its comma.
fn json_len(value: &impl serde::Serialize) -> usize {
    serde_json::to_vec(value).map_or(0, |bytes| bytes.len()) + 1
}

fn cursor_of(seq: u64, at: usize) -> String {
    format!("{seq}.{at}")
}

/// A partial observation's walk cursor.
fn walk_cursor(seq: u64) -> String {
    format!("w{seq}")
}

/// A row answer's cursor: the answer's number and the row its page starts at.
fn rows_cursor(answer: u64, at: usize) -> String {
    format!("r{answer}.{at}")
}
