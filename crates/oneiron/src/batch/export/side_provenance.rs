//! An Owner's copy's judgement of what the side ledgers and each row's birth
//! record its body was made from (fix list rows 15416, 22344 and 22345),
//! before it reads a body. The records come from the one shared reader
//! ([`SideSources`], Engine ruling EXPORT-EDGES = C); this module only
//! judges them.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::provenance::side_sources::SideSources;
use crate::source_audience::ExportJudge;
use crate::store::Store;

/// What the side ledgers and births record each row's body was made from,
/// read once in an Owner's copy's own snapshot, and the copy's verdict on
/// each row it judged by them: a body whose words came from a member's
/// mailbox the copy leaves out stays home though no edge or stamp names
/// that row, however many recorded hops lie between them.
#[derive(Default)]
pub(crate) struct SideProvenance {
    recorded: SideSources,
    /// Each row's settled verdict: a refusal holds whatever row asks, a carry
    /// only once no row still being judged stood in for it.
    settled: BTreeMap<EntityId, bool>,
    /// The sources each carried row's records name, for the rows that count
    /// as carried once a row ships ([`Self::reached`]).
    named: BTreeMap<EntityId, Vec<EntityId>>,
}

/// One row on the walk: every row its records name must go, and, for bytes a
/// blob version holds, every row of one recorded use of them.
struct Frame {
    id: EntityId,
    /// The row's requirements in order: its named sources, then each use.
    groups: Vec<Vec<EntityId>>,
    /// Whether it has uses to meet (groups past the first).
    has_uses: bool,
    /// Whether one of its uses does not read.
    unreadable_use: bool,
    group: usize,
    at: usize,
    /// Whether every named source so far went.
    named_ok: bool,
    /// Whether every row of the current use so far went.
    use_ok: bool,
    /// Whether some use went whole.
    kept_use: bool,
    /// The lowest walk depth of a row still being judged that this frame
    /// took as carried; its own depth when none.
    low: usize,
    /// Its sources that count as carried with it: every named source, and
    /// the rows of each use that went whole.
    sources: Vec<EntityId>,
}

impl SideProvenance {
    /// What the side ledgers record, read in the snapshot `rtxn`.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn read_in(store: &Store, rtxn: &RoTxn<'_>) -> Result<Self> {
        Ok(Self {
            recorded: SideSources::read_in(store, rtxn)?,
            ..Self::default()
        })
    }

    /// The rows the side ledgers and its birth record the body of `id` was
    /// made from, when `judge` carries `id` (its bytes `raw`, else as the
    /// pass's view holds them) and every row they name, each judged again by
    /// its own records (a row whose own recorded source stays home stays home
    /// too; a row met again on the same walk counts as carried), and, for
    /// bytes a blob version holds, every row of one recorded use of them:
    /// those rows, to count as carried once the body ships
    /// ([`Self::reached`]). `None` when the body stays home. A row nothing
    /// records goes as its own lineage judges it, with nothing beside it.
    /// Every recorded source is judged, so the copy's notices name each
    /// mailbox one of them is of.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn admitted(
        &mut self,
        judge: &mut ExportJudge<'_, '_, '_>,
        id: EntityId,
        raw: Option<&[u8]>,
    ) -> Result<Option<Vec<EntityId>>> {
        if let Some(settled) = self.settled.get(&id) {
            return Ok(settled.then(|| self.named.get(&id).cloned().unwrap_or_default()));
        }
        let own = judge.carries(id, raw)?;
        let recorded = self.walk(judge, id)?.filter(|_| own);
        self.settled.insert(id, recorded.is_some());
        match &recorded {
            Some(sources) => self.named.insert(id, sources.clone()),
            None => self.named.remove(&id),
        };
        Ok(recorded)
    }

    /// Whether every row the records of `id` name goes, as
    /// [`Self::admitted`] judges each, and the rows that count as carried
    /// with it; `id`'s own lineage is its caller's. Settles each row below
    /// `id` that no row still on the walk stood in for.
    fn walk(
        &mut self,
        judge: &mut ExportJudge<'_, '_, '_>,
        id: EntityId,
    ) -> Result<Option<Vec<EntityId>>> {
        let mut walk = vec![self.frame(judge, id, 0)?];
        loop {
            let depth = walk.len() - 1;
            let (current, next) = {
                let frame = &mut walk[depth];
                (frame.id, frame.next())
            };
            if let Some(child) = next {
                let carried = if child == current {
                    Some(true)
                } else if let Some(settled) = self.settled.get(&child) {
                    Some(*settled)
                } else if let Some(on_walk) = walk.iter().position(|open| open.id == child) {
                    let frame = &mut walk[depth];
                    frame.low = frame.low.min(on_walk);
                    Some(true)
                } else if judge.carries(child, None)? {
                    None
                } else {
                    self.settled.insert(child, false);
                    Some(false)
                };
                match carried {
                    Some(carried) => walk[depth].took(child, carried),
                    None => {
                        let opened = self.frame(judge, child, depth + 1)?;
                        walk.push(opened);
                    }
                }
                continue;
            }
            let frame = walk.pop().ok_or(crate::error::Error::InvariantViolation(
                "side provenance walk lost its frame",
            ))?;
            let carried = frame.carried(judge)?;
            let Some(parent) = walk.last_mut() else {
                return Ok(carried.then_some(frame.sources));
            };
            parent.low = parent.low.min(frame.low);
            parent.took(frame.id, carried);
            if carried {
                self.named.insert(frame.id, frame.sources);
            }
            if !carried || frame.low >= depth {
                self.settled.insert(frame.id, carried);
            }
        }
    }

    /// Whether `judge` carries every row of `rows` and every row each was
    /// recorded as made from, over every hop ([`Self::admitted`]); `None`,
    /// rows not all known, is carried by no judge. Every row is judged.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn carries_all(
        &mut self,
        judge: &mut ExportJudge<'_, '_, '_>,
        rows: Option<&[EntityId]>,
    ) -> Result<bool> {
        let Some(rows) = rows else {
            return judge.carries_all(None);
        };
        let mut carried = true;
        for row in rows {
            carried &= self.admitted(judge, *row, None)?.is_some();
        }
        Ok(carried)
    }

    /// Every row the rows `roots` were recorded as made from, over every
    /// hop the walk carried ([`Self::admitted`]): what counts as carried
    /// once a row whose sources they are ships.
    pub(crate) fn reached(&self, roots: impl IntoIterator<Item = EntityId>) -> BTreeSet<EntityId> {
        let mut reached = BTreeSet::new();
        let mut pending: Vec<EntityId> = roots.into_iter().collect();
        while let Some(row) = pending.pop() {
            if !reached.insert(row) {
                continue;
            }
            if let Some(sources) = self.named.get(&row) {
                pending.extend(sources.iter().copied());
            }
        }
        reached
    }

    /// The walk's frame for `id` at depth `depth`: what the shared reader
    /// records its body was made from. A record that does not read is a
    /// source this vault cannot name, and the judge is told.
    fn frame(
        &self,
        judge: &mut ExportJudge<'_, '_, '_>,
        id: EntityId,
        depth: usize,
    ) -> Result<Frame> {
        let sources = judge.recorded_sources(&self.recorded, id)?;
        let named_ok = match &sources.named {
            Some(_) => true,
            None => judge.carries_all(None)?,
        };
        let mut groups = vec![sources.named.into_iter().flatten().collect::<Vec<_>>()];
        groups.extend(
            sources
                .uses
                .iter()
                .flatten()
                .map(|rows| rows.iter().copied().collect::<Vec<_>>()),
        );
        Ok(Frame {
            id,
            has_uses: !sources.uses.is_empty(),
            unreadable_use: sources.uses.iter().any(Option::is_none),
            groups,
            group: 0,
            at: 0,
            named_ok,
            use_ok: true,
            kept_use: false,
            low: depth,
            sources: Vec::new(),
        })
    }
}

impl Frame {
    /// The next row to judge, closing each finished use on the way.
    fn next(&mut self) -> Option<EntityId> {
        loop {
            let group = self.groups.get(self.group)?;
            if let Some(row) = group.get(self.at) {
                return Some(*row);
            }
            if self.group > 0 && self.use_ok {
                self.kept_use = true;
                self.sources.extend(group.iter().copied());
            }
            self.group += 1;
            self.at = 0;
            self.use_ok = true;
        }
    }

    /// The row `row` the walk judged for this frame went (`carried`) or
    /// stays home.
    fn took(&mut self, row: EntityId, carried: bool) {
        if self.group == 0 {
            self.named_ok &= carried;
            if carried {
                self.sources.push(row);
            }
        } else {
            self.use_ok &= carried;
        }
        self.at += 1;
    }

    /// Whether the body goes: every named source went, and one use went
    /// whole when it has any. A use whose made_by does not read keeps
    /// nothing, and is of a source this vault cannot name when no use went.
    fn carried(&self, judge: &mut ExportJudge<'_, '_, '_>) -> Result<bool> {
        if self.has_uses && !self.kept_use && self.unreadable_use {
            judge.carries_all(None)?;
        }
        Ok(self.named_ok && (!self.has_uses || self.kept_use))
    }
}
