//! One read of floors in one transaction (Fable design pass 31, sections 1.3
//! and 1.4): what each input is now, and the verdict of a row.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use super::judge::Act;
use super::{
    DeleteLevel, MAX_DEPTH, OpenFlags, SHELL_ERASED, SourceState, Verdict, delete_level_in,
    has_open_in, later_owner_erase_in, migrated_in, open_of_in,
};
use crate::error::{Error, Result};
use crate::source_audience::floor::OwnSource;
use crate::source_audience::floor_migration::{self, Visit};
use crate::{EntityId, Vault};

/// One link of a row to a row its words came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LinkKind {
    /// Lineage the walk reads: an edge, a CLAIM's subject, a summary's held
    /// word source, a MESSAGE's TURN.
    Walked,
    /// Lineage no read walks: a birth input, a dependency source, or a word
    /// source a body names that this vault does not hold.
    Unwalked,
    /// A CLAIM's support: one free support frees the group.
    Attestation,
}

/// The links of one row, one level.
pub(super) struct Links {
    pub(super) links: Vec<(EntityId, LinkKind)>,
    /// Its lineage does not resolve here yet.
    pub(super) unresolved: bool,
}

impl Links {
    pub(super) fn of(vault: &Vault, txn: &RoTxn<'_>, row: &EntityId, raw: &[u8]) -> Result<Self> {
        let sources = crate::source_audience::floor::row_sources_in(vault, txn, row, raw)?;
        let mut kinds: BTreeMap<EntityId, LinkKind> = BTreeMap::new();
        for source in &sources.written_from {
            kinds.entry(*source).or_insert(LinkKind::Walked);
        }
        for source in sources.unwalked.iter().chain(&sources.unheld) {
            kinds.insert(*source, LinkKind::Unwalked);
        }
        for support in &sources.attested_by {
            kinds.entry(*support).or_insert(LinkKind::Attestation);
        }
        kinds.remove(row);
        Ok(Self {
            links: kinds.into_iter().collect(),
            unresolved: sources.unresolved,
        })
    }

    /// Its links, by input.
    pub(super) fn by_input(&self) -> BTreeMap<EntityId, LinkKind> {
        self.links.iter().copied().collect()
    }

    /// The inputs whose link is new against `before`, the links the row held
    /// before a write: an input `before` did not name, or named by another
    /// kind of link. A support that became a required input, or a walked
    /// link that became one no read walks, is judged in full as a new link
    /// (#10315 review 1 P1-1; pass 31 oracle case 70).
    pub(super) fn changed_since(
        &self,
        before: &BTreeMap<EntityId, LinkKind>,
    ) -> BTreeSet<EntityId> {
        self.links
            .iter()
            .filter(|(input, kind)| before.get(input) != Some(kind))
            .map(|(input, _)| *input)
            .collect()
    }

    /// The kind of the link to `input`, if the row names it.
    fn kind_of(&self, input: &EntityId) -> Option<LinkKind> {
        self.links
            .iter()
            .find(|(named, _)| named == input)
            .map(|(_, kind)| *kind)
    }

    pub(super) fn supports(&self) -> impl Iterator<Item = &EntityId> {
        self.links
            .iter()
            .filter(|(_, kind)| *kind == LinkKind::Attestation)
            .map(|(input, _)| input)
    }
}

/// One read of floors in one transaction: verdicts kept per row, inputs
/// followed to the end of their chain. One judgement recurses up to
/// [`MAX_DEPTH`]; a row it meets past that goes on the read's own stack,
/// which judges that row first and the judgement again after it.
pub(crate) struct StateReader<'a, 't> {
    vault: &'a Vault,
    txn: &'a RoTxn<'t>,
    /// Whether any row here can have a floor
    /// ([`crate::source_audience::floor::floors_possible_in`]).
    pub(super) floors_possible: bool,
    migrated: bool,
    /// Whether the migration has judged every row here.
    judged_all: bool,
    verdicts: BTreeMap<EntityId, Verdict>,
    /// Verdicts the stack judged across a cut to a row below them on it:
    /// they hold until the row at its bottom is judged.
    provisional: BTreeMap<EntityId, Verdict>,
    /// The rows whose verdict this read is judging now, from the row on top
    /// of [`Self::stack`] down.
    judging: Vec<EntityId>,
    /// The rows this read follows ([`Self::follow`]): each below the top
    /// waits for the verdicts of the rows above it.
    stack: Vec<EntityId>,
    /// The rows a judgement met past [`MAX_DEPTH`], for the stack.
    wanted: Vec<EntityId>,
    /// How many times a row met again inside its own judgement cut a
    /// verdict short: a verdict judged across a cut is not kept.
    cuts: usize,
    /// How many times a judgement met a row past [`MAX_DEPTH`] and read it
    /// as waiting until the stack judges it: a verdict judged across one is
    /// not kept.
    deferrals: usize,
}

impl<'a, 't> StateReader<'a, 't> {
    /// A reader over `txn`.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn reader(vault: &'a Vault, txn: &'a RoTxn<'t>) -> Result<Self> {
        let migrated = migrated_in(&vault.store, txn)?;
        Ok(Self {
            vault,
            txn,
            floors_possible: crate::source_audience::floor::floors_possible_in(vault, txn)?,
            migrated,
            judged_all: super::judged_all_in(&vault.store, txn)?,
            verdicts: BTreeMap::new(),
            provisional: BTreeMap::new(),
            judging: Vec::new(),
            stack: Vec::new(),
            wanted: Vec::new(),
            cuts: 0,
            deferrals: 0,
        })
    }

    /// Where `row` stands in the migration ([`floor_migration::visit_in`]).
    fn visit(&self, row: &EntityId) -> Result<Visit> {
        if self.judged_all {
            return Ok(Visit::Visited);
        }
        floor_migration::visit_in(&self.vault.store, self.txn, row)
    }

    /// What `input` is now (section 1.3).
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn state(&mut self, input: &EntityId) -> Result<SourceState> {
        if crate::ports::erased_in_txn(&self.vault.store, self.txn, input)? {
            return Ok(SourceState::Erased);
        }
        // Not landed, or a released ASSET whose bytes left with it.
        let Some(raw) = self.vault.get_raw_in(self.txn, input)? else {
            return Ok(SourceState::Pending { held: false });
        };
        if crate::source_audience::held_back_in(self.vault, self.txn, input)?.is_some()
            || crate::source_audience::floor::own_source_in(self.vault, self.txn, input, &raw)?
                == OwnSource::Unbound
        {
            return Ok(SourceState::Pending { held: true });
        }
        if !has_open_in(&self.vault.store, self.txn, input)?
            && !floor_migration::has_old_marks_in(
                &self.vault.store,
                self.txn,
                input,
                self.migrated,
            )?
            && self.visit(input)? == Visit::Visited
        {
            let floor = crate::source_audience::floor::floor_in(self.vault, self.txn, input, &raw)?;
            // A floor that names a source that reads to no one reads sealed,
            // as the input's verdict would (#10315 review 1 P1-2; case 71).
            if crate::source_audience::floor::names_unknown_source_in(
                &self.vault.store,
                self.txn,
                &floor,
            )? {
                return Ok(SourceState::Sealed);
            }
            return Ok(SourceState::Bound(floor));
        }
        Ok(match self.verdict(input, Some(&raw))? {
            Verdict::Whole(floor) => SourceState::Bound(floor),
            Verdict::Waiting => SourceState::Pending { held: true },
            Verdict::Sealed => SourceState::Sealed,
        })
    }

    /// The verdict of `row` (bytes `raw`, else as `txn` holds them).
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn verdict(&mut self, row: &EntityId, raw: Option<&[u8]>) -> Result<Verdict> {
        if !self.floors_possible {
            return Ok(Verdict::Whole(BTreeSet::new()));
        }
        if let Some(known) = self.verdicts.get(row) {
            return Ok(known.clone());
        }
        // A verdict the stack judged across a cut cuts what reads it too.
        if let Some(known) = self.provisional.get(row) {
            let known = known.clone();
            self.cuts += 1;
            return Ok(known);
        }
        // A row met again inside its own judgement (a MESSAGE and its TURN
        // name each other) adds nothing the first visit does not.
        if self.judging.contains(row) || self.stack.contains(row) {
            self.cuts += 1;
            return Ok(Verdict::Whole(BTreeSet::new()));
        }
        if self.judging.is_empty() {
            return self.follow(row, raw);
        }
        // Past the depth one judgement recurses, the row waits for the
        // stack, and this judgement is judged again once it has its verdict.
        if self.judging.len() >= MAX_DEPTH {
            self.deferrals += 1;
            if !self.wanted.contains(row) {
                self.wanted.push(*row);
            }
            return Ok(Verdict::Waiting);
        }
        let (cuts, deferrals) = (self.cuts, self.deferrals);
        let verdict = self.judge_on_path(row, raw)?;
        if self.cuts == cuts && self.deferrals == deferrals {
            self.verdicts.insert(*row, verdict.clone());
        }
        Ok(verdict)
    }

    /// The verdict this read holds for `row`, if it has judged it.
    fn known(&self, row: &EntityId) -> Option<Verdict> {
        self.verdicts
            .get(row)
            .or_else(|| self.provisional.get(row))
            .cloned()
    }

    /// Judges `row` (bytes `raw`, else as `txn` holds them) with it on the
    /// judging path.
    fn judge_on_path(&mut self, row: &EntityId, raw: Option<&[u8]>) -> Result<Verdict> {
        let fetched = match raw {
            Some(_) => None,
            None => self.vault.get_raw_in(self.txn, row)?,
        };
        let raw = raw.or(fetched.as_deref());
        self.judging.push(*row);
        let verdict = self.judge(row, raw);
        self.judging.pop();
        verdict
    }

    /// The verdict of `row`, the first a read asks, with its inputs
    /// followed to the end of their chain on the read's own stack: a
    /// judgement that meets a row past [`MAX_DEPTH`] leaves it to the stack,
    /// which judges that row, then the judgement again. An erase at any
    /// depth of the chain seals its first row (#10315 review 1 P1-4; pass 31
    /// oracle case 73). Each row goes on the stack at most once, so the read
    /// ends.
    fn follow(&mut self, row: &EntityId, raw: Option<&[u8]>) -> Result<Verdict> {
        self.stack.push(*row);
        let verdict = self.follow_stack(raw);
        self.stack.clear();
        self.wanted.clear();
        self.provisional.clear();
        verdict
    }

    /// [`Self::follow`] from the stack as it stands, `raw` the bytes of the
    /// row at its bottom.
    fn follow_stack(&mut self, raw: Option<&[u8]>) -> Result<Verdict> {
        loop {
            // The loop returns once it has judged the row at the bottom.
            let Some(&top) = self.stack.last() else {
                return Ok(Verdict::Sealed);
            };
            let bottom = self.stack.len() == 1;
            if !bottom && self.known(&top).is_some() {
                self.stack.pop();
                continue;
            }
            let (cuts, deferrals) = (self.cuts, self.deferrals);
            let verdict = self.judge_on_path(&top, if bottom { raw } else { None })?;
            if self.deferrals != deferrals {
                let wanted: Vec<EntityId> = std::mem::take(&mut self.wanted)
                    .into_iter()
                    .filter(|input| self.known(input).is_none() && !self.stack.contains(input))
                    .collect();
                self.stack.extend(wanted);
                continue;
            }
            self.stack.pop();
            if bottom {
                self.verdicts.insert(top, verdict.clone());
                return Ok(verdict);
            }
            if self.cuts == cuts {
                self.verdicts.insert(top, verdict);
            } else {
                self.provisional.insert(top, verdict);
            }
        }
    }

    fn judge(&mut self, row: &EntityId, raw: Option<&[u8]>) -> Result<Verdict> {
        let mut sources = match raw {
            Some(raw) => crate::source_audience::floor::floor_in(self.vault, self.txn, row, raw)?,
            None => crate::source_audience::DERIVED
                .get(&self.vault.store, self.txn, row)?
                .unwrap_or_default(),
        };
        let mut waits = false;
        let mut entries = open_of_in(&self.vault.store, self.txn, row)?;
        let old =
            floor_migration::old_marks_of_in(&self.vault.store, self.txn, row, self.migrated)?;
        waits |= old.pending;
        let mut links = None;
        for (input, flags) in old.entries {
            if !entries.iter().any(|(held, _)| *held == input) {
                let flags = mark_flags(self.links_of(&mut links, row, raw)?, &input, flags);
                entries.push((input, flags));
            }
        }
        // The open attestations read as one group with every support the row
        // has now: one free support frees, a support written before an old
        // build's mark became an entry included (#10315 review 1 P1-3).
        let mut attestations = Vec::new();
        for (input, flags) in &entries {
            if flags.is_attestation() && flags.before_floors_level().is_none() {
                attestations.push(*input);
            }
        }
        if !attestations.is_empty()
            && let Some(held) = self.links_of(&mut links, row, raw)?
        {
            for support in held.supports() {
                if !attestations.contains(support) {
                    attestations.push(*support);
                }
            }
        }
        let freed = self.frees_any(&attestations)?;
        for (input, flags) in entries {
            if flags.is_attestation() && freed && flags.before_floors_level().is_none() {
                continue;
            }
            if input == *row {
                match self.resolved_self(row, raw)? {
                    SelfEntry::Waits => waits = true,
                    SelfEntry::Sealed => return Ok(Verdict::Sealed),
                    SelfEntry::Resolved(floor) => sources.extend(floor),
                }
                continue;
            }
            match flags.before_floors_level() {
                Some(DeleteLevel::Soft)
                    if later_owner_erase_in(&self.vault.store, self.txn, &input)? =>
                {
                    return Ok(Verdict::Sealed);
                }
                Some(_) => waits = true,
                None => match self.state(&input)? {
                    SourceState::Bound(floor) => sources.extend(floor),
                    SourceState::Pending { .. } => waits = true,
                    SourceState::Sealed | SourceState::Erased => return Ok(Verdict::Sealed),
                },
            }
        }
        // A row the migration has not visited yet is judged one level
        // here, as the migration would judge it: an old fact every link, a
        // row an older build raised by its birth inputs and dependency
        // sources.
        if let Some(raw) = raw
            && !crate::source_audience::obligation::row_obligation(raw).is_present()
        {
            let visit = self.visit(row)?;
            match visit {
                Visit::Visited => {}
                Visit::OldFact | Visit::Raised => {
                    let level = if visit == Visit::OldFact {
                        self.old_fact(row, raw, &mut sources)?
                    } else {
                        self.healed(row, raw, &mut sources)?
                    };
                    match level {
                        OneLevel::Whole => {}
                        OneLevel::Waits => waits = true,
                        OneLevel::Sealed => return Ok(Verdict::Sealed),
                    }
                }
            }
        }
        if crate::source_audience::floor::names_unknown_source_in(
            &self.vault.store,
            self.txn,
            &sources,
        )? {
            return Ok(Verdict::Sealed);
        }
        Ok(if waits {
            Verdict::Waiting
        } else {
            Verdict::Whole(sources)
        })
    }

    /// The links of `row` (bytes `raw`), read once into `links`; `None` for
    /// a row not held here.
    fn links_of<'l>(
        &self,
        links: &'l mut Option<Links>,
        row: &EntityId,
        raw: Option<&[u8]>,
    ) -> Result<Option<&'l Links>> {
        let Some(raw) = raw else {
            return Ok(None);
        };
        if links.is_none() {
            *links = Some(Links::of(self.vault, self.txn, row, raw)?);
        }
        Ok(links.as_ref())
    }

    /// Whether one of `supports` is bound with an empty floor.
    pub(super) fn frees_any(&mut self, supports: &[EntityId]) -> Result<bool> {
        for support in supports {
            if let SourceState::Bound(floor) = self.state(support)?
                && floor.is_empty()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// A self entry: the row's lineage did not resolve when it was judged.
    /// Its word sources are judged again from its bytes.
    fn resolved_self(&mut self, row: &EntityId, raw: Option<&[u8]>) -> Result<SelfEntry> {
        let Some(raw) = raw else {
            return Ok(SelfEntry::Waits);
        };
        let Some(named) = word_sources_now_in(self.vault, self.txn, row, raw)? else {
            return Ok(SelfEntry::Waits);
        };
        let mut floor = BTreeSet::new();
        let mut waits = false;
        for source in named {
            if source == *row {
                continue;
            }
            match self.state(&source)? {
                SourceState::Bound(add) => floor.extend(add),
                SourceState::Pending { .. } => waits = true,
                SourceState::Sealed | SourceState::Erased => return Ok(SelfEntry::Sealed),
            }
        }
        Ok(if waits {
            SelfEntry::Waits
        } else {
            SelfEntry::Resolved(floor)
        })
    }

    /// The one-level heal of a row an older build raised (section 5, M2),
    /// as [`super::heal_row_in_txn`] stores it ([`super::judge::heal_acts_in`]).
    fn healed(
        &mut self,
        row: &EntityId,
        raw: &[u8],
        sources: &mut BTreeSet<EntityId>,
    ) -> Result<OneLevel> {
        let (vault, txn) = (self.vault, self.txn);
        let mut waits = false;
        for (_, act) in super::judge::heal_acts_in(self, vault, txn, row, raw)? {
            match act {
                Act::Take(floor) => sources.extend(floor),
                Act::Open(_) => waits = true,
                Act::OpenSelf => match self.resolved_self(row, Some(raw))? {
                    SelfEntry::Waits => waits = true,
                    SelfEntry::Sealed => return Ok(OneLevel::Sealed),
                    SelfEntry::Resolved(floor) => sources.extend(floor),
                },
                Act::Seal | Act::Free => {}
            }
        }
        Ok(if waits {
            OneLevel::Waits
        } else {
            OneLevel::Whole
        })
    }

    /// The one-level judgement of a row written before floors (section 5,
    /// M2): a bound input's floor joins `sources`; a pending input keeps it
    /// waiting (a walked input only when it is held here); an erased input no
    /// read walks leaves it waiting for good, owner-readable, unless the row
    /// took that input's floor before (its binding is still on record and on
    /// the row's floor) or a later owner erase reached it.
    fn old_fact(
        &mut self,
        row: &EntityId,
        raw: &[u8],
        sources: &mut BTreeSet<EntityId>,
    ) -> Result<OneLevel> {
        let links = Links::of(self.vault, self.txn, row, raw)?;
        let mut waits = links.unresolved;
        let supports: Vec<EntityId> = links.supports().copied().collect();
        let freed = self.frees_any(&supports)?;
        for (input, kind) in &links.links {
            if *kind == LinkKind::Attestation && freed {
                continue;
            }
            match self.state(input)? {
                SourceState::Bound(floor) => sources.extend(floor),
                SourceState::Pending { held } => {
                    if held || *kind == LinkKind::Unwalked {
                        waits = true;
                    }
                }
                SourceState::Sealed => return Ok(OneLevel::Sealed),
                SourceState::Erased => {
                    if *kind != LinkKind::Unwalked
                        || took_floor_of_in(self.vault, self.txn, input, sources)?
                    {
                        continue;
                    }
                    if delete_level_in(&self.vault.store, self.txn, input)? == DeleteLevel::Soft
                        && SHELL_ERASED.contains(&self.vault.store, self.txn, input)?
                    {
                        return Ok(OneLevel::Sealed);
                    }
                    waits = true;
                }
            }
        }
        Ok(if waits {
            OneLevel::Waits
        } else {
            OneLevel::Whole
        })
    }
}

/// The flags an old build's mark on `awaited` reads with, `flags` as
/// [`floor_migration`] reads the mark: a support's when the link to
/// `awaited` is a CLAIM's support and no more, since a mark names no kind
/// of link (#10315 review 1 P1-3; pass 31 oracle case 72).
fn mark_flags(links: Option<&Links>, awaited: &EntityId, flags: OpenFlags) -> OpenFlags {
    if flags.before_floors_level().is_none()
        && links.is_some_and(|links| links.kind_of(awaited) == Some(LinkKind::Attestation))
    {
        flags.attestation()
    } else {
        flags
    }
}

/// The entry M1 makes of an old build's mark of the held row `row` (bytes
/// `raw`) on `awaited`, read with `flags` (section 5, M1): a support's when
/// the link is a support only, and none when a support of the row frees it
/// now, as a write that judged the link would (#10315 review 1 P1-3; pass 31
/// oracle case 72).
///
/// # Errors
///
/// Storage failures.
pub(in crate::source_audience) fn mark_entry_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
    awaited: &EntityId,
    flags: OpenFlags,
) -> Result<Option<OpenFlags>> {
    if awaited == row {
        return Ok(Some(flags));
    }
    let links = Links::of(vault, txn, row, raw)?;
    let flags = mark_flags(Some(&links), awaited, flags);
    if flags.is_attestation() {
        let supports: Vec<EntityId> = links.supports().copied().collect();
        if StateReader::reader(vault, txn)?.frees_any(&supports)? {
            return Ok(None);
        }
    }
    Ok(Some(flags))
}

/// What a self entry gives at a read.
enum SelfEntry {
    Waits,
    Sealed,
    Resolved(BTreeSet<EntityId>),
}

/// What the one-level judgement of a row the migration has not visited
/// gives.
enum OneLevel {
    Whole,
    Waits,
    Sealed,
}

/// Whether a row whose floor is `floor` took the floor of `input`, an
/// erased input: its binding is still on record, and the floor holds it.
pub(super) fn took_floor_of_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    input: &EntityId,
    floor: &BTreeSet<EntityId>,
) -> Result<bool> {
    Ok(crate::source_audience::binding_in(vault, txn, input)?
        .is_some_and(|policy| floor.contains(&policy)))
}

/// The word sources the bytes `raw` of `row` name now, when they resolve:
/// a summary's or merge header's named sources and a carried summary.
/// `None` while they do not resolve.
pub(super) fn word_sources_now_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    row: &EntityId,
    raw: &[u8],
) -> Result<Option<Vec<EntityId>>> {
    let mut named = match crate::scope_summary::word_sources_in(vault, txn, row, raw) {
        Ok(crate::scope_summary::WordSources::Own) => Vec::new(),
        Ok(crate::scope_summary::WordSources::From(named)) => named,
        Ok(crate::scope_summary::WordSources::Unresolved)
        | Err(Error::InvalidClaimBody(_) | Error::Record(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    match crate::scope_summary::carried_summary(raw) {
        Ok(carried) => named.extend(carried),
        Err(_) => return Ok(None),
    }
    Ok(Some(named))
}
