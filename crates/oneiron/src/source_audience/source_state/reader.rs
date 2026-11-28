//! One read of floors in one transaction (Fable design pass 31, sections 1.3
//! and 1.4): what each input is now, and the verdict of a row.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use super::{
    DeleteLevel, MAX_DEPTH, SHELL_ERASED, SourceState, Verdict, delete_level_in, has_open_in,
    later_owner_erase_in, migrated_in, open_of_in,
};
use crate::error::{Error, Result};
use crate::source_audience::floor::{FloorSource, OwnSource};
use crate::source_audience::floor_migration;
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

    /// Every input it names.
    pub(super) fn inputs(&self) -> BTreeSet<EntityId> {
        self.links.iter().map(|(input, _)| *input).collect()
    }

    pub(super) fn supports(&self) -> impl Iterator<Item = &EntityId> {
        self.links
            .iter()
            .filter(|(_, kind)| *kind == LinkKind::Attestation)
            .map(|(input, _)| input)
    }
}

/// One read of floors in one transaction: verdicts kept per row, inputs
/// followed to a bounded depth.
pub(crate) struct StateReader<'a, 't> {
    vault: &'a Vault,
    txn: &'a RoTxn<'t>,
    /// Whether any row here can have a floor
    /// ([`crate::source_audience::floor::floors_possible_in`]).
    pub(super) floors_possible: bool,
    migrated: bool,
    old_backfill_done: bool,
    verdicts: BTreeMap<EntityId, Verdict>,
    /// The rows whose verdict this read is judging now.
    judging: Vec<EntityId>,
    /// How many times a row met again inside its own judgement cut a
    /// verdict short: a verdict judged across a cut is not kept.
    cuts: usize,
}

impl<'a, 't> StateReader<'a, 't> {
    /// A reader over `txn`.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn reader(vault: &'a Vault, txn: &'a RoTxn<'t>) -> Result<Self> {
        let migrated = migrated_in(vault, txn)?;
        Ok(Self {
            vault,
            txn,
            floors_possible: crate::source_audience::floor::floors_possible_in(vault, txn)?,
            migrated,
            old_backfill_done: migrated || floor_migration::old_backfill_done_in(vault, txn)?,
            verdicts: BTreeMap::new(),
            judging: Vec::new(),
            cuts: 0,
        })
    }

    /// Whether `row` was judged here: the migration has ended, the old
    /// backfill raised every row, or a judgement since marked it.
    fn judged(&self, row: &EntityId) -> Result<bool> {
        Ok(self.old_backfill_done || floor_migration::raised_in(self.vault, self.txn, row)?)
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
        if !has_open_in(self.vault, self.txn, input)?
            && !floor_migration::has_old_marks_in(self.vault, self.txn, input, self.migrated)?
            && self.judged(input)?
        {
            return Ok(SourceState::Bound(crate::source_audience::floor::floor_in(
                self.vault, self.txn, input, &raw,
            )?));
        }
        if self.judging.len() >= MAX_DEPTH {
            return Ok(SourceState::Pending { held: true });
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
        // A row met again inside its own judgement (a MESSAGE and its TURN
        // name each other) adds nothing the first visit does not.
        if self.judging.contains(row) {
            self.cuts += 1;
            return Ok(Verdict::Whole(BTreeSet::new()));
        }
        let fetched = match raw {
            Some(_) => None,
            None => self.vault.get_raw_in(self.txn, row)?,
        };
        let raw = raw.or(fetched.as_deref());
        let cuts = self.cuts;
        self.judging.push(*row);
        let verdict = self.judge(row, raw);
        self.judging.pop();
        let verdict = verdict?;
        if self.cuts == cuts || self.judging.is_empty() {
            self.verdicts.insert(*row, verdict.clone());
        }
        Ok(verdict)
    }

    fn judge(&mut self, row: &EntityId, raw: Option<&[u8]>) -> Result<Verdict> {
        let mut sources = match raw {
            Some(raw) => crate::source_audience::floor::floor_in(self.vault, self.txn, row, raw)?,
            None => crate::source_audience::DERIVED
                .get(&self.vault.store, self.txn, row)?
                .unwrap_or_default(),
        };
        let mut waits = false;
        let mut entries = open_of_in(self.vault, self.txn, row)?;
        let old = floor_migration::old_marks_of_in(self.vault, self.txn, row, self.migrated)?;
        waits |= old.pending;
        for (input, flags) in old.entries {
            if !entries.iter().any(|(held, _)| *held == input) {
                entries.push((input, flags));
            }
        }
        // The open attestations read as one group: one free support frees.
        let mut attestations = Vec::new();
        for (input, flags) in &entries {
            if flags.is_attestation() && flags.before_floors_level().is_none() {
                attestations.push(*input);
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
                Some(DeleteLevel::Soft) if later_owner_erase_in(self.vault, self.txn, &input)? => {
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
        // A row this vault has not judged yet (written before floors, the
        // migration not there yet) is judged one level here, as the
        // migration would judge it.
        if let Some(raw) = raw
            && !self.judged(row)?
            && !crate::source_audience::obligation::row_obligation(raw).is_present()
        {
            match self.old_fact(row, raw, &mut sources)? {
                OldFact::Whole => {}
                OldFact::Waits => waits = true,
                OldFact::Sealed => return Ok(Verdict::Sealed),
            }
        }
        for source in &sources {
            if crate::source_audience::floor::floor_source_in(self.vault, self.txn, source)?
                == FloorSource::Unknown
            {
                return Ok(Verdict::Sealed);
            }
        }
        Ok(if waits {
            Verdict::Waiting
        } else {
            Verdict::Whole(sources)
        })
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
    ) -> Result<OldFact> {
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
                SourceState::Sealed => return Ok(OldFact::Sealed),
                SourceState::Erased => {
                    if *kind != LinkKind::Unwalked
                        || took_floor_of_in(self.vault, self.txn, input, sources)?
                    {
                        continue;
                    }
                    if delete_level_in(self.vault, self.txn, input)? == DeleteLevel::Soft
                        && SHELL_ERASED.contains(&self.vault.store, self.txn, input)?
                    {
                        return Ok(OldFact::Sealed);
                    }
                    waits = true;
                }
            }
        }
        Ok(if waits {
            OldFact::Waits
        } else {
            OldFact::Whole
        })
    }
}

/// What a self entry gives at a read.
enum SelfEntry {
    Waits,
    Sealed,
    Resolved(BTreeSet<EntityId>),
}

/// What the one-level judgement of an old fact gives.
enum OldFact {
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
