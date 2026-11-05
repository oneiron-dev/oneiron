//! A vault's body history in its exterior custody (KS-2A/KS-2B1, FIX 6229,
//! 6023): the obligations an erase follows to every image's copy of a body,
//! kept beside the keys they retire, outside every image.
//!
//! The rows are the vault's own custody-state rows, ids only: each instance
//! a row-held response was carried under, by each owner its stamps name
//! (`PROVENANCE_BODY_RESPONSE_OWNER`); each instance a body digest was bound
//! under that its row no longer names (`PROVENANCE_BODY_INSTANCE`); each
//! instance an owner's erase retired or owes (`PROVENANCE_BODY_ERASED`); and
//! each actual historical source fact naming its source, body owner,
//! published digest, and real vault instance (`PROVENANCE_BODY_SOURCE`). The
//! writer that adds one journals it as a `BodyHistory` frame, synced, before
//! it commits, so an aborted writer leaves the journal a row more, never one
//! less, and the log moves on, so every member's head is sealed and
//! acknowledged again. The latest rows are the fold of the lineage's frames,
//! from the history a takeover landed or the newest cache of an earlier fold;
//! a head carries them in its host-readable compartments, sealed under the
//! same wraps as the keys. Every same-lineage restore that keeps its image's
//! custody unions them into the image's rows, so an image older than the
//! newest one still names every later instance its owners' erase must reach.
//! A row whose instance custody already retired is pruned from the fold: no
//! erase is owed to it any longer.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_crypto::Purpose;

use super::KeyCustody;
use super::files::{LocalCustody, read_whole, replace_file, write_once};
use super::identity::{CustodyId, CustodyKind};
use super::log::{
    Control, CustodyPosition, Journal, LogEntry, frame_hash, log_corrupt, open_frame, open_sym,
    seal_sym,
};
use crate::error::Result;
use crate::side_table;

/// One history row: a `vault_meta` key and its value, as the vault stores it.
pub(crate) type HistoryRow = (Vec<u8>, Vec<u8>);

/// The latest history rows, by key.
pub(crate) type HistoryRows = BTreeMap<Vec<u8>, Vec<u8>>;

/// The cache of the newest fold, beside the frames.
const CACHE: &str = "history";
/// The history a takeover landed with, at its base position.
const BASE: &str = "history.base";
const HISTORY_KEY_ID: &[u8] = b"oneiron/custody-body-history/v1";
const HISTORY_RECIPIENT: &[u8] = b"oneiron/custody-body-history/fold/v1";
/// The cache of the minted-instances fold, beside the frames (FIX 9067).
/// No base beside it: a takeover lineage minted nothing here, and starting
/// empty is the spec.
const MINTED: &str = "minted";
const MINTED_KEY_ID: &[u8] = b"oneiron/custody-body-minted/v1";
const MINTED_RECIPIENT: &[u8] = b"oneiron/custody-body-minted/fold/v1";
/// The most rows one fold part or one frame holds: a codec bound that keeps
/// each far inside one envelope; more take more parts or frames.
const FOLD_PART_ROWS: usize = 16 * 1024;

/// The families a history row may be of, and the bytes each key holds after
/// its prefix: an id16 or a digest32, then the instance16; a source fact
/// names source16, owner16, and digest32, then the instance16.
fn families() -> [(&'static [u8], usize); 4] {
    [
        (side_table::PROVENANCE_BODY_ERASED.prefix, 32),
        (side_table::PROVENANCE_BODY_INSTANCE.prefix, 48),
        (side_table::PROVENANCE_BODY_RESPONSE_OWNER.prefix, 32),
        (side_table::PROVENANCE_BODY_SOURCE.prefix, 80),
    ]
}

/// Whether `key` is a history row's: of one of its families, and its shape.
pub(super) fn admits(key: &[u8]) -> bool {
    families().iter().any(|(prefix, len)| {
        key.strip_prefix(*prefix)
            .is_some_and(|rest| rest.len() == *len)
    })
}

/// The instance a history row names, its key's last 16 bytes, when its
/// family's obligation ends with the instance's retirement (an erase's
/// receipt row stays).
fn owed_instance(key: &[u8]) -> Option<[u8; 16]> {
    if key.starts_with(side_table::PROVENANCE_BODY_ERASED.prefix) {
        return None;
    }
    key.len()
        .checked_sub(16)
        .and_then(|at| key.get(at..))
        .and_then(|tail| tail.try_into().ok())
}

/// `u32be count`, then each row as `u32be len | key | u32be len | value`.
pub(super) fn encode_rows<'a>(
    rows: impl ExactSizeIterator<Item = (&'a [u8], &'a [u8])>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(rows.len() as u32).to_be_bytes());
    for (key, value) in rows {
        for part in [key, value] {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part);
        }
    }
    out
}

/// The rows [`encode_rows`] wrote, refused when one is not a history row's.
pub(super) fn decode_rows(bytes: &[u8]) -> Option<Vec<HistoryRow>> {
    let take = |at: &mut usize| -> Option<Vec<u8>> {
        let len = u32::from_be_bytes(bytes.get(*at..*at + 4)?.try_into().ok()?) as usize;
        let part = bytes.get(*at + 4..(*at + 4).checked_add(len)?)?.to_vec();
        *at += 4 + len;
        Some(part)
    };
    let count = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?);
    let mut at = 4;
    let mut rows = Vec::new();
    for _ in 0..count {
        let key = take(&mut at)?;
        let value = take(&mut at)?;
        if !admits(&key) {
            return None;
        }
        rows.push((key, value));
    }
    (at == bytes.len()).then_some(rows)
}

/// Unions `history` into sorted image `rows` (`vault_meta`'s): a row the
/// history holds takes its place or is added in key order.
pub(crate) fn merge_history_into_rows(rows: &mut Vec<HistoryRow>, history: &HistoryRows) {
    for (key, value) in history {
        match rows.binary_search_by(|(row, _)| row.as_slice().cmp(key)) {
            Ok(at) => rows[at].1.clone_from(value),
            Err(at) => rows.insert(at, (key.clone(), value.clone())),
        }
    }
}

/// The body instances `census` holds retired.
pub(super) fn retired_instances(census: &[(CustodyId, super::EntryState)]) -> BTreeSet<[u8; 16]> {
    census
        .iter()
        .filter(|(id, state)| {
            id.kind() == CustodyKind::BodyInstance && *state == super::EntryState::Retired
        })
        // A body instance's item is `instance (16) | scope (1)`.
        .filter_map(|(id, _)| id.subject().item().get(..16)?.try_into().ok())
        .collect()
}

/// A fold read back from a file: where it stands and its rows.
struct Fold {
    seq: u64,
    tip: [u8; 32],
    rows: HistoryRows,
}

impl Journal {
    /// The fold kept as `name`'s parts; `None` when there is none. A part
    /// missing or of another fold leaves it incomplete: `None` too.
    fn read_fold(&self, control: &Control, name: &str) -> Result<Option<Fold>> {
        let mut fold = Fold {
            seq: 0,
            tip: [0; 32],
            rows: BTreeMap::new(),
        };
        let mut count = 1;
        let mut index = 0;
        while index < count {
            let Some(sealed) = read_whole(&self.dir().join(format!("{name}.{index}")))? else {
                return Ok(None);
            };
            let plain = open_sym(
                Purpose::CustodyLogFrame,
                self.vault(),
                HISTORY_KEY_ID,
                HISTORY_RECIPIENT,
                &control.log_kek(),
                &sealed,
            )?;
            let part = (|| {
                let seq = u64::from_be_bytes(plain.get(..8)?.try_into().ok()?);
                let tip: [u8; 32] = plain.get(8..40)?.try_into().ok()?;
                let at = u32::from_be_bytes(plain.get(40..44)?.try_into().ok()?);
                let of = u32::from_be_bytes(plain.get(44..48)?.try_into().ok()?);
                Some((seq, tip, at, of, decode_rows(plain.get(48..)?)?))
            })();
            let (seq, tip, at, of, rows) = part.ok_or_else(log_corrupt)?;
            if index == 0 {
                (fold.seq, fold.tip, count) = (seq, tip, of);
            }
            if at != index || of != count || seq != fold.seq || tip != fold.tip {
                return Ok(None);
            }
            fold.rows.extend(rows);
            index += 1;
        }
        Ok(Some(fold))
    }

    /// Keeps `rows`, the fold at `at`, as `name`'s parts, each far inside
    /// one envelope's bound, so a fold of any size is kept whole (Rule 5).
    fn write_fold(
        &self,
        control: &Control,
        name: &str,
        at: &CustodyPosition,
        rows: &HistoryRows,
        once: bool,
    ) -> Result<()> {
        let rows: Vec<(&Vec<u8>, &Vec<u8>)> = rows.iter().collect();
        let parts: Vec<_> = rows.chunks(FOLD_PART_ROWS).collect();
        let count = u32::try_from(parts.len().max(1)).map_err(|_| log_corrupt())?;
        for index in 0..count {
            let part = parts.get(index as usize).copied().unwrap_or_default();
            let mut plain = zeroize::Zeroizing::new(at.seq.to_be_bytes().to_vec());
            plain.extend_from_slice(&at.tip);
            plain.extend_from_slice(&index.to_be_bytes());
            plain.extend_from_slice(&count.to_be_bytes());
            plain.extend_from_slice(&encode_rows(
                part.iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
            ));
            let sealed = seal_sym(
                Purpose::CustodyLogFrame,
                self.vault(),
                HISTORY_KEY_ID,
                HISTORY_RECIPIENT,
                &control.log_kek(),
                &plain,
            )?;
            let file = format!("{name}.{index}");
            if once {
                if !write_once(self.dir(), &file, &sealed)? {
                    return Err(log_corrupt());
                }
            } else {
                replace_file(self.dir(), &file, &sealed)?;
            }
        }
        Ok(())
    }

    /// Keeps `rows` as the history a takeover at `at`, its base, landed.
    pub(super) fn put_history_base(
        &self,
        control: &Control,
        at: &CustodyPosition,
        rows: &HistoryRows,
    ) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        self.write_fold(control, BASE, at, rows, true)
    }

    /// Whether the fold at `seq`, `tip` stands on this log: its base, or a
    /// frame here whose hash it names.
    fn stands(&self, control: &Control, seq: u64, tip: &[u8; 32]) -> Result<bool> {
        if seq == control.base_seq() {
            return Ok(*tip == control.base_tip());
        }
        Ok(seq > control.base_seq()
            && self
                .frame(seq)?
                .is_some_and(|frame| super::log::frame_hash(&frame) == *tip))
    }

    /// The latest history rows at `at`, the local log's position: the newest
    /// fold that stands on the log at or before it, then every frame after.
    pub(super) fn body_history(
        &self,
        control: &Control,
        at: &CustodyPosition,
    ) -> Result<HistoryRows> {
        let mut from = None;
        for name in [CACHE, BASE] {
            if let Some(fold) = self.read_fold(control, name)?
                && fold.seq <= at.seq
                && self.stands(control, fold.seq, &fold.tip)?
            {
                from = Some(fold);
                break;
            }
        }
        let Fold {
            mut seq,
            mut tip,
            mut rows,
        } = from.unwrap_or(Fold {
            seq: control.base_seq(),
            tip: control.base_tip(),
            rows: BTreeMap::new(),
        });
        while seq < at.seq {
            seq += 1;
            let frame = self.frame(seq)?.ok_or_else(log_corrupt)?;
            let (header, entry) = super::log::open_frame(control, &frame)?;
            if header.seq != seq || header.prev != tip {
                return Err(log_corrupt());
            }
            tip = super::log::frame_hash(&frame);
            if let LogEntry::BodyHistory(put) = entry {
                rows.extend(put);
            }
        }
        if tip != at.tip {
            return Err(log_corrupt());
        }
        Ok(rows)
    }

    /// [`Self::body_history`] for a head sealed at `at`, a row whose
    /// instance `census` holds retired pruned, the fold cached for the next.
    pub(super) fn head_history(
        &self,
        control: &Control,
        at: &CustodyPosition,
        census: &[(CustodyId, super::EntryState)],
    ) -> Result<HistoryRows> {
        let mut rows = self.body_history(control, at)?;
        let retired = retired_instances(census);
        rows.retain(|key, _| {
            owed_instance(key).is_none_or(|instance| !retired.contains(&instance))
        });
        // Only a cache: the next fold walks the frames when it is gone.
        let _ = self.write_fold(control, CACHE, at, &rows, false);
        Ok(rows)
    }

    /// The body instances this lineage minted on this host, at `at` (FIX
    /// 9067): the cached fold when it stands on this log at this base,
    /// extended by every frame after it, else the whole walk from the
    /// base, which is what every read paid before. The set only grows
    /// within a lineage, so a fold that does not stand is only slow; one
    /// that stands is exact, as each frame past it is replayed and its
    /// chain checked. The fold is rewritten best-effort whenever a frame
    /// was folded in.
    pub(super) fn minted_body_instances_cached(
        &self,
        control: &Control,
        at: &CustodyPosition,
    ) -> Result<BTreeSet<[u8; 16]>> {
        if let Some(fold) = self.read_minted_fold(control)
            && fold.seq <= at.seq
            && fold.base_seq == control.base_seq()
            && fold.base_tip == control.base_tip()
            && self.stands(control, fold.seq, &fold.tip).unwrap_or(false)
            && let Ok((minted, folded)) = self.replay_minted(control, fold, at)
        {
            if folded {
                let _ = self.write_minted_fold(control, at, &minted);
            }
            return Ok(minted);
        }
        let minted = self.minted_from_base(control, at)?;
        if at.seq > control.base_seq() {
            let _ = self.write_minted_fold(control, at, &minted);
        }
        Ok(minted)
    }

    /// Every Mint frame's body instance from after the base to `at`: the
    /// walk the cache only shortens, kept as it read before the cache.
    fn minted_from_base(
        &self,
        control: &Control,
        at: &CustodyPosition,
    ) -> Result<BTreeSet<[u8; 16]>> {
        let mut minted = BTreeSet::new();
        for seq in control.base_seq().saturating_add(1)..=at.seq {
            let frame = self.frame(seq)?.ok_or_else(log_corrupt)?;
            let (_, entry) = open_frame(control, &frame)?;
            collect_minted(&mut minted, &entry)?;
        }
        Ok(minted)
    }

    /// `fold` carried to `at`, each frame's chain checked as
    /// [`Self::body_history`] checks it; whether any frame was folded in.
    fn replay_minted(
        &self,
        control: &Control,
        fold: MintedFold,
        at: &CustodyPosition,
    ) -> Result<(BTreeSet<[u8; 16]>, bool)> {
        let MintedFold {
            mut seq,
            mut tip,
            mut minted,
            ..
        } = fold;
        let folded = seq < at.seq;
        while seq < at.seq {
            seq += 1;
            let frame = self.frame(seq)?.ok_or_else(log_corrupt)?;
            let (header, entry) = open_frame(control, &frame)?;
            if header.seq != seq || header.prev != tip {
                return Err(log_corrupt());
            }
            tip = frame_hash(&frame);
            collect_minted(&mut minted, &entry)?;
        }
        if tip != at.tip {
            return Err(log_corrupt());
        }
        Ok((minted, folded))
    }

    /// The minted fold kept beside the frames; `None` on any doubt about
    /// it, as a cache is only ever a shortcut to the walk.
    fn read_minted_fold(&self, control: &Control) -> Option<MintedFold> {
        let mut fold = MintedFold {
            seq: 0,
            tip: [0; 32],
            base_seq: 0,
            base_tip: [0; 32],
            minted: BTreeSet::new(),
        };
        let mut count = 1;
        let mut index = 0;
        while index < count {
            let sealed = read_whole(&self.dir().join(format!("{MINTED}.{index}"))).ok()??;
            let plain = open_sym(
                Purpose::CustodyLogFrame,
                self.vault(),
                MINTED_KEY_ID,
                MINTED_RECIPIENT,
                &control.log_kek(),
                &sealed,
            )
            .ok()?;
            let seq = u64::from_be_bytes(plain.get(..8)?.try_into().ok()?);
            let tip: [u8; 32] = plain.get(8..40)?.try_into().ok()?;
            let at_part = u32::from_be_bytes(plain.get(40..44)?.try_into().ok()?);
            let of = u32::from_be_bytes(plain.get(44..48)?.try_into().ok()?);
            let base_seq = u64::from_be_bytes(plain.get(48..56)?.try_into().ok()?);
            let base_tip: [u8; 32] = plain.get(56..88)?.try_into().ok()?;
            let rows = u32::from_be_bytes(plain.get(88..92)?.try_into().ok()?) as usize;
            let bytes = plain.get(92..)?;
            if bytes.len() != rows.checked_mul(16)? {
                return None;
            }
            if index == 0 {
                (fold.seq, fold.tip, fold.base_seq, fold.base_tip, count) =
                    (seq, tip, base_seq, base_tip, of);
            }
            if at_part != index
                || of != count
                || seq != fold.seq
                || tip != fold.tip
                || base_seq != fold.base_seq
                || base_tip != fold.base_tip
            {
                return None;
            }
            for instance in bytes.chunks_exact(16) {
                fold.minted.insert(instance.try_into().ok()?);
            }
            index += 1;
        }
        Some(fold)
    }

    /// Keeps `minted`, the fold at `at`, as the minted parts: the position
    /// and the base it stands on in each part's header, then the instances
    /// in order, `u32be count` first.
    fn write_minted_fold(
        &self,
        control: &Control,
        at: &CustodyPosition,
        minted: &BTreeSet<[u8; 16]>,
    ) -> Result<()> {
        let minted: Vec<[u8; 16]> = minted.iter().copied().collect();
        let parts: Vec<_> = minted.chunks(FOLD_PART_ROWS).collect();
        let count = u32::try_from(parts.len().max(1)).map_err(|_| log_corrupt())?;
        for index in 0..count {
            let part: &[[u8; 16]] = parts.get(index as usize).copied().unwrap_or_default();
            let mut plain = zeroize::Zeroizing::new(at.seq.to_be_bytes().to_vec());
            plain.extend_from_slice(&at.tip);
            plain.extend_from_slice(&index.to_be_bytes());
            plain.extend_from_slice(&count.to_be_bytes());
            plain.extend_from_slice(&control.base_seq().to_be_bytes());
            plain.extend_from_slice(&control.base_tip());
            plain.extend_from_slice(&(part.len() as u32).to_be_bytes());
            for instance in part {
                plain.extend_from_slice(instance);
            }
            let sealed = seal_sym(
                Purpose::CustodyLogFrame,
                self.vault(),
                MINTED_KEY_ID,
                MINTED_RECIPIENT,
                &control.log_kek(),
                &plain,
            )?;
            replace_file(self.dir(), &format!("{MINTED}.{index}"), &sealed)?;
        }
        Ok(())
    }
}

/// A minted fold read back from its parts: where it stands, the base it
/// was folded from, and its instances.
struct MintedFold {
    seq: u64,
    tip: [u8; 32],
    base_seq: u64,
    base_tip: [u8; 32],
    minted: BTreeSet<[u8; 16]>,
}

/// A Mint frame's body instance into `minted`, as the fold reads it.
fn collect_minted(minted: &mut BTreeSet<[u8; 16]>, entry: &LogEntry) -> Result<()> {
    if let LogEntry::Mint(id) = entry
        && id.kind() == CustodyKind::BodyInstance
        && let Some(instance) = id.subject().item().get(..16)
    {
        minted.insert(instance.try_into().map_err(|_| log_corrupt())?);
    }
    Ok(())
}

impl LocalCustody<'_> {
    /// The latest history rows of this binding's lineage, at its local log's
    /// position: none before its first journaled act.
    pub(super) fn body_history(&self) -> Result<HistoryRows> {
        let journal = self.journal()?;
        let Some(control) = journal.control()? else {
            return Ok(BTreeMap::new());
        };
        journal.body_history(&control, &journal.position()?)
    }
}

impl KeyCustody {
    /// Journals `rows`, history rows a writer is about to commit, as one
    /// synced `BodyHistory` frame of this vault's lineage, before it commits.
    /// Nothing for no rows, for an archived vault (its custody is its
    /// replacement's) or before the vault's first publication (no instance
    /// a row could name exists).
    ///
    /// # Errors
    ///
    /// Custody errors, and a row that is not a history row's.
    pub(crate) fn journal_body_history(&self, rows: Vec<HistoryRow>) -> Result<()> {
        if rows.is_empty() || self.archived_at_open() {
            return Ok(());
        }
        if rows.iter().any(|(key, _)| !admits(key)) {
            return Err(crate::error::Error::InvariantViolation(
                "a body history row of another family",
            ));
        }
        let Some(custody) = self.local() else {
            return Ok(());
        };
        for part in rows.chunks(FOLD_PART_ROWS) {
            custody.journal_entry(&LogEntry::BodyHistory(part.to_vec()))?;
        }
        Ok(())
    }
}
