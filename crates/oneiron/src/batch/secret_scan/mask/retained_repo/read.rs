//! The masked copy a reader gets of a marked retained repository blob (FIX
//! 7608 slice 2a). A read never plans, places or mints: the places come
//! from the blob's marks, the copy is rebuilt under the retained repository
//! read (no member, object, depth or byte bound, rule 5), and the rebuilt
//! copy is read again by the same release rules and custody automaton the
//! receive door's plan used. A copy that cannot be rebuilt, or that still
//! reads as secret, is no copy: the reader gets the opaque placeholder,
//! never these bytes and never a terminal refusal.
//!
//! A value custody came to know after the blob was stored is masked at the
//! read too (FIX 8966): the read checks the blob, its own bytes and every
//! member, against the values custody knows now, with the leaf selection
//! the lift sweep uses, and the rebuilt copy is checked against them again,
//! each raw container buffer included. A value no place can cover (a ZIP
//! entry's name) leaves the blob opaque. Nothing is written: a Git-only
//! blob the sweep never walks reads masked all the same.

use heed::RoTxn;
use zeroize::Zeroizing;

use super::super::super::container::{
    Stop, masked_retained_repo_copy, walk_retained_repo_members,
    walk_retained_repo_members_with_hidden,
};
use super::super::super::lift_history::{LiftFamily, owner_kept_in_txn};
use super::super::known_marks::known_leaf_hits;
use super::super::offset;
use super::validate_retained_repo_copy;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::file_secret_marks::{KeyPlaces, MemberStep};
use crate::secret_custody::KeptValues;
use crate::store::known_value_index::KnownValues;

/// What a masked repo read checks one blob against beside its marks (FIX
/// 8966): the values custody knows now, past what the owner ruled in the
/// blob's own snapshot record, as the lift sweep reads that record. A
/// record the owner kept whole is checked against none.
pub(crate) struct RepoKnownCheck<'a> {
    known: &'a KnownValues,
    record: EntityId,
    kept: KeptValues,
    owner_kept: bool,
}

impl<'a> RepoKnownCheck<'a> {
    /// The check of the blob whose bytes hash to `hash`, against `known`, in
    /// `txn`: its record is the snapshot ASSET its BLAKE3 names, held or not.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn for_blob_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        known: &'a KnownValues,
        hash: &[u8; 32],
    ) -> Result<Self> {
        let record = crate::codebase::snapshot_asset_entity_id(hash)?;
        let owner_kept = owner_kept_in_txn(vault, txn, LiftFamily::Records, record.as_bytes())?;
        let kept = if owner_kept {
            KeptValues::default()
        } else {
            KeptValues::for_records_in_txn(&vault.store, txn, [record])?
        };
        Ok(Self {
            known,
            record,
            kept,
            owner_kept,
        })
    }

    fn keep(&self, value: &[u8]) -> bool {
        self.kept.holds(&self.record, value)
    }

    /// Each place a known value takes in `bytes`, its own and each member's,
    /// read the retained repository way, as far as the walk reads.
    fn places(&self, bytes: &[u8]) -> Result<Vec<(Vec<MemberStep>, (u64, u64))>> {
        if self.owner_kept {
            return Ok(Vec::new());
        }
        let keep = |value: &[u8]| self.keep(value);
        let mut found = Vec::new();
        let mut read_leaf = |path: &[MemberStep], leaf: &[u8]| -> Result<()> {
            for hit in known_leaf_hits(path, leaf, self.known, &keep) {
                found.push((hit.path, (offset(hit.span.start)?, offset(hit.span.end)?)));
            }
            Ok(())
        };
        read_leaf(&[], bytes)?;
        let mut visit = |path: &[MemberStep], member: &[u8]| -> std::result::Result<(), Stop> {
            read_leaf(path, member).map_err(Stop::Fail)
        };
        // A container no reader here reads is checked as far as it reads,
        // as the sweep marks it: its sealed bytes show a reader nothing more.
        match walk_retained_repo_members(bytes, &mut visit) {
            Ok(()) | Err(Stop::Refuse(_)) => Ok(found),
            Err(Stop::Fail(error)) => Err(error),
        }
    }

    /// Whether a known value reads anywhere in `bytes`: its own bytes, every
    /// member, each raw container buffer, and the bytes no reader shows
    /// beside a container's members (a ZIP's local entries outside its
    /// central directory, a PDF's superseded revisions), each decoded as a
    /// scan reads them. A value there, or in a container's own bytes such as
    /// a ZIP entry's name, takes no place a copy can overwrite, so a blob it
    /// reads in has no masked copy (FIX 8966).
    ///
    /// # Errors
    /// A walk failure.
    pub(crate) fn reads_known(&self, bytes: &[u8]) -> Result<bool> {
        if self.owner_kept {
            return Ok(false);
        }
        let keep = |value: &[u8]| self.keep(value);
        if !self.known.spans_except(bytes, keep).is_empty() {
            return Ok(true);
        }
        let mut hit = false;
        let mut visit = |_: &[MemberStep], member: &[u8]| -> std::result::Result<(), Stop> {
            if self.known.spans_except(member, keep).is_empty() {
                return Ok(());
            }
            hit = true;
            Err(Stop::Refuse("known value"))
        };
        // A container no reader here reads shows a reader nothing more.
        match walk_retained_repo_members_with_hidden(bytes, &mut visit) {
            Ok(()) | Err(Stop::Refuse(_)) => Ok(hit),
            Err(Stop::Fail(error)) => Err(error),
        }
    }
}

/// `places`, a blob's marked places, with each place a value `check` knows
/// takes in `bytes` that they do not cover whole (FIX 8966). A known span
/// that overlaps a marked one joins it, so the copy overwrites both.
///
/// # Errors
/// A store failure while the check reads the blob.
pub(crate) fn retained_repo_known_places(
    bytes: &[u8],
    check: &RepoKnownCheck<'_>,
    places: &KeyPlaces,
) -> Result<KeyPlaces> {
    let mut joined = places.clone();
    for (path, span) in check.places(bytes)? {
        join_place(&mut joined, &path, span);
    }
    Ok(joined)
}

/// `span` placed at `member`: nothing when a span there already covers it
/// whole, else one span over it and every span it overlaps.
fn join_place(places: &mut KeyPlaces, member: &[MemberStep], span: (u64, u64)) {
    let at = match places
        .iter()
        .position(|(path, _)| path.as_slice() == member)
    {
        Some(at) => at,
        None => {
            places.push((member.to_vec(), Vec::new()));
            places.len() - 1
        }
    };
    let spans = &mut places[at].1;
    let (mut from, mut to) = span;
    if spans.iter().any(|&(start, end)| start <= from && to <= end) {
        return;
    }
    while let Some(index) = spans
        .iter()
        .position(|&(start, end)| start < to && from < end)
    {
        let (start, end) = spans.remove(index);
        from = from.min(start);
        to = to.max(end);
    }
    let index = spans.partition_point(|&(start, _)| start < from);
    spans.insert(index, (from, to));
}

/// `bytes` with every span `places` names overwritten, members rebuilt and
/// re-encoded, once the copy reads clean: by the release rules and the
/// custody automaton, and, with `check`, by the values custody knows now
/// (FIX 8966). `None` when no such copy stands.
pub(crate) fn project_marked_retained_repo_blob(
    bytes: &[u8],
    places: &KeyPlaces,
    check: Option<&RepoKnownCheck<'_>>,
) -> Option<Vec<u8>> {
    if places.is_empty() {
        return None;
    }
    let mut copy = match masked_retained_repo_copy(bytes, places) {
        Ok(copy) => Zeroizing::new(copy),
        Err(Stop::Refuse(_) | Stop::Fail(_)) => return None,
    };
    match validate_retained_repo_copy(&copy) {
        Ok(None) => {}
        Ok(Some(_)) | Err(_) => return None,
    }
    if let Some(check) = check {
        match check.reads_known(&copy) {
            Ok(false) => {}
            Ok(true) | Err(_) => return None,
        }
    }
    Some(std::mem::take(&mut *copy))
}
