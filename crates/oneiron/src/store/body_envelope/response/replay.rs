//! A replay row's and a step start's parts as row-held responses (FIX 9180,
//! coord-b slice d; L04 option (b)).
//!
//! A decoded replay row whose spawns reached resolved targets travels as
//! parts (`crate::code_run::replay_row_parts`): its reply, and each such
//! spawn's ask. A step start whose prefix holds such a spawn travels the
//! same way: its rest, and each ask. Each part is a response of its own,
//! bound in [`super::RESPONSE_BINDINGS`] under a carrier, an instance and
//! obligations of its own: the reply's or rest's owed to the owners the
//! whole row's are, each ask's to every seat its call's host resolved.
//! The carrier is no row's: a tag no [`ResponseDb`] has, which part it is
//! (the rest, or one call's ask by its place and seq), then the raw
//! `vault_meta` key of the row it recomposes into, a replay row's or a
//! capsule's. [`super::carrier_row`] finds no row in it, so each path that
//! binds, releases, retires or activates a part dispatches on the tag
//! first.
//!
//! An activation applies what its source retired of each row's or start's
//! parts once per destination ([`ReplayPrune`]): read before its prune
//! takes a start's rows, applied after it.

use std::collections::BTreeMap;

use heed::{RoTxn, RwTxn};

use super::{ResponseDb, ResponseFamily, carrier_row};
use crate::error::Result;
use crate::side_table::{self, SideTableDbs};
use crate::store::Store;

/// The first byte of a Replay part's carrier, which no [`ResponseDb`] tag
/// is.
const REPLAY_PART_TAG: u8 = 0x10;

/// The part byte of a destination's rest.
const REST_PART: u8 = 0;

/// The part byte of one call's ask.
const REQUEST_PART: u8 = 1;

impl ResponseFamily {
    /// FIX 9180: the carrier of a Replay part of the row `row`, a raw
    /// `vault_meta` key (a replay row's or a capsule's): its rest for
    /// `None`, else the ask of the call at `request`, by its place among
    /// the record's calls and its seq.
    pub(crate) fn replay_part_carrier(row: &[u8], request: Option<(u32, u64)>) -> Vec<u8> {
        let mut carrier = Vec::with_capacity(row.len() + 14);
        carrier.push(REPLAY_PART_TAG);
        match request {
            None => carrier.push(REST_PART),
            Some((index, seq)) => {
                carrier.push(REQUEST_PART);
                carrier.extend_from_slice(&index.to_be_bytes());
                carrier.extend_from_slice(&seq.to_be_bytes());
            }
        }
        carrier.extend_from_slice(row);
        carrier
    }

    /// FIX 9180: the row and the part a Replay part's carrier names; `None`
    /// for any other carrier.
    pub(crate) fn replay_part_of(carrier: &[u8]) -> Option<(&[u8], Option<(u32, u64)>)> {
        let (&tag, rest) = carrier.split_first()?;
        if tag != REPLAY_PART_TAG {
            return None;
        }
        let (&part, rest) = rest.split_first()?;
        match part {
            REST_PART => Some((rest, None)),
            REQUEST_PART => {
                let (index, rest) = rest.split_first_chunk::<4>()?;
                let (seq, row) = rest.split_first_chunk::<8>()?;
                Some((
                    row,
                    Some((u32::from_be_bytes(*index), u64::from_be_bytes(*seq))),
                ))
            }
            _ => None,
        }
    }

    /// FIX 9180: what an activation's source retired of each replay row's
    /// and step start's parts, among `responses` (each carrier the prune
    /// took, with the instance it was bound to), grouped by the row they
    /// recompose into and read in `txn` before the prune takes a start's
    /// rows: each row with its reply's erased disposition when its reply or
    /// its whole row's response retired, then each retired ask's call in
    /// its erased form; each start without the asks that retired, or
    /// released whole when its rest did.
    ///
    /// # Errors
    ///
    /// Storage and custody errors, and a row that does not encode again.
    pub(crate) fn replay_prune_in_txn(
        store: &Store,
        txn: &RoTxn<'_>,
        responses: &BTreeMap<Vec<u8>, [u8; 16]>,
    ) -> Result<ReplayPrune> {
        let mut groups: BTreeMap<Vec<u8>, (bool, Vec<(u32, u64)>)> = BTreeMap::new();
        for carrier in responses.keys() {
            if let Some((row, request)) = Self::replay_part_of(carrier) {
                let group = groups.entry(row.to_vec()).or_default();
                match request {
                    None => group.0 = true,
                    Some(call) => group.1.push(call),
                }
            }
        }
        let mut prune = ReplayPrune::default();
        if groups.is_empty() {
            return Ok(prune);
        }
        // A whole row's response retired beside its parts retires its reply.
        for carrier in responses.keys() {
            if let Some((ResponseDb::VaultMeta, key)) = carrier_row(carrier)
                && let Some(group) = groups.get_mut(key)
            {
                group.0 = true;
            }
        }
        for (row, (rest, requests)) in groups {
            if row.starts_with(side_table::CODE_RUN_REPLAY.prefix) {
                let Some(value) = store.side_vault_meta().get(txn, &row)? else {
                    continue;
                };
                if let Some(value) =
                    crate::code_run::retire_replay_row_parts(&value, rest, &requests)?
                {
                    prune.rows.push((row, value));
                }
            } else if !crate::code_run::step_capsule_row(&row) {
                continue;
            } else if rest {
                prune.starts.push((row, None));
            } else if let Some(kept) = crate::code_run::kept_step_start_in_txn(store, txn, &row)?
                && let Some(bytes) =
                    crate::code_run::retire_step_start_parts(&kept.bytes, &requests)?
            {
                prune.starts.push((row, Some(bytes)));
            }
        }
        Ok(prune)
    }
}

/// What an activation's source retired of the replay rows' and step
/// starts' parts (FIX 9180), each destination once.
#[derive(Default)]
pub(crate) struct ReplayPrune {
    /// Each replay row's key, and the row its retired parts leave.
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    /// Each capsule's key, and the start body its retired asks leave;
    /// `None` when its rest retired.
    starts: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}

impl ReplayPrune {
    /// Applies the prune in the activation's writer, after its generic
    /// prune: each row takes what its parts left, each start is
    /// republished without its retired asks, or released.
    ///
    /// # Errors
    ///
    /// Storage and custody errors.
    pub(crate) fn apply_in_txn(self, store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
        for (row, value) in &self.rows {
            store.side_vault_meta().put(wtxn, row, value)?;
        }
        for (row, bytes) in &self.starts {
            match bytes {
                Some(bytes) => {
                    crate::code_run::republish_step_start_in_txn(store, wtxn, row, bytes)?
                }
                None => crate::code_run::release_step_start_in_txn(store, wtxn, row)?,
            }
        }
        Ok(())
    }
}
