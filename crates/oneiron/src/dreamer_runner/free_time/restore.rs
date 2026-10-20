//! FIX 6577: the `job_records` rows a restore over a live vault keeps as the
//! live vault holds them. A free-time item's binding is live across a restore
//! (its home-move carrier keeps the ITEM rows live, FIX 5661 C2b), so the
//! tries it binds follow it, a try the live vault no longer holds included:
//! a try only the image holds does not come back, and no queued state of the
//! image replaces a later terminal one here. Every other attempt stays
//! content, as the image holds it.
//!
//! A free-time try is the attempt an item binding is keyed by or names, or a
//! cycle's item names; a try queued under a cycle's own run, the exact run
//! its items queue under (`store::free_time_item_run_id`), never a guess at a
//! run's name; or a retry whose lineage, walked through `retry_of` as a
//! binding is looked up, reaches one of those. The live rows and the image's
//! name them alike. Only keys come back from here: nothing is queued. The
//! same keys carry each try's resident stamp and run-tree row, which go with
//! the try (`recovery::checkpoint::restore_class`).

use std::collections::{BTreeMap, BTreeSet};

use super::items::MAX_RETRY_DEPTH;
use super::{CYCLE, FreeTimeCycle, ITEM};
use crate::attempt_queue::{AttemptId, AttemptRecord, decode_record};
use crate::{Result, Vault};

/// One attempt row's run, and the try it retries.
type Link = (Option<String>, Option<[u8; 16]>);

/// What the free-time tries are found by, over the live vault and the image.
#[derive(Default)]
struct Found {
    /// The attempts an item binding or a cycle's item names.
    bound: BTreeSet<[u8; 16]>,
    /// The runs the cycles' items queue under.
    runs: BTreeSet<String>,
    /// Every attempt row by id, the live vault's read first.
    links: BTreeMap<[u8; 16], Link>,
}

impl Found {
    /// A cycle's items' attempts, and the run they queue under.
    fn cycle(&mut self, cycle: &FreeTimeCycle) {
        self.bound
            .extend(cycle.items.iter().filter_map(|item| item.attempt));
        self.runs
            .insert(crate::dreamer_runner::store::free_time_item_run_id(
                cycle.cycle,
            ));
    }

    /// One attempt row. The live vault's is read first and stands.
    fn attempt(&mut self, record: AttemptRecord) {
        self.links.entry(*record.id.as_bytes()).or_insert((
            record.run_id,
            record.retry_of.map(|previous| *previous.as_bytes()),
        ));
    }

    /// The free-time tries' keys: the bound attempts, every try of a cycle's
    /// run, and each retry of one of those.
    fn keys(self) -> BTreeSet<Vec<u8>> {
        let Self {
            mut bound,
            runs,
            links,
        } = self;
        bound.extend(
            links
                .iter()
                .filter(|(_, link)| link.0.as_ref().is_some_and(|run| runs.contains(run)))
                .map(|(id, _)| *id),
        );
        let retries: Vec<[u8; 16]> = links
            .keys()
            .copied()
            .filter(|id| retries_a_try(&links, &bound, *id))
            .collect();
        bound.extend(retries);
        bound.into_iter().map(|id| id.to_vec()).collect()
    }
}

/// Whether the lineage of the try `id`, walked through `retry_of` within the
/// bound a binding is looked up along, reaches one of `tries`. A chain past
/// the bound reaches none.
fn retries_a_try(
    links: &BTreeMap<[u8; 16], Link>,
    tries: &BTreeSet<[u8; 16]>,
    id: [u8; 16],
) -> bool {
    let mut cursor = id;
    for _ in 0..MAX_RETRY_DEPTH {
        if tries.contains(&cursor) {
            return true;
        }
        match links.get(&cursor).and_then(|link| link.1) {
            Some(previous) => cursor = previous,
            None => return false,
        }
    }
    false
}

/// The `job_records` keys a restore over `vault` keeps as `vault` holds them
/// (FIX 6577): every free-time try that `vault`, or `image`, the restore
/// image's rows by database, holds. A try only the image holds is named, so
/// its absence here wins.
///
/// # Errors
///
/// A live item binding, cycle or attempt row that does not read or decode.
/// An image row that does not decode names nothing.
pub(crate) fn free_time_attempt_restore_keys(
    vault: &Vault,
    image: &BTreeMap<String, Vec<(Vec<u8>, Vec<u8>)>>,
) -> Result<BTreeSet<Vec<u8>>> {
    let mut found = Found::default();
    let txn = vault.store.env.read_txn()?;
    for row in ITEM.iter_from(&vault.store, &txn, &[])? {
        let (attempt, binding) = row?;
        found.bound.insert(*attempt.as_bytes());
        found.bound.insert(binding.attempt);
    }
    for row in CYCLE.iter_from(&vault.store, &txn, &[])? {
        let (_, cycle) = row?;
        found.cycle(&cycle);
    }
    for row in vault.store.attempt_records.iter(&txn)? {
        let (key, raw) = row?;
        found.attempt(decode_record(&raw, AttemptId::from_bytes(&key)?)?);
    }
    let vault_meta = image.get("vault_meta").map_or(&[][..], Vec::as_slice);
    for (key, value) in vault_meta {
        if let Some(attempt) = key.strip_prefix(ITEM.decl().prefix) {
            if let Ok(attempt) = AttemptId::from_bytes(attempt) {
                found.bound.insert(*attempt.as_bytes());
            }
            if let Ok(binding) = ITEM.decode_value(value) {
                found.bound.insert(binding.attempt);
            }
        } else if key.starts_with(CYCLE.decl().prefix)
            && let Ok(cycle) = CYCLE.decode_value(value)
        {
            found.cycle(&cycle);
        }
    }
    let job_records = image.get("job_records").map_or(&[][..], Vec::as_slice);
    for (key, value) in job_records {
        if let Ok(record) = AttemptId::from_bytes(key).and_then(|id| decode_record(value, id)) {
            found.attempt(record);
        }
    }
    Ok(found.keys())
}
