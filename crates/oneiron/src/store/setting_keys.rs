//! The store's catalogue keys (DESIGN 15-setting-primitive): the owner's retrieval-policy pins,
//! each engine scan's threshold on this machine, and the owner's wait for each queue of retained
//! peer work. The wait's readers are in
//! `sync::federation_burst`, which only some builds compile; the catalogue names every key in
//! every build, so its row is here.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::{ItemDomain, Kind, Restore, SettingChange, SettingSync, SettingValue};
use crate::store::{EngineScan, RetrievalPolicyPins};

/// The pins' hook: holds the served blend weights to the pins now in force, in the write that
/// changed them, as the pins' own door did.
fn hold_weights_to_pins(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    _change: &SettingChange,
) -> Result<()> {
    let pins = RETRIEVAL_POLICY_PINS
        .read_in_dbs_txn(&vault.store, txn, &[], None)?
        .value;
    vault.store.hold_weights_to_pins_in_txn(txn, &pins)?;
    Ok(())
}

crate::setting::setting_keys! {
    /// The owner's pins over the retrieval blend weights: a pinned signal's share stays at its
    /// value, and learned updates move only the unpinned remainder. A change holds the served
    /// weights to the new pins in its own write. The pins go with the weights they hold through
    /// a restore, so it gives back one weight state (FIX 22408).
    pub(crate) RETRIEVAL_POLICY_PINS: RetrievalPolicyPins = "retrieval.policy_pins" {
        kind: Kind::new(RetrievalPolicyPins::default),
        restore: Restore::Content,
        on_change: Some(hold_weights_to_pins),
    };
}

/// Seconds one queue's retained work waits for its turn before it expires. Never zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct RetainedWorkWaitSecs(pub(crate) u64);

impl SettingValue for RetainedWorkWaitSecs {
    fn check(self) -> Result<Self> {
        if self.0 == 0 {
            return Err(Error::InvalidConfig(
                "a retained work wait must be greater than zero".into(),
            ));
        }
        Ok(self)
    }
}

/// The queues of retained peer work, by their codes (`RetainedWorkQueue::code`).
const RETAINED_WORK_QUEUE: ItemDomain = ItemDomain {
    name: "retained work queue",
    admits: is_retained_work_queue,
};

fn is_retained_work_queue(item: &str) -> bool {
    matches!(
        item,
        "federation_burst" | "maintenance_ingest" | "facet_stamp"
    )
}

fn queue_default() -> Option<RetainedWorkWaitSecs> {
    None
}

crate::setting::setting_keys! {
    /// How long work one queue retains from peers waits for its turn before it expires, in
    /// seconds. With no row the queue's own default holds: 7 days for federation bursts and
    /// maintenance ingest, 30 days for facet stamps. A change holds for work that arrives after
    /// it.
    pub(crate) RETAINED_WORK_WAIT: Option<RetainedWorkWaitSecs> = "sync.retained_work.wait_secs" {
        kind: Kind::new(queue_default),
        item: Some(RETAINED_WORK_QUEUE),
    };
}

/// The engine scans whose threshold is a row of this key: every scan but the dependent walk,
/// whose threshold is part of its own policy (`Vault::set_dependent_walk_policy`).
const ENGINE_SCAN: ItemDomain = ItemDomain {
    name: "engine scan",
    admits: is_thresholded_scan,
};

fn is_thresholded_scan(item: &str) -> bool {
    EngineScan::ALL
        .iter()
        .any(|scan| *scan != EngineScan::DependentWalkRows && scan.code() == item)
}

fn scan_default() -> Option<u64> {
    None
}

crate::setting::setting_keys! {
    /// The rows one engine scan counts on this machine before it raises a check (OF-520). No
    /// value makes a scan refuse; with no row the scan's own default holds.
    pub(crate) SCAN_THRESHOLD: Option<u64> = "origin.scan_threshold" {
        kind: Kind::new(scan_default),
        item: Some(ENGINE_SCAN),
        sync: SettingSync::Install,
    };
}
