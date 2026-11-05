//! Scan-crossing evidence and the store's waiting crossings.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

pub type CheckKey = ([u8; 1], Vec<u8>);

/// OF-520 question one engine scan raised for one scope, the first time it
/// read more rows than its threshold. Evidence for the host, never a
/// refusal: the scan read on and served.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanCheck {
    /// The scan ([`super::scan_kind::EngineScan::code`]).
    pub scan: String,
    /// The scope the scan read, in hex: a repository's or a record's id, a
    /// type byte, a window. `None` for a vault-wide scan.
    #[serde(alias = "repo_id")]
    pub scope: Option<String>,
    /// The threshold in force at the crossing.
    pub threshold: u64,
    /// Rows the scan read when it crossed it.
    pub rows: u64,
    /// Unix seconds of the crossing.
    pub raised_at: u64,
}

impl ScanCheck {
    /// Machine-readable check discriminator; presentation text belongs to hosts.
    pub const KIND: &'static str = "scan_size";
}

/// Crossings a store holds until a point no write is held keeps them: one
/// per scan and scope, the first.
#[derive(Default)]
pub struct PendingScanChecks(Mutex<BTreeMap<CheckKey, ScanCheck>>);

impl PendingScanChecks {
    pub fn park(&self, key: CheckKey, check: ScanCheck) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(key)
            .or_insert(check);
    }

    /// Whether a crossing waits to be kept (FIX 11664).
    pub fn any_waiting(&self) -> bool {
        !self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    pub fn waiting(&self) -> BTreeMap<CheckKey, ScanCheck> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn clear(&self, keys: &[CheckKey]) {
        let mut waiting = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for key in keys {
            waiting.remove(key);
        }
    }
}
