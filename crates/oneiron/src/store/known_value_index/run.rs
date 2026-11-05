//! Run-local PERSON prints alongside the custody matcher (FIX 4974).

use std::sync::{Arc, Weak};

use heed::RwTxn;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{Keys, KnownSource, KnownValues, MatchedSpan, ValueOrigin, replace_spans};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::overlay_db::OverlayDb;
use crate::store::known_history::master_in_snapshot;
use crate::store::{KnownEntry, Store, StoreCore};
use crate::vault::Vault;

/// The value-free keyed print kept by an actual PERSON delivery, not a
/// global custody holder. Its key remains in native custody.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct PersonValuePrint {
    len: u32,
    tag: [u8; super::TAG_BYTES],
    rolling: u16,
    fingerprint: [u8; 32],
}

impl std::fmt::Debug for PersonValuePrint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PersonValuePrint(..)")
    }
}

impl PersonValuePrint {
    pub(crate) fn delivered_in_txn(
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        value: &[u8],
    ) -> Result<Option<Self>> {
        if value.len() < super::KNOWN_VALUE_MIN_BYTES {
            return Ok(None);
        }
        let len = u32::try_from(value.len())
            .map_err(|_| Error::ArithmeticOverflow("known value length"))?;
        let master = store.known_master_or_mint_in_txn(wtxn)?;
        let entry = Keys::derive(&master).entry(value, len);
        Ok(Some(Self {
            len: entry.len,
            tag: entry.tag,
            rolling: entry.rolling,
            fingerprint: entry.fingerprint,
        }))
    }

    fn entry(&self) -> KnownEntry {
        KnownEntry {
            len: self.len,
            tag: self.tag,
            rolling: self.rolling,
            fingerprint: self.fingerprint,
        }
    }
}

/// Always present for a bound run, even before its first PERSON delivery.
/// It holds no store open and keeps neither prints nor the master between passes.
pub(crate) struct RunKnownSource {
    core: Weak<StoreCore>,
    exec_run: EntityId,
    custody: Option<KnownSource>,
}

impl Vault {
    pub(crate) fn run_known_source(&self, exec_run: EntityId) -> Result<RunKnownSource> {
        Ok(RunKnownSource {
            core: Arc::downgrade(&self.store.core),
            exec_run,
            custody: self.known_source()?,
        })
    }
}

impl RunKnownSource {
    pub(super) fn pass<T>(
        &self,
        use_pass: impl FnOnce(Option<&KnownValues>, Option<&KnownValues>) -> T,
    ) -> Result<T> {
        let core = self.core.upgrade().ok_or(Error::InvariantViolation(
            "a known-value sweep outlived its vault",
        ))?;
        let _guard = core.key_custody.read_guard()?;
        let txn = core.env.read_txn()?;
        let vault_meta = OverlayDb::canonical(core.raw.vault_meta);
        let history = self
            .custody
            .as_ref()
            .map(|source| source.ids.read_in_snapshot(&txn, &vault_meta))
            .transpose()?;
        let custody = match (&self.custody, &history) {
            (Some(source), Some(history)) => KnownValues::of(history, |id| Ok(source.handle(id)))?,
            _ => None,
        };
        let prints =
            crate::secret_custody::run_person_prints_in_txn(&vault_meta, &txn, self.exec_run)?;
        let entries: Vec<_> = prints
            .iter()
            .map(|(handle, print)| (handle, print.entry()))
            .collect();
        let person = if entries.is_empty() {
            None
        } else {
            let current_master;
            let master = match &history {
                Some(history) => &history.master,
                None => {
                    let binding = core.key_custody.bind_in_txn(&vault_meta, &txn)?;
                    current_master = master_in_snapshot(&vault_meta, &txn, binding)?.ok_or(
                        Error::InvariantViolation(
                            "a delivered PERSON print has no known-value master",
                        ),
                    )?;
                    &current_master
                }
            };
            KnownValues::of_entries(
                master,
                entries
                    .iter()
                    .map(|(handle, entry)| (entry, ValueOrigin::Person, (*handle).clone())),
            )?
        };
        // Matchers, entries and prints drop before the snapshot and guard.
        Ok(use_pass(custody.as_ref(), person.as_ref()))
    }
}

pub(super) fn replaced_until(
    custody: Option<&KnownValues>,
    person: Option<&KnownValues>,
    data: &[u8],
    limit: usize,
) -> (Vec<u8>, usize) {
    let Some(person) = person else {
        return match custody {
            Some(known) => known.replaced_until(data, limit),
            None => (data[..limit].to_vec(), limit),
        };
    };
    // Compute custody's original hit set independently: a longer PERSON
    // match must not hide a custody match before overlap precedence runs.
    let mut spans = custody
        .map(|known| known.matched_spans_except(data, |_| false))
        .unwrap_or_default();
    let mut persons = person.matched_spans_except(data, |_| false);
    persons.retain(|hit| {
        !spans
            .iter()
            .any(|custody| hit.span.start < custody.span.end && custody.span.start < hit.span.end)
    });
    spans.extend(persons);
    spans.sort_by_key(|hit: &MatchedSpan<'_>| hit.span.start);
    replace_spans(data, limit, spans)
}
