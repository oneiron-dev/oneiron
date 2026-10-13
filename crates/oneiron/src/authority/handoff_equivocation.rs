//! Evidence that a retired key signed beside the handoff that retired it: the
//! first record of OF-166, ahead of its fork alarm.
//!
//! No door admits a row that a key a handoff retired signs, so the first of
//! two sibling handoffs a vault settles keeps it: signatures alone cannot tell
//! the genuine one from a forgery. A replica that settled a forged handoff
//! first therefore refuses the real one, and this record is how it says so.
//! Each refusal of a row signed by such a key names the key, the handoffs this
//! vault holds that it signed, and the refused row. Only a row whose
//! signatures verify is recorded, so no one without the key can plant a
//! record. It is evidence for the owner, never a reason to admit. Records live with the vault handle and go
//! when it closes; the persisted alarm the owner acknowledges is OF-166.

use std::collections::BTreeSet;
use std::sync::{Mutex, PoisonError};

use crate::Vault;
use crate::error::Result;
use crate::store::Store;

use super::retired_signers::entry_signer_keys;
use super::*;

/// A key that a handoff this vault holds retired signed another row, which a
/// door refused.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorityHandoffEquivocation {
    /// The retired key that signed the refused row.
    pub signer: AuthorityKey,
    /// The handoffs this vault holds that `signer` also signed: none when a
    /// handoff fenced it as another key of its parents' roster.
    pub handoffs: BTreeSet<AuthorityEntryHash>,
    /// The refused row, a sibling handoff or any other row.
    pub refused: AuthorityEntryHash,
}

impl AuthorityHandoffEquivocation {
    /// Machine-readable record discriminator; presentation text belongs to hosts.
    pub const KIND: &'static str = "authority_handoff_equivocation";
}

/// The most records one vault handle keeps. The first ones carry the alarm;
/// later refusals are still logged.
const RECORD_LIMIT: usize = 256;

/// This vault handle's records, first come.
#[derive(Default)]
pub(crate) struct HandoffEquivocations(Mutex<BTreeSet<AuthorityHandoffEquivocation>>);

impl HandoffEquivocations {
    fn record(&self, evidence: AuthorityHandoffEquivocation) {
        tracing::warn!(
            kind = AuthorityHandoffEquivocation::KIND,
            signer = ?evidence.signer,
            refused = %crate::entity_id::bytes_to_hex_lower(&evidence.refused),
            handoffs = ?evidence
                .handoffs
                .iter()
                .map(|hash| crate::entity_id::bytes_to_hex_lower(hash))
                .collect::<Vec<_>>(),
            "door refused a row signed by a key a held handoff retired"
        );
        let mut records = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if records.len() < RECORD_LIMIT {
            records.insert(evidence);
        }
    }
}

/// Whether a door refuses `entry` because it stands on a retired key (see
/// [`AuthorityFold::stands_on_retired_key`]). A refused row that a retired
/// key signed, with signatures that verify, is recorded first, with the
/// handoffs `fold` holds that the same key signed. `row` reads a row by hash,
/// stored or arriving beside it.
pub(crate) fn door_refuses_retired_standing(
    store: &Store,
    fold: &AuthorityFold,
    hash: &AuthorityEntryHash,
    entry: &AuthorityLogEntry,
    row: &mut dyn FnMut(&AuthorityEntryHash) -> Result<Option<AuthorityLogEntry>>,
) -> Result<bool> {
    if !fold.stands_on_retired_key(hash, entry, row)? {
        return Ok(false);
    }
    if entry.validate_shape().is_err() || verify_entry_signatures(entry).is_err() {
        return Ok(true);
    }
    for signer in entry_signer_keys(entry).filter(|key| fold.retired_keys.contains(*key)) {
        let mut handoffs = BTreeSet::new();
        for held in &fold.closed_handoffs {
            if row(held)?
                .is_some_and(|handoff| entry_signer_keys(&handoff).any(|key| key == signer))
            {
                handoffs.insert(*held);
            }
        }
        store
            .authority_handoff_equivocations
            .record(AuthorityHandoffEquivocation {
                signer: signer.clone(),
                handoffs,
                refused: *hash,
            });
    }
    Ok(true)
}

impl Vault {
    /// The rows a door refused since this handle opened because a key a held
    /// handoff retired signed them (OF-166 evidence).
    #[must_use]
    pub fn authority_handoff_equivocations(&self) -> Vec<AuthorityHandoffEquivocation> {
        self.store
            .authority_handoff_equivocations
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }
}
