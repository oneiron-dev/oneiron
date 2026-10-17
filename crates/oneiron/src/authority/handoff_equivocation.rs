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
//! record. It is evidence for the owner, never a reason to admit. Records live
//! with the vault handle and go when it closes. Each retired key's first such
//! record also raises a saved alarm (key and refused row hash) that stays until
//! the vault's owner acknowledges it (OF-166); a row the owner has not seen
//! raises it again.

use std::collections::BTreeSet;
use std::sync::{Mutex, PoisonError};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
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

const ALARM_PREFIX: &[u8] = b"authority:handoff-alarm:v1:";

/// The saved fork alarm for one key a held handoff retired: the refused row
/// that raised it and the handoffs the key signed. It stays until the vault's
/// owner acknowledges it; a refused row the owner has not seen raises it again.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHandoffAlarm {
    /// The retired key, `suite:hex`.
    pub signer: String,
    /// The refused row's hash, hex.
    pub refused: String,
    /// The held handoffs the key signed, hex.
    pub handoffs: Vec<String>,
    pub raised_at: u64,
    pub acknowledged: Option<AuthorityHandoffAlarmAck>,
    /// Refused rows the owner has acknowledged.
    pub seen: BTreeSet<String>,
}

/// Who acknowledged an alarm, and when.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHandoffAlarmAck {
    pub by: String,
    pub at: u64,
}

fn signer_label(key: &AuthorityKey) -> String {
    let (suite, bytes) = match key {
        AuthorityKey::Ed25519(bytes) => ("ed25519", &bytes[..]),
        AuthorityKey::P256(bytes) => ("p256", &bytes[..]),
    };
    format!("{suite}:{}", crate::entity_id::bytes_to_hex_lower(bytes))
}
fn alarm_key(signer: &str) -> Vec<u8> {
    let mut key = ALARM_PREFIX.to_vec();
    key.extend_from_slice(signer.as_bytes());
    key
}
fn invalid_alarm() -> Error {
    Error::InvalidConfig("invalid authority handoff alarm".into())
}

/// Raises `evidence`'s alarm in `txn`, unless one stands unacknowledged or
/// the owner has already seen this refused row.
fn raise_alarm_in_txn(
    db: heed::Database<heed::types::Bytes, heed::types::Bytes>,
    txn: &mut heed::RwTxn<'_>,
    evidence: &AuthorityHandoffEquivocation,
    now: u64,
) -> Result<()> {
    let signer = signer_label(&evidence.signer);
    let key = alarm_key(&signer);
    let refused = crate::entity_id::bytes_to_hex_lower(&evidence.refused);
    let handoffs = evidence
        .handoffs
        .iter()
        .map(|hash| crate::entity_id::bytes_to_hex_lower(hash))
        .collect();
    let alarm = match db.get(txn, &key)? {
        Some(raw) => {
            let alarm: AuthorityHandoffAlarm =
                serde_json::from_slice(raw).map_err(|_| invalid_alarm())?;
            if alarm.acknowledged.is_none()
                || alarm.refused == refused
                || alarm.seen.contains(&refused)
            {
                return Ok(());
            }
            AuthorityHandoffAlarm {
                refused,
                handoffs,
                raised_at: now,
                acknowledged: None,
                ..alarm
            }
        }
        None => AuthorityHandoffAlarm {
            signer,
            refused,
            handoffs,
            raised_at: now,
            acknowledged: None,
            seen: BTreeSet::new(),
        },
    };
    let value = serde_json::to_vec(&alarm).map_err(|_| invalid_alarm())?;
    db.put(txn, &key, &value)?;
    Ok(())
}

/// Saves `evidence`'s alarm from its own writer. The refusal that found it
/// rolls its transaction back, so the alarm cannot ride that one; this
/// writer waits for it to end.
fn save_alarm_after_refusal(store: &Store, evidence: AuthorityHandoffEquivocation) {
    let env = (*store.env).clone();
    let now = store.clock.now_recorded_at();
    let spawned = std::thread::Builder::new()
        .name("handoff-alarm".into())
        .spawn(move || {
            let saved = env.write_txn().map_err(Error::from).and_then(|mut txn| {
                let db = env
                    .open_database::<heed::types::Bytes, heed::types::Bytes>(
                        &txn,
                        Some("vault_meta"),
                    )?
                    .ok_or(Error::CorruptedIndex("vault holds no side-table database"))?;
                raise_alarm_in_txn(db, &mut txn, &evidence, now)?;
                Ok(txn.commit()?)
            });
            if let Err(error) = saved {
                tracing::warn!(
                    kind = AuthorityHandoffEquivocation::KIND,
                    error = %error,
                    "handoff equivocation alarm not saved"
                );
            }
        });
    if let Err(error) = spawned {
        tracing::warn!(
            kind = AuthorityHandoffEquivocation::KIND,
            error = %error,
            "handoff equivocation alarm not saved"
        );
    }
}

/// The most records one vault handle keeps. The first ones carry the alarm;
/// later ones are counted as dropped.
pub(super) const RECORD_LIMIT: usize = 256;

#[derive(Default)]
struct Records {
    held: BTreeSet<AuthorityHandoffEquivocation>,
    /// New records refused past [`RECORD_LIMIT`].
    dropped: u64,
}

/// This vault handle's records, first come.
#[derive(Default)]
pub(crate) struct HandoffEquivocations(Mutex<Records>);

impl HandoffEquivocations {
    /// Keeps `evidence` once and logs it once, so a peer that replays one
    /// refused row cannot flood the log. Past the bound, only the first
    /// dropped record and each power of two log, with the count. It logs
    /// after the record is kept and the lock released, so a log consumer
    /// that reads the records sees this one and does not wait on the door.
    /// Returns whether it logged.
    pub(super) fn record(&self, evidence: AuthorityHandoffEquivocation) -> bool {
        let dropped = {
            let mut records = self.records();
            if records.held.contains(&evidence) {
                return false;
            }
            if records.held.len() < RECORD_LIMIT {
                records.held.insert(evidence.clone());
                None
            } else {
                records.dropped += 1;
                if !records.dropped.is_power_of_two() {
                    return false;
                }
                Some(records.dropped)
            }
        };
        match dropped {
            None => tracing::warn!(
                kind = AuthorityHandoffEquivocation::KIND,
                signer = ?evidence.signer,
                refused = %crate::entity_id::bytes_to_hex_lower(&evidence.refused),
                handoffs = ?evidence
                    .handoffs
                    .iter()
                    .map(|hash| crate::entity_id::bytes_to_hex_lower(hash))
                    .collect::<Vec<_>>(),
                "door refused a row signed by a key a held handoff retired"
            ),
            Some(dropped) => tracing::warn!(
                kind = AuthorityHandoffEquivocation::KIND,
                dropped,
                "handoff equivocation records past the bound were dropped"
            ),
        }
        true
    }

    /// Whether `evidence` is new and within the bound, so recording keeps it.
    fn would_keep(&self, evidence: &AuthorityHandoffEquivocation) -> bool {
        let records = self.records();
        !records.held.contains(evidence) && records.held.len() < RECORD_LIMIT
    }

    fn records(&self) -> std::sync::MutexGuard<'_, Records> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
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
        let evidence = AuthorityHandoffEquivocation {
            signer: signer.clone(),
            handoffs,
            refused: *hash,
        };
        if store.authority_handoff_equivocations.would_keep(&evidence) {
            save_alarm_after_refusal(store, evidence.clone());
        }
        store.authority_handoff_equivocations.record(evidence);
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
            .records()
            .held
            .iter()
            .cloned()
            .collect()
    }

    /// How many such records this handle dropped past its bound.
    #[must_use]
    pub fn authority_handoff_equivocations_dropped(&self) -> u64 {
        self.store.authority_handoff_equivocations.records().dropped
    }

    /// Every saved handoff alarm, acknowledged or not, by the time it was
    /// raised and then its signer: the one order the SDK read and the owner
    /// route both answer (OF-158).
    pub fn authority_handoff_alarms(&self) -> Result<Vec<AuthorityHandoffAlarm>> {
        let txn = self.store.env.read_txn()?;
        let mut alarms: Vec<AuthorityHandoffAlarm> = Vec::new();
        for row in self.store.vault_meta.prefix_iter(&txn, ALARM_PREFIX)? {
            let (_, raw) = row?;
            alarms.push(serde_json::from_slice(&raw).map_err(|_| invalid_alarm())?);
        }
        alarms.sort_by(|a, b| {
            a.raised_at
                .cmp(&b.raised_at)
                .then_with(|| a.signer.cmp(&b.signer))
        });
        Ok(alarms)
    }

    /// The vault's owner acknowledges `signer`'s alarm. It stays saved, its
    /// refused row marked seen, and only a row the owner has not seen raises
    /// it again.
    pub fn acknowledge_authority_handoff_alarm(
        &self,
        owner: &AuthenticatedOwner,
        signer: &str,
    ) -> Result<AuthorityHandoffAlarm> {
        let mut txn = self.store.env.write_txn()?;
        // Owner tier: only the vault's owner answers its fork alarm.
        let by = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let key = alarm_key(signer);
        let raw = self
            .store
            .vault_meta
            .get(&txn, &key)?
            .ok_or(Error::EntityNotFound)?;
        let mut alarm: AuthorityHandoffAlarm =
            serde_json::from_slice(&raw).map_err(|_| invalid_alarm())?;
        if alarm.acknowledged.is_none() {
            let at = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
            alarm.seen.insert(alarm.refused.clone());
            alarm.acknowledged = Some(AuthorityHandoffAlarmAck {
                by: by.to_hex(),
                at,
            });
            let value = serde_json::to_vec(&alarm).map_err(|_| invalid_alarm())?;
            self.store.vault_meta.put(&mut txn, &key, &value)?;
        }
        txn.commit()?;
        Ok(alarm)
    }
}
