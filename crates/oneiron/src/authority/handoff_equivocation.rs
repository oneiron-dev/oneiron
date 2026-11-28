//! Evidence that a retired key signed beside the handoff that retired it: the
//! first record of OF-166, ahead of its fork alarm.
//!
//! No door admits a row that a key a handoff retired signs, so the first of
//! two sibling handoffs a vault settles keeps it: signatures alone cannot tell
//! the genuine one from a forgery. A replica that settled a forged handoff
//! first therefore refuses the real one, and this record is how it says so.
//! Each record names the key, the handoffs it signed that the vault held
//! before the write, and the refused row. Only a row of this vault
//! whose signatures verify is recorded, so no one without the key can plant a
//! record, and a peer replaying another vault's genuine rows, signed by a key
//! enrolled there too, plants none. It is evidence for the owner, never a
//! reason to admit. Records live with the vault handle and go when it closes.
//! Each retired key's first such record also raises a saved alarm (key and
//! refused row hash) that stays until the vault's owner acknowledges it
//! (OF-166); a row the owner has not seen raises it again.
//!
//! Such a key is one that a closed handoff or appointment fence holds
//! (`AuthorityFold::handoff_or_appointment_retired_keys`). A key that only a
//! revocation (`RevokeDevice`) retired is refused at the same doors and leaves
//! no record and no alarm: a revoked device that signs late is no sign of a
//! forked handoff.
//!
//! A refused row's signer is recorded only if a handoff or appointment
//! fence the vault held before the write holds it, or if it signed a handoff
//! the judging fold holds closed. That handoff may already be held, arrive
//! beside the refused row, or be the refused row itself. A key that only an
//! arriving fence holds and that signed no handoff leaves no record or
//! alarm until the fence lands and a door refuses its next late row. An
//! appointment has no such signer rule: its only signer is its anchor key,
//! and an anchor's rows stand on no roster key, so the door never judges them.
//! One root that signs two sibling handoffs is recorded when both arrive
//! together: a fork needs no earlier fence.

use std::collections::BTreeSet;
use std::sync::{Mutex, PoisonError};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::store::Store;

use super::log_structure::row_signatures_verified;
use super::retired_signers::row_signer_keys;
use super::*;

/// A key that a closed handoff or root appointment fence holds signed a row,
/// which a door refused. The vault held that fence before the refused write,
/// or the key signed a handoff the refusing door's fold held closed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorityHandoffEquivocation {
    /// The retired key that signed the refused row.
    pub signer: AuthorityKey,
    /// The handoffs `signer` also signed that the vault held before the write:
    /// none when a handoff fenced it as another key of its parents' roster.
    /// This never names the refused row itself.
    pub handoffs: BTreeSet<AuthorityEntryHash>,
    /// The refused row, a sibling handoff or any other row.
    pub refused: AuthorityEntryHash,
}

impl AuthorityHandoffEquivocation {
    /// Machine-readable record discriminator; presentation text belongs to hosts.
    pub const KIND: &'static str = "authority_handoff_equivocation";
}

const ALARM_PREFIX: &[u8] = b"authority:handoff-alarm:v1:";

#[doc(hidden)]
pub use oneiron_verb_wire::authority::handoff_equivocation::{
    AuthorityHandoffAlarm, AuthorityHandoffAlarmAck,
};

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

/// The stack of the thread that reads the committed state: a main thread's
/// default, so the fold runs there with no less stack than on its caller's.
const COMMITTED_READ_STACK_BYTES: usize = 8 << 20;

/// What this vault held before the write a refusing door is in.
#[derive(Default)]
struct HeldBeforeWrite {
    /// The keys its closed handoff and appointment fences held.
    fenced: BTreeSet<AuthorityKey>,
    /// The closed handoffs of the judging fold that it stored, or that the
    /// checkpoint image it had adopted covered.
    handoffs: BTreeSet<AuthorityEntryHash>,
}

/// Reads [`HeldBeforeWrite`] from the committed state, on a thread of its own.
/// A door runs inside its caller's transaction. Its fold may count rows the
/// write staged and a checkpoint image its prelude adopted. They all roll back
/// when the door refuses, and the committed read sees none of them. While a
/// writer is open, the committed state is the vault as it was before the write.
/// For a door in a read transaction, it is the vault as it stands, without
/// the rows the door is judging. A second read transaction on the door's own
/// thread fails with MDB_BAD_RSLOT, so the read runs on a separate thread.
/// If the committed fold lacks history it needs (OF-469), it names no fences.
/// If the thread fails to start, returns another error, or panics, the read
/// names neither fences nor handoffs. The refusal still stands.
fn held_before_write(
    store: &Store,
    posture: crate::HostingPrivacyPosture,
    closed_handoffs: &BTreeSet<AuthorityEntryHash>,
) -> HeldBeforeWrite {
    let held = std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("held-before-write".into())
            .stack_size(COMMITTED_READ_STACK_BYTES)
            .spawn_scoped(scope, || -> std::result::Result<HeldBeforeWrite, String> {
                let committed = store.env.read_txn().map_err(|error| error.to_string())?;
                let fenced = match super::readonly_fold::authority_view_readonly_for_store_in_txn(
                    store, posture, &committed,
                ) {
                    Ok(view) => view.handoff_or_appointment_retired_keys.clone(),
                    Err(error) if super::readonly_fold::is_history_incomplete(&error) => {
                        BTreeSet::new()
                    }
                    Err(error) => return Err(error.to_string()),
                };
                let evidence = super::adopted_evidence::adopted_evidence_in_txn(store, &committed)
                    .map_err(|error| error.to_string())?;
                let mut handoffs = BTreeSet::new();
                for hash in closed_handoffs {
                    if super::retired_signers::authority_row_held(
                        store,
                        &committed,
                        evidence.as_deref(),
                        hash,
                    )
                    .map_err(|error| error.to_string())?
                    {
                        handoffs.insert(*hash);
                    }
                }
                Ok(HeldBeforeWrite { fenced, handoffs })
            })
            .map_err(|error| error.to_string())?
            .join()
            .map_err(|_| "committed reader panicked".to_owned())?
    });
    match held {
        Ok(held) => held,
        Err(error) => {
            tracing::warn!(
                kind = AuthorityHandoffEquivocation::KIND,
                error = %error,
                "could not read the vault before the write; the refusal records only a signer of a closed handoff"
            );
            HeldBeforeWrite::default()
        }
    }
}

/// Whether a door refuses `entry` because it stands on a retired key (see
/// [`AuthorityFold::stands_on_retired_key`]). A refused row of `fold`'s own
/// vault that a key a closed handoff or appointment fence holds signed, with
/// signatures that verify, can leave a record before the door refuses. A
/// signer that only a revocation retired is
/// refused the same way and recorded nowhere: its late row is no evidence of
/// a forked handoff. A row of another vault is refused the same way and
/// recorded nowhere: a key also enrolled in a second vault signs that vault's
/// rows rightly, so they are no evidence of a fork here. Doors that compare
/// the vault first never reach that case; the append door does, and so does
/// any door added later. `row` reads a row by hash, stored or arriving beside
/// it. The door reads what the vault held before the write from its committed
/// state under `posture`. It records a fenced signer only if a handoff or
/// appointment fence held it before the write or it signed a handoff `fold`
/// holds closed. The record names only handoffs the signer signed and the
/// vault held before the write, never the refused row itself.
pub(crate) fn door_refuses_retired_standing(
    store: &Store,
    posture: crate::HostingPrivacyPosture,
    fold: &AuthorityFold,
    hash: &AuthorityEntryHash,
    entry: &FoldRow,
    row: &mut dyn FnMut(&AuthorityEntryHash) -> Result<Option<FoldRow>>,
) -> Result<bool> {
    if !fold.stands_on_retired_key(hash, entry, row)? {
        return Ok(false);
    }
    if entry
        .open()
        .is_some_and(|entry| entry.validate_shape().is_err())
        || !row_signatures_verified(entry)
        || !of_fold_vault(fold, entry)?
    {
        return Ok(true);
    }
    let fenced_signers: Vec<_> = row_signer_keys(entry)
        .filter(|key| fold.handoff_or_appointment_retired_keys.contains(*key))
        .collect();
    if fenced_signers.is_empty() {
        return Ok(true);
    }
    let before = held_before_write(store, posture, &fold.closed_handoffs);
    for signer in fenced_signers {
        // A door whose fold already counts the arriving rows (a batch's or an
        // import's preflight) holds each as a closed handoff in conflict with
        // the real one. A record names only handoffs this vault held before
        // the write, never the refused row or a sibling the refused write brings.
        let mut handoffs = BTreeSet::new();
        let mut signed_handoff = false;
        for candidate in &fold.closed_handoffs {
            if candidate == hash {
                signed_handoff = true;
                continue;
            }
            // A closed handoff the door cannot read is no evidence, and its
            // read error never replaces the refusal: the replicated door's
            // fold counts rows beside the judged one that its `row` does not
            // read, and on an adopted vault that read answers a history error.
            if row(candidate).is_ok_and(|read| {
                read.is_some_and(|handoff| row_signer_keys(&handoff).any(|key| key == signer))
            }) {
                signed_handoff = true;
                if before.handoffs.contains(candidate) {
                    handoffs.insert(*candidate);
                }
            }
        }
        let held_fence = before.fenced.contains(signer);
        if !held_fence && !signed_handoff {
            continue;
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

/// Whether `row` belongs to the vault `fold` folds: a genesis founds the
/// vault its own hash names, and every other row names its vault. A sealed
/// row whose record does not open here reads both from its envelope. A fold
/// with no settled root holds no vault to match.
fn of_fold_vault(fold: &AuthorityFold, row: &FoldRow) -> Result<bool> {
    let vault_id = match row {
        FoldRow::Open(entry) if matches!(entry.op, AuthorityOp::Genesis { .. }) => {
            Some(genesis_vault_id(entry)?)
        }
        FoldRow::PassThrough(public)
            if matches!(public.standing(), PublicStanding::Genesis { .. }) =>
        {
            if row.vault_id().is_some() {
                return Err(invalid_authority());
            }
            Some(row.hash()?)
        }
        _ => row.vault_id(),
    };
    Ok(fold.vault_id.is_some() && vault_id == fold.vault_id)
}

impl Vault {
    /// Evidence of retired-key signatures a door recorded since this handle
    /// opened (OF-166). A key that only a revocation retired leaves none.
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
