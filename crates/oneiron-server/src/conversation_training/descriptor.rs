//! The intake's public descriptor on a self-hosted vault (TL-6): the
//! intake's sealing key and receipt keys, fetched from
//! `GET <origin>/feedback/training/v1/keys` and installed as the outbox's
//! two key files, the very files the offer gate and the receipt pass read.
//! A managed vault's supervisor pushes those files itself, and nothing here
//! runs there.
//!
//! It runs on plain serve with `--publisher-training-self-host-shipper`
//! only (CALLS TL6_DESCRIPTOR_PACE): at start, then every hour, and at the
//! next outbox tick after a [`Descriptor::refresh`], each at the earliest
//! the retry pace allows (`retry`). Trust is HTTPS to the intake's origin;
//! v1 adds no signing root (CALLS TL6_DESCRIPTOR_TRUST).
//!
//! A fetched descriptor is checked whole before anything is written: its
//! recipient is the 1,600 bytes of a hybrid public key whose BLAKE3 is its
//! `recipient_blake3`, and each of its one or two receipt keys is the 32
//! bytes of an Ed25519 public key. Then, under the outbox's lock, the
//! receipt key ring is written first and the recipient second, each whole,
//! and a file that already holds its bytes is left as it is. A fetch, a
//! check or a write that fails keeps the last installed pair: nothing here
//! deletes it or lets it expire on a timer, and the next attempt waits the
//! retry pace.
//!
//! The pair has no commit record (CALLS TL6_DESCRIPTOR_COMMIT). A crash
//! between the two writes leaves the new ring beside the previous
//! recipient, and the next fetch, the one the restart makes, writes the
//! recipient too.
//!
//! Logs name a failure's class, a status and counts only: never a key byte,
//! a body or a URL.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oneiron::feedback::{IntakeReceiptKey, IntakeRecipient};
use oneiron_vault_contract::conversation_training::{PIECE_KEYS_PATH, decode_training_keys};

use super::http::Intake;
use super::outbox::Outbox;
use super::retry::{Failure, Retry};

/// How often the descriptor is fetched while every fetch succeeds.
const PACE: Duration = Duration::from_secs(60 * 60);
/// The length of the intake's recipient: a hybrid (X25519 + ML-KEM-1024)
/// public key.
const RECIPIENT_BYTES: usize = 1_600;
/// The length of one receipt key: an Ed25519 public key.
const RECEIPT_KEY_BYTES: usize = 32;

/// The self-host shipper's view of the intake's descriptor.
pub(super) struct Descriptor {
    /// The intake it is fetched from.
    intake: Arc<Intake>,
    /// When it is next fetched.
    schedule: Mutex<Schedule>,
}

/// When the descriptor is next fetched.
struct Schedule {
    /// When the pace next fetches it; `None` while no fetch is due until a
    /// refresh.
    due: Option<Instant>,
    /// The retry pace after a failed fetch.
    retry: Retry,
}

/// The two key files a checked descriptor installs.
struct Keys {
    /// The receipt key ring: the current key, then the previous one.
    ring: Vec<u8>,
    /// The recipient.
    recipient: Vec<u8>,
    /// How many receipt keys the ring holds.
    receipt_keys: usize,
}

impl Descriptor {
    /// The descriptor of `intake`, due at once: the start's fetch is its
    /// first refresh.
    pub(super) fn new(intake: Arc<Intake>) -> Self {
        let descriptor = Self {
            intake,
            schedule: Mutex::new(Schedule {
                due: None,
                retry: Retry::default(),
            }),
        };
        descriptor.refresh();
        descriptor
    }

    /// Fetches the descriptor again at the next outbox tick, at the earliest
    /// the retry pace allows: what the shipper asks once the intake answers
    /// `recipient_refresh_required`. It never shortens a retry's wait.
    pub(super) fn refresh(&self) {
        let now = Instant::now();
        let mut schedule = self.schedule();
        schedule.due = Some(schedule.due.map_or(now, |due| due.min(now)));
    }

    /// One pass, at the start of an outbox tick, before the tick locks the
    /// outbox: when a fetch is due and the retry pace allows one, fetches
    /// and checks the descriptor with no lock held, then installs it under
    /// the outbox's lock.
    pub(super) fn upkeep(&self, dir: &Path) {
        let now = Instant::now();
        let due = {
            let schedule = self.schedule();
            schedule.due.is_some_and(|due| now >= due) && schedule.retry.ready(now)
        };
        if !due {
            return;
        }
        let fetched = self
            .intake
            .get(PIECE_KEYS_PATH)
            .and_then(|body| checked(&body).ok_or(Failure::Reply(None)));
        let keys = match fetched {
            Ok(keys) => keys,
            Err(failure) => {
                let failures = self.failed(failure.retry_after());
                tracing::warn!(
                    failure = failure.class(),
                    status = ?failure.status(),
                    failures,
                    "the intake's training descriptor was not fetched; the installed keys stay"
                );
                return;
            }
        };
        match install(dir, &keys) {
            Ok(Some(written)) => {
                let mut schedule = self.schedule();
                schedule.retry.succeeded();
                schedule.due = Instant::now().checked_add(PACE);
                if written > 0 {
                    tracing::info!(
                        written,
                        receipt_keys = keys.receipt_keys,
                        "the intake's training descriptor is installed"
                    );
                }
            }
            Ok(None) => {
                let failures = self.failed(None);
                tracing::debug!(
                    failures,
                    "another process holds the publisher training outbox; the intake's \
                     descriptor waits"
                );
            }
            Err(error) => {
                let failures = self.failed(None);
                tracing::warn!(
                    error = %format!("{error:#}"),
                    failures,
                    "the intake's training descriptor was not installed; the installed keys stay"
                );
            }
        }
    }

    /// Counts a failed attempt, waiting at least `floor` before the next:
    /// how many failed in a row.
    fn failed(&self, floor: Option<Duration>) -> u32 {
        let mut schedule = self.schedule();
        schedule.retry.failed(Instant::now(), floor);
        schedule.retry.failures()
    }

    /// The schedule, even after a panic elsewhere held it.
    fn schedule(&self) -> MutexGuard<'_, Schedule> {
        self.schedule.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The key files a descriptor's `body` installs, checked whole; `None` for a
/// body that does not decode, or a key that does not check. No partial
/// descriptor is taken.
fn checked(body: &[u8]) -> Option<Keys> {
    let keys = decode_training_keys(body).ok()?;
    let recipient = STANDARD
        .decode(&keys.recipient)
        .ok()
        .filter(|bytes| bytes.len() == RECIPIENT_BYTES)?;
    let parsed = IntakeRecipient::from_key_file(&recipient).ok()?;
    if oneiron_vault_contract::hex(parsed.key_id()) != keys.recipient_blake3 {
        return None;
    }
    let mut ring = Vec::new();
    for key in &keys.receipt_keys {
        let key = STANDARD
            .decode(key)
            .ok()
            .filter(|bytes| bytes.len() == RECEIPT_KEY_BYTES)?;
        ring.extend_from_slice(&key);
    }
    // Every member an Ed25519 public key: the receipt pass's own reader.
    IntakeReceiptKey::from_key_file(&ring).ok()?;
    Some(Keys {
        ring,
        recipient,
        receipt_keys: keys.receipt_keys.len(),
    })
}

/// Installs `keys` into the outbox at `dir`, under its lock: how many files
/// it wrote, or `None` while another process holds the lock.
fn install(dir: &Path, keys: &Keys) -> anyhow::Result<Option<usize>> {
    let Some(outbox) = Outbox::open(dir)? else {
        return Ok(None);
    };
    Ok(Some(
        outbox.install_intake_keys(&keys.ring, &keys.recipient)?,
    ))
}
