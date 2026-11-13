//! Each account's own bearer key for the shared embedder (CROSS-ARCH-0019
//! #dm-xaccount-embedder): one server, many accounts, and one key per
//! account rather than one key for every caller.
//!
//! The operator lists the accounts in a TOML file of `[[account]]` rows,
//! each an `id` and the SHA-256 digest of that account's key as 64 hex
//! digits (`key_sha256`). The file holds digests only, so whoever writes it
//! (the operator, or a Hypnos adapter later) never stores a key in it. A
//! request's bearer key is hashed and compared in constant time with every
//! row; the account it names is the request's caller.
//!
//! The server re-reads the file on SIGHUP, so one account is revoked, or a
//! new one added, without a restart that would load the model again. A file
//! that does not read or parse leaves the table as it was.
//!
//! A row may also set `daily_input_tokens`, the account's soft quota: the
//! input tokens its requests may use in one UTC day before the endpoint asks
//! whether everything is okay. Crossing it never refuses a request (ARCH-0044
//! C5, "the wire never refuses a call for rate"; RULING L10-10-QUOTA = A):
//! the request is served, and the account's first crossing in a day raises
//! one OF-520 question on `embedder.serve:account_daily_input_tokens` and
//! logs the account's id. A hard money stop is Cloud billing's.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Who a request with an accepted key is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Caller {
    /// No key is configured: a loopback server open to its host.
    Open,
    /// The operator's key, from `--api-key-env`.
    Operator,
    /// An account's key, from the accounts file: its `id`.
    Account(Arc<str>),
}

impl Caller {
    /// The name a log line gives the caller.
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Open => "open",
            Self::Operator => "operator",
            Self::Account(id) => id,
        }
    }
}

/// One account's row: its id, its key's digest and its soft quota.
#[derive(Debug, PartialEq, Eq)]
struct AccountKey {
    id: Arc<str>,
    key_sha256: [u8; 32],
    daily_input_tokens: Option<u64>,
}

/// The accounts file's rows, swapped whole on a re-read, and what each
/// account has used today.
pub(crate) struct AccountKeys {
    path: PathBuf,
    rows: ArcSwap<Vec<AccountKey>>,
    /// Each account's input tokens on its current UTC day, by id. A re-read
    /// keeps the accounts it still lists.
    days: Mutex<HashMap<Arc<str>, AccountDay>>,
}

/// One account's use on one UTC day.
struct AccountDay {
    /// Days since the Unix epoch, in UTC.
    day: u64,
    input_tokens: u64,
    /// Whether the account's crossing has asked on this day.
    asked: bool,
}

/// An account's first crossing of its soft quota in a UTC day.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct QuotaCrossing {
    pub(crate) bound: u64,
    pub(crate) observed: u64,
}

/// Seconds in a UTC day.
const DAY_SECS: u64 = 86_400;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountsFile {
    #[serde(default, rename = "account")]
    accounts: Vec<AccountRow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountRow {
    id: String,
    key_sha256: String,
    #[serde(default)]
    daily_input_tokens: Option<u64>,
}

impl AccountKeys {
    /// Reads the accounts file at `path`. The server does not start on a
    /// file that does not read or parse.
    pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
        let rows = read_rows(path)?;
        Ok(Self {
            path: path.to_owned(),
            rows: ArcSwap::from_pointee(rows),
            days: Mutex::default(),
        })
    }

    /// Reads the file again and swaps its rows in whole. On an error the
    /// rows stay as they were, and the error says why.
    pub(crate) fn reload(&self) -> anyhow::Result<usize> {
        let rows = read_rows(&self.path)?;
        let count = rows.len();
        self.days
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| rows.iter().any(|row| row.id == *id));
        self.rows.store(Arc::new(rows));
        Ok(count)
    }

    /// How many accounts the table holds now.
    pub(crate) fn count(&self) -> usize {
        self.rows.load().len()
    }

    /// The account whose key is `presented`, if any. Every row is compared,
    /// in constant time, whichever matches.
    pub(crate) fn account_for(&self, presented: &[u8]) -> Option<Arc<str>> {
        let digest: [u8; 32] = Sha256::digest(presented).into();
        self.rows.load().iter().fold(None, |found, row| {
            if bool::from(row.key_sha256.ct_eq(&digest)) {
                Some(Arc::clone(&row.id))
            } else {
                found
            }
        })
    }

    /// Counts `tokens` of model input to account `id` at `now` (Unix
    /// seconds), on that UTC day. The account's first crossing of its
    /// `daily_input_tokens` in the day is returned, once; the work is served
    /// either way.
    pub(crate) fn count_input_tokens(
        &self,
        id: &Arc<str>,
        tokens: u64,
        now: u64,
    ) -> Option<QuotaCrossing> {
        let bound = self
            .rows
            .load()
            .iter()
            .find(|row| row.id == *id)
            .and_then(|row| row.daily_input_tokens);
        let today = now / DAY_SECS;
        let mut days = self.days.lock().unwrap_or_else(PoisonError::into_inner);
        let used = days.entry(Arc::clone(id)).or_insert(AccountDay {
            day: today,
            input_tokens: 0,
            asked: false,
        });
        if used.day != today {
            *used = AccountDay {
                day: today,
                input_tokens: 0,
                asked: false,
            };
        }
        used.input_tokens = used.input_tokens.saturating_add(tokens);
        let bound = bound?;
        if used.asked || used.input_tokens <= bound {
            return None;
        }
        used.asked = true;
        Some(QuotaCrossing {
            bound,
            observed: used.input_tokens,
        })
    }

    /// Re-reads the file each time the process gets SIGHUP, for as long as
    /// the server runs.
    #[cfg(unix)]
    pub(crate) fn reload_on_hangup(self: &Arc<Self>) -> anyhow::Result<()> {
        use tokio::signal::unix::{SignalKind, signal};
        let mut hangups = signal(SignalKind::hangup())?;
        let keys = Arc::clone(self);
        tokio::spawn(async move {
            while hangups.recv().await.is_some() {
                match keys.reload() {
                    Ok(accounts) => {
                        tracing::info!(accounts, "embedder serve re-read its accounts file");
                    }
                    Err(error) => tracing::warn!(
                        error = %error,
                        "embedder serve could not re-read its accounts file; the accounts it had stay"
                    ),
                }
            }
        });
        Ok(())
    }
}

fn read_rows(path: &Path) -> anyhow::Result<Vec<AccountKey>> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        anyhow::anyhow!(
            "the accounts file {} does not read: {error}",
            path.display()
        )
    })?;
    parse_rows(&text)
        .map_err(|error| anyhow::anyhow!("the accounts file {}: {error}", path.display()))
}

/// The rows of an accounts file's text: each id non-empty and named once,
/// each digest 64 hex digits and given to one account only, and each soft
/// quota, if set, at least one token.
fn parse_rows(text: &str) -> anyhow::Result<Vec<AccountKey>> {
    let file: AccountsFile = toml::from_str(text)
        .map_err(|error| anyhow::anyhow!("not [[account]] rows of id and key_sha256: {error}"))?;
    let mut rows: Vec<AccountKey> = Vec::with_capacity(file.accounts.len());
    for row in file.accounts {
        let id = row.id.trim();
        if id.is_empty() {
            anyhow::bail!("an account row has an empty id");
        }
        let key_sha256 = digest_from_hex(&row.key_sha256).ok_or_else(|| {
            anyhow::anyhow!("account {id}: key_sha256 is not a SHA-256 digest in 64 hex digits")
        })?;
        if rows.iter().any(|seen| &*seen.id == id) {
            anyhow::bail!("account {id} is named twice");
        }
        if let Some(seen) = rows.iter().find(|seen| seen.key_sha256 == key_sha256) {
            anyhow::bail!("accounts {} and {id} have the same key", seen.id);
        }
        if row.daily_input_tokens == Some(0) {
            anyhow::bail!(
                "account {id}: daily_input_tokens is at least 1; leave it out for no quota"
            );
        }
        rows.push(AccountKey {
            id: Arc::from(id),
            key_sha256,
            daily_input_tokens: row.daily_input_tokens,
        });
    }
    Ok(rows)
}

fn digest_from_hex(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim().as_bytes();
    if hex.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.chunks_exact(2)) {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        *byte = u8::try_from(high * 16 + low).ok()?;
    }
    Some(digest)
}

/// A key's `key_sha256`, as an accounts file names it.
#[cfg(test)]
pub(super) fn digest_hex(key: &str) -> String {
    format!("{:x}", Sha256::digest(key.as_bytes()))
}
