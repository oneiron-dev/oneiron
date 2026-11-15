//! The housekeeping tick's restore of a lapsed SIWC login
//! (SEAT-PARK-MODEL-STEP-PATH, RULING 05:39). A Dreamer step an SIWC offer
//! refused for a lapsed login parks on the offer's seat with no reset, so no
//! time wakes it. The CLI's sign-in rewrites the credential file in its own
//! process, with no vault write, and a parked step sends nothing. So each
//! tick looks at every configured SIWC offer whose seat row is Unavailable
//! with no reset, and opens its credential: only when the file changed since
//! the park (or since the last try), or else at most once every 30 minutes,
//! since a token refresh can succeed with no file change. An open that
//! succeeds writes the seat Available (LoginRestored) at the row's
//! generation, which wakes its parks. A failed open writes nothing and is
//! logged once per park. Nothing here calls a model or spends.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::dreamer_runner::{ModelSeatAvailability, ModelSeatAvailableSource, ModelSeatId};

use super::siwc_responses::siwc_offer_seat;
use crate::config::models::ModelsConfig;
use crate::runtime::seat_login::siwc::CredentialSource;

/// How long a lapsed login waits between two opens of an unchanged file.
pub(crate) const LAPSED_LOGIN_RETRY: Duration = Duration::from_secs(30 * 60);

/// One configured SIWC offer's login: its seat and the credential file the
/// offer reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SiwcSeatLogin {
    pub(crate) seat: ModelSeatId,
    pub(crate) credential_file: PathBuf,
    pub(crate) timeout_secs: u64,
}

/// What the tick last did for one lapsed seat's current park.
#[derive(Clone, Copy, Debug)]
struct LapsedLoginTry {
    /// The seat row's generation this park names.
    generation: u64,
    /// The credential file's modification time the last open read.
    tried_mtime: Option<SystemTime>,
    /// When an open of an unchanged file is next due.
    next_try: SystemTime,
    /// Whether this park's failed open was logged.
    failure_logged: bool,
}

/// What one restore pass did, for its caller's log and for the tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SiwcSeatRestorePass {
    /// Lapsed seats whose credential the pass opened.
    pub(crate) tried: usize,
    /// Seats the pass wrote Available.
    pub(crate) restored: usize,
}

/// The configured SIWC logins and the tick's record of each lapsed seat.
#[derive(Debug, Default)]
pub(crate) struct SiwcSeatLogins {
    logins: Vec<SiwcSeatLogin>,
    tries: Mutex<HashMap<ModelSeatId, LapsedLoginTry>>,
}

impl SiwcSeatLogins {
    /// Every `[models.providers.<name>] siwc` login in `config`. A provider
    /// whose seat cannot be named is left out, with a warning.
    pub(crate) fn from_config(config: &ModelsConfig) -> Self {
        let logins = config
            .providers
            .iter()
            .filter_map(|(name, provider)| {
                let selection = provider.siwc.as_ref()?;
                match siwc_offer_seat(&selection.credential_file) {
                    Ok(seat) => Some(SiwcSeatLogin {
                        seat,
                        credential_file: selection.credential_file.clone(),
                        timeout_secs: provider.timeout_secs,
                    }),
                    Err(error) => {
                        tracing::warn!(provider = %name, %error, "SIWC offer has no model seat");
                        None
                    }
                }
            })
            .collect();
        Self::with_logins(logins)
    }

    /// The tick's restore over exactly `logins`.
    pub(crate) fn with_logins(logins: Vec<SiwcSeatLogin>) -> Self {
        Self {
            logins,
            tries: Mutex::new(HashMap::new()),
        }
    }

    /// One tick: opens the credential of each lapsed SIWC seat that is due,
    /// and writes the seat Available when the open succeeds.
    pub(crate) async fn restore_lapsed(&self, vault: &Arc<oneiron::Vault>) -> SiwcSeatRestorePass {
        let mut pass = SiwcSeatRestorePass::default();
        for login in &self.logins {
            let row = match vault.model_seat_state(login.seat) {
                Ok(row) => row,
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "SIWC seat row could not be read");
                    continue;
                }
            };
            let Some(row) = row.filter(|row| {
                row.availability == ModelSeatAvailability::Unavailable && row.reset_at_s.is_none()
            }) else {
                self.forget(login.seat);
                continue;
            };
            let mtime = std::fs::metadata(&login.credential_file)
                .and_then(|metadata| metadata.modified())
                .ok();
            let now = SystemTime::now();
            if !self.claim_try(login.seat, row.generation, row.changed_at_s, mtime, now) {
                continue;
            }
            pass.tried += 1;
            let opened = match CredentialSource::select(&login.credential_file, login.timeout_secs)
            {
                Ok(source) => source.open().await.map(drop),
                Err(error) => Err(error),
            };
            if opened.is_err() {
                if self.first_failure(login.seat, row.generation) {
                    tracing::info!(
                        seat = %login.seat.to_hex(),
                        generation = row.generation,
                        "a lapsed SIWC login is still signed out; its parks keep waiting"
                    );
                }
                continue;
            }
            let restoring = Arc::clone(vault);
            let (seat, generation) = (login.seat, row.generation);
            match tokio::task::spawn_blocking(move || {
                restoring.record_model_seat_available(
                    seat,
                    generation,
                    ModelSeatAvailableSource::LoginRestored,
                )
            })
            .await
            {
                Ok(Ok(woken)) => {
                    pass.restored += 1;
                    self.forget(seat);
                    tracing::info!(
                        seat = %seat.to_hex(),
                        generation,
                        woken = woken.len(),
                        "a lapsed SIWC login is back; its seat parks resume"
                    );
                }
                Ok(Err(error)) => {
                    tracing::info!(
                        seat = %seat.to_hex(),
                        generation,
                        kind = ?error.kind(),
                        "a restored SIWC login's seat write was refused"
                    );
                }
                Err(error) => {
                    tracing::warn!(panicked = error.is_panic(), "SIWC seat restore task failed");
                }
            }
        }
        pass
    }

    /// Whether the tick opens `seat`'s credential now, for the park at
    /// `generation` made at `parked_at_s`; when it does, the try is recorded.
    /// Due when the file changed since the park and since the last try, or
    /// when [`LAPSED_LOGIN_RETRY`] has passed since the park or the last try.
    fn claim_try(
        &self,
        seat: ModelSeatId,
        generation: u64,
        parked_at_s: u64,
        mtime: Option<SystemTime>,
        now: SystemTime,
    ) -> bool {
        let parked_at = UNIX_EPOCH + Duration::from_secs(parked_at_s);
        let mut tries = self.tries.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = tries.entry(seat).or_insert(LapsedLoginTry {
            generation,
            tried_mtime: None,
            next_try: parked_at + LAPSED_LOGIN_RETRY,
            failure_logged: false,
        });
        if entry.generation != generation {
            *entry = LapsedLoginTry {
                generation,
                tried_mtime: None,
                next_try: parked_at + LAPSED_LOGIN_RETRY,
                failure_logged: false,
            };
        }
        let changed =
            mtime.is_some_and(|mtime| mtime >= parked_at && Some(mtime) != entry.tried_mtime);
        if !changed && now < entry.next_try {
            return false;
        }
        entry.tried_mtime = mtime;
        entry.next_try = now + LAPSED_LOGIN_RETRY;
        true
    }

    /// Whether this is the first failed open logged for the park at
    /// `generation`; records that it is logged.
    fn first_failure(&self, seat: ModelSeatId, generation: u64) -> bool {
        let mut tries = self.tries.lock().unwrap_or_else(PoisonError::into_inner);
        match tries.get_mut(&seat) {
            Some(entry) if entry.generation == generation && !entry.failure_logged => {
                entry.failure_logged = true;
                true
            }
            _ => false,
        }
    }

    /// Drops the record of `seat`, whose row no longer waits on a login.
    fn forget(&self, seat: ModelSeatId) {
        self.tries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&seat);
    }
}
