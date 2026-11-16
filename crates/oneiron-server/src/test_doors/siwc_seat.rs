//! Doors for `tests/siwc_seat_login.rs` (SEAT-PARK-MODEL-STEP-PATH): an SIWC
//! offer's model seat, the refusal mapper its calls go through, a local
//! credential record written as the CLI's sign-in writes one, and one
//! housekeeping tick's restore of a lapsed login. Thin wrappers over crate
//! items only. Compiled only under `--cfg oneiron_test_support`; hidden,
//! never API.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::LlmError;
use oneiron::dreamer_runner::ModelSeatId;

use crate::models::siwc_seat_login::{SiwcSeatLogin, SiwcSeatLogins};

/// The issuer every local SIWC record names.
const SIWC_ISSUER: &str = "https://auth.openai.com";
/// The scope that lets a record's token spend its plan directly.
const SIWC_DIRECT_SCOPE: &str = "chatgpt.tokens.use.direct";

/// The model seat of the SIWC offer whose credential file is
/// `credential_file`.
///
/// # Errors
/// The path has no absolute form.
#[doc(hidden)]
pub fn siwc_offer_seat(credential_file: &Path) -> anyhow::Result<ModelSeatId> {
    crate::models::siwc_offer_seat(credential_file)
}

/// `error` as an SIWC offer on `seat` answers it.
#[doc(hidden)]
#[must_use]
pub fn seat_refusal(seat: ModelSeatId, error: LlmError) -> LlmError {
    crate::models::seat_refusal(seat, error)
}

/// Writes a local SIWC credential record at `path`, owner-only, as the CLI's
/// sign-in replaces one: signed in with a direct-plan token that expires in
/// an hour, or signed out with no token. The file's modification time always
/// moves past the one it replaces.
///
/// # Errors
/// The clock or the file's.
#[doc(hidden)]
pub fn write_siwc_credential(path: &Path, signed_in: bool) -> anyhow::Result<()> {
    let previous = std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let record = serde_json::json!({
        "version": 1,
        "issuer": SIWC_ISSUER,
        "subject": "user-seat-park-test",
        "email": null,
        "client_id": "app-seat-park-test",
        "ext_agent_host_id": "host-seat-park-test",
        "redirect_uri": "http://localhost:1455/auth/callback",
        "nonce": "nonce-seat-park-test",
        "session_active": signed_in,
        "id_token": if signed_in { "id-token-seat-park-test" } else { "" },
        "access_token": if signed_in { "access-token-seat-park-test" } else { "" },
        "refresh_token": null,
        "scopes": if signed_in { vec![SIWC_DIRECT_SCOPE] } else { Vec::new() },
        "saved_at": now,
        "expires_at": if signed_in { now + 3_600 } else { 0 },
        "earliest_refresh_at": null,
    });
    crate::commands::credential_file::replace(path, &serde_json::to_vec(&record)?)?;
    if let Some(previous) = previous {
        let written = std::fs::metadata(path)?.modified()?;
        if written <= previous {
            std::fs::File::options()
                .write(true)
                .open(path)?
                .set_modified(previous + Duration::from_secs(1))?;
        }
    }
    Ok(())
}

/// One configured SIWC login's housekeeping restore, as the tick runs it.
#[doc(hidden)]
pub struct SiwcSeatTick {
    logins: SiwcSeatLogins,
}

impl SiwcSeatTick {
    /// The restore over the one SIWC offer whose credential file is
    /// `credential_file`.
    ///
    /// # Errors
    /// The path has no absolute form.
    #[doc(hidden)]
    pub fn new(credential_file: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            logins: SiwcSeatLogins::with_logins(vec![SiwcSeatLogin {
                seat: crate::models::siwc_offer_seat(credential_file)?,
                credential_file: credential_file.to_owned(),
                timeout_secs: 10,
            }]),
        })
    }

    /// Runs one tick's restore over `vault`: `(tried, restored)`, the lapsed
    /// seats whose credential it opened and those it wrote Available.
    #[doc(hidden)]
    pub async fn run(&self, vault: &Arc<oneiron::Vault>) -> (usize, usize) {
        let pass = self.logins.restore_lapsed(vault).await;
        (pass.tried, pass.restored)
    }
}
