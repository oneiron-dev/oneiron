//! Explicit revocation of the credential accepted on one counted TCP body.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

#[derive(Clone, Default)]
pub(crate) struct BodyRevocation(Arc<State>);

#[derive(Default)]
struct State {
    credential: OnceLock<Credential>,
    ended_revoked: AtomicBool,
    read_wait: Mutex<ReadWait>,
}

#[derive(Default)]
struct ReadWait {
    total: Duration,
    started: Option<Instant>,
}

enum Credential {
    Slip {
        vault: Arc<oneiron::Vault>,
        slip: Arc<oneiron::authority::VerifiedSlip>,
    },
    AccountKey(Arc<AtomicBool>),
}

tokio::task_local! {
    static BODY_REVOCATION: Option<BodyRevocation>;
}

pub(super) fn with_body_revocation<F: Future>(
    body: Option<BodyRevocation>,
    request: F,
) -> impl Future<Output = F::Output> {
    BODY_REVOCATION.scope(body, request)
}

/// Attaches only the native identity from the request's admitted holder proof
/// and the owned vault that verified it. Outside a TCP body this does nothing.
pub(crate) fn attach_body_slip(
    vault: Arc<oneiron::Vault>,
    slip: Arc<oneiron::authority::VerifiedSlip>,
) {
    attach(Credential::Slip { vault, slip });
}

/// The latch was registered by the exact verifier that accepted this key.
pub(crate) fn attach_body_account_key(revoked: Arc<AtomicBool>) {
    attach(Credential::AccountKey(revoked));
}

fn attach(credential: Credential) {
    let _ = BODY_REVOCATION.try_with(|body| {
        if let Some(body) = body {
            let _ = body.0.credential.set(credential);
        }
    });
}

impl BodyRevocation {
    pub(super) fn read_finished(&self) {
        let mut wait = self
            .0
            .read_wait
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(started) = wait.started.take() {
            wait.total += started.elapsed();
        }
    }

    fn read_wait(&self) -> Duration {
        let wait = self
            .0
            .read_wait
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        wait.total
            + wait
                .started
                .map_or(Duration::ZERO, |started| started.elapsed())
    }

    pub(super) fn end_revoked(&self) {
        self.0.ended_revoked.store(true, Ordering::Release);
    }

    pub(super) fn ended_revoked(&self) -> bool {
        self.0.ended_revoked.load(Ordering::Acquire)
    }

    pub(super) fn account_key_revoked(&self) -> bool {
        matches!(self.0.credential.get(), Some(Credential::AccountKey(revoked)) if revoked.load(Ordering::Acquire))
    }

    /// One current fold read for a frame already received. A fault is unknown,
    /// not a revocation; the caller keeps the frame in that case.
    pub(super) fn check_slip(&self) -> Option<JoinHandle<bool>> {
        let Credential::Slip { vault, slip } = self.0.credential.get()? else {
            return None;
        };
        let vault = Arc::clone(vault);
        let slip = Arc::clone(slip);
        self.0
            .read_wait
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .started = Some(Instant::now());
        Some(tokio::task::spawn_blocking(move || {
            matches!(vault.capability_slip_is_explicitly_revoked(&slip), Ok(true))
        }))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("credential_revoked")]
pub(crate) struct CredentialRevoked;

/// Body consumers may turn a read error into a parse error. The listener
/// retains the actual body outcome so the response keeps its typed cause.
pub(super) fn revoked_response() -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::UNAUTHORIZED,
        [(axum::http::header::CONNECTION, "close")],
        axum::Json(serde_json::json!({
            "error": {
                "code": "credential_revoked",
                "message": "the credential this request body was admitted under was explicitly revoked"
            }
        })),
    )
        .into_response()
}

/// Capture while the feed future is created, before a caller spawns it.
pub(crate) fn current_body_revocation() -> Option<BodyRevocation> {
    BODY_REVOCATION.try_with(Clone::clone).ok().flatten()
}

/// The existing transfer-idle clock, excluding only this body's own fold read.
/// Reusing the pending read future never polls another frame or repeats a check.
pub(crate) async fn body_read_timeout<F: Future>(
    body: Option<&BodyRevocation>,
    idle: Duration,
    read: F,
) -> Option<F::Output> {
    let started = tokio::time::Instant::now();
    let before = body.map_or(Duration::ZERO, BodyRevocation::read_wait);
    let mut read = std::pin::pin!(read);
    loop {
        let excluded = body
            .map_or(Duration::ZERO, BodyRevocation::read_wait)
            .saturating_sub(before);
        match tokio::time::timeout_at(started + idle + excluded, read.as_mut()).await {
            Ok(value) => return Some(value),
            Err(_) => {
                let excluded = body
                    .map_or(Duration::ZERO, BodyRevocation::read_wait)
                    .saturating_sub(before);
                if started.elapsed().saturating_sub(excluded) >= idle {
                    return None;
                }
            }
        }
    }
}
