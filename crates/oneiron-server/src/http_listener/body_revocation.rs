//! Explicit revocation of the credential accepted on one counted TCP body.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::task::JoinHandle;

#[derive(Clone, Default)]
pub(super) struct BodyRevocation(Arc<State>);

#[derive(Default)]
struct State {
    credential: OnceLock<Credential>,
    ended_revoked: AtomicBool,
}

enum Credential {
    Slip {
        vault: Arc<oneiron::Vault>,
        slip_id: [u8; 32],
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
pub(crate) fn attach_body_slip(vault: Arc<oneiron::Vault>, slip_id: [u8; 32]) {
    attach(Credential::Slip { vault, slip_id });
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
        let Credential::Slip { vault, slip_id } = self.0.credential.get()? else {
            return None;
        };
        let vault = Arc::clone(vault);
        let slip_id = *slip_id;
        Some(tokio::task::spawn_blocking(move || {
            matches!(
                vault.capability_slip_is_explicitly_revoked(&slip_id),
                Ok(true)
            )
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
