//! The reap freeze's whitelist of requests a frozen vault still answers.

use axum::extract::Request;
use axum::http::{Method, header::UPGRADE};

/// Whether a frozen vault may still answer this request.
///
/// A whitelist, so the failure direction is refusal: a method this build does
/// not recognise reads as a write rather than getting waved through. The
/// upgrade check is the other half — a WebSocket handshake is a `GET`, but what
/// it opens is a bidirectional sync session whose updates ride past every
/// per-request gate, so a frozen engine refuses the handshake rather than
/// frames it has no way to inspect.
///
/// The method is deliberately the whole test. Several reads on this surface are
/// `POST` (query, hydrate, context-pack) and a frozen engine refuses those too;
/// a path list that spared them would be one rename away from sparing a write,
/// and this window is the few seconds before a reap.
pub(super) fn is_read_only(request: &Request) -> bool {
    if request.headers().contains_key(UPGRADE) {
        return false;
    }
    let method = request.method();
    *method == Method::GET || *method == Method::HEAD || *method == Method::OPTIONS
}
