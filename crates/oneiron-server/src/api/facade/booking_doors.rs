//! Owner discovery of the opaque address of an existing booking page.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{BookingPageTokenRequest, BookingPageTokenResponse};

use super::FacadeApiError;
use super::host_doors::internal;
use crate::api::booking::{booking_page_token, resolve_booking_page};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The same owner proof as every owner door; a token grants no new authority.
pub(crate) async fn vault_booking_page_token(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: BookingPageTokenRequest,
) -> MemoryResult<BookingPageTokenResponse> {
    const VERB: &str = "vault.booking.page_token";
    let _owner = crate::api::owner_routes::owner(auth, server).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{VERB} is the vault owner's"),
            &["Present the owner's own verified, unattenuated credential."],
        )
    })?;
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        let page_ref = EntityId::from_hex(input.page_ref.trim())
            .map_err(|_| MemoryError::bad_request("invalid booking page_ref"))?;
        let page_token = booking_page_token(page_ref);
        // Discovery addresses only pages the existing booking executor resolves.
        resolve_booking_page(&server, &page_token)
            .map_err(|error| FacadeApiError::from(error).into_memory_error())?;
        Ok(BookingPageTokenResponse { page_token })
    })
    .await
    .map_err(|_| internal(VERB))?
}
