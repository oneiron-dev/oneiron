//! Doors for `tests/wake_d1_park_release.rs`, as they read the code BEFORE
//! review 6910's fix (red evidence only, never merged): the notice has one
//! ownerless id per park, and the release request has no lease generation,
//! so `release_as_owner` drops it. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::Result;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    DreamerParkedAttemptRecord, ParkReleaseView, ReleaseParkedAttemptRequest,
    release_parked_attempt_as_owner,
};
use crate::memory::DreamerParkCauseView;
use crate::vault::Vault;

#[doc(hidden)]
pub fn load_or_mint_client_id(vault: &Vault) -> Result<u64> {
    crate::identity::load_or_mint_client_id(vault)
}

#[doc(hidden)]
pub fn park_notice_seen(vault: &Vault, park: &DreamerParkedAttemptRecord) -> Result<Option<bool>> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's embedded owner");
    let txn = vault.store.env.read_txn()?;
    vault.notification_seen_in_txn(
        &txn,
        &crate::dreamer_runner::park_release_notice_source(park),
        &owner,
    )
}

#[doc(hidden)]
pub fn park_notice_recipient(
    vault: &Vault,
    park: &DreamerParkedAttemptRecord,
) -> Result<Option<Option<String>>> {
    let txn = vault.store.env.read_txn()?;
    let id =
        crate::inbox::notification_id(&crate::dreamer_runner::park_release_notice_source(park))?;
    let crate::vault::LiveEntityRow::Live { body, .. } =
        crate::vault::live_entity_row_in_txn(&vault.store, &txn, &id)?
    else {
        return Ok(None);
    };
    Ok(Some(
        crate::inbox::decode_notification_body(&body)?.recipient,
    ))
}

#[doc(hidden)]
pub fn release_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    attempt: &str,
    cause: DreamerParkCauseView,
    parked_at: u64,
    _attempt_count: u32,
) -> Result<ParkReleaseView> {
    release_parked_attempt_as_owner(
        vault,
        owner,
        &ReleaseParkedAttemptRequest {
            attempt: attempt.to_owned(),
            cause,
            parked_at,
            note: None,
        },
    )
}
