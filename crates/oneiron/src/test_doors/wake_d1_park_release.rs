//! Doors for `tests/wake_d1_park_release.rs` (#6877, WAKE-D1): the wake
//! pass's local node id, the owner notice a park waiting on the owner's
//! release raises, and the owner's release. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::Result;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    DreamerParkedAttemptRecord, ParkReleaseView, ReleaseParkedAttemptRequest,
    release_parked_attempt_as_owner,
};
use crate::entity_id::EntityId;
use crate::memory::DreamerParkCauseView;
use crate::vault::Vault;

/// This device's stable client id (`identity::load_or_mint_client_id`), which
/// a wake pass takes as its local node id.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn load_or_mint_client_id(vault: &Vault) -> Result<u64> {
    crate::identity::load_or_mint_client_id(vault)
}

/// The vault's embedded owner. Resolved before a read txn opens: the resolve
/// opens its own txn, and LMDB allows one reader slot per thread.
fn embedded_owner(vault: &Vault) -> EntityId {
    vault
        .ensure_embedded_owner_actor()
        .expect("the vault's embedded owner")
}

/// `park`'s notice source for `owner`, at the try's current lease generation.
fn park_notice_source(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    park: &DreamerParkedAttemptRecord,
    owner: &EntityId,
) -> Result<crate::inbox::NotificationSource> {
    let attempt = crate::attempt_queue::AttemptQueue::new(vault)
        .get_in_write_txn(txn, park.attempt_id)?
        .expect("the parked try");
    Ok(crate::dreamer_runner::park_release_notice_source(
        park,
        attempt.attempt_count,
        owner,
    ))
}

/// Whether the vault's embedded owner saw `park`'s release notice; `None`
/// when it was never raised.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn park_notice_seen(vault: &Vault, park: &DreamerParkedAttemptRecord) -> Result<Option<bool>> {
    let owner = embedded_owner(vault);
    let txn = vault.store.env.read_txn()?;
    let source = park_notice_source(vault, &txn, park, &owner)?;
    vault.notification_seen_in_txn(&txn, &source, &owner)
}

/// The recipient stored on the embedded owner's notice of `park`: `None` when
/// no such notice exists, `Some(None)` when it names no recipient.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn park_notice_recipient(
    vault: &Vault,
    park: &DreamerParkedAttemptRecord,
) -> Result<Option<Option<String>>> {
    let owner = embedded_owner(vault);
    let txn = vault.store.env.read_txn()?;
    let source = park_notice_source(vault, &txn, park, &owner)?;
    let id = crate::inbox::notification_id(&source)?;
    let crate::vault::LiveEntityRow::Live { body, .. } =
        crate::vault::live_entity_row_in_txn(&vault.store, &txn, &id)?
    else {
        return Ok(None);
    };
    Ok(Some(
        crate::inbox::decode_notification_body(&body)?.recipient,
    ))
}

/// The owner's release of the park a read showed: the try, its park's cause
/// and time, and the try's lease generation.
///
/// # Errors
/// The release's.
#[doc(hidden)]
pub fn release_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    attempt: &str,
    cause: DreamerParkCauseView,
    parked_at: u64,
    attempt_count: u32,
) -> Result<ParkReleaseView> {
    release_parked_attempt_as_owner(
        vault,
        owner,
        &ReleaseParkedAttemptRequest {
            attempt: attempt.to_owned(),
            cause,
            parked_at,
            attempt_count,
            note: None,
        },
    )
}

/// Red adapter (scratch, never merged): the owner's stop as this head offers
/// it, the run tree's cancel of the try (`Memory::cancel_run_branch`, as the
/// owner). Returns the try's queue state after the cancel.
///
/// # Errors
/// The cancel's.
#[doc(hidden)]
pub fn stop_as_owner(
    vault: &Vault,
    _owner: &AuthenticatedOwner,
    attempt: &str,
    _cause: DreamerParkCauseView,
    _parked_at: u64,
    _attempt_count: u32,
) -> Result<String> {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's embedded owner");
    let id = EntityId::from_hex(attempt)
        .map_err(|_| crate::Error::InvalidConfig("attempt must be 32 hex".to_owned()))?;
    let id = crate::attempt_queue::AttemptId::from_bytes(id.as_bytes())?;
    let outcome = vault
        .memory(owner, crate::edge::EdgeActorClass::Human)
        .cancel_run_branch(crate::attempt_queue::InterveneAttempt {
            id,
            kind: crate::attempt_queue::AttemptInterventionKind::Cancel,
            actor: owner.to_hex(),
            note: Some("the owner stops this run".to_owned()),
            now: vault.now_recorded_at(),
        })
        .map_err(|error| {
            crate::Error::InvalidConfig(format!("the run tree's cancel refused: {error:?}"))
        })?;
    match outcome {
        crate::task_verb::run_cancel::RunCancelOutcome::Applied(applied) => {
            Ok(applied.record.state.as_str().to_owned())
        }
        crate::task_verb::run_cancel::RunCancelOutcome::Proposed { .. } => Err(
            crate::Error::InvalidConfig("the owner's cancel became a proposal".to_owned()),
        ),
    }
}
