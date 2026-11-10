//! The owner's release of a parked Dreamer attempt that no resumer frees (untangle slice 3, WAKE-D1; lead 14:3x and
//! 15:2x, 9 Nov).
//!
//! An ExecutorError park and a private Other park wait on an owner act: a budget, a consent, a seat or a peer. No
//! resumer retries them blindly (constraint C5), boot included. Each such park raises one notice for each live owner
//! (recipient set, so no other reader sees the try) in its own write, and the vault's authenticated owner releases
//! it, against the exact park a read showed him (its cause, when it was parked and the try's lease generation, as
//! `vault.consolidation.status` and the owner's lineage show them), so a park that changed since refuses and nothing
//! moves. A try parks only under a lease, so a later park of the same try is a later generation, even within the same
//! second (review 6910 P1). The release resumes the park as the same try and resolves its notices. In slice 6.5 typed waits replace this door for budget, consent, seat and peer:
//! the matching signal resumes the park.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptInterventionKind, AttemptQueue, InterveneAttempt};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::inbox::{
    NotificationEvent, NotificationKind, NotificationSource, decode_notification_body,
};
use crate::memory::DreamerParkCauseView;
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

use super::{DreamerParkedAttemptRecord, DreamerRunnerStore, ParkResumer};

/// The producer of the owner notice a park waiting on the owner's release raises.
pub const PARK_RELEASE_OWED_PRODUCER: &str = "dreamer.park.release_owed";
/// The notice's detail code.
const PARK_RELEASE_OWED_DETAIL: &str = "dreamer.park.owner_release";
/// The note the release's intervention carries when the owner gave none.
const RELEASE_NOTE: &str = "the owner released the parked try";

/// The owner's release of one parked Dreamer try.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleaseParkedAttemptRequest {
    /// 32-hex id of the parked try (`job:` prefix allowed).
    pub attempt: String,
    /// The park's cause and the time it was parked, as a read showed them (`vault.consolidation.status`, the
    /// owner's lineage): a park that changed since refuses.
    pub cause: DreamerParkCauseView,
    pub parked_at: u64,
    /// The try's lease generation (`attempt_count`) as the same read showed it: a release of an earlier park of
    /// the same try refuses, even when both parks fall in the same second.
    pub attempt_count: u32,
    /// The owner's note on the try's queue row.
    #[serde(default)]
    pub note: Option<String>,
}

/// What releasing one park did.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ParkReleaseView {
    /// 32-hex try.
    pub attempt: String,
    /// The released park's exact reason.
    pub released: String,
    /// The released park's cause.
    pub cause: String,
    /// The try's queue state after the release.
    pub state: String,
}

/// The source of `owner`'s notice for `record`, parked under lease generation `attempt_count`: one per park and
/// owner, its id derived from the try, its generation, its park time and the owner, so a replay finds the row it
/// wrote and a new park of the same try (a later generation) raises its own.
pub(crate) fn park_release_notice_source(
    record: &DreamerParkedAttemptRecord,
    attempt_count: u32,
    owner: &EntityId,
) -> NotificationSource {
    let attempt = bytes_to_hex_lower(record.attempt_id.as_bytes());
    NotificationSource {
        producer: PARK_RELEASE_OWED_PRODUCER.to_owned(),
        event: format!(
            "{attempt}:{attempt_count}:{}:{}",
            record.parked_at,
            owner.to_hex()
        ),
        attempt: Some(attempt),
        detail: Some(PARK_RELEASE_OWED_DETAIL.to_owned()),
        ..NotificationSource::default()
    }
}

/// Raises each live owner's notice for `record` in its park's own write, when only the owner's release resumes it:
/// one notice per owner, for that owner only (review 6910 P1). A notice that is not written is logged; the park
/// still lands.
pub(crate) fn raise_park_release_notice_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerParkedAttemptRecord,
) {
    if !record.resumable_by(ParkResumer::OwnerRelease) {
        return;
    }
    let raised = (|| -> Result<()> {
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        let Some(attempt) =
            AttemptQueue::new(vault).get_in_write_txn(&savepoint, record.attempt_id)?
        else {
            return Ok(());
        };
        for owner in crate::policy_model::owners_in_txn(vault, &savepoint)? {
            vault.record_notification_in_txn(
                &mut savepoint,
                &NotificationEvent {
                    kind: NotificationKind::Finding,
                    source: park_release_notice_source(record, attempt.attempt_count, &owner),
                    subject_refs: Vec::new(),
                    recipient: Some(owner),
                    created_at: record.parked_at,
                    origin_conversation: None,
                },
            )?;
        }
        savepoint.commit()?;
        Ok(())
    })();
    match raised {
        // The notice's savepoint is not the parent's post-commit scope.
        Ok(()) => crate::batch::queue_notification_change(vault, wtxn),
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            attempt = %bytes_to_hex_lower(record.attempt_id.as_bytes()),
            "a parked try's owner release notice was not raised"
        ),
    }
}

/// Releases one parked try as the vault's authenticated owner: the owner is revalidated in the writer; the park
/// must be one only the owner's release resumes (the park resume table's OwnerRelease row), with exactly the cause
/// and park time the request names, as the owner's reads show them; a settled try is never reopened. The owner's intervention is recorded on the
/// queue row, the park resumes as the same try under its own owner token, and its notice is resolved for the owner.
///
/// # Errors
///
/// A malformed attempt id ([`Error::InvalidConfig`]); a proof that no longer holds; a try with no park, or a park
/// some other resumer frees ([`Error::EntityNotFound`]); a park that changed since it was read
/// ([`Error::ConcurrentWrite`]); a settled try ([`Error::InvalidConfig`]); a note the queue refuses; storage errors.
pub fn release_parked_attempt_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ReleaseParkedAttemptRequest,
) -> Result<ParkReleaseView> {
    let attempt = attempt_id(&input.attempt)?;
    let now = vault.now_recorded_at();
    let view = vault
        .with_write_txn_grouped(|wtxn| release_in_txn(vault, wtxn, owner, attempt, input, now))?;
    // Committed: the resumed try is visible to admission.
    vault.store.notify_proactivity_changes();
    Ok(view)
}

fn release_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    attempt: AttemptId,
    input: &ReleaseParkedAttemptRequest,
    now: u64,
) -> Result<ParkReleaseView> {
    let actor = owner.revalidate_in_txn(vault, &*wtxn)?;
    let store = DreamerRunnerStore::new(vault);
    let Some((status, Some(park))) = store.status_with_park_in_txn(&*wtxn, attempt)? else {
        return Err(Error::EntityNotFound);
    };
    if !park.resumable_by(ParkResumer::OwnerRelease) {
        return Err(Error::EntityNotFound);
    }
    if DreamerParkCauseView::from(park.cause) != input.cause
        || park.parked_at != input.parked_at
        || status.attempt.attempt_count != input.attempt_count
    {
        return Err(Error::ConcurrentWrite(
            "the parked try changed since it was read",
        ));
    }
    if status.attempt.state.is_terminal() {
        return Err(Error::InvalidConfig(
            "a settled try is never reopened".to_owned(),
        ));
    }
    AttemptQueue::new(vault).intervene_in_txn(
        wtxn,
        InterveneAttempt {
            id: attempt,
            kind: AttemptInterventionKind::Interrupt,
            actor: actor.to_hex(),
            note: Some(
                input
                    .note
                    .clone()
                    .unwrap_or_else(|| RELEASE_NOTE.to_owned()),
            ),
            now,
        },
    )?;
    store
        .resume_parked_in_txn(wtxn, attempt, &park.park_owner, now)?
        .ok_or(Error::EntityNotFound)?;
    resolve_notices_in_txn(vault, wtxn, &park, input.attempt_count)?;
    let state = store
        .status_with_park_in_txn(&*wtxn, attempt)?
        .map(|(status, _)| status.attempt.state.as_str().to_owned())
        .ok_or(Error::EntityNotFound)?;
    Ok(ParkReleaseView {
        attempt: bytes_to_hex_lower(attempt.as_bytes()),
        released: park.reason,
        cause: park.cause.as_str().to_owned(),
        state,
    })
}

/// Marks each live owner's notice of `park` (lease generation `attempt_count`) seen and acknowledged for that
/// owner: the park is released for all of them. A notice that was never raised, or is gone, stays as it is.
fn resolve_notices_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    park: &DreamerParkedAttemptRecord,
    attempt_count: u32,
) -> Result<()> {
    let mut resolved = false;
    for owner in crate::policy_model::owners_in_txn(vault, &*wtxn)? {
        let id = crate::inbox::notification_id(&park_release_notice_source(
            park,
            attempt_count,
            &owner,
        ))?;
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&vault.store, &*wtxn, &id)?
        else {
            continue;
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            continue;
        }
        let mut body = decode_notification_body(&body)?;
        let reader = owner.to_hex();
        body.seen_by.insert(reader.clone(), true);
        body.acked_by.insert(reader, true);
        vault.put_notification_in_txn(wtxn, &id, &body)?;
        resolved = true;
    }
    if resolved {
        crate::batch::queue_notification_change(vault, wtxn);
    }
    Ok(())
}

fn attempt_id(text: &str) -> Result<AttemptId> {
    let text = text.trim();
    let id = EntityId::from_hex(text.strip_prefix("job:").unwrap_or(text))
        .map_err(|_| Error::InvalidConfig("attempt must be a 32-hex attempt id".to_owned()))?;
    AttemptId::from_bytes(id.as_bytes())
}
