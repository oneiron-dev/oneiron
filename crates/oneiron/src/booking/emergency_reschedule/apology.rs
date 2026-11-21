//! The emergency apology's two texts (FIX [BK-EMERGENCY-APOLOGY-BLOB-HOLDS-RAW-PICK-TOKENS]; lead
//! ruling BK-EMERGENCY-APOLOGY-BLOB-TOKENS-SEALED = B, 21 Nov 15:1x).
//! Entry: `apology_send_content_in`.
//! Defines its own items.
//!
//! The owner keeps a readable copy of each apology on every device: the blob artifact the
//! owner's run writes ([`apology_bytes`]), which sync carries with its body. It names each pick
//! link by the digest its `booking.token.v1:` pick row is keyed by, labelled as the link sent to
//! the booker, so no synced copy holds a bearer link. The booker's text holds the raw links
//! ([`sent_apology_bytes`]): the home builds it from its checkpoint only when that apology's own
//! send goes ([`emergency_apology_send_text`]), and stores it nowhere. A blob an earlier build
//! wrote with the raw links is released wherever a node holding the checkpoint's links meets it
//! ([`release_raw_apology_in`]): its `blob.version` claim goes as a released version's does, so
//! its body leaves every machine sync carried it to.

use heed::{RoTxn, RwTxn};

use super::*;

/// The action the owner's copy names a pick link by: the token's digest, in hex.
const PICK_DIGEST_ACTION_PREFIX: &str = "booking:emergency-pick-digest:";

/// A raw pick link in the booker's text.
const PICK_ACTION_PREFIX: &str = "booking:emergency-pick:";

/// The lane of the apology's send (`state::effect_ref`).
const APOLOGY_LANE: &str = "apology";

/// The owner's copy of `item`'s apology, the body of the blob artifact the owner's run writes:
/// the reason, and each proposal with its pick link named by the token's digest and labelled as
/// the link sent to the booker (the booker contact's ref). It holds no bearer link.
pub(super) fn apology_bytes(item: &EmergencyItem) -> Result<Vec<u8>, BookingError> {
    let label = format!("link sent to {}", item.plan.booking.context.booker_ref);
    serde_json::to_vec(&serde_json::json!({ "reason": item.plan.request.reason,
        "actions": item.actions.iter().zip(&item.plan.proposals).map(|(token, slot)| {
            let digest = crate::booking::lifecycle::emergency_action_digest(token);
            serde_json::json!({
                "action": format!("{PICK_DIGEST_ACTION_PREFIX}{}", hex_lower(&digest)),
                "label": label,
                "proposal": slot,
            })
        }).collect::<Vec<_>>() }))
    .map_err(storage_failure)
}

/// The booker's text of `item`'s apology: the reason, and each proposal with its raw pick link.
/// Byte for byte the body earlier builds wrote as the apology's blob.
pub(super) fn sent_apology_bytes(item: &EmergencyItem) -> Result<Vec<u8>, BookingError> {
    serde_json::to_vec(&serde_json::json!({ "reason": item.plan.request.reason,
        "actions": item.actions.iter().zip(&item.plan.proposals).map(|(token, slot)| serde_json::json!({
            "action": format!("{PICK_ACTION_PREFIX}{}", token.0), "proposal": slot
        })).collect::<Vec<_>>() }))
    .map_err(storage_failure)
}

/// The `blob:` content ref of the content-addressed artifact holding `bytes`.
pub(super) fn apology_content_ref(bytes: &[u8]) -> Result<String, BookingError> {
    Ok(format!("blob:{}", blob_id(bytes)?.to_hex()))
}

/// The content ref the owner's run sends `item`'s apology with, in the run's write `txn`. The
/// ref an earlier build froze on the send's current ledger row, when that is the raw body's: the
/// row is sent again as it was admitted, and its text still comes from the checkpoint. Else the
/// owner's copy ([`apology_bytes`]), written here as `name`. A raw body an earlier build wrote
/// goes first ([`release_raw_apology_in`]).
pub(super) fn apology_send_content_in(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    request: &EmergencyRescheduleRequest,
    item: &EmergencyItem,
    name: &str,
) -> Result<String, BookingError> {
    release_raw_apology_in(vault, txn, item)?;
    let raw = apology_content_ref(&sent_apology_bytes(item)?)?;
    let generation = state::ledger_generation(item, APOLOGY_LANE);
    if let Some(record) = state::ledger_record_in(
        vault,
        txn,
        item,
        APOLOGY_LANE,
        item.plan.content_hash,
        generation,
    )? && serde_json::from_slice::<serde_json::Value>(record.payload())
        .is_ok_and(|frozen| frozen["content_ref"].as_str() == Some(raw.as_str()))
    {
        return Ok(raw);
    }
    persist_content_in(
        vault,
        txn,
        request,
        name,
        "application/json",
        &apology_bytes(item)?,
        item.committed_at,
    )
}

/// Which of `item`'s apology contents `content_ref` names: the owner's copy, the raw body a send
/// an earlier build froze, or neither.
pub(super) fn apology_content_of(
    item: &EmergencyItem,
    content_ref: &str,
) -> Result<ApologyContent, BookingError> {
    if content_ref == apology_content_ref(&apology_bytes(item)?)? {
        return Ok(ApologyContent::OwnerCopy);
    }
    if content_ref == apology_content_ref(&sent_apology_bytes(item)?)? {
        return Ok(ApologyContent::FrozenRawBody);
    }
    Ok(ApologyContent::Other)
}

/// Which of an item's apology contents a send's content ref names ([`apology_content_of`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ApologyContent {
    /// The owner's copy, a blob this home wrote.
    OwnerCopy,
    /// The raw body a send an earlier build froze; the blob itself may be released.
    FrozenRawBody,
    /// Neither.
    Other,
}

/// The text the emergency apology's own send carries: [`sent_apology_bytes`] of the checkpoint
/// this home holds whose apology effect `intent_ref` names, when `content_ref` is that
/// apology's content ([`apology_content_of`]) and `target` its booker. `None` for any other
/// send. A send that names an emergency apology this node cannot fill (not the home, no such
/// checkpoint, its links dropped after a move, another content or recipient) is refused, so
/// neither the owner's copy nor another text goes in its place, and no other send can carry the
/// raw links.
pub(crate) fn emergency_apology_send_text(
    vault: &Vault,
    intent_ref: &str,
    target: &str,
    content_ref: &str,
) -> Result<Option<String>, BookingError> {
    if !(intent_ref.starts_with("intent:booking_emergency:")
        && intent_ref.ends_with(&format!(":{APOLOGY_LANE}")))
    {
        return Ok(None);
    }
    let txn = vault.store.custody_snapshot().map_err(storage_failure)?;
    let item = apology_item_in(vault, &txn, intent_ref)?
        .ok_or_else(|| refused("emergency apology has no checkpoint on this node"))?;
    verify_owner_home_in(vault, &txn, item.plan.request.owner_ref)?;
    if target != item.plan.recipient {
        return Err(refused("emergency apology names another recipient"));
    }
    if item.actions.is_empty() {
        return Err(refused(
            "this node holds no pick link of the emergency apology",
        ));
    }
    if apology_content_of(&item, content_ref)? == ApologyContent::Other {
        return Err(refused(
            "emergency apology content differs from its checkpoint",
        ));
    }
    String::from_utf8(sent_apology_bytes(&item)?)
        .map(Some)
        .map_err(storage_failure)
}

/// The checkpoint here whose apology effect `intent_ref` names.
fn apology_item_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    intent_ref: &str,
) -> Result<Option<EmergencyItem>, BookingError> {
    for item in items_in(vault, txn)? {
        if state::effect_ref(&item, APOLOGY_LANE, item.plan.content_hash)? == intent_ref {
            return Ok(Some(item));
        }
    }
    Ok(None)
}

/// The raw body an earlier build wrote as `item`'s apology ([`sent_apology_bytes`]): its
/// artifact, its content hash, and the live `blob.version` claims here that name that artifact
/// holding those bytes. None for a checkpoint with no links left (a former home after the ack).
fn raw_apology_claims_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    item: &EmergencyItem,
) -> Result<Option<(EntityId, [u8; 32], Vec<EntityId>)>, BookingError> {
    if item.actions.is_empty() {
        return Ok(None);
    }
    let bytes = sent_apology_bytes(item)?;
    let artifact = blob_id(&bytes)?;
    let hash = *blake3::hash(&bytes).as_bytes();
    let mut claims = Vec::new();
    for claim in vault
        .claims_for_subject_in_txn(txn, &artifact)
        .map_err(boundary)?
    {
        if crate::blob_artifact::live_version_claim_reference(&vault.store, txn, &claim)
            .map_err(boundary)?
            == Some((artifact, hash))
        {
            claims.push(claim);
        }
    }
    Ok(Some((artifact, hash, claims)))
}

/// Releases the blob an earlier build wrote as `item`'s apology with the raw pick links, as far
/// as this vault holds it, in `txn`: each live `blob.version` claim naming those bytes goes with
/// the version it records (`release_claimed_version_in_txn`), on a node holding the version
/// chain or a replica holding the claim alone. The claim's erase replicates, so every machine
/// sync carried the body to drops it, unless another holder or a legal hold keeps it. Nothing
/// for a checkpoint with no links left or a vault holding no such claim.
pub(super) fn release_raw_apology_in(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    item: &EmergencyItem,
) -> Result<(), BookingError> {
    let Some((artifact, hash, claims)) = raw_apology_claims_in(vault, txn, item)? else {
        return Ok(());
    };
    let write = crate::secret_custody::CustodyWrite::of(vault);
    for claim in claims {
        crate::blob_artifact::release_claimed_version_in_txn(&write, txn, &claim, &artifact, &hash)
            .map_err(boundary)?;
    }
    Ok(())
}

/// [`release_raw_apology_in`] for every checkpoint here that still holds its links.
pub(super) fn release_raw_apologies_in(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
) -> Result<(), BookingError> {
    for item in items_in(vault, txn)? {
        release_raw_apology_in(vault, txn, &item)?;
    }
    Ok(())
}

/// The release of every raw apology body an earlier build wrote ([`release_raw_apologies_in`])
/// at vault open: the scrub of the copies sync already carried, run once a node holding the
/// checkpoints opens on this build, and again on a later open while one stays (a claim that
/// reached this node after the last open). Reads first and writes only when a release is due;
/// an archived image is left as it is.
pub(crate) fn release_raw_apologies_on_open(vault: &Vault) -> crate::error::Result<()> {
    let due = {
        let txn = vault.store.env.read_txn()?;
        if vault.store.archived_in_txn(&txn)? {
            return Ok(());
        }
        let mut due = false;
        for item in items_in(vault, &txn).map_err(open_failure)? {
            if raw_apology_claims_in(vault, &txn, &item)
                .map_err(open_failure)?
                .is_some_and(|(_, _, claims)| !claims.is_empty())
            {
                due = true;
                break;
            }
        }
        due
    };
    if due {
        vault.with_write_txn_grouped(|txn| {
            release_raw_apologies_in(vault, txn).map_err(open_failure)
        })?;
    }
    Ok(())
}

fn open_failure(error: BookingError) -> crate::error::Error {
    crate::error::Error::InvalidConfig(error.to_string())
}

/// Every checkpoint here that decodes.
fn items_in(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<EmergencyItem>, BookingError> {
    let mut items = Vec::new();
    for key in planning::ITEM
        .scan_keys(&vault.store, txn, &[])
        .map_err(storage_failure)?
    {
        if let Some(item) = planning::ITEM
            .get_lenient(&vault.store, txn, &key)
            .map_err(storage_failure)?
        {
            items.push(item);
        }
    }
    Ok(items)
}

fn boundary(error: crate::error::Error) -> BookingError {
    BookingError::Boundary(Box::new(error.into()))
}

/// The blob an earlier build wrote as `item`'s apology, written again on this home: the booker's
/// text with the raw links ([`sent_apology_bytes`]), as the owner's run wrote it before this fix.
/// Its `blob:` content ref. For the tests of the scrub of such blobs.
#[cfg(oneiron_test_support)]
pub(crate) fn write_raw_apology_for_doors(
    vault: &Vault,
    request: &EmergencyRescheduleRequest,
    item: &EmergencyItem,
) -> Result<String, BookingError> {
    let bytes = sent_apology_bytes(item)?;
    booking_writer(vault, |txn| {
        persist_content_in(
            vault,
            txn,
            request,
            &item.plan.booking.event_type.0,
            "application/json",
            &bytes,
            item.committed_at,
        )
    })
}
