//! Doors for the peer-redaction refusal test (ARCH-0055 author-carrier-open):
//! this vault's own author carrier for a held decision, a peer's actorless
//! redaction landed through the replicated type-76 door, and the decisions
//! the effective identity fold holds in force.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimApprovalStatus;
use crate::identity_topology::{StoredIdentityOpAction, StoredIdentityOpEvent};
use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, Vault};

/// The lease stream a peer's type-76 rows arrive on.
const PEER_LEASE_VAULT_ID: u64 = 7;

fn held_decision_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<(StoredIdentityOpEvent, [u8; 32])> {
    let core =
        vault
            .identity_topology_event_in_txn(rtxn, &target)?
            .ok_or(Error::CorruptedIndex(
                "peer redaction door: no held decision",
            ))?;
    let digest = crate::identity_topology::core_digest(&core)?;
    Ok((core, digest))
}

/// Writes this vault's own author carrier for the held decision `target`,
/// naming `actor`, as the local decision door does in its transaction, but
/// without the door's class check: the state a bound author whose class does
/// not fit its entity leaves, which the fold reads as an observed admission
/// failure. Returns the carrier's id.
pub fn put_own_author_attribution(
    vault: &Vault,
    target: EntityId,
    actor: WriteActor,
    now: u64,
) -> Result<EntityId> {
    vault.with_write_txn(|wtxn| {
        let (core, digest) = held_decision_in_txn(vault, wtxn, target)?;
        crate::identity_topology::record_author_attribution_in_txn(
            vault,
            wtxn,
            target,
            digest,
            actor,
            core.source,
            now,
        )?
        .ok_or(Error::CorruptedIndex(
            "peer redaction door: the decision is already redacted",
        ))
    })
}

/// Lands a peer's actorless `AuthorRedaction` of the held decision `target`
/// through the replicated type-76 door, as Observer B's entity pass does for
/// a row of the peer's stream. `seq` is the peer's stamp. Returns whether the
/// row landed fresh.
pub fn ingest_peer_author_redaction(
    vault: &Vault,
    target: EntityId,
    seq: u64,
    at: u64,
) -> Result<bool> {
    let id = EntityId::now();
    vault.with_write_txn(|wtxn| {
        let (core, core_digest) = held_decision_in_txn(vault, wtxn, target)?;
        let record = StoredIdentityOpEvent {
            seq,
            validated_at_write: true,
            invalidated: false,
            at,
            actor: None,
            source: core.source,
            approval: ClaimApprovalStatus::Auto,
            confidence: 1.0,
            evidence: None,
            action: StoredIdentityOpAction::AuthorRedaction {
                target,
                core_digest,
            },
        };
        let body = crate::identity_topology::encode_identity_topology_event_body(&record)?;
        let mut blob = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
        blob.push(ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT);
        blob.extend_from_slice(&at.to_be_bytes());
        blob.extend_from_slice(&at.to_be_bytes());
        blob.extend_from_slice(&at.to_be_bytes());
        // The row version: zero on every native kind but a CLAIM.
        blob.extend_from_slice(&0_u64.to_be_bytes());
        blob.extend_from_slice(&body);
        let header = EntityMetadataHeader::parse(&blob)
            .ok_or(Error::CorruptedIndex("peer redaction door: row header"))?;
        let window_key = crate::sync::types::WindowKey::from_timestamp(at);
        crate::sync::bridge::ingest_replicated_identity_topology_event_in_txn(
            vault,
            wtxn,
            &id,
            &header,
            (&blob, window_key.0.as_str()),
            &blob[ENTITY_METADATA_HEADER_LEN..],
            PEER_LEASE_VAULT_ID,
        )
    })
}

/// The decisions the effective identity fold holds in force, by event id.
pub fn effective_identity_events(vault: &Vault) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .fold_effective_identity_topology_events_in_txn(&rtxn)?
        .into_iter()
        .map(|event| event.event_id)
        .collect())
}
