//! Grants a backdated withdrawal voids (FIX [VOICE-WITHDRAWAL-BACKDATED-LEAVES-GRANT]; RULING
//! VOICE-BACKDATED-WITHDRAWAL-SHAPE = B, lead 21 Nov 04:3x).
//!
//! A withdrawal is never refused: "the way out never harder than the way in". It voids every
//! grant it covers that the consent log already holds dated after it, so a withdrawal logged with
//! an earlier time than the grant it answers still stops that grant from enrolling or
//! recognising. A grant recorded after the withdrawal stands on its own date. The consent log
//! keeps each event as recorded; a void is a separate row naming the grant and the withdrawal.
//! A void binds the exact events it was written for: each is named by its id and by a digest of
//! its stored encoding, so a void an owner restore brings in never reaches a different event that
//! reuses one of those ids here.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

use super::math_keys::digest16;
use super::storage_admission::{CONSENT, read_consent_event, read_consent_events};
use super::types::{VoiceConsentEventV1, VoiceConsentState, VoicePrintPurpose};

/// One grant one withdrawal voided: the grant was in the log when the withdrawal was recorded,
/// and is dated after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct VoiceConsentVoid {
    /// The voided grant's consent event id.
    pub(super) grant_event_id: String,
    /// [`consent_event_fingerprint`] of the voided grant.
    pub(super) grant_fingerprint: [u8; 16],
    /// The withdrawal's consent event id; the purposes it voids are the withdrawal's own.
    pub(super) withdrawal_event_id: String,
    /// [`consent_event_fingerprint`] of the withdrawal.
    pub(super) withdrawal_fingerprint: [u8; 16],
}

/// Voided grants. Key: subject id16 + [`consent_void_digest`].
pub(super) const CONSENT_VOID: SideTable<(EntityId, [u8; 16]), VoiceConsentVoid, Named> =
    SideTable::new(&side_table::VOICE_IDENTITY_CONSENT_VOID);

/// The key digest of one void: both fingerprints, then the length-prefixed grant id and the
/// withdrawal id, so no two voids share a digest input.
pub(super) fn consent_void_digest(void: &VoiceConsentVoid) -> [u8; 16] {
    let grant = void.grant_event_id.as_bytes();
    let mut material = Vec::with_capacity(40 + grant.len() + void.withdrawal_event_id.len());
    material.extend_from_slice(&void.grant_fingerprint);
    material.extend_from_slice(&void.withdrawal_fingerprint);
    material.extend_from_slice(&(grant.len() as u64).to_be_bytes());
    material.extend_from_slice(grant);
    material.extend_from_slice(void.withdrawal_event_id.as_bytes());
    digest16(b"voice_identity.consent_void", &material)
}

/// The digest of one consent event's stored encoding: two events with one id and any other
/// difference (date, purposes, basis, recorder, state) have different fingerprints.
fn consent_event_fingerprint(event: &VoiceConsentEventV1) -> Result<[u8; 16]> {
    Ok(digest16(
        b"voice_identity.consent_void.event",
        &CONSENT.encode_value(event)?,
    ))
}

/// In the withdrawal's own write, after its first insertion: voids every grant of its subject
/// that covers one of its purposes and is dated after it. A grant dated at or before it needs no
/// row: [`grant_withdrawn_for`] reads that from the dates.
pub(super) fn void_later_dated_grants_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    withdrawal: &VoiceConsentEventV1,
) -> Result<()> {
    let withdrawal_fingerprint = consent_event_fingerprint(withdrawal)?;
    let voided = read_consent_events(store, txn, &withdrawal.subject_ref)?
        .into_iter()
        .filter(|grant| {
            grant.state == VoiceConsentState::Granted
                && grant.occurred_at > withdrawal.occurred_at
                && grant
                    .purposes
                    .iter()
                    .any(|purpose| withdrawal.covers(purpose))
        })
        .map(|grant| -> Result<VoiceConsentVoid> {
            Ok(VoiceConsentVoid {
                grant_fingerprint: consent_event_fingerprint(&grant)?,
                grant_event_id: grant.event_id,
                withdrawal_event_id: withdrawal.event_id.clone(),
                withdrawal_fingerprint,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for void in &voided {
        let key = (withdrawal.subject_ref, consent_void_digest(void));
        CONSENT_VOID.put(store, txn, &key, void)?;
    }
    Ok(())
}

/// Whether `grant` no longer grants `purpose`: a withdrawal covering it is dated at or after the
/// grant, or a withdrawal covering it voided the grant when it was recorded. A void applies only
/// while both events it names are stored exactly as it fingerprinted them.
pub(super) fn grant_withdrawn_for(
    store: &Store,
    rtxn: &RoTxn<'_>,
    grant: &VoiceConsentEventV1,
    purpose: &VoicePrintPurpose,
) -> Result<bool> {
    let subject = &grant.subject_ref;
    let dated_after = read_consent_events(store, rtxn, subject)?
        .into_iter()
        .any(|later| {
            later.state == VoiceConsentState::Withdrawn
                && later.covers(purpose)
                && later.occurred_at >= grant.occurred_at
        });
    if dated_after {
        return Ok(true);
    }
    let grant_fingerprint = consent_event_fingerprint(grant)?;
    for (_, void) in CONSENT_VOID.scan_from(store, rtxn, subject.as_bytes())? {
        if void.grant_event_id != grant.event_id || void.grant_fingerprint != grant_fingerprint {
            continue;
        }
        let Some(withdrawal) = read_consent_event(store, rtxn, subject, &void.withdrawal_event_id)?
        else {
            continue;
        };
        if withdrawal.state == VoiceConsentState::Withdrawn
            && withdrawal.covers(purpose)
            && consent_event_fingerprint(&withdrawal)? == void.withdrawal_fingerprint
        {
            return Ok(true);
        }
    }
    Ok(false)
}
