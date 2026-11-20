//! Grants a backdated withdrawal voids (FIX [VOICE-WITHDRAWAL-BACKDATED-LEAVES-GRANT]; RULING
//! VOICE-BACKDATED-WITHDRAWAL-SHAPE = B, lead 21 Nov 04:3x).
//!
//! A withdrawal is never refused: "the way out never harder than the way in". It voids every
//! grant it covers that the consent log already holds dated after it, so a withdrawal logged with
//! an earlier time than the grant it answers still stops that grant from enrolling or
//! recognising. A grant recorded after the withdrawal stands on its own date. The consent log
//! keeps each event as recorded; a void is a separate row naming the grant and the withdrawal.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

use super::math_keys::digest16;
use super::storage_admission::{read_consent_event, read_consent_events};
use super::types::{VoiceConsentEventV1, VoiceConsentState, VoicePrintPurpose};

/// One grant one withdrawal voided: the grant was in the log when the withdrawal was recorded,
/// and is dated after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct VoiceConsentVoid {
    /// The voided grant's consent event id.
    pub(super) grant_event_id: String,
    /// The withdrawal's consent event id; the purposes it voids are the withdrawal's own.
    pub(super) withdrawal_event_id: String,
}

/// Voided grants. Key: subject id16 + [`consent_void_digest`].
pub(super) const CONSENT_VOID: SideTable<(EntityId, [u8; 16]), VoiceConsentVoid, Named> =
    SideTable::new(&side_table::VOICE_IDENTITY_CONSENT_VOID);

/// The key digest of one (grant, withdrawal) pair; the grant id is length-prefixed so no two
/// pairs share a digest input.
pub(super) fn consent_void_digest(void: &VoiceConsentVoid) -> [u8; 16] {
    let grant = void.grant_event_id.as_bytes();
    let mut material = Vec::with_capacity(8 + grant.len() + void.withdrawal_event_id.len());
    material.extend_from_slice(&(grant.len() as u64).to_be_bytes());
    material.extend_from_slice(grant);
    material.extend_from_slice(void.withdrawal_event_id.as_bytes());
    digest16(b"voice_identity.consent_void", &material)
}

/// In the withdrawal's own write, after its first insertion: voids every grant of its subject
/// that covers one of its purposes and is dated after it. A grant dated at or before it needs no
/// row: [`grant_withdrawn_for`] reads that from the dates.
pub(super) fn void_later_dated_grants_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    withdrawal: &VoiceConsentEventV1,
) -> Result<()> {
    let voided: Vec<VoiceConsentVoid> = read_consent_events(store, txn, &withdrawal.subject_ref)?
        .into_iter()
        .filter(|grant| {
            grant.state == VoiceConsentState::Granted
                && grant.occurred_at > withdrawal.occurred_at
                && grant
                    .purposes
                    .iter()
                    .any(|purpose| withdrawal.covers(purpose))
        })
        .map(|grant| VoiceConsentVoid {
            grant_event_id: grant.event_id,
            withdrawal_event_id: withdrawal.event_id.clone(),
        })
        .collect();
    for void in &voided {
        let key = (withdrawal.subject_ref, consent_void_digest(void));
        CONSENT_VOID.put(store, txn, &key, void)?;
    }
    Ok(())
}

/// Whether `grant` no longer grants `purpose`: a withdrawal covering it is dated at or after the
/// grant, or a withdrawal covering it voided the grant when it was recorded.
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
    for (_, void) in CONSENT_VOID.scan_from(store, rtxn, subject.as_bytes())? {
        if void.grant_event_id != grant.event_id {
            continue;
        }
        let voided = read_consent_event(store, rtxn, subject, &void.withdrawal_event_id)?
            .is_some_and(|withdrawal| {
                withdrawal.state == VoiceConsentState::Withdrawn && withdrawal.covers(purpose)
            });
        if voided {
            return Ok(true);
        }
    }
    Ok(false)
}
