//! A voice's render history (FIX 4396). Every render decision recorded for
//! a voice is kept once, in the transaction that records it, and never
//! rewritten: the decision, its revision and sequence, and the target
//! pointers it dropped. The voice's current decision stays the projection
//! the bank fences on. An event is named by its voice and its own event id,
//! never by when it was made or by the call that recorded it, so a replay
//! of a recorded decision answers its original receipt and evicts nothing,
//! however many decisions came after it. The history is erased with the
//! bank, under the same subject or creator the projection is indexed by; a
//! render withdrawal keeps it.
use serde::{Deserialize, Serialize};

use super::owner_acts::{VoiceRenderConsentView, VoiceTargetCloneView};
use super::{
    BankRow, OWNER_INDEX, RENDER_CONSENT, RENDER_EVENTS, TARGETS, VoiceRenderConsent,
    VoiceRenderDecision, VoiceTargetRecord, invalid, read_identity, read_row, valid_id,
};
use crate::error::{Error, Result};
use crate::side_table::SideKey;
use crate::voice_identity::VoiceConsentState;

/// [`RENDER_EVENTS`]' key: the voice id and the event id, joined by a NUL
/// neither may contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RenderEventKey {
    voice_id: String,
    event_id: String,
}

impl RenderEventKey {
    fn new(voice_id: &str, event_id: &str) -> Result<Self> {
        valid_id(voice_id)?;
        valid_id(event_id)?;
        Ok(Self {
            voice_id: voice_id.into(),
            event_id: event_id.into(),
        })
    }
}

/// The key bytes every row of `voice_id` starts with, in a table keyed by
/// the voice id and a NUL: its events here, its target pointers in
/// [`TARGETS`].
fn voice_prefix(voice_id: &str) -> Vec<u8> {
    let mut prefix = voice_id.as_bytes().to_vec();
    prefix.push(0);
    prefix
}

impl SideKey for RenderEventKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.voice_id.as_bytes());
        out.push(0);
        out.extend_from_slice(self.event_id.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let split = bytes.iter().position(|byte| *byte == 0)?;
        Some(Self {
            voice_id: String::decode_key(&bytes[..split])?,
            event_id: String::decode_key(&bytes[split + 1..])?,
        })
    }
}

/// One recorded render decision, as the bank keeps it: the decision with its
/// revision and sequence, and each target pointer it dropped from the bank.
/// What the vendors did with those clones happens after the decision commits
/// and is not kept here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderEventReceipt {
    pub consent: VoiceRenderConsent,
    pub evicted: Vec<VoiceTargetRecord>,
}

/// What recording a render decision did: its event's receipt, whether the
/// decision was already recorded under its event id, and the target
/// pointers this call dropped. A replay drops none, so no caller deletes a
/// vendor's clone, or evicts a later target, twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceRenderConsentWrite {
    pub receipt: VoiceRenderEventReceipt,
    pub replayed: bool,
    pub newly_evicted: Vec<VoiceTargetRecord>,
}

/// One render decision in a voice's history, metadata only: the decision as
/// [`VoiceRenderConsentView`] shows it, with its revision and sequence, and
/// each target clone it dropped. No reference audio, transcript or provider
/// configuration, and no vendor's deletion outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceRenderEventView {
    pub voice_id: String,
    pub decision: VoiceRenderConsentView,
    /// The target pointers this decision dropped from the bank: a
    /// withdrawal's, else none.
    pub dropped: Vec<VoiceDroppedTargetView>,
}

/// A target pointer a render decision dropped: the target and its clone as
/// the bank held it then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceDroppedTargetView {
    pub target: String,
    pub held: VoiceTargetCloneView,
}

impl From<VoiceRenderEventReceipt> for VoiceRenderEventView {
    fn from(receipt: VoiceRenderEventReceipt) -> Self {
        Self {
            voice_id: receipt.consent.decision.voice_id.clone(),
            decision: VoiceRenderConsentView::from(receipt.consent),
            dropped: receipt
                .evicted
                .into_iter()
                .map(|record| VoiceDroppedTargetView {
                    target: record.target.clone(),
                    held: VoiceTargetCloneView::from(record),
                })
                .collect(),
        }
    }
}

/// The voice's current render decision, granted or withdrawn.
pub(super) fn read_render_consent(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    voice_id: &str,
) -> Result<Option<VoiceRenderConsent>> {
    valid_id(voice_id)?;
    let Some(consent) = read_row(
        RENDER_CONSENT,
        store,
        txn,
        &voice_id.to_owned(),
        "corrupt voice render consent",
    )?
    else {
        return Ok(None);
    };
    if consent.version != 1 || consent.decision.voice_id != voice_id || consent.sequence == 0 {
        return Err(invalid("corrupt voice render consent"));
    }
    Ok(Some(consent))
}

/// One recorded event, checked against its key.
fn read_event(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    key: &RenderEventKey,
) -> Result<Option<VoiceRenderEventReceipt>> {
    let Some(receipt) = read_row(RENDER_EVENTS, store, txn, key, "corrupt voice render event")?
    else {
        return Ok(None);
    };
    check_event(key, &receipt)?;
    Ok(Some(receipt))
}

fn check_event(key: &RenderEventKey, receipt: &VoiceRenderEventReceipt) -> Result<()> {
    let decision = &receipt.consent.decision;
    if receipt.consent.version != 1
        || receipt.consent.sequence == 0
        || decision.voice_id != key.voice_id
        || decision.event_id != key.event_id
    {
        return Err(invalid("corrupt voice render event"));
    }
    Ok(())
}

/// Refuses unless `decision` names the voice's subject, and its kind, as the
/// bank holds them: its identity's, and its current decision's.
fn bind_decision_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    decision: &VoiceRenderDecision,
    current: Option<&VoiceRenderConsent>,
) -> Result<()> {
    let held = read_identity(store, txn, &decision.voice_id)?
        .map(|identity| (identity.owner, identity.subject_kind))
        .into_iter()
        .chain(current.map(|consent| (consent.decision.subject, consent.decision.subject_kind)));
    for (subject, kind) in held {
        if subject != decision.subject {
            return Err(invalid("voice identity owner mismatch"));
        }
        if kind != decision.subject_kind {
            return Err(invalid(
                "a voice's kind is bound when the bank first holds it: a person's voice stays a \
                 person's, a designed voice stays designed",
            ));
        }
    }
    Ok(())
}

/// [`crate::Vault::record_voice_render_consent`]'s write of a validated
/// `decision`, in `txn`, which it commits when the decision is new. Its
/// caller holds the ref guard's write lock. The decision's event and the
/// voice's current decision are written together, each indexed under the
/// decision's subject, so an erase finds both.
pub(super) fn record_render_consent_in(
    store: &crate::store::Store,
    mut txn: heed::RwTxn<'_>,
    decision: &VoiceRenderDecision,
) -> Result<VoiceRenderConsentWrite> {
    let current = read_render_consent(store, &txn, &decision.voice_id)?;
    bind_decision_in(store, &txn, decision, current.as_ref())?;
    // An event is its voice's and its id's, whenever it is replayed.
    let key = RenderEventKey::new(&decision.voice_id, &decision.event_id)?;
    if let Some(receipt) = read_event(store, &txn, &key)? {
        if receipt.consent.decision == *decision {
            return Ok(VoiceRenderConsentWrite {
                receipt,
                replayed: true,
                newly_evicted: Vec::new(),
            });
        }
        return Err(invalid(
            "voice render consent event id already names another decision",
        ));
    }
    if current
        .as_ref()
        .is_some_and(|current| current.decision.occurred_at > decision.occurred_at)
    {
        return Err(invalid("a later voice render decision is recorded"));
    }
    let sequence = match &current {
        Some(current) => current
            .sequence
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("voice render sequence"))?,
        None => 1,
    };
    let consent = VoiceRenderConsent {
        version: 1,
        decision: decision.clone(),
        revision: uuid::Uuid::new_v4().into_bytes(),
        sequence,
    };
    let mut evicted = Vec::new();
    if decision.state == VoiceConsentState::Withdrawn {
        let prefix = voice_prefix(&decision.voice_id);
        for key in TARGETS.scan_keys(store, &txn, &prefix)? {
            // A corrupt pointer is dropped all the same.
            if let Ok(Some(record)) =
                read_row(TARGETS, store, &txn, &key, "corrupt voice target clone")
            {
                evicted.push(record);
            }
            TARGETS.delete(store, &mut txn, &key)?;
            OWNER_INDEX.delete(
                store,
                &mut txn,
                &(decision.subject, TARGETS.key_bytes(&key)),
            )?;
        }
    }
    let receipt = VoiceRenderEventReceipt { consent, evicted };
    RENDER_EVENTS.put(store, &mut txn, &key, &receipt)?;
    BankRow::RenderEvent(key).index(store, &mut txn, decision.subject)?;
    RENDER_CONSENT.put(store, &mut txn, &decision.voice_id, &receipt.consent)?;
    BankRow::Consent(decision.voice_id.clone()).index(store, &mut txn, decision.subject)?;
    txn.commit()?;
    let newly_evicted = receipt.evicted.clone();
    Ok(VoiceRenderConsentWrite {
        receipt,
        replayed: false,
        newly_evicted,
    })
}

/// Every recorded render decision of `voice_id`, in sequence order, read in
/// `txn`: empty for a voice the bank keeps no history of.
pub(super) fn voice_render_lineage_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    voice_id: &str,
) -> Result<Vec<VoiceRenderEventReceipt>> {
    valid_id(voice_id)?;
    let prefix = voice_prefix(voice_id);
    let mut events = Vec::new();
    for (key, receipt) in RENDER_EVENTS.scan_from(store, txn, &prefix)? {
        check_event(&key, &receipt)?;
        events.push(receipt);
    }
    events.sort_by_key(|receipt| receipt.consent.sequence);
    Ok(events)
}
