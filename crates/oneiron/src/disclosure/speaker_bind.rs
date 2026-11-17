//! The owner's bind of one call speaker to a PERSON (UNBUILT-02-SPEAKER-BIND).
//!
//! Every kept call turn of another person carries its call ref, its speaker key and the label
//! kept with it. The owner says "this speaker of this call is PERSON P": the bind lands as a
//! private `disclosure.speaker_bind` CLAIM on the call speaker (a derived id with no row, the
//! `disclosure.import_audience` shape), so each (call, speaker) has exactly one claim and a
//! rebind rewrites it. An unbind writes the same claim with no person and never deletes it: a
//! sync tombstone would beat a later rebind on another device. The transcript shows the bound
//! name at read time; no turn is ever rewritten.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, derived_domains};
use crate::error::{Error, Result};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, Store};

use super::tier_classification::{PREDICATE_DISCLOSURE_SPEAKER_BIND, read_stored_claim_body};

/// The call-ref prefix every kept call turn carries (`voice-call:<hex>`).
const CALL_REF_PREFIX: &str = "voice-call:";
/// The most bytes a bound speaker key holds.
const SPEAKER_MAX_BYTES: usize = 128;
/// The gate receipt family's content kind for a bind act.
const SPEAKER_BIND_CONTENT_KIND: &str = "speaker_bind";

/// `vault.calls.speakers.bind`'s input: the owner names one speaker of one kept call as a
/// PERSON. A later bind replaces it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallSpeakerBindRequest {
    /// The call ref as kept on the turns, `voice-call:<hex>`.
    pub call: String,
    /// The speaker key as kept on the turns.
    pub speaker: String,
    /// The PERSON the speaker is.
    pub person: EntityId,
}

/// `vault.calls.speakers.unbind`'s input: the owner removes the PERSON named for one speaker
/// of one kept call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallSpeakerUnbindRequest {
    /// The call ref as kept on the turns, `voice-call:<hex>`.
    pub call: String,
    /// The speaker key as kept on the turns.
    pub speaker: String,
}

/// Either verb's answer: the call speaker, the PERSON it names now, and the gate decision
/// that recorded the act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallSpeakerBindReceipt {
    /// The call ref as kept on the turns.
    pub call: String,
    /// The speaker key as kept on the turns.
    pub speaker: String,
    /// The PERSON named now; `None` after an unbind.
    pub person: Option<EntityId>,
    /// The gate decision that recorded the act, 32-hex.
    #[serde(with = "decision_hex")]
    #[schemars(with = "String")]
    pub decision: GateDecisionId,
}

/// A gate decision id as 32-hex, as the gate receipts name it.
mod decision_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::store::GateDecisionId;

    pub(super) fn serialize<S: Serializer>(
        id: &GateDecisionId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&id.to_hex())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<GateDecisionId, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = oneiron_hex::decode::<16>(&text)
            .ok_or_else(|| serde::de::Error::custom("decision is 32 hex"))?;
        Ok(GateDecisionId::from_bytes(bytes))
    }
}

/// One bind claim's decoded value: the call speaker it names and the PERSON it binds, or none
/// after an unbind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SpeakerBind {
    pub call: String,
    pub speaker: String,
    pub person: Option<EntityId>,
}

/// Strict decode of a `disclosure.speaker_bind` value: the call, its speaker and the bound
/// person, in that order.
pub(super) fn decode_speaker_bind_value(value: &Value) -> Result<SpeakerBind> {
    let Value::Map(entries) = value else {
        return Err(invalid());
    };
    let [
        (call_key, call),
        (speaker_key, speaker),
        (person_key, person),
    ] = entries.as_slice()
    else {
        return Err(invalid());
    };
    if [call_key, speaker_key, person_key]
        .iter()
        .map(|key| key.as_str())
        .ne(["call", "speaker", "person"].map(Some))
    {
        return Err(invalid());
    }
    let text = |value: &Value| value.as_str().map(str::to_owned).ok_or_else(invalid);
    let call = text(call)?;
    let speaker = text(speaker)?;
    if call.trim().is_empty() || speaker.trim().is_empty() {
        return Err(invalid());
    }
    Ok(SpeakerBind {
        call,
        speaker,
        person: match person {
            Value::Nil => None,
            person => Some(decode_id(person)?),
        },
    })
}

fn speaker_bind_value(call: &str, speaker: &str, person: Option<EntityId>) -> Value {
    Value::Map(vec![
        (Value::from("call"), Value::from(call)),
        (Value::from("speaker"), Value::from(speaker)),
        (Value::from("person"), person.map_or(Value::Nil, id_value)),
    ])
}

/// The call speaker id: the claim's subject, a derived id with no row.
fn call_speaker_id(call: &str, speaker: &str) -> Result<EntityId> {
    Ok(EntityId::derive(
        derived_domains::CALL_SPEAKER,
        &[call.as_bytes(), speaker.as_bytes()],
    )?)
}

/// The bind claim id of one call speaker.
fn call_speaker_bind_claim_id(speaker_id: &EntityId) -> Result<EntityId> {
    Ok(EntityId::derive(
        derived_domains::CALL_SPEAKER_BIND,
        &[speaker_id.as_bytes()],
    )?)
}

/// The stored bind of one call speaker as `rtxn` reads it now: the decoded bind and the raw
/// value the receipt digests. `None` while no live bind claim stands there. A stored claim of
/// another predicate, a superseded one, or one naming another speaker is no bind.
fn stored_speaker_bind_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
    call: &str,
    speaker: &str,
) -> Result<Option<(SpeakerBind, Value)>> {
    let Some(body) = read_stored_claim_body(store, rtxn, claim_id)? else {
        return Ok(None);
    };
    if body.predicate != PREDICATE_DISCLOSURE_SPEAKER_BIND
        || body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Ok(None);
    }
    let bind = decode_speaker_bind_value(&body.value)?;
    if bind.call != call || bind.speaker != speaker {
        return Ok(None);
    }
    Ok(Some((bind, body.value)))
}

/// The PERSON one call speaker is bound to, `None` while unbound: the stored bind's person,
/// which an unbind left nil.
pub(crate) fn call_speaker_bind_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    call: &str,
    speaker: &str,
) -> Result<Option<EntityId>> {
    let speaker_id = call_speaker_id(call, speaker)?;
    let claim_id = call_speaker_bind_claim_id(&speaker_id)?;
    Ok(
        stored_speaker_bind_in_txn(store, rtxn, &claim_id, call, speaker)?
            .and_then(|(bind, _)| bind.person),
    )
}

/// blake3 of the msgpack encoding of one bind claim value; all zero for no value.
fn claim_value_digest(value: Option<&Value>) -> Result<[u8; 32]> {
    let Some(value) = value else {
        return Ok([0; 32]);
    };
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value).map_err(|_| invalid())?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

/// A call and speaker the owner may bind: a kept call ref and a trimmed, non-empty speaker
/// key of at most 128 bytes.
fn validate_call_speaker(call: &str, speaker: &str) -> Result<()> {
    let hex = call
        .strip_prefix(CALL_REF_PREFIX)
        .filter(|hex| EntityId::from_hex(hex).is_ok());
    if hex.is_none() {
        return Err(Error::InvalidClaimBody(
            "disclosure.speaker_bind call is voice-call:<hex>",
        ));
    }
    if speaker.trim() != speaker || speaker.is_empty() || speaker.len() > SPEAKER_MAX_BYTES {
        return Err(Error::InvalidClaimBody(
            "disclosure.speaker_bind speaker is trimmed, non-empty, and at most 128 bytes",
        ));
    }
    Ok(())
}

/// One bind or unbind act, as its receipt records it.
struct SpeakerBindAct {
    actor: EntityId,
    claim_id: EntityId,
    call: String,
    speaker: String,
    person: Option<EntityId>,
    before_digest: [u8; 32],
    after_digest: [u8; 32],
}

impl Vault {
    /// The owner names one speaker of one kept call as a PERSON. The person must be a live,
    /// unremoved, active PERSON now and is stored as stated; a later bind replaces it. Answers
    /// the receipt the act minted.
    pub fn bind_call_speaker(
        &self,
        owner: &AuthenticatedOwner,
        input: CallSpeakerBindRequest,
    ) -> Result<CallSpeakerBindReceipt> {
        self.put_call_speaker_bind(owner, input.call, input.speaker, Some(input.person))
    }

    /// The owner removes the PERSON named for one speaker of one kept call: the bind claim
    /// stays with no person. Answers the receipt the act minted.
    pub fn unbind_call_speaker(
        &self,
        owner: &AuthenticatedOwner,
        input: CallSpeakerUnbindRequest,
    ) -> Result<CallSpeakerBindReceipt> {
        self.put_call_speaker_bind(owner, input.call, input.speaker, None)
    }

    /// One bind or unbind: the owner's act lands as the call speaker's `disclosure.speaker_bind`
    /// CLAIM and one engine-minted gate receipt, in one transaction.
    fn put_call_speaker_bind(
        &self,
        owner: &AuthenticatedOwner,
        call: String,
        speaker: String,
        person: Option<EntityId>,
    ) -> Result<CallSpeakerBindReceipt> {
        validate_call_speaker(&call, &speaker)?;
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, &*txn)?;
            if let Some(person) = person
                && crate::memory::live_canonical_person_in_txn(self, &*txn, &person)?.is_none()
            {
                return Err(Error::EntityNotFound);
            }
            let speaker_id = call_speaker_id(&call, &speaker)?;
            let claim_id = call_speaker_bind_claim_id(&speaker_id)?;
            let before =
                stored_speaker_bind_in_txn(&self.store, &*txn, &claim_id, &call, &speaker)?
                    .map(|(_, value)| value);
            let before_digest = claim_value_digest(before.as_ref())?;
            let value = speaker_bind_value(&call, &speaker, person);
            let after_digest = claim_value_digest(Some(&value))?;
            let mut claim = ClaimBody::new(
                PREDICATE_DISCLOSURE_SPEAKER_BIND,
                ClaimSubject::Entity(speaker_id),
                value,
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            )?;
            // The speaker is a derived id with no row, so it has no FACET.
            claim.scope_facet = self.claim_put_facet_in_txn(txn, &claim_id)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            self.put_disclosure_claim_in_txn(txn, &claim_id, &claim, now)?;
            let decision = self.append_speaker_bind_receipt_in_txn(
                txn,
                &SpeakerBindAct {
                    actor,
                    claim_id,
                    call: call.clone(),
                    speaker: speaker.clone(),
                    person,
                    before_digest,
                    after_digest,
                },
            )?;
            Ok(CallSpeakerBindReceipt {
                call,
                speaker,
                person,
                decision,
            })
        })
    }

    /// The bind act's receipt in the existing Gate receipt family: the claim reference joins
    /// it to the bind, the after digest is its diff handle, and the before digest is the
    /// revert reference.
    fn append_speaker_bind_receipt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        act: &SpeakerBindAct,
    ) -> Result<GateDecisionId> {
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let hex = |digest: &[u8; 32]| crate::entity_id::bytes_to_hex_lower(digest);
        let receipt_reasons = vec![
            format!("call:{}", act.call),
            format!("speaker:{}", act.speaker),
            format!(
                "person:{}",
                act.person
                    .map_or_else(|| "none".to_owned(), |person| person.to_hex())
            ),
            format!("before:{}", hex(&act.before_digest)),
            format!("after:{}", hex(&act.after_digest)),
        ];
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id,
            created_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            outcome: "approved".into(),
            // The ledger takes only the gate's own reason grammar
            // (`gate.` codes; #8934 review r2 P1).
            reason_codes: vec![
                (if act.person.is_some() {
                    "gate.allow.speaker_bind"
                } else {
                    "gate.allow.speaker_unbind"
                })
                .into(),
            ],
            receipt_reasons: Vec::new(),
            system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
                SPEAKER_BIND_CONTENT_KIND,
                receipt_reasons,
            ),
            actor_class: "human".into(),
            actor_ref: Some(act.actor.to_hex()),
            content_kind: SPEAKER_BIND_CONTENT_KIND.into(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
            claim_id: None,
            grant_ref: Some(format!("speaker_bind:{}", act.claim_id.to_hex())),
            diff_handle: act.after_digest.to_vec(),
            read_frontier_hash: [0; 32],
            context: Default::default(),
            redacted_at: None,
        };
        self.store.append_gate_decision_in_txn(txn, &record)?;
        Ok(decision_id)
    }
}

fn id_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn decode_id(value: &Value) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid());
    };
    EntityId::from_bytes(bytes.as_slice().try_into().map_err(|_| invalid())?).map_err(|_| invalid())
}

fn invalid() -> Error {
    Error::InvalidClaimBody("disclosure.speaker_bind value invalid")
}
