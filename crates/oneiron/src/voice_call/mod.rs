//! Transcripts of voice calls with other people (UNBUILT-02 PR 3; Engine
//! ruling VOICE-CALL-SCOPE, corrected 15 Nov 22:53). A phone call is kept
//! like any other conversation, under the owner's own Setting: the engine
//! sets no legal limit, since recording-consent rules differ by place and
//! bind the vault's owner, who chooses. The keys live in the Setting
//! catalogue ([`setting_keys`]); the server reads them when a call opens.
//! With `voice.call_transcripts.announce` on, the agent opens the call by
//! saying it is transcribed (UNBUILT-02 PR 3B).
//!
//! Each phone thread's CONVERSATION carries its line agent's mark
//! ([`PHONE_LINE_AGENT_KEY`]), and the line agent holds a witness-read grant
//! over it from its first kept turn (owner ruling 16 Nov 00:44; this replaces
//! PHONE-CALL-READ-GRANT = B for phone threads).

pub mod reach;
pub mod setting_keys;

pub use reach::PhoneReach;

use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::{MemoryResult, WitnessReceipt, WitnessTurn};
use crate::setting::SettingScope;

/// The door-owned CONVERSATION body key naming a phone thread's line agent:
/// the agent's id as a 32-char lower hex string. Only the phone keep path
/// stamps it, when the base witness landing mints the conversation; it is a
/// birth fact after that (VOICE-PHONE-AGENT-REACH R1).
pub(crate) const PHONE_LINE_AGENT_KEY: &str = "phone_line_agent";

/// The line agent a phone thread's CONVERSATION body names, if any: `None`
/// for a non-map body, a missing key, or a value that is not one 32-hex
/// string.
pub(crate) fn phone_thread_agent(body: &[u8]) -> Option<EntityId> {
    let mut cursor = body;
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut cursor) else {
        return None;
    };
    if !cursor.is_empty() {
        return None;
    }
    let mut found = None;
    for (key, value) in &fields {
        if key.as_str() != Some(PHONE_LINE_AGENT_KEY) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        let Some(text) = value.as_str() else {
            return None;
        };
        let id = EntityId::from_hex(text).ok()?;
        if id.to_hex() != text {
            return None;
        }
        found = Some(id);
    }
    found
}

/// The TURN/MESSAGE/SESSION body key naming a phone row's thread: the thread's
/// CONVERSATION id as a 32-char lower hex string. Only the phone keep path
/// stamps it, when the base witness landing mints the TURN and every MESSAGE,
/// and when the thread SESSION is minted; it is a birth fact after that
/// (VOICE-PHONE-AGENT-REACH R1 fix). The CONVERSATION itself keeps
/// [`PHONE_LINE_AGENT_KEY`] unchanged.
/// The literal must match `oneiron-store`'s MESSAGE codec (`PHONE_THREAD_KEY`
/// there); both encoders append the key last with the same map-header rewrite.
pub(crate) const PHONE_THREAD_KEY: &str = "phone_thread";

/// The thread a phone TURN, MESSAGE or SESSION body names, if any: `None`
/// for a non-map body, a missing key, or a value that is not one canonical
/// 32-hex string (a duplicate key, a non-string value, invalid or
/// non-canonical hex, trailing bytes).
pub(crate) fn phone_thread_stamp(body: &[u8]) -> Option<EntityId> {
    let mut cursor = body;
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut cursor) else {
        return None;
    };
    if !cursor.is_empty() {
        return None;
    }
    let mut found = None;
    for (key, value) in &fields {
        if key.as_str() != Some(PHONE_THREAD_KEY) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        let Some(text) = value.as_str() else {
            return None;
        };
        let id = EntityId::from_hex(text).ok()?;
        if id.to_hex() != text {
            return None;
        }
        found = Some(id);
    }
    found
}

/// `body`, a MessagePack map that does not carry [`PHONE_THREAD_KEY`], with
/// the key appended last as `thread`'s 32-char lower hex. The map's own
/// entries keep their exact bytes; only its length header is rewritten (the
/// same algorithm as `encode_source_audience_required`).
///
/// # Errors
///
/// [`crate::error::Error::InvariantViolation`] when `body` is not exactly one
/// MessagePack map, or already carries the key in any shape.
pub(crate) fn stamp_phone_thread(body: &[u8], thread: EntityId) -> Result<Vec<u8>> {
    let refused = || {
        crate::error::Error::InvariantViolation("a phone-thread stamp goes on one unstamped map")
    };
    let mut cursor = body;
    let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut cursor) else {
        return Err(refused());
    };
    if !cursor.is_empty() {
        return Err(refused());
    }
    for (key, _) in &entries {
        if key.as_str() == Some(PHONE_THREAD_KEY) {
            return Err(refused());
        }
    }
    let header = match body.first() {
        Some(0x80..=0x8f) => 1,
        Some(0xde) => 3,
        Some(0xdf) => 5,
        _ => return Err(refused()),
    };
    let len = u32::try_from(entries.len())
        .ok()
        .and_then(|len| len.checked_add(1))
        .ok_or_else(refused)?;
    let mut out = Vec::with_capacity(body.len() + PHONE_THREAD_KEY.len() + 40);
    match len {
        0..=15 => out.push(0x80 | u8::try_from(len).map_err(|_| refused())?),
        16..=0xffff => {
            out.push(0xde);
            out.extend_from_slice(&u16::try_from(len).map_err(|_| refused())?.to_be_bytes());
        }
        _ => {
            out.push(0xdf);
            out.extend_from_slice(&len.to_be_bytes());
        }
    }
    out.extend_from_slice(body.get(header..).ok_or_else(refused)?);
    rmpv::encode::write_value(&mut out, &rmpv::Value::from(PHONE_THREAD_KEY))
        .map_err(|_| refused())?;
    rmpv::encode::write_value(&mut out, &rmpv::Value::from(thread.to_hex()))
        .map_err(|_| refused())?;
    Ok(out)
}

/// The body a phone thread's CONVERSATION is minted with: the line agent's
/// mark alone.
pub(crate) fn phone_thread_mark_body(agent: EntityId) -> MemoryResult<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from(PHONE_LINE_AGENT_KEY),
            rmpv::Value::from(agent.to_hex()),
        )]),
    )
    .map_err(|_| crate::memory::MemoryError::bad_request("phone thread mark is not encodable"))?;
    Ok(out)
}

/// A phone thread. Parts: the line agent, then the caller's number as kept.
const VOICE_PHONE_DOMAIN: &[u8] = b"oneiron.conversation.voice_phone.v1";
/// The thread of a call whose number is withheld. Parts: the line agent,
/// then the call.
const VOICE_PHONE_CALL_DOMAIN: &[u8] = b"oneiron.conversation.voice_phone_call.v1";
/// The most characters a kept caller number holds, its `+` included.
const CALLER_NUMBER_MAX: usize = 20;

/// The number a phone thread keeps for `caller`, the line provider's
/// untrusted text: a leading `+` and its digits, at most
/// [`CALLER_NUMBER_MAX`] characters, nothing else. `None` when it holds no
/// digit, as a withheld number does.
#[must_use]
pub fn caller_number(caller: Option<&str>) -> Option<String> {
    let text = caller?.trim();
    let plus = text.starts_with('+');
    let digits: String = text
        .chars()
        .filter(char::is_ascii_digit)
        .take(CALLER_NUMBER_MAX - usize::from(plus))
        .collect();
    (!digits.is_empty()).then(|| if plus { format!("+{digits}") } else { digits })
}

/// The thread the line agent `agent`'s calls from `number` (as
/// [`caller_number`] keeps it) land in: one per agent and number, the same
/// id on every host of the vault. A call whose number is withheld (`None`)
/// gets a thread of its own, derived from `call_ref`.
///
/// # Errors
///
/// The id does not derive.
pub fn voice_phone_conversation_id(
    agent: EntityId,
    number: Option<&str>,
    call_ref: &str,
) -> Result<EntityId> {
    Ok(match number {
        Some(number) => {
            EntityId::derive(VOICE_PHONE_DOMAIN, &[agent.as_bytes(), number.as_bytes()])?
        }
        None => EntityId::derive(
            VOICE_PHONE_CALL_DOMAIN,
            &[agent.as_bytes(), call_ref.as_bytes()],
        )?,
    })
}

impl Vault {
    /// Whether calls with other people keep their transcripts here: the
    /// vault's `voice.call_transcripts.keep`, on unless the owner turned it
    /// off. With it off a call keeps only its two divider rows.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn keeps_call_transcripts(&self) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(setting_keys::CALL_TRANSCRIPTS_KEEP
            .read_in_txn(self, &txn, &[], None)?
            .value)
    }

    /// What the phone agent of the line `identity_ref` can see while on a
    /// call: the line's `voice.phone.reach`, read for that line's agent. A
    /// missing row reads the catalogue default: this caller's own history and
    /// no picked documents.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn phone_line_reach(
        &self,
        identity_ref: EntityId,
        agent_ref: EntityId,
    ) -> Result<PhoneReach> {
        let txn = self.store.env.read_txn()?;
        self.phone_line_reach_in(&txn, identity_ref, agent_ref)
    }

    /// [`Self::phone_line_reach`] in the caller's read: the reach in force
    /// for the line `identity_ref`'s item, where the reader knows its agent.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn phone_line_reach_in(
        &self,
        txn: &heed::RoTxn<'_>,
        identity_ref: EntityId,
        agent_ref: EntityId,
    ) -> Result<PhoneReach> {
        Ok(setting_keys::CALL_REACH
            .read_in_txn(
                self,
                txn,
                &[SettingScope::Agent(agent_ref)],
                Some(&identity_ref.to_hex()),
            )?
            .value)
    }

    /// Whether a call with another person opens with the agent saying it is
    /// transcribed: the vault's `voice.call_transcripts.announce`, on unless
    /// the owner turned it off. A row that does not read reads as on.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn announces_call_transcripts(&self) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        Ok(setting_keys::CALL_TRANSCRIPTS_ANNOUNCE
            .read_in_txn(self, &txn, &[], None)?
            .value)
    }

    /// The name a call's opening line gives the vault's owner: the display
    /// name on the owner's own PERSON row. `None` when the vault records no
    /// live owner PERSON, several, or one with no name of its own: the
    /// embedded owner's seeded name names the role, not the person.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn call_owner_display_name(&self) -> Result<Option<String>> {
        let txn = self.store.env.read_txn()?;
        let owners = crate::policy_model::owners_in_txn(self, &txn)?;
        let [owner] = owners.as_slice() else {
            return Ok(None);
        };
        let crate::vault::LiveEntityRow::Live {
            entity_type: crate::registry::ENTITY_TYPE_PERSON,
            body,
        } = crate::vault::live_entity_row_in_txn(&self.store, &txn, owner)?
        else {
            return Ok(None);
        };
        Ok(oneiron_records::context_board::people::person_name(&body)
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty() && name != crate::vault::EMBEDDED_OWNER_ACTOR_NAME))
    }

    /// Witnesses one turn of a call with another person, written by the
    /// answering `agent`, and holds the conversation's turns in the
    /// conversation's own thread SESSION in the same write
    /// (PHONE-CALL-SESSION = A, as UNBUILT-02-SITTING = A rules for mail and
    /// LINE threads). That SESSION is no actor's sitting, so no sitting's
    /// close learns from a stranger's words. The landing mints the call's
    /// thread with the line agent's mark ([`PHONE_LINE_AGENT_KEY`]), stamps
    /// the TURN it mints and every MESSAGE it puts with the thread
    /// ([`PHONE_THREAD_KEY`]), and mints the thread SESSION carrying that
    /// stamp too; the line agent holds a witness-read grant over the thread
    /// from this first kept turn (owner ruling 16 Nov 00:44 replaces
    /// PHONE-CALL-READ-GRANT = B for this).
    ///
    /// # Errors
    ///
    /// The turn names no conversation id, the witness refuses it, the thread
    /// stands without this line agent's mark, the thread SESSION does not
    /// hold, or the line agent's witness-read grant over the thread does not
    /// issue.
    pub fn witness_call_turn(
        &self,
        agent: EntityId,
        turn: &WitnessTurn,
    ) -> MemoryResult<WitnessReceipt> {
        let conversation = EntityId::from_hex(&turn.conversation_ref)?;
        let now = self.now_recorded_at();
        let mark = phone_thread_mark_body(agent)?;
        self.memory(agent, EdgeActorClass::Agent)
            .witness_with_minted_conversation_body_and_txn_effect(
                turn,
                mark,
                crate::store::Callback::Audited,
                || {},
                |_| Ok(None),
                |txn| {
                    use crate::ports::EntityStoreRead;
                    // The thread's id derives from the agent and the number,
                    // so another door may have put a CONVERSATION there first:
                    // a thread whose body does not name this line agent keeps
                    // nothing, since its rows would read as no phone thread.
                    let thread = self.store.port_entity_record(&*txn, &conversation)?;
                    if thread
                        .as_ref()
                        .and_then(|row| phone_thread_agent(&row.body))
                        != Some(agent)
                    {
                        return Err(crate::memory::MemoryError::new(
                            crate::memory::MEMORY_CODE_INVALID_STATE,
                            "the call's thread does not name this line agent",
                            &[],
                        ));
                    }
                    crate::ingest::hold_in_thread_session_in_txn(
                        self,
                        txn,
                        agent,
                        conversation,
                        now,
                        Some(conversation),
                    )?;
                    self.issue_connector_witness_read_grant_in_txn(txn, agent, conversation, now)?;
                    Ok(())
                },
            )
    }
}
