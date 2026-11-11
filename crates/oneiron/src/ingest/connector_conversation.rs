//! A served connector conversation as the answering agent's memory (FIX
//! 2404). The message a connector reply answers, and the reply itself, each
//! land as one turn of an imported conversation through the witness
//! program's import door, on the agent's own Memory. The sender's words are
//! the source's, never the owner's: no turn carries a byline, and the sender
//! stays named in the message's provenance. Conversation, turn and message
//! ids derive from the exchange, so a rerun lands the same rows at the same
//! ids. An inbound witness can also record the native archive version its
//! source names; that metadata binding stays frozen once recorded. The reply
//! worker reads the conversation back
//! through the agent's own read lane, every page of it, as the history its
//! next reply answers in. The lane admits the conversation's MESSAGEs by the
//! read grant the agent's first witness of it issues (FIX 10895,
//! [`super::connector_witness_grant`]); a grant that fails to issue is owed
//! a repair and never holds the turn back.

use rmpv::Value as Msgpack;
use serde_json::json;

use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::{
    IMPORTED_SOURCE_KEY, ImportedTurnStamp, MAX_TRANSCRIPT_PAGE_TURNS, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult, TranscriptMessage, WitnessAuthor,
    WitnessMessage, WitnessTurn,
};
use crate::surface_event::SurfaceConnectorPayload;

/// The import source every connector conversation lands under.
const CONNECTOR_IMPORT_SOURCE: &str = "connector";
/// The message type a connector conversation's messages carry.
const CONNECTOR_MESSAGE_TYPE: &str = "import.connector";
/// A connector conversation. Parts: channel, receiving identity, provider
/// thread (empty when none), audience (the reply target).
const CONNECTOR_CONVERSATION_DOMAIN: &[u8] = b"oneiron.ingest.connector.conversation.v1";
/// A connector conversation's TURN. Parts: conversation, then the side.
const CONNECTOR_TURN_DOMAIN: &[u8] = b"oneiron.ingest.connector.turn.v1";
/// A connector conversation's MESSAGE. Parts: conversation, then the side.
const CONNECTOR_MESSAGE_DOMAIN: &[u8] = b"oneiron.ingest.connector.message.v1";
/// The side an inbound message lands as. Parts after it: the provider event.
const INBOUND_SIDE: &str = "inbound";
/// The side a reply lands as. Parts after it: the provider event, the agent
/// and the reply ref.
const REPLY_SIDE: &str = "reply";

impl Vault {
    /// Witnesses `text`, the message `origin` brought `agent`, as the
    /// sender's turn of their conversation, and issues `agent` its read
    /// grant over the conversation once. Returns the conversation, turn and
    /// message ids it landed at.
    ///
    /// # Errors
    /// The witness program refuses the turn, or the vault write fails.
    pub fn witness_connector_inbound(
        &self,
        agent: EntityId,
        origin: &SurfaceConnectorPayload,
        text: &str,
        now: u64,
    ) -> MemoryResult<ConnectorWitness> {
        self.witness_connector_inbound_with_effect(agent, origin, text, now, |_, _| Ok(()))
    }

    pub(crate) fn witness_connector_inbound_with_effect(
        &self,
        agent: EntityId,
        origin: &SurfaceConnectorPayload,
        text: &str,
        now: u64,
        effect: impl FnOnce(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>,
    ) -> MemoryResult<ConnectorWitness> {
        let message = WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: CONNECTOR_MESSAGE_TYPE.to_owned(),
            content: text.to_owned(),
            parts: None,
            metadata: Some(json!({
                "import": {
                    "source": CONNECTOR_IMPORT_SOURCE,
                    "channel": &origin.channel,
                    "id": &origin.surface_event_id,
                    "role": "user",
                    "said_by": &origin.source.user_ref,
                }
            })),
            is_visible: true,
            order: 0,
            quote: None,
        };
        self.witness_connector_turn(
            agent,
            origin,
            &inbound_side(origin),
            message,
            origin.received_at,
            now,
            Some(origin),
            effect,
        )
    }

    /// Witnesses `text`, the reply `agent` kept as `reply_ref` to the
    /// message `origin` brought, as the agent's turn of their conversation,
    /// and issues `agent` its read grant over the conversation once.
    /// Returns the conversation, turn and message ids it landed at.
    ///
    /// # Errors
    /// The witness program refuses the turn, or the vault write fails.
    pub fn witness_connector_reply(
        &self,
        agent: EntityId,
        origin: &SurfaceConnectorPayload,
        reply_ref: &str,
        text: &str,
        occurred_at: u64,
        now: u64,
    ) -> MemoryResult<ConnectorWitness> {
        self.witness_connector_reply_with_effect(
            agent,
            origin,
            reply_ref,
            text,
            occurred_at,
            now,
            |_, _| Ok(()),
        )
    }

    pub(crate) fn witness_connector_reply_with_effect(
        &self,
        agent: EntityId,
        origin: &SurfaceConnectorPayload,
        reply_ref: &str,
        text: &str,
        occurred_at: u64,
        now: u64,
        effect: impl FnOnce(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>,
    ) -> MemoryResult<ConnectorWitness> {
        let side = reply_side(origin, agent, reply_ref);
        let message = WitnessMessage {
            id: None,
            author: WitnessAuthor::Companion,
            message_type: CONNECTOR_MESSAGE_TYPE.to_owned(),
            content: text.to_owned(),
            parts: None,
            metadata: Some(json!({
                "import": {
                    "source": CONNECTOR_IMPORT_SOURCE,
                    "channel": &origin.channel,
                    "id": &origin.surface_event_id,
                    "role": "assistant",
                    "agent": agent.to_hex(),
                    "reply_ref": reply_ref,
                }
            })),
            is_visible: true,
            order: 0,
            quote: None,
        };
        self.witness_connector_turn(
            agent,
            origin,
            &side,
            message,
            occurred_at,
            now,
            None,
            effect,
        )
    }

    /// Every message of the conversation `origin` belongs to that `agent`'s
    /// own read lane admits, in order, read page by page to the end, less
    /// this exchange's own inbound and reply turns. A conversation not yet
    /// witnessed, or one the lane does not admit, has none.
    ///
    /// # Errors
    /// The transcript read fails.
    pub fn connector_conversation_history(
        &self,
        agent: EntityId,
        origin: &SurfaceConnectorPayload,
        reply_ref: &str,
    ) -> MemoryResult<Vec<TranscriptMessage>> {
        let conversation = connector_conversation_id(origin)?;
        let conversation_hex = conversation.to_hex();
        let current = [
            derive(
                CONNECTOR_TURN_DOMAIN,
                &conversation_hex,
                &inbound_side(origin),
            )?
            .to_hex(),
            derive(
                CONNECTOR_TURN_DOMAIN,
                &conversation_hex,
                &reply_side(origin, agent, reply_ref),
            )?
            .to_hex(),
        ];
        let memory = self.memory(agent, EdgeActorClass::Agent);
        let mut history = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = match memory.conversation_transcript(
                &conversation,
                after.as_deref(),
                MAX_TRANSCRIPT_PAGE_TURNS,
            ) {
                Ok(read) => read.value,
                Err(error) if error.code == MEMORY_CODE_NOT_FOUND => break,
                Err(error) => return Err(error),
            };
            history.extend(
                page.turns
                    .into_iter()
                    .filter(|turn| !current.contains(&turn.id))
                    .flat_map(|turn| turn.messages),
            );
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        Ok(history)
    }

    fn witness_connector_turn(
        &self,
        agent: EntityId,
        origin: &SurfaceConnectorPayload,
        side: &[impl AsRef<str>],
        mut message: WitnessMessage,
        occurred_at: u64,
        now: u64,
        archive_source: Option<&SurfaceConnectorPayload>,
        effect: impl FnOnce(&mut heed::RwTxn<'_>, EntityId) -> MemoryResult<()>,
    ) -> MemoryResult<ConnectorWitness> {
        let conversation = connector_conversation_id(origin)?;
        let conversation_hex = conversation.to_hex();
        let turn_id = derive(CONNECTOR_TURN_DOMAIN, &conversation_hex, side)?;
        let message_id = derive(CONNECTOR_MESSAGE_DOMAIN, &conversation_hex, side)?;
        message.id = Some(message_id.to_hex());
        let turn = WitnessTurn {
            conversation_ref: conversation_hex.clone(),
            turn_ref: Some(turn_id.to_hex()),
            thread_audience: None,
            messages: vec![message],
            occurred_at,
            assertions: Default::default(),
        };
        let stamp = ImportedTurnStamp {
            source: CONNECTOR_IMPORT_SOURCE,
            imported_at: now,
            conversation_body: conversation_body(origin)?,
            message_occurred: vec![occurred_at],
            source_audience: None,
        };
        let receipt =
            self.memory(agent, EdgeActorClass::Agent)
                .witness_imported(&turn, &stamp, |txn| {
                    reject_erased_participants_in_txn(self, txn, agent, origin)?;
                    effect(txn, conversation)?;
                    if let Some(source) = archive_source {
                        super::connector_archive_link::record_in_txn(
                            self,
                            txn,
                            conversation,
                            message_id,
                            source,
                        );
                    }
                    Ok(())
                })?;
        let read_grant_repair = self
            .issue_connector_witness_read_grant(agent, conversation, now)
            .err()
            .map(MemoryError::from);
        let mut refs = vec![conversation_hex];
        refs.extend(receipt.turn.map(|turn| turn.id));
        refs.extend(receipt.messages.into_iter().map(|message| message.id));
        Ok(ConnectorWitness {
            refs,
            read_grant_repair,
        })
    }
}

/// Refuses the witness when its agent, or anyone its exchange names, is
/// hard-erased here (FIX 10897). An erase that committed after the worker
/// read the words found no row of them to take and cleared the job that
/// names them, so the words must not land after it; an erase that commits
/// after the witness finds the rows through that job.
fn reject_erased_participants_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    origin: &SurfaceConnectorPayload,
) -> MemoryResult<()> {
    let mut ids = crate::outbound::surface_participant_ids(origin);
    ids.push(agent);
    for id in ids {
        if vault.local_hard_delete_marker_exists_in_txn(txn, &id)? {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "a participant of this connector exchange is erased",
                &[],
            ));
        }
    }
    Ok(())
}

/// One side of a connector exchange as it landed in its conversation.
#[derive(Debug)]
pub struct ConnectorWitness {
    /// The conversation, turn and message ids the turn landed at.
    pub refs: Vec<String>,
    /// Why the agent's read grant over the conversation was not issued
    /// (FIX 10895), owed a repair; the turn stands either way.
    pub read_grant_repair: Option<MemoryError>,
}

/// The MESSAGE and TURN ids `agent`'s witness of the exchange `origin`
/// brought lands at (FIX 10897): the inbound side, then the reply kept as
/// `reply_ref`, each as (message, turn). They derive from the exchange
/// alone, as the witness derives them, so they name its rows whether or
/// not a side landed.
///
/// # Errors
/// An id does not derive.
pub(crate) fn connector_witness_row_ids(
    origin: &SurfaceConnectorPayload,
    agent: EntityId,
    reply_ref: &str,
) -> MemoryResult<[(EntityId, EntityId); 2]> {
    let conversation_hex = connector_conversation_id(origin)?.to_hex();
    let inbound = inbound_side(origin);
    let reply = reply_side(origin, agent, reply_ref);
    Ok([
        (
            derive(CONNECTOR_MESSAGE_DOMAIN, &conversation_hex, &inbound)?,
            derive(CONNECTOR_TURN_DOMAIN, &conversation_hex, &inbound)?,
        ),
        (
            derive(CONNECTOR_MESSAGE_DOMAIN, &conversation_hex, &reply)?,
            derive(CONNECTOR_TURN_DOMAIN, &conversation_hex, &reply)?,
        ),
    ])
}

/// The conversation an event belongs to: one per channel, receiving
/// identity, provider thread and audience, so a LINE group's members share
/// one and a direct message has its own.
fn connector_conversation_id(origin: &SurfaceConnectorPayload) -> MemoryResult<EntityId> {
    let parts = [
        origin.channel.as_bytes(),
        origin.receiving_identity_ref.as_bytes(),
        origin.thread_ref.as_deref().unwrap_or_default().as_bytes(),
        origin.reply_target().as_bytes(),
    ];
    EntityId::derive(CONNECTOR_CONVERSATION_DOMAIN, &parts).map_err(MemoryError::from)
}

fn inbound_side(origin: &SurfaceConnectorPayload) -> [&str; 2] {
    [INBOUND_SIDE, origin.surface_event_id.as_str()]
}

fn reply_side(origin: &SurfaceConnectorPayload, agent: EntityId, reply_ref: &str) -> [String; 4] {
    [
        REPLY_SIDE.to_owned(),
        origin.surface_event_id.clone(),
        agent.to_hex(),
        reply_ref.to_owned(),
    ]
}

fn derive(
    domain: &[u8],
    conversation_hex: &str,
    side: &[impl AsRef<str>],
) -> MemoryResult<EntityId> {
    let mut parts = vec![conversation_hex.as_bytes()];
    parts.extend(side.iter().map(|part| part.as_ref().as_bytes()));
    EntityId::derive(domain, &parts).map_err(MemoryError::from)
}

/// The body a connector conversation is minted with: its import source and
/// its channel.
fn conversation_body(origin: &SurfaceConnectorPayload) -> MemoryResult<Vec<u8>> {
    let fields = vec![
        (
            Msgpack::from(IMPORTED_SOURCE_KEY),
            Msgpack::from(CONNECTOR_IMPORT_SOURCE),
        ),
        (
            Msgpack::from("import_kind"),
            Msgpack::from(origin.channel.as_str()),
        ),
    ];
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Msgpack::Map(fields))
        .map_err(|_| MemoryError::bad_request("connector conversation body is not encodable"))?;
    Ok(out)
}

/// Whether `body`, a CONVERSATION's, is a connector conversation's: one
/// minted under the connector's import source.
pub(super) fn is_connector_conversation_body(mut body: &[u8]) -> bool {
    let Ok(Msgpack::Map(fields)) = rmpv::decode::read_value(&mut body) else {
        return false;
    };
    fields.iter().any(|(key, value)| {
        key.as_str() == Some(IMPORTED_SOURCE_KEY) && value.as_str() == Some(CONNECTOR_IMPORT_SOURCE)
    })
}
