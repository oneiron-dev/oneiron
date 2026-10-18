//! Quote spans: a transient scalar selection over one MESSAGE becomes an
//! engine-issued anchor in the reply's own write transaction.
//!
//! A MESSAGE with an entity document is quoted through the document's
//! citation pin (frontier, stable cursors, retained quote, hash). An atomic
//! MESSAGE has no document and cannot change in place, so its span is bound
//! to the BLAKE3 hash of its canonical text instead; nothing is born or
//! rewritten on the quoted author's row.

use super::graph::{self, edge_ids, invalid, require_member, require_type};
use super::{AppendRecord, QuoteSpan};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault, WriteActor};
use heed::{RoTxn, RwTxn};
use rmpv::Value;
use std::collections::BTreeMap;

/// The anchor a quote reply's pointer records. Neither variant copies the
/// quoted text into the reply. Engine-issued only: a caller names a
/// [`QuoteSpan`], never an anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "anchor", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuoteAnchor {
    /// A MESSAGE that owns a document: its citation pin, keyed by the message
    /// and the citing reply, holds the frontier, cursors, quote and hash.
    Document {
        message: EntityId,
        citation: EntityId,
    },
    /// An atomic MESSAGE: the scalar span is stable only as bound to the
    /// BLAKE3 hash of the canonical text it was taken from.
    Body {
        message: EntityId,
        #[serde(with = "hex32")]
        body_hash: [u8; 32],
        start: u32,
        end: u32,
        #[serde(with = "hex32")]
        quote_hash: [u8; 32],
    },
}

/// A witnessed message's quote (OF-460, FIX 2028), kept against the citing
/// MESSAGE's id: in its project room's turn row, on trunk and thread turns
/// alike, or in an ordinary room's TURN's first body. A quote never becomes
/// a `Parent`, a typed trunk record or another DAG root. It holds references
/// and hashes only, never a copied excerpt. A native append's quote stays in
/// its TURN's own reply pointer, cited by that TURN, never here as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomQuote {
    /// The TURN holding the quoted MESSAGE.
    pub target_turn: EntityId,
    /// The engine-issued anchor of the quoted span.
    pub anchor: QuoteAnchor,
}

impl QuoteAnchor {
    /// The quoted MESSAGE.
    pub(crate) fn message(&self) -> EntityId {
        match self {
            Self::Document { message, .. } | Self::Body { message, .. } => *message,
        }
    }

    /// `<message>:<citation>` names a document citation pin;
    /// `<message>#<body hash>` names an atomic message's immutable text.
    pub(crate) fn reference(&self) -> String {
        match self {
            Self::Document { message, citation } => {
                format!("{}:{}", message.to_hex(), citation.to_hex())
            }
            Self::Body {
                message, body_hash, ..
            } => format!("{}#{}", message.to_hex(), hex(body_hash)),
        }
    }

    fn to_value(self) -> Value {
        match self {
            Self::Document { message, citation } => Value::Map(vec![
                (Value::from("anchor"), Value::from("document")),
                (Value::from("message"), Value::from(message.to_hex())),
                (Value::from("citation"), Value::from(citation.to_hex())),
            ]),
            Self::Body {
                message,
                body_hash,
                start,
                end,
                quote_hash,
            } => Value::Map(vec![
                (Value::from("anchor"), Value::from("body")),
                (Value::from("message"), Value::from(message.to_hex())),
                (Value::from("body_hash"), Value::from(hex(&body_hash))),
                (Value::from("start"), Value::from(start)),
                (Value::from("end"), Value::from(end)),
                (Value::from("quote_hash"), Value::from(hex(&quote_hash))),
            ]),
        }
    }

    fn from_value(value: &Value) -> Result<Self> {
        let fields = value
            .as_map()
            .ok_or_else(|| invalid("invalid quote anchor"))?;
        let mut keys = std::collections::HashSet::new();
        for (key, _) in fields {
            let key = key
                .as_str()
                .ok_or_else(|| invalid("invalid quote anchor"))?;
            if !keys.insert(key) {
                return Err(invalid("duplicate quote anchor field"));
            }
        }
        let get = |name| -> Result<&Value> {
            fields
                .iter()
                .find(|(key, _)| key.as_str() == Some(name))
                .map(|(_, value)| value)
                .ok_or_else(|| invalid("incomplete quote anchor"))
        };
        let id = |name| -> Result<EntityId> {
            EntityId::from_hex(
                get(name)?
                    .as_str()
                    .ok_or_else(|| invalid("invalid quote anchor id"))?,
            )
        };
        let hash = |name| -> Result<[u8; 32]> {
            unhex(
                get(name)?
                    .as_str()
                    .ok_or_else(|| invalid("invalid quote anchor hash"))?,
            )
        };
        let scalar = |name| -> Result<u32> {
            get(name)?
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| invalid("invalid quote anchor span"))
        };
        match get("anchor")?.as_str() {
            Some("document") if fields.len() == 3 => Ok(Self::Document {
                message: id("message")?,
                citation: id("citation")?,
            }),
            Some("body") if fields.len() == 6 => {
                let (start, end) = (scalar("start")?, scalar("end")?);
                if start >= end {
                    return Err(invalid("invalid quote anchor span"));
                }
                Ok(Self::Body {
                    message: id("message")?,
                    body_hash: hash("body_hash")?,
                    start,
                    end,
                    quote_hash: hash("quote_hash")?,
                })
            }
            _ => Err(invalid("invalid quote anchor")),
        }
    }
}

/// A quote proven against the writer's view, before its pin is written.
pub(super) struct ProvenQuote {
    /// The TURN holding the quoted MESSAGE: the reply target.
    pub(super) turn: EntityId,
    /// The anchor the reply pointer records.
    pub(super) anchor: QuoteAnchor,
    /// The scalar span a document pin turns into cursors.
    span: (usize, usize),
}

/// [`prove_quote_in_txn`] for an append: its conversation, parent and writer.
pub(super) fn prove_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    input: &AppendRecord,
    quote: QuoteSpan,
    citation: EntityId,
) -> Result<ProvenQuote> {
    prove_quote_in_txn(
        vault,
        txn,
        input.conversation,
        input.parent,
        input.actor,
        quote,
        citation,
    )
}

/// Proves a quote without writing: the MESSAGE is live, visible and in
/// `conversation`, its owning TURN is readable from the branch through
/// `parent`, a PERSON `actor` is in its audience, and the span is nonempty,
/// ordered and inside its current text. `citation` is the reply's own id.
/// Both reply doors call it: the append and a room witness (OF-460).
pub(super) fn prove_quote_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    conversation: EntityId,
    parent: Option<EntityId>,
    actor: WriteActor,
    quote: QuoteSpan,
    citation: EntityId,
) -> Result<ProvenQuote> {
    if quote.start >= quote.end {
        return Err(invalid("quote span must be nonempty and ordered"));
    }
    let message = quote.message;
    let body = match live_entity_row_in_txn(&vault.store, txn, &message)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_MESSAGE,
            body,
        } => body,
        LiveEntityRow::Live { .. } => return Err(invalid("a quote selects a MESSAGE")),
        _ => return Err(Error::EntityNotFound),
    };
    if vault.archive_tombstone_in_txn(txn, &message)?.is_some() {
        return Err(Error::EntityNotFound);
    }
    if crate::conversation::room_message_owner_in(&vault.store, txn, message)? != Some(conversation)
    {
        return Err(invalid("quoted message belongs to another room"));
    }
    let turn = owning_turn_in(&vault.store, txn, &message)?;
    require_member(&vault.store, txn, &conversation, &turn)?;
    if !branch_reads_in(&vault.store, txn, conversation, parent, turn)? {
        return Err(invalid("quoted message is outside the writer's branch"));
    }
    if writer_is_person(&vault.store, txn, actor)?
        && !crate::conversation::AudienceCache::default().readable(
            vault,
            txn,
            message,
            &[actor.entity_ref()],
        )?
    {
        return Err(invalid("quoted message is outside the writer's audience"));
    }
    let fields = message_fields(&body)?;
    if !matches!(field(&fields, "is_visible"), Some(Value::Boolean(true))) {
        return Err(invalid("a quote selects a visible message"));
    }
    let span = (
        usize::try_from(quote.start).map_err(|_| invalid("quote span overflow"))?,
        usize::try_from(quote.end).map_err(|_| invalid("quote span overflow"))?,
    );
    if crate::entity_doc::has_record_head(&vault.store, txn, &message)? {
        // The document's text API indexes Unicode scalar values, so the span
        // reaches the pin unconverted; the pin bounds it against that text.
        return Ok(ProvenQuote {
            turn,
            anchor: QuoteAnchor::Document { message, citation },
            span,
        });
    }
    let text = field(&fields, "content")
        .and_then(Value::as_str)
        .ok_or(Error::CorruptedIndex("message canonical content"))?;
    let quoted = scalar_slice(text, span.0, span.1)
        .ok_or_else(|| invalid("quote span is outside the message text"))?;
    Ok(ProvenQuote {
        turn,
        anchor: QuoteAnchor::Body {
            message,
            body_hash: *blake3::hash(text.as_bytes()).as_bytes(),
            start: quote.start,
            end: quote.end,
            quote_hash: *blake3::hash(quoted.as_bytes()).as_bytes(),
        },
        span,
    })
}

/// Writes a document quote's citation pin in the append transaction. A body
/// anchor needs no row: the reply pointer carries all of it.
pub(super) fn pin_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    proven: &ProvenQuote,
    actor: WriteActor,
) -> Result<()> {
    if let QuoteAnchor::Document { message, citation } = proven.anchor {
        vault.pin_message_quote_in_txn(
            txn,
            &citation,
            &message,
            proven.span.0,
            proven.span.1,
            actor,
        )?;
    }
    Ok(())
}

/// Pins, in a MESSAGE document's birth transaction, each body-anchored quote
/// of that MESSAGE as a citation pin keyed by its citer, at the birth
/// frontier, so the quoted text stays retained and purge-protected once the
/// document is edited (OF-460): a witnessed message's quote by the citing
/// MESSAGE, a native append's by its TURN (FIX 2028). Only an anchor whose
/// hashes still bind `text`, the born document's text, is pinned. Body
/// anchors sit in native TURN reply pointers, ordinary room TURN bodies and
/// room turn rows, none indexed by the quoted MESSAGE, so the walk reads
/// every TURN.
pub(crate) fn pin_body_quotes_at_message_birth_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    message: &EntityId,
    text: &str,
    actor: WriteActor,
) -> Result<()> {
    let body_hash = *blake3::hash(text.as_bytes()).as_bytes();
    let turns = crate::ports::EntityStoreRead::port_entity_ids_by_type(
        &vault.store,
        txn,
        ENTITY_TYPE_TURN,
        None,
    )?
    .collect::<Result<Vec<_>>>()?;
    let mut spans = std::collections::BTreeMap::new();
    for turn in turns {
        // Each anchor beside the record that cites it.
        let mut anchors = Vec::new();
        if let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &turn)?
        {
            // A typed record's reply pointer is read strictly, its TURN the
            // citer. An opaque TURN keeps quotes only as an ordinary room's
            // quoted turn, by citing MESSAGE (FIX 2027); one whose body
            // keeps none carries no anchor.
            if super::topology::record_kind(&body)?.is_some() {
                anchors.extend(read_pointer(&body)?.map(|(_, anchor)| (turn, anchor)));
            } else {
                anchors.extend(
                    witness_turn_quotes(&body)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(citer, quote)| (citer, quote.anchor)),
                );
            }
        }
        if let Some(row) = crate::workspace_roster::replicated_turn_in(vault, txn, turn)? {
            for (citer, quote) in row.quotes {
                anchors.push((EntityId::from_hex(&citer)?, quote.anchor));
            }
        }
        for (citation, anchor) in anchors {
            let QuoteAnchor::Body {
                message: quoted,
                body_hash: bound,
                start,
                end,
                quote_hash,
            } = anchor
            else {
                continue;
            };
            if quoted != *message || bound != body_hash {
                continue;
            }
            let span = (
                usize::try_from(start).map_err(|_| invalid("quote span overflow"))?,
                usize::try_from(end).map_err(|_| invalid("quote span overflow"))?,
            );
            if scalar_slice(text, span.0, span.1)
                .is_some_and(|quote| blake3::hash(quote.as_bytes()).as_bytes() == &quote_hash)
            {
                spans.insert(citation, span);
            }
        }
    }
    for (citation, (start, end)) in spans {
        vault.pin_message_quote_in_txn(txn, &citation, message, start, end, actor)?;
    }
    Ok(())
}

/// The reply target of an append: the caller's, or the quoted message's
/// TURN. A quote answers exactly the TURN that holds its message.
pub(super) fn reply_target(
    asked: Option<EntityId>,
    quote: Option<&ProvenQuote>,
) -> Result<Option<EntityId>> {
    match (asked, quote) {
        (Some(asked), Some(quote)) if asked != quote.turn => {
            Err(invalid("a quote answers the turn that holds its message"))
        }
        (asked, quote) => Ok(asked.or(quote.map(|quote| quote.turn))),
    }
}

/// The reply pointer for `target` at `revision`, carrying the quote anchor.
pub(super) fn reply_pointer(
    target: EntityId,
    revision: String,
    quote: Option<&ProvenQuote>,
) -> Value {
    let mut pointer = vec![
        (Value::from("record"), Value::from(target.to_hex())),
        (Value::from("revision"), Value::from(revision)),
    ];
    if let Some(quote) = quote {
        pointer.push((Value::from("quote"), quote.anchor.to_value()));
    }
    Value::Map(pointer)
}

/// A quoted room turn's reply topology, fixed in the room witness's
/// transaction before its TURN is minted (OF-460, FIX 2028). The quotes are
/// its messages' own ([`ProvenRoomQuote`]); the witness mints the TURN once,
/// with the reply mode, a pointer answering `target`, the TURN of its first
/// quoted message, at the revision captured in this transaction, and
/// `RepliesTo` in its first body and write; nothing patches it later. A
/// project room's thread reply is also a DAG thread record whose chain
/// continues `parent`, the reply's own. An ordinary room's quoted turn (FIX
/// 2027) has no `parent`, so it stays an opaque turn, classified as no thread
/// and chained to nothing, and it has no room row, so its first body keeps
/// its messages' quotes by citing MESSAGE.
pub(crate) struct QuotedReply {
    parent: Option<EntityId>,
    target: EntityId,
    revision: String,
    quotes: BTreeMap<EntityId, RoomQuote>,
}

impl QuotedReply {
    /// The topology of a project room thread reply that continues the thread
    /// chain at `parent` in `conversation` and answers `target`, its first
    /// quoted message's TURN.
    pub(crate) fn thread_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        conversation: EntityId,
        parent: EntityId,
        target: EntityId,
    ) -> Result<Self> {
        require_member(&vault.store, txn, &conversation, &parent)?;
        require_type(&vault.store, txn, &parent, ENTITY_TYPE_TURN)?;
        Ok(Self {
            parent: Some(parent),
            target,
            revision: revision_in_txn(vault, txn, target)?,
            quotes: BTreeMap::new(),
        })
    }

    /// The topology of an ordinary room's quoted turn (FIX 2027) answering
    /// `target`, its first quoted message's TURN, whose first body keeps
    /// `quotes`, its messages' by citing MESSAGE.
    pub(crate) fn ordinary_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        target: EntityId,
        quotes: BTreeMap<EntityId, RoomQuote>,
    ) -> Result<Self> {
        Ok(Self {
            parent: None,
            target,
            revision: revision_in_txn(vault, txn, target)?,
            quotes,
        })
    }

    /// The door-owned fields the reply's first TURN body carries: a reply
    /// answering `target` at its revision, on a project thread reply the
    /// thread record kind, and on an ordinary room's turn its messages'
    /// quotes.
    pub(crate) fn body_fields(&self) -> Vec<(Value, Value)> {
        let mut fields = vec![
            (Value::from("addr"), Value::from("reply")),
            (
                Value::from("reply_to"),
                reply_pointer(self.target, self.revision.clone(), None),
            ),
        ];
        if self.parent.is_some() {
            fields.insert(
                0,
                (
                    Value::from("dag_kind"),
                    Value::from(super::topology::RecordKind::Thread.as_str()),
                ),
            );
        }
        if !self.quotes.is_empty() {
            let quotes = quotes_value(&self.quotes);
            fields.push((Value::from(WITNESS_QUOTES_KEY), quotes));
        }
        fields
    }

    /// Stages the minted reply's `RepliesTo` edge and, on a project thread
    /// reply, its `Parent`.
    pub(crate) fn edges<'v>(
        &self,
        mut batch: crate::BatchBuilder<'v>,
        record: &EntityId,
        learned_at: u64,
    ) -> crate::BatchBuilder<'v> {
        let value = super::writes::value;
        if let Some(parent) = self.parent {
            batch =
                batch.edge_with_value_fields(record, EdgeKind::Parent, &parent, value(learned_at));
        }
        batch.edge_with_value_fields(record, EdgeKind::RepliesTo, &self.target, value(learned_at))
    }
}

/// The revision a reply pointer captures of the TURN `target` it answers.
fn revision_in_txn(vault: &Vault, txn: &RoTxn<'_>, target: EntityId) -> Result<String> {
    let body = require_type(&vault.store, txn, &target, ENTITY_TYPE_TURN)?;
    Ok(blake3::hash(&body).to_hex().to_string())
}

/// One witnessed message's quote, proven in the room witness's transaction
/// and cited by that MESSAGE (OF-460, FIX 2028). Its anchor is kept against
/// the message's id ([`RoomQuote`]): in the turn's room row, or an ordinary
/// room TURN's first body.
pub(crate) struct ProvenRoomQuote {
    proven: ProvenQuote,
    actor: WriteActor,
}

impl ProvenRoomQuote {
    /// Proves `quote` for the message `citation` that `actor` speaks in
    /// `room`, read from `branch`: `None` is the trunk, which reads no thread
    /// or private branch merely because the target sits in the same room; a
    /// thread reply's is its own DAG chain's parent.
    pub(crate) fn prove_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        room: EntityId,
        branch: Option<EntityId>,
        actor: WriteActor,
        quote: QuoteSpan,
        citation: EntityId,
    ) -> Result<Self> {
        let proven = prove_quote_in_txn(vault, txn, room, branch, actor, quote, citation)?;
        Ok(Self { proven, actor })
    }

    /// Proves `quote` for the message `citation` that `actor` speaks in the
    /// ordinary room `room` (FIX 2027), read from the quoted TURN's own
    /// chain. That read anchor is no `Parent` of the new turn: the caller's
    /// scoped read under the room's ceiling has already admitted the
    /// selection.
    pub(crate) fn prove_ordinary_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        room: EntityId,
        actor: WriteActor,
        quote: QuoteSpan,
        citation: EntityId,
    ) -> Result<Self> {
        let turn = owning_turn_in(&vault.store, txn, &quote.message)?;
        Self::prove_in_txn(vault, txn, room, Some(turn), actor, quote, citation)
    }

    /// The TURN holding the quoted MESSAGE.
    pub(crate) fn target_turn(&self) -> EntityId {
        self.proven.turn
    }

    /// The kept quote: target and anchor, no excerpt.
    pub(crate) fn metadata(&self) -> RoomQuote {
        RoomQuote {
            target_turn: self.proven.turn,
            anchor: self.proven.anchor,
        }
    }

    /// Writes a document anchor's citation pin, keyed by the citing MESSAGE,
    /// at the message's birth only.
    pub(crate) fn pin_in_txn(&self, vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
        pin_in_txn(vault, txn, &self.proven, self.actor)
    }

    /// Refuses unless `stored`, the message's kept quote, is exactly this
    /// one; a retry never re-pins it.
    pub(crate) fn require_stored_in_txn(
        &self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        stored: &RoomQuote,
    ) -> Result<()> {
        require_stored_quote_in_txn(
            vault,
            txn,
            &self.proven,
            Some((stored.target_turn, stored.anchor)),
        )
    }
}

/// Refuses unless `stored` is exactly `proven`'s quote: the same target and
/// anchor and, for a document anchor, a pinned quote that is the text the
/// span selects now.
fn require_stored_quote_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    proven: &ProvenQuote,
    stored: Option<(EntityId, QuoteAnchor)>,
) -> Result<()> {
    let changed = || invalid("a stored message's quote is immutable");
    let Some((target, anchor)) = stored else {
        return Err(changed());
    };
    if target != proven.turn || anchor != proven.anchor {
        return Err(changed());
    }
    if let QuoteAnchor::Document { message, citation } = anchor {
        let pin = vault
            .message_quote_pin_in_txn(txn, &message, &citation)?
            .ok_or_else(changed)?;
        let row = require_type(&vault.store, txn, &message, ENTITY_TYPE_MESSAGE)?;
        let row = crate::entity_doc::resolve_record_body(&vault.store, txn, &message, &row)?;
        let fields = message_fields(&row)?;
        let text = field(&fields, "content")
            .and_then(Value::as_str)
            .ok_or(Error::CorruptedIndex("message canonical content"))?;
        if scalar_slice(text, proven.span.0, proven.span.1).as_deref() != Some(pin.anchor.quote()) {
            return Err(changed());
        }
    }
    Ok(())
}

/// The TURN body key under which an ordinary room's quoted turn keeps its
/// messages' quotes, by citing MESSAGE (FIX 2027, FIX 2028).
const WITNESS_QUOTES_KEY: &str = "quotes";

fn quotes_value(quotes: &BTreeMap<EntityId, RoomQuote>) -> Value {
    Value::Map(
        quotes
            .iter()
            .map(|(citer, quote)| {
                (
                    Value::from(citer.to_hex()),
                    Value::Map(vec![
                        (
                            Value::from("target_turn"),
                            Value::from(quote.target_turn.to_hex()),
                        ),
                        (Value::from("anchor"), quote.anchor.to_value()),
                    ]),
                )
            })
            .collect(),
    )
}

/// The quotes an ordinary room TURN's `body` keeps by citing MESSAGE (FIX
/// 2027, FIX 2028); empty for a body that keeps none.
pub(crate) fn witness_turn_quotes(body: &[u8]) -> Result<BTreeMap<EntityId, RoomQuote>> {
    let mut input = body;
    let Value::Map(fields) =
        rmpv::decode::read_value(&mut input).map_err(|_| invalid("invalid record body"))?
    else {
        return Err(invalid("invalid record body"));
    };
    let Some(entries) = field(&fields, WITNESS_QUOTES_KEY) else {
        return Ok(BTreeMap::new());
    };
    let bad = || invalid("invalid turn quote");
    let mut quotes = BTreeMap::new();
    for (citer, quote) in entries.as_map().ok_or_else(bad)? {
        let citer = EntityId::from_hex(citer.as_str().ok_or_else(bad)?)?;
        let quote = quote.as_map().ok_or_else(bad)?;
        let target = field(quote, "target_turn")
            .and_then(Value::as_str)
            .ok_or_else(bad)?;
        let anchor = field(quote, "anchor").ok_or_else(bad)?;
        let quote = RoomQuote {
            target_turn: EntityId::from_hex(target)?,
            anchor: QuoteAnchor::from_value(anchor)?,
        };
        if quotes.insert(citer, quote).is_some() {
            return Err(bad());
        }
    }
    Ok(quotes)
}

/// How many door-owned reply fields a witness TURN's `body` carries
/// (OF-460): none, or its reply mode and pointer, with an ordinary room's
/// message quotes beside them when it keeps any.
pub(crate) fn witness_reply_field_count(body: &[u8]) -> Result<usize> {
    let mut input = body;
    let Value::Map(fields) =
        rmpv::decode::read_value(&mut input).map_err(|_| invalid("invalid record body"))?
    else {
        return Err(invalid("invalid record body"));
    };
    let has = |name| field(&fields, name).is_some();
    match (has("addr"), has("reply_to"), has(WITNESS_QUOTES_KEY)) {
        (false, false, false) => Ok(0),
        (true, true, quotes) => Ok(2 + usize::from(quotes)),
        _ => Err(invalid("invalid witness reply fields")),
    }
}

/// The reply target and quote anchor a TURN body's reply pointer records;
/// `None` for a body with no quote.
pub(super) fn read_pointer(body: &[u8]) -> Result<Option<(EntityId, QuoteAnchor)>> {
    let mut input = body;
    let Value::Map(fields) =
        rmpv::decode::read_value(&mut input).map_err(|_| invalid("invalid record body"))?
    else {
        return Err(invalid("invalid record body"));
    };
    let Some(pointer) = field(&fields, "reply_to") else {
        return Ok(None);
    };
    let pointer = pointer
        .as_map()
        .ok_or_else(|| invalid("invalid reply pointer"))?;
    let Some(quote) = field(pointer, "quote") else {
        return Ok(None);
    };
    let target = field(pointer, "record")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("invalid reply target"))?;
    Ok(Some((
        EntityId::from_hex(target)?,
        QuoteAnchor::from_value(quote)?,
    )))
}

/// The TURN a MESSAGE is `PartOf`: exactly one, and a TURN.
pub(super) fn owning_turn_in(
    store: &Store,
    txn: &RoTxn<'_>,
    message: &EntityId,
) -> Result<EntityId> {
    let turns = edge_ids(store, txn, message, EdgeKind::PartOf, false, 2)?;
    let [turn] = turns[..] else {
        return Err(invalid("quoted message needs exactly one turn"));
    };
    require_type(store, txn, &turn, ENTITY_TYPE_TURN)?;
    Ok(turn)
}

/// FIX 3127: a private thread's (FIX 2951) MESSAGE is quoted only from
/// inside that same thread. `landing` is the root of the thread the quoting
/// record lands in, `None` on the trunk; a thread born by this write has a
/// root no quoted MESSAGE sits under yet. A MESSAGE off any private thread
/// passes, and one whose thread's root no longer resolves refuses, as a
/// missing thread does. Every quote door runs it beside its proof: the
/// append, and both room witness arms.
pub(crate) fn require_quote_landing_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    conversation: EntityId,
    message: EntityId,
    landing: Option<EntityId>,
) -> Result<()> {
    let turn = owning_turn_in(&vault.store, txn, &message)?;
    let body = require_type(&vault.store, txn, &turn, ENTITY_TYPE_TURN)?;
    let Some(binding) = crate::workspace_roster::thread_binding(&body)? else {
        return Ok(());
    };
    if landing != Some(binding.root)
        && crate::workspace_roster::thread_audience_in(vault, txn, conversation, turn)?.is_some()
    {
        return Err(invalid(
            "a private thread's message is quoted only inside that thread",
        ));
    }
    Ok(())
}

/// A room-level record (neither a thread reply nor a worker record) reads
/// from every branch of its room. Any other record reads only from a branch
/// that runs through it.
fn branch_reads_in(
    store: &Store,
    txn: &RoTxn<'_>,
    conversation: EntityId,
    parent: Option<EntityId>,
    turn: EntityId,
) -> Result<bool> {
    if !graph::is_thread_record(store, txn, &turn)?
        && !graph::is_sub_session_record(store, txn, &turn)?
    {
        return Ok(true);
    }
    Ok(match parent {
        Some(parent) => graph::chain(store, txn, &conversation, parent)?.contains(&turn),
        None => false,
    })
}

fn writer_is_person(store: &Store, txn: &RoTxn<'_>, actor: WriteActor) -> Result<bool> {
    Ok(matches!(
        live_entity_row_in_txn(store, txn, &actor.entity_ref())?,
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_PERSON,
            ..
        }
    ))
}

/// The fields of a MESSAGE body (its row, or its body with document text).
pub(super) fn message_fields(body: &[u8]) -> Result<Vec<(Value, Value)>> {
    let mut input = body;
    match rmpv::decode::read_value(&mut input) {
        Ok(Value::Map(fields)) if input.is_empty() => Ok(fields),
        _ => Err(Error::CorruptedIndex("message body")),
    }
}

pub(super) fn field<'a>(fields: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    fields
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}

/// The scalars `start..end` of `text`, or `None` past its end.
pub(super) fn scalar_slice(text: &str, start: usize, end: usize) -> Option<String> {
    if start >= end {
        return None;
    }
    let quoted: String = text.chars().skip(start).take(end - start).collect();
    (quoted.chars().count() == end - start).then_some(quoted)
}

/// A BLAKE3 hash as its 64 lowercase hex digits on the wire.
mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        bytes: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(blake3::Hash::from_bytes(*bytes).to_hex().as_str())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        blake3::Hash::from_hex(value)
            .map(|hash| *hash.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Result<[u8; 32]> {
    let mut out = [0_u8; 32];
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("invalid quote anchor hash"));
    }
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| invalid("invalid quote anchor hash"))?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| invalid("invalid quote anchor hash"))?;
    }
    Ok(out)
}
