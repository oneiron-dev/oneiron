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

/// The anchor a quote reply's pointer records. Neither variant copies the
/// quoted text into the reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuoteAnchor {
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
        body_hash: [u8; 32],
        start: u32,
        end: u32,
        quote_hash: [u8; 32],
    },
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

/// Proves a quote for `input` without writing: the MESSAGE is live, visible
/// and in the same room, its owning TURN is readable from the writer's
/// branch, a PERSON writer is in its audience, and the span is nonempty,
/// ordered and inside its current text. `citation` is the reply's own id.
pub(super) fn prove_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    input: &AppendRecord,
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
    if crate::conversation::room_message_owner_in(&vault.store, txn, message)?
        != Some(input.conversation)
    {
        return Err(invalid("quoted message belongs to another room"));
    }
    let turn = owning_turn_in(&vault.store, txn, &message)?;
    require_member(&vault.store, txn, &input.conversation, &turn)?;
    if !branch_reads_in(&vault.store, txn, input, turn)? {
        return Err(invalid("quoted message is outside the writer's branch"));
    }
    if writer_is_person(&vault.store, txn, input.actor)?
        && !crate::conversation::AudienceCache::default().readable(
            vault,
            txn,
            message,
            &[input.actor.entity_ref()],
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

/// A room-level record (neither a thread reply nor a worker record) reads
/// from every branch of its room. Any other record reads only from a branch
/// that runs through it.
fn branch_reads_in(
    store: &Store,
    txn: &RoTxn<'_>,
    input: &AppendRecord,
    turn: EntityId,
) -> Result<bool> {
    if !graph::is_thread_record(store, txn, &turn)?
        && !graph::is_sub_session_record(store, txn, &turn)?
    {
        return Ok(true);
    }
    Ok(match input.parent {
        Some(parent) => graph::chain(store, txn, &input.conversation, parent)?.contains(&turn),
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
