//! Epoch-summary codec and transactional lineage mint.

use rmpv::Value;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SUMMARY;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

use super::driver::{CompactionProduct, CompactionRequest, CompactionWindowMessage};

/// Pinned body keys for an epoch summary, in encode order.
///
/// `actor` is LAST: the dreamer/loom byline is persisted as the final key, so
/// authorship closes the record rather than opening it.
pub const EPOCH_SUMMARY_BODY_KEYS: [&str; 8] = [
    "v",
    "session",
    "epoch",
    "turn_start",
    "turn_end",
    "level",
    "text",
    "actor",
];

/// Current epoch-summary body codec version.
pub const EPOCH_SUMMARY_BODY_VERSION: u64 = 1;

/// `SUMMARY.level` an epoch summary mints at.
///
/// Storage truth is an UNBOUNDED integer (owner comment `9d06995b`). There is
/// no tier ladder here and no tier vocabulary anywhere in this module: names
/// for grains are display-layer property owned elsewhere.
pub const EPOCH_SUMMARY_LEVEL: u64 = 0;

/// Hard cap on the `DerivedFrom` edges one epoch summary emits.
///
/// The body's full turn RANGE remains truth; capped edges are provenance
/// accelerators, never the fence oracle. The mint's H-S3 probe reads every
/// covered turn regardless of this cap.
pub const EPOCH_SUMMARY_MAX_DERIVED_EDGES: usize = 256;

const KEY_EPOCH_V: &str = EPOCH_SUMMARY_BODY_KEYS[0];
const KEY_EPOCH_SESSION: &str = EPOCH_SUMMARY_BODY_KEYS[1];
const KEY_EPOCH_EPOCH: &str = EPOCH_SUMMARY_BODY_KEYS[2];
const KEY_EPOCH_TURN_START: &str = EPOCH_SUMMARY_BODY_KEYS[3];
const KEY_EPOCH_TURN_END: &str = EPOCH_SUMMARY_BODY_KEYS[4];
const KEY_EPOCH_LEVEL: &str = EPOCH_SUMMARY_BODY_KEYS[5];
const KEY_EPOCH_TEXT: &str = EPOCH_SUMMARY_BODY_KEYS[6];
const KEY_EPOCH_ACTOR: &str = EPOCH_SUMMARY_BODY_KEYS[7];

/// The typed epoch-summary body — the CB-A render contract.
///
/// CB-A (ONE-1701 keyframe render, ONE-1797 board tail) decodes an epoch
/// summary by calling the re-exported [`decode_epoch_summary_body`]. The body
/// deliberately does NOT ride `serialize.rs` SUMMARY field profiles
/// (`txt`/`lvl`/`at`/`src`): the typed codec IS the contract, so a render
/// cannot drift with a field-profile table it does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EpochSummaryBody {
    /// Codec version, currently [`EPOCH_SUMMARY_BODY_VERSION`].
    pub v: u64,
    /// 32-hex ref of the SESSION this epoch belongs to.
    pub session: String,
    /// 1-based. The next epoch number derives from the session's existing
    /// epoch summaries — durable entities ARE the counter, crash-safe by
    /// append-only lineage — never from a mutable session row.
    pub epoch: u64,
    pub turn_start: u64,
    pub turn_end: u64,
    /// Storage-truth ladder integer, unbounded and never named.
    pub level: u64,
    pub text: String,
    /// 32-hex ref of the host-stamped [`WriteActor`] passed to
    /// [`crate::compaction::CompactionDriver::integrate`]. Guest-supplied authorship is
    /// unrepresentable: the writer stamps this, never the body's author.
    pub actor: String,
}

/// Encodes an epoch-summary body into its pinned-key MessagePack form.
///
/// The encoder enforces the SAME axes [`decode_epoch_summary_body`] refuses,
/// so this module cannot emit bytes it would itself reject on the way back
/// in: an unsupported codec version, an inverted turn range, a `session` or
/// `actor` that is not a 32-hex entity ref, or blank text is a refusal here —
/// at the moment the value is still in hand — rather than a durable row whose
/// consumers discover the problem at render time.
pub fn encode_epoch_summary_body(body: &EpochSummaryBody) -> Result<Vec<u8>> {
    if body.v != EPOCH_SUMMARY_BODY_VERSION {
        return Err(Error::InvariantViolation(
            "unsupported epoch summary codec version",
        ));
    }
    if body.turn_end < body.turn_start {
        return Err(Error::InvariantViolation("turn_end precedes turn_start"));
    }
    for hex in [body.session.as_str(), body.actor.as_str()] {
        EntityId::from_hex(hex)
            .map_err(|_| Error::InvariantViolation("entity refs must be 32-hex strings"))?;
    }
    if body.text.trim().is_empty() {
        return Err(Error::InvariantViolation("epoch summary text is empty"));
    }
    let value = Value::Map(vec![
        (Value::from(KEY_EPOCH_V), Value::from(body.v)),
        (
            Value::from(KEY_EPOCH_SESSION),
            Value::from(body.session.as_str()),
        ),
        (Value::from(KEY_EPOCH_EPOCH), Value::from(body.epoch)),
        (
            Value::from(KEY_EPOCH_TURN_START),
            Value::from(body.turn_start),
        ),
        (Value::from(KEY_EPOCH_TURN_END), Value::from(body.turn_end)),
        (Value::from(KEY_EPOCH_LEVEL), Value::from(body.level)),
        (Value::from(KEY_EPOCH_TEXT), Value::from(body.text.as_str())),
        (
            Value::from(KEY_EPOCH_ACTOR),
            Value::from(body.actor.as_str()),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("MessagePack encode failed"))?;
    Ok(out)
}

/// Strictly decodes an epoch-summary body.
///
/// Trailing bytes, non-map values, non-string keys, unknown keys and
/// duplicate keys are all refused — the same discipline the AGENT_DEF and
/// SKILL codecs enforce, so a host cannot smuggle a field into the keyframe.
pub fn decode_epoch_summary_body(bytes: &[u8]) -> Result<EpochSummaryBody> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvariantViolation("body is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvariantViolation("trailing bytes after body map"));
    }
    let Value::Map(entries) = value else {
        return Err(Error::InvariantViolation("body must be a MessagePack map"));
    };

    let mut integers: [Option<u64>; EPOCH_SUMMARY_BODY_KEYS.len()] = [None; 8];
    let mut session = None;
    let mut text = None;
    let mut actor = None;
    let mut seen = [false; EPOCH_SUMMARY_BODY_KEYS.len()];

    for (key, value) in &entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvariantViolation("body keys must be strings"));
        };
        let Some(index) = EPOCH_SUMMARY_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvariantViolation(
                "body key is not in the pinned EPOCH_SUMMARY_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvariantViolation("duplicate body key"));
        }
        seen[index] = true;
        match EPOCH_SUMMARY_BODY_KEYS[index] {
            KEY_EPOCH_SESSION => session = Some(epoch_summary_hex_ref(value)?),
            KEY_EPOCH_ACTOR => actor = Some(epoch_summary_hex_ref(value)?),
            KEY_EPOCH_TEXT => {
                text = Some(
                    value
                        .as_str()
                        .ok_or(Error::InvariantViolation("text must be a UTF-8 string"))?
                        .to_owned(),
                );
            }
            _ => {
                integers[index] = Some(value.as_u64().ok_or(Error::InvariantViolation(
                    "numeric body keys must be unsigned integers",
                ))?);
            }
        }
    }

    let missing = || Error::InvariantViolation("missing required body key");
    let body = EpochSummaryBody {
        v: integers[0].ok_or_else(missing)?,
        session: session.ok_or_else(missing)?,
        epoch: integers[2].ok_or_else(missing)?,
        turn_start: integers[3].ok_or_else(missing)?,
        turn_end: integers[4].ok_or_else(missing)?,
        level: integers[5].ok_or_else(missing)?,
        text: text.ok_or_else(missing)?,
        actor: actor.ok_or_else(missing)?,
    };
    if body.v != EPOCH_SUMMARY_BODY_VERSION {
        return Err(Error::InvariantViolation(
            "unsupported epoch summary codec version",
        ));
    }
    if body.turn_end < body.turn_start {
        return Err(Error::InvariantViolation("turn_end precedes turn_start"));
    }
    // Symmetric with the encoder: a keyframe whose whole point is prose the
    // render and the embedder consume cannot carry no prose at all, so the
    // codec refuses in both directions rather than round-tripping a body its
    // consumers would have to special-case.
    if body.text.trim().is_empty() {
        return Err(Error::InvariantViolation("epoch summary text is empty"));
    }
    Ok(body)
}

/// A 32-hex entity ref, validated as one rather than accepted as any string.
fn epoch_summary_hex_ref(value: &Value) -> Result<String> {
    let text = value.as_str().ok_or(Error::InvariantViolation(
        "entity refs must be 32-hex strings",
    ))?;
    EntityId::from_hex(text)
        .map_err(|_| Error::InvariantViolation("entity refs must be 32-hex strings"))?;
    Ok(text.to_owned())
}

/// One durable prior epoch of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PriorEpoch {
    epoch: u64,
    turn_end: u64,
}

/// The claimed range must cover every distinct turn, in message-log order.
pub(super) fn validate_window_span(window: &[CompactionWindowMessage]) -> Result<(u64, u64)> {
    let Some(first) = window.first() else {
        return Err(Error::InvariantViolation(
            "compaction window carries no messages",
        ));
    };
    let mut last = first.turn;
    for message in &window[1..] {
        if message.turn != last && last.checked_add(1) != Some(message.turn) {
            return Err(Error::InvariantViolation(
                "compaction window turns must be ordered and contiguous",
            ));
        }
        last = message.turn;
    }
    Ok((first.turn, last))
}

/// Checked both at request issuance and under the mint's write transaction.
pub(super) fn validate_epoch_boundary(prior: Option<PriorEpoch>, turn_start: u64) -> Result<()> {
    if let Some(prior) = prior {
        let next = prior
            .turn_end
            .checked_add(1)
            .ok_or(Error::InvariantViolation(
                "compaction turn boundary is exhausted",
            ))?;
        if turn_start != next {
            return Err(Error::InvariantViolation(
                "compaction window does not start at the next durable turn boundary",
            ));
        }
    }
    Ok(())
}

/// Reads the session's highest durable epoch summary.
///
/// The DURABLE entities are the counter: a crash between two compactions can
/// never desynchronize an epoch number from the rows that justify it, because
/// there is no separate mutable counter to desynchronize.
///
/// Rows whose body is not an epoch-summary record are SKIPPED, not refused: an
/// ordinary witness SUMMARY is a different kind of row that happens to share
/// the type byte, and it carries no epoch to compare.
pub(super) fn prior_epoch_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    session_ref: &EntityId,
) -> Result<Option<PriorEpoch>> {
    let session = session_ref.to_hex();
    let mut best: Option<EpochSummaryBody> = None;
    let mut conflicting = false;
    for row in store.entities.iter(rtxn)? {
        let (_, raw) = row?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SUMMARY || raw.len() <= ENTITY_METADATA_HEADER_LEN {
            continue;
        }
        let Ok(body) = decode_epoch_summary_body(&raw[ENTITY_METADATA_HEADER_LEN..]) else {
            continue;
        };
        if body.session != session {
            continue;
        }
        match best.as_ref() {
            Some(prior) if body.epoch < prior.epoch => {}
            Some(prior) if body.epoch == prior.epoch => {
                // Identical copies are harmless. Different keyframes at the
                // highest epoch have no agreed successor boundary or content.
                conflicting |= body != *prior;
            }
            _ => {
                best = Some(body);
                conflicting = false;
            }
        }
    }
    // Wait until the maximum is known: a lower tied epoch must not make the
    // answer depend on which entity ID the store iterated first.
    if conflicting {
        return Err(Error::InvariantViolation(
            "conflicting summaries at the highest compaction epoch",
        ));
    }
    Ok(best.map(|body| PriorEpoch {
        epoch: body.epoch,
        turn_end: body.turn_end,
    }))
}

/// Mints ONE session-kind SUMMARY entity for a finished compaction.
///
/// Everything that decides what the row IS happens inside a single write
/// transaction: the H-S3 probe over every covered turn, the epoch derivation
/// from durable prior summaries, the body encode, the put, its
/// pending-embedding marker and the capped `DerivedFrom` edge set. A refusal
/// on any axis rolls the whole transaction back, so a half-minted keyframe
/// cannot exist.
///
/// The shape checks that need no transaction — the session match, a non-empty
/// window, a non-empty product — run BEFORE one opens, so a refused mint never
/// touches storage at all.
///
/// The row is BYTE-STABLE from this moment: this module exposes no update
/// path, which is what lets CB-A cache the rendered prefix.
pub(super) fn mint_epoch_summary(
    vault: &Vault,
    session_ref: &EntityId,
    byline: WriteActor,
    request: &CompactionRequest,
    product: &CompactionProduct,
) -> Result<(u64, EntityId)> {
    if request.session_ref != *session_ref {
        return Err(Error::InvariantViolation(
            "request session_ref does not match the integrated session",
        ));
    }
    let (turn_start, turn_end) = validate_window_span(&request.window)?;
    if request.turn_start != turn_start {
        return Err(Error::InvariantViolation(
            "compaction request turn_start does not match its window",
        ));
    }

    // An empty or whitespace-only product is a FAILED compaction wearing a
    // success's clothes: minting it would swap a real message-log prefix out
    // for a keyframe that carries none of it, and the row is byte-stable with
    // no update path, so the loss would be permanent. Refusing BEFORE the
    // write transaction opens means `integrate` returns `Err` before it
    // mutates state: the driver stays `Compacting`, and the host takes the
    // documented backend-failure exit (`CompactionDriver::abandon`), whose
    // next threshold crossing emits `Begin` again.
    if product.summary_text.trim().is_empty() {
        return Err(Error::InvariantViolation(
            "compaction product summary_text is empty",
        ));
    }

    // `DerivedFrom` targets come from the REQUEST's window, deduplicated in
    // first-seen order and hard-capped. The body's turn range stays truth.
    let mut derived: Vec<EntityId> = Vec::new();
    for message in &request.window {
        if derived.len() >= EPOCH_SUMMARY_MAX_DERIVED_EDGES {
            break;
        }
        if !derived.contains(&message.turn_id) {
            derived.push(message.turn_id);
        }
    }

    // The keyframe's temporal position IS the compaction moment: the recorded
    // watermark. Wall-clock would make an otherwise byte-stable row depend on
    // when it happened to be minted.
    let at = request.watermark.learned_at.max(1);
    let summary_id = EntityId::now();

    let epoch = vault.with_write_txn(|wtxn| {
        refuse_overlay_derived_mint(&vault.store, &request.window)?;
        let prior = prior_epoch_in_txn(&vault.store, &*wtxn, session_ref)?;
        validate_epoch_boundary(prior, turn_start)?;
        let epoch = match prior {
            Some(prior) => prior.epoch.checked_add(1).ok_or(Error::InvariantViolation(
                "compaction epoch counter is exhausted",
            ))?,
            None => 1,
        };
        let body = encode_epoch_summary_body(&EpochSummaryBody {
            v: EPOCH_SUMMARY_BODY_VERSION,
            session: session_ref.to_hex(),
            epoch,
            turn_start,
            turn_end,
            level: EPOCH_SUMMARY_LEVEL,
            text: product.summary_text.clone(),
            actor: byline.entity_ref().to_hex(),
        })?;
        let mut batch = vault.batch_in().put(
            &summary_id,
            ENTITY_TYPE_SUMMARY,
            TimeRange { start: at, end: at },
            at,
            &body,
        );
        for target in &derived {
            batch = batch.edge(&summary_id, EdgeKind::DerivedFrom, target, 1.0);
        }
        batch.apply(wtxn)?;
        // Explicitly scheduled for embedding inside the mint transaction, so
        // the ratified "vector-indexed, RAPTOR-retrievable" contract is a
        // durable fact of the mint rather than a later sweep's guess.
        vault
            .store
            .mark_pending_embedding(wtxn, &summary_id, &body)?;
        Ok(epoch)
    })?;
    Ok((epoch, summary_id))
}

// ─── H-S3: creation-time refusal under the ARCH-0052 overlay model ──────

/// H-S3 (ARCH-0052 P6): refuses a base epoch-summary mint whose window covers
/// a turn that is still a LIVE session-overlay member.
///
/// Under the overlay model there is no durable fence row to write and no
/// fenced base row to suppress: an off-record turn lives in the room's own
/// [`crate::session_overlay::SessionOverlay`] and never reaches base at all
/// (ONE-1731/ONE-1732 removed the durable off-record contract outright). So
/// "fenced at creation" reads, at this head, as REFUSED at creation: the
/// engine will not mint a base keyframe derived from room content, and the
/// refusal is the landed [`Error::OffRecordTaintedBaseWrite`] the K4 taint
/// guard already raises for the same class of write.
///
/// The probe covers EVERY covered turn, so it is independent of
/// [`EPOCH_SUMMARY_MAX_DERIVED_EDGES`]: a room turn at window position 1000
/// refuses the mint even though no edge is emitted for it. Membership is read
/// from live registry state INSIDE the applying transaction, which is the
/// state the transaction applies against — the same TOCTOU-free discipline
/// the K4 guard uses.
fn refuse_overlay_derived_mint(store: &Store, window: &[CompactionWindowMessage]) -> Result<()> {
    if !store.off_record_sessions.has_overlay_entities()? {
        return Ok(());
    }
    for message in window {
        if store
            .off_record_sessions
            .contains_entity(&message.turn_id)?
        {
            return Err(Error::OffRecordTaintedBaseWrite {
                entity_ref: message.turn_id.to_hex(),
            });
        }
    }
    Ok(())
}
