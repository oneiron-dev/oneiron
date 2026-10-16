//! Epoch-summary codec and transactional lineage mint.

use crate::ports::{EdgeDirection, EdgeStoreRead, EntityRecord, EntityStoreRead};
use rmpv::Value;

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SUMMARY;
use crate::store::{ManifestDbs, Store};
use crate::temporal::TimeRange;
use crate::tokenizer::count_context_pack_tokens;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

use super::driver::{CompactionProduct, CompactionRequest, CompactionWindowMessage, WindowLog};
use super::stored_epoch::{StoredEpoch, stored_epoch_in};
use super::withdrawn::WithdrawnKeyframe;
use crate::error::OffRecordError;

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

/// Hard cap on the sources a host-numbered log's summary derives from.
///
/// For an executor run the `DerivedFrom` set IS the erasure and disclosure
/// fence (there is no turn range to fall back on), so a window naming more
/// sources is refused, never cut.
pub const EPOCH_SUMMARY_MAX_SOURCES: usize = 1024;

const KEY_EPOCH_V: &str = EPOCH_SUMMARY_BODY_KEYS[0];
const KEY_EPOCH_SESSION: &str = EPOCH_SUMMARY_BODY_KEYS[1];
const KEY_EPOCH_EPOCH: &str = EPOCH_SUMMARY_BODY_KEYS[2];
const KEY_EPOCH_TURN_START: &str = EPOCH_SUMMARY_BODY_KEYS[3];
const KEY_EPOCH_TURN_END: &str = EPOCH_SUMMARY_BODY_KEYS[4];
const KEY_EPOCH_LEVEL: &str = EPOCH_SUMMARY_BODY_KEYS[5];
pub(super) const KEY_EPOCH_TEXT: &str = EPOCH_SUMMARY_BODY_KEYS[6];
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

/// Walks every record an epoch summary's words came from: its `DerivedFrom`
/// targets, and theirs through any nested epoch summary, each record once.
///
/// A summary's own birth scope is its run's position and cannot stand for
/// what it was written from, so a reader that is not the owner takes an
/// epoch summary only while `admit` takes each record reached here (nested
/// summaries included). The walk refuses as soon as one is refused or a source no
/// longer resolves, or a summary's pointer does ([`stored_epoch_in`]).
/// `Ok(None)` when `body` is not an epoch summary.
pub(crate) fn epoch_sources_admitted_in(
    dbs: &impl ManifestDbs,
    rtxn: &heed::RoTxn<'_>,
    summary: &EntityId,
    body: &[u8],
    mut admit: impl FnMut(&EntityId, &EntityRecord) -> Result<bool>,
) -> Result<Option<bool>> {
    match stored_epoch_in(dbs, rtxn, summary, body)? {
        StoredEpoch::No => return Ok(None),
        StoredEpoch::Unresolved => return Ok(Some(false)),
        StoredEpoch::Yes => {}
    }
    let mut seen = std::collections::BTreeSet::from([*summary]);
    let mut pending = vec![*summary];
    while let Some(next) = pending.pop() {
        for edge in dbs.port_edges(
            rtxn,
            &next,
            EdgeDirection::Out,
            Some(EdgeKind::DerivedFrom),
            None,
        )? {
            let source = edge?.target;
            if !seen.insert(source) {
                continue;
            }
            let Some(row) = dbs.port_entity_record(rtxn, &source)? else {
                return Ok(Some(false));
            };
            if !admit(&source, &row)? {
                return Ok(Some(false));
            }
            if row.entity_type == ENTITY_TYPE_SUMMARY {
                match stored_epoch_in(dbs, rtxn, &source, &row.body)? {
                    StoredEpoch::No => {}
                    StoredEpoch::Yes => pending.push(source),
                    StoredEpoch::Unresolved => return Ok(Some(false)),
                }
            }
        }
    }
    Ok(Some(true))
}

/// Where a run's epoch summary is born: the run credential's world and
/// facet, as the run's other records are. `None` is a vault-wide run's:
/// base reality, and the vault's default facet (ARCH-0022: with no active
/// mask, the vault's default facet stamps a record).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EpochPlacement {
    pub(crate) world: Option<EntityId>,
    pub(crate) facet: Option<EntityId>,
}

impl EpochPlacement {
    /// Settles the minted summary's birth stamp in its mint transaction.
    pub(crate) fn settle_in(
        self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        summary: EntityId,
    ) -> Result<()> {
        let world = self.world.unwrap_or_else(crate::claim::base_world_id);
        let facet = match self.facet {
            Some(facet) => facet,
            None => crate::claim::default_facet_in(store, txn)?,
        };
        crate::federation::record_scope::settle_epoch_birth(store, txn, summary, world, facet)
    }
}

/// Whether row `id` may leave through an export door, as the epoch fence
/// judges it: an epoch summary leaves only while it is not withdrawn and the
/// door would carry every record its words came from, through nested epochs
/// (`carries` judges one source's row; an erased or withdrawn source carries
/// nothing). The fence never exports those sources along with it. Every
/// other row passes.
pub(crate) fn epoch_exportable_in(
    store: &impl ManifestDbs,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
    mut carries: impl FnMut(&EntityId, &EntityRecord) -> Result<bool>,
) -> Result<bool> {
    if entity_type != ENTITY_TYPE_SUMMARY {
        return Ok(true);
    }
    let withdrawn = |id: &EntityId| -> Result<bool> {
        let state = crate::ports::TombstoneStoreRead::port_deletion_state(store, rtxn, id)?;
        Ok(state.deleted || state.stale)
    };
    match epoch_sources_admitted_in(store, rtxn, id, body, |source, row| {
        Ok(!withdrawn(source)? && carries(source, row)?)
    })? {
        None => Ok(true),
        Some(false) => Ok(false),
        Some(true) => Ok(!withdrawn(id)?),
    }
}

/// Whether a reader who is not the owner may be shown row `id`, as the epoch
/// fence judges it: by the export door's rule, with `admits` judging one
/// source's row for that reader. An epoch summary shows only while neither
/// it nor any record its words came from (through nested epochs) is
/// withdrawn, and the reader may see each of those records. Every other row
/// passes.
pub(crate) fn epoch_disclosable_in(
    store: &impl ManifestDbs,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
    admits: impl FnMut(&EntityId, &EntityRecord) -> Result<bool>,
) -> Result<bool> {
    epoch_exportable_in(store, rtxn, id, entity_type, body, admits)
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

/// Recognizes a session's epoch-shaped map even when strict decoding fails.
///
/// Identity requires the pinned version/session/epoch/turn-range keys, or
/// the full pinned key set with just one key missing. A lone shared application
/// field is not epoch identity. Read top-level keys in order so a damaged
/// suffix cannot hide identity already read. Apart from the session match,
/// strict decoding owns value validation; the codec permits any key order.
fn is_epoch_candidate_for_session(bytes: &[u8], session_ref: &EntityId) -> bool {
    let (pairs, mut cursor) = match bytes {
        [marker @ 0x80..=0x8f, rest @ ..] => (u32::from(*marker & 0x0f), rest),
        [0xde, a, b, rest @ ..] => (u32::from(u16::from_be_bytes([*a, *b])), rest),
        [0xdf, a, b, c, d, rest @ ..] => (u32::from_be_bytes([*a, *b, *c, *d]), rest),
        _ => return false,
    };
    let mut matching_session = false;
    let mut seen = [false; EPOCH_SUMMARY_BODY_KEYS.len()];
    for _ in 0..pairs {
        let Ok(key) = rmpv::decode::read_value(&mut cursor) else {
            break;
        };
        if let Some(index) = EPOCH_SUMMARY_BODY_KEYS
            .iter()
            .position(|known| Some(*known) == key.as_str())
        {
            seen[index] = true;
        }
        let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
            break;
        };
        if key.as_str() == Some(KEY_EPOCH_SESSION) {
            matching_session |= value
                .as_str()
                .and_then(|text| EntityId::from_hex(text).ok())
                .is_some_and(|id| id == *session_ref);
        }
    }
    // The first five pinned keys carry codec, session and lineage identity.
    // Count distinct keys, not occurrences: duplicates cannot supply identity.
    let identity_keys = seen[..5].iter().all(|&present| present);
    let one_missing_key = seen.iter().filter(|&&present| !present).count() == 1;
    matching_session && (identity_keys || one_missing_key)
}

/// One durable prior epoch of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PriorEpoch {
    epoch: u64,
    turn_end: u64,
}

impl PriorEpoch {
    pub(crate) const fn new(epoch: u64, turn_end: u64) -> Self {
        Self { epoch, turn_end }
    }
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
/// the type byte, and it carries no epoch to compare. An identifiable malformed
/// epoch candidate for this session is refused rather than losing its lineage.
/// A withdrawn epoch counts by the keyframe it keeps, so numbering never
/// restarts under a scrubbed one.
pub(super) fn prior_epoch_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    session_ref: &EntityId,
) -> Result<Option<PriorEpoch>> {
    let mut best: Option<(WithdrawnKeyframe, Option<String>)> = None;
    let mut conflicting = false;
    for row in store.port_entity_records(rtxn)? {
        let (_, row) = row?;
        if row.entity_type != ENTITY_TYPE_SUMMARY || row.body.is_empty() {
            continue;
        }
        let bytes = &row.body;
        let (keyframe, text) = match decode_epoch_summary_body(bytes) {
            Ok(body) => (WithdrawnKeyframe::of_body(&body)?, Some(body.text)),
            Err(error) => match WithdrawnKeyframe::decode(bytes) {
                Ok(keyframe) => (keyframe, None),
                Err(_) if is_epoch_candidate_for_session(bytes, session_ref) => return Err(error),
                Err(_) => continue,
            },
        };
        if keyframe.session != *session_ref {
            continue;
        }
        match best.as_ref() {
            Some((prior, _)) if keyframe.epoch < prior.epoch => {}
            Some((prior, prior_text)) if keyframe.epoch == prior.epoch => {
                // Session IDs and epoch numbers already match; actor IDs
                // compare as IDs, not as the codec spells them. Different
                // keyframes at the highest epoch remain conflicts, and so do
                // words beside none: a withdrawn one keeps nothing to compare.
                conflicting |= keyframe != *prior || text != *prior_text;
            }
            _ => {
                best = Some((keyframe, text));
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
    Ok(best.map(|(keyframe, _)| PriorEpoch {
        epoch: keyframe.epoch,
        turn_end: keyframe.turn_end,
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
/// Minted identity supplied only while the SUMMARY row is in the same write
/// transaction. Consumers cannot substitute a caller's summary reference.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EpochMint {
    summary_id: EntityId,
    session_ref: EntityId,
    epoch: u64,
    turn_start: u64,
    turn_end: u64,
}

impl EpochMint {
    pub(crate) const fn summary_id(self) -> EntityId {
        self.summary_id
    }
    pub(crate) const fn session_ref(self) -> EntityId {
        self.session_ref
    }
    pub(crate) const fn epoch(self) -> u64 {
        self.epoch
    }
    pub(crate) const fn turn_start(self) -> u64 {
        self.turn_start
    }
    pub(crate) const fn turn_end(self) -> u64 {
        self.turn_end
    }
}

/// The extra write shares the summary mint transaction. Failure of EITHER
/// operation rolls back both, leaving the driver request retryable.
pub(super) fn mint_epoch_summary_with(
    vault: &Vault,
    session_ref: &EntityId,
    byline: WriteActor,
    request: &CompactionRequest,
    product: &CompactionProduct,
    extra: impl FnOnce(&mut heed::RwTxn<'_>, &EpochMint) -> Result<()>,
) -> Result<(u64, EntityId)> {
    mint_epoch_summary_guarded(vault, session_ref, byline, request, product, |_| Ok(()), extra)
}

/// [`mint_epoch_summary_with`] whose `landing` runs FIRST in the mint's own
/// transaction (Docs Q17): a session-bound run on a route that went on
/// record lands its summary in base only while its participant, its saver
/// and its route still stand, exactly as its other base writes do. A refused
/// landing writes nothing.
pub(super) fn mint_epoch_summary_guarded(
    vault: &Vault,
    session_ref: &EntityId,
    byline: WriteActor,
    request: &CompactionRequest,
    product: &CompactionProduct,
    landing: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
    extra: impl FnOnce(&mut heed::RwTxn<'_>, &EpochMint) -> Result<()>,
) -> Result<(u64, EntityId)> {
    let (turn_start, turn_end) = check_mint(session_ref, request, product)?;

    // `DerivedFrom` targets are the sealed request's sources: a conversation
    // window's turns (deduplicated, hard-capped; the body's turn range stays
    // truth), or every record a host-numbered log was read from.
    let derived = &request.sources;

    // The keyframe's temporal position IS the compaction moment: the recorded
    // watermark. Wall-clock would make an otherwise byte-stable row depend on
    // when it happened to be minted.
    let at = request.watermark.learned_at;
    let summary_id = vault.store.clock.entity_id()?;

    let epoch = vault.with_write_txn_grouped(|wtxn| {
        landing(wtxn)?;
        refuse_overlay_derived_mint(
            &vault.store,
            request
                .window
                .iter()
                .map(|message| message.turn_id)
                .filter(|_| request.log == WindowLog::Conversation)
                .chain(request.sources.iter().copied()),
        )?;
        let prior = match request.log {
            WindowLog::Conversation => prior_epoch_in_txn(&vault.store, &*wtxn, session_ref)?,
            // The host's own rows re-check this position in `extra`.
            WindowLog::Host { prior, .. } => prior,
        };
        validate_epoch_boundary(prior, turn_start)?;
        let epoch = next_epoch(prior)?;
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
        // A source erased or withdrawn before this mint has already run its
        // invalidation, so the summary is born withdrawn, as it would be had
        // the erasure come after it: never indexed, never embedded, its row
        // left with only its keyframe. Such a source takes no new dependency
        // row; the summary is stale for good, withdrawn for where that
        // source's words sat.
        let mut born_withdrawn = None::<crate::settings::CarriedWorlds>;
        for target in derived {
            let state =
                crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, wtxn, target)?;
            if state.deleted || state.stale {
                born_withdrawn
                    .get_or_insert_default()
                    .absorb(&crate::settings::minted_worlds_in(
                        &vault.store,
                        wtxn,
                        target,
                    )?);
            } else {
                batch = batch.edge(&summary_id, EdgeKind::DerivedFrom, target, 1.0);
            }
        }
        batch.apply(wtxn)?;
        // Explicitly scheduled for embedding inside the mint transaction, so
        // the ratified "vector-indexed, RAPTOR-retrievable" contract is a
        // durable fact of the mint rather than a later sweep's guess.
        if born_withdrawn.is_none() {
            vault
                .store
                .mark_pending_embedding(wtxn, &summary_id, &body)?;
        }
        // The compacted turns leave their boards' retained history in the
        // same act: reconstructing one now fails explicitly (ARCH-0067).
        if request.log == WindowLog::Conversation {
            crate::context_board::fold_board_turns_in_txn(
                vault,
                wtxn,
                request.window.iter().map(|message| message.turn_id),
            )?;
        }
        extra(
            wtxn,
            &EpochMint {
                summary_id,
                session_ref: *session_ref,
                epoch,
                turn_start,
                turn_end,
            },
        )?;
        if let Some(worlds) = &born_withdrawn {
            crate::ports::record_withdrawn_in_txn(&vault.store, wtxn, &summary_id, worlds)?;
            crate::ports::RetrievalIndex::port_retrieval_mark_stale(vault, wtxn, &summary_id)?;
            super::withdrawn::scrub_withdrawn_epoch_in_txn(&vault.store, wtxn, &summary_id)?;
        }
        Ok(epoch)
    })?;
    Ok((epoch, summary_id))
}

/// The shape checks a mint makes before any transaction opens: the session
/// match, a window and its span, and a product that is nonblank prose
/// inside its sealed budget. Returns the window's first and last turns.
fn check_mint(
    session_ref: &EntityId,
    request: &CompactionRequest,
    product: &CompactionProduct,
) -> Result<(u64, u64)> {
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

    // Use the same tokenizer as context-pack accounting. Reject, never trim:
    // the backend owns the prose, but cannot exceed the sealed allocation.
    if count_context_pack_tokens(&product.summary_text) as u64 > request.summary_token_budget {
        return Err(Error::InvariantViolation(
            "compaction product summary_text exceeds summary_token_budget",
        ));
    }

    Ok((turn_start, turn_end))
}

/// The epoch after `prior`, or the first.
fn next_epoch(prior: Option<PriorEpoch>) -> Result<u64> {
    match prior {
        Some(prior) => prior.epoch.checked_add(1).ok_or(Error::InvariantViolation(
            "compaction epoch counter is exhausted",
        )),
        None => Ok(1),
    }
}

/// [`mint_epoch_summary_with`] for a run in an off-record room
/// (agent-runtime-v1 §d7): the compactor read the room's overlay over base,
/// and the summary lands through the run's own session handle, on the route
/// the run captured at entry. The SUMMARY, its `DerivedFrom` lineage, its
/// text and `extra`'s rows stage in one overlay segment and drop with the
/// overlay at close; a room closed or flipped since the pass began refuses
/// the landing.
///
/// Nothing reaches base: no pending embedding (a room has no `pe:`
/// keyspace), no withdrawal marker and no birth stamp (overlay rows carry no
/// record scope, and export and sync stay base-only). Each op is journaled
/// under the run's compaction session and the summary itself, a turn no
/// promotion names, so promoting the room's turns never carries it.
///
/// A source withdrawn before the mint keeps its edge: base erasure cannot
/// mark an overlay summary, so the room's render walks the lineage and the
/// summary reads as withdrawn there.
pub(super) fn mint_epoch_summary_in_overlay(
    session: &crate::off_record::OffRecordSession<'_>,
    route: &crate::session_overlay::SessionWriteRoute,
    session_ref: &EntityId,
    byline: WriteActor,
    request: &CompactionRequest,
    product: &CompactionProduct,
    extra: impl FnOnce(
        &crate::store::SessionStoreView<'_>,
        &mut heed::RwTxn<'_>,
        &EpochMint,
    ) -> Result<()>,
) -> Result<(u64, EntityId)> {
    use crate::batch::BatchOp;
    use crate::session_overlay::{JournalEntry, JournalRole, JournalScope};

    let (turn_start, turn_end) = check_mint(session_ref, request, product)?;
    let WindowLog::Host { prior, .. } = request.log else {
        return Err(Error::InvariantViolation(
            "an off-record mint takes a host-numbered log",
        ));
    };
    // The host's own rows re-check this position in `extra`.
    validate_epoch_boundary(prior, turn_start)?;
    let epoch = next_epoch(prior)?;
    let at = request.watermark.learned_at;
    let occurred = TimeRange { start: at, end: at };
    let summary_id = session.read_view()?.clock().entity_id()?;
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
    let scope = JournalScope::new(*session_ref, summary_id);
    let entry = |role, op| JournalEntry {
        scope,
        role,
        learned_at: at,
        occurred,
        op,
    };
    session.overlay_write_routed(route, |wtxn, apply| {
        apply(
            wtxn,
            entry(
                JournalRole::SummaryDerivedFrom,
                BatchOp::Put {
                    id: summary_id,
                    entity_type: ENTITY_TYPE_SUMMARY,
                    occurred,
                    learned_at: at,
                    data: body,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                },
            ),
        )?;
        for target in &request.sources {
            apply(
                wtxn,
                entry(
                    JournalRole::SummaryDerivedFrom,
                    BatchOp::Edge {
                        src: summary_id,
                        kind: EdgeKind::DerivedFrom,
                        tgt: *target,
                        weight: 1.0,
                        vad: crate::affect::Vad::NEUTRAL,
                    },
                ),
            )?;
        }
        apply(
            wtxn,
            entry(
                JournalRole::TurnOwnedArtifact,
                BatchOp::Text {
                    id: summary_id,
                    fields: vec![("content".to_owned(), product.summary_text.clone())],
                },
            ),
        )?;
        extra(
            &session.read_view()?,
            wtxn,
            &EpochMint {
                summary_id,
                session_ref: *session_ref,
                epoch,
                turn_start,
                turn_end,
            },
        )
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
/// refusal is the landed [`OffRecordError::OffRecordTaintedBaseWrite`](crate::error::OffRecordError::OffRecordTaintedBaseWrite) the K4 taint
/// guard already raises for the same class of write.
///
/// The probe covers EVERY covered turn, so it is independent of
/// [`EPOCH_SUMMARY_MAX_DERIVED_EDGES`]: a room turn at window position 1000
/// refuses the mint even though no edge is emitted for it. Membership is read
/// from live registry state INSIDE the applying transaction, which is the
/// state the transaction applies against — the same TOCTOU-free discipline
/// the K4 guard uses.
fn refuse_overlay_derived_mint(
    store: &Store,
    covered: impl Iterator<Item = EntityId>,
) -> Result<()> {
    if !store.off_record_sessions.has_overlay_entities()? {
        return Ok(());
    }
    for id in covered {
        if store.off_record_sessions.contains_entity(&id)? {
            return Err(Error::OffRecord(
                OffRecordError::OffRecordTaintedBaseWrite {
                    entity_ref: id.to_hex(),
                },
            ));
        }
    }
    Ok(())
}
