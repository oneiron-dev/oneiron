//! FIX 3103 (OF-540, OF-397): the derivation witnesses of leased runs, one
//! event stream that does not wait for a run's pack attribution to bind.
//!
//! Each row is one exact DerivedFrom edge `(derived, source)` a run's write
//! left stored, keyed by the run's attempt and lease generation, so a retried
//! write records it once and two tries of a run never share a row. A run's
//! bind and close project its live rows onto its used chain
//! ([`super::bind_agent_run_attribution`], [`super::witness_agent_run_close`]).
//! An edge that lands for a run after its lease ended (an off-record op an
//! authorized promotion replays, or a summary the run asked for) is kept as a
//! late landing: the run's terminal receipt stays as it froze.
//!
//! A scope summary a run asks for is kept beside them, under the Dreamer
//! attempt that mints it, so its landing is witnessed for the run that asked
//! and never for the attempt's parent or another run of the same actor.
//!
//! A write with no token, or whose lease no longer holds, records nothing and
//! lands as it would. Every witness is captured in a savepoint of the
//! writer's transaction (the FIX 7021 shape): one that fails is dropped
//! whole with a WARN, and never holds, fails or rolls back the write,
//! compaction, summary or promotion carrying it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::limit_ask::EngineLimit;
use crate::ports::{EdgeDirection, EdgeStore, EdgeStoreRead};
use crate::receipt::{PackAttributionFields, UsedProvenanceEdge};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

use super::run_writes::{RunWriteToken, current_run_write_token};

/// `(kind, id, rest)`: a derivation is [`DERIVATION`], the run's attempt,
/// its lease generation and a digest of the pair; a request is [`REQUEST`],
/// the summary's Dreamer attempt, the asking run's attempt and its
/// generation. An erase moves a derivation it scrubs to a fresh opaque key
/// that no id it held derives: the run's attempt and generation and a new
/// ULID, or [`ERASED`] and a new ULID once the run itself is erased.
type WitnessKey = ([u8; 1], [u8; 16], Vec<u8>);

const WITNESS: SideTable<WitnessKey, WitnessRow, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_DERIVATION_WITNESS);

const DERIVATION: [u8; 1] = *b"d";
const ERASED: [u8; 1] = *b"e";
const REQUEST: [u8; 1] = *b"r";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum WitnessRow {
    Derivation(DerivationWitness),
    Request(SummaryRequest),
}

/// One DerivedFrom edge a run's write left stored. An erase keeps the row
/// and clears the end it names (FIX 8988).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DerivationWitness {
    /// The derived end; `None` once that entity is erased.
    derived: Option<EntityId>,
    /// The source end; `None` once that entity is erased.
    source: Option<EntityId>,
    producer: WitnessProducer,
    /// Whether the run's lease held as the edge landed. A late landing joins
    /// no frozen receipt; the run's later credit reads it.
    live: bool,
    /// When the writing transaction recorded it.
    at: u64,
}

/// A run's request for a scope summary: its lease owner, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SummaryRequest {
    owner: String,
    at: u64,
}

/// What wrote a witnessed edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum WitnessProducer {
    /// A batch applied under the run's envelope.
    Write,
    /// A code revision's lifecycle link, written directly.
    RevisionLink,
    /// An off-record op the run journaled, replayed by an authorized
    /// promotion.
    Promotion,
    /// A scope summary the run asked for, minted or reused by this Dreamer
    /// attempt; `None` once that attempt's run is erased.
    Summary(Option<AttemptId>),
}

impl WitnessProducer {
    /// Whether this producer lands a run's edge after the run's own write:
    /// its token held as it was captured, so the edge stays the run's once
    /// the lease has ended.
    const fn lands_late(self) -> bool {
        matches!(self, Self::Promotion | Self::Summary(_))
    }
}

/// Runs `capture`, one witness, in a savepoint of `wtxn` that commits only
/// when all of it lands: an error aborts the savepoint alone and logs one
/// WARN naming `what`, so no part of the witness stays and the write
/// carrying it goes on.
pub(super) fn capture_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    what: &'static str,
    capture: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
) {
    if let Err(error) = in_savepoint(store, wtxn, capture) {
        tracing::warn!(
            kind = ?error.kind(),
            %error,
            what,
            "a derivation witness was not recorded; the write stands without it"
        );
    }
}

fn in_savepoint(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    capture: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
) -> Result<()> {
    let mut savepoint = store.env.nested_write_txn(wtxn)?;
    capture(&mut savepoint)?;
    savepoint.commit()?;
    Ok(())
}

/// Records `pairs`, the DerivedFrom edges `token`'s run wrote through
/// `producer`, in the writer's `wtxn`, capture-only
/// ([`capture_in_txn`]).
pub(super) fn record_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    token: &RunWriteToken,
    pairs: &[(EntityId, EntityId)],
    producer: WitnessProducer,
) {
    capture_in_txn(store, wtxn, "derivation", |txn| {
        record_pairs_in_txn(store, txn, token, pairs, producer)
    });
}

/// [`record_in_txn`] inside a caller's savepoint: only edges the writer left
/// stored, each once per run try. A live run's bound attribution gains them
/// now. A producer that lands late records them once the lease has ended;
/// any other write whose lease no longer holds records nothing.
pub(super) fn record_pairs_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    token: &RunWriteToken,
    pairs: &[(EntityId, EntityId)],
    producer: WitnessProducer,
) -> Result<()> {
    let live = token.lease_holds_in_txn(store, wtxn);
    if !live && !producer.lands_late() {
        return Ok(());
    }
    let at = store.clock.now_recorded_at();
    let mut landed = Vec::new();
    for &(derived, source) in pairs {
        if derived == source
            || !store.port_edge_present(
                wtxn,
                &derived,
                EdgeDirection::Out,
                EdgeKind::DerivedFrom,
                &source,
            )?
        {
            continue;
        }
        let key = derivation_key(token, derived, source);
        // A retried write finds its witness and records nothing new.
        if WITNESS.contains(store, wtxn, &key)? {
            continue;
        }
        let witness = DerivationWitness {
            derived: Some(derived),
            source: Some(source),
            producer,
            live,
            at,
        };
        WITNESS.put(store, wtxn, &key, &WitnessRow::Derivation(witness))?;
        landed.push((derived, source));
    }
    if live && !landed.is_empty() {
        project_in_txn(store, wtxn, token.attempt(), &landed)?;
    }
    Ok(())
}

/// Appends `pairs` to `attempt`'s bound attribution in `wtxn`; a run not yet
/// bound projects them as it binds. Every edge is kept; the chain's length
/// is measured (Rule 5).
fn project_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    pairs: &[(EntityId, EntityId)],
) -> Result<()> {
    let Some(mut fields) = crate::receipt::attempt_pack_attribution_in_txn(store, wtxn, attempt)?
    else {
        return Ok(());
    };
    if !extend_used(&mut fields, pairs.iter().copied()) {
        return Ok(());
    }
    store.limit_watch.measure(
        EngineLimit::AttemptManifestEntries,
        fields.used_edges.len() as u64,
    );
    crate::receipt::put_attempt_pack_attribution_in_txn(store, wtxn, attempt, &fields)
}

/// Projects the live witnesses of `attempt`'s try `generation` onto
/// `fields`' used chain, reading only through `txn`. A row with an erased
/// end, or that no longer decodes, projects nothing, and a read that fails
/// projects nothing with a WARN.
pub(super) fn drain_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    generation: u32,
    fields: &mut PackAttributionFields,
) {
    match live_pairs_in_txn(store, txn, attempt, generation) {
        Ok(pairs) => {
            extend_used(fields, pairs);
        }
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                %error,
                ?attempt,
                "a run's derivation witnesses were not read; its used chain goes on without them"
            );
        }
    }
}

/// [`drain_in_txn`] in a read transaction of its own, for a bind that holds
/// none.
pub(super) fn drain(
    store: &Store,
    attempt: AttemptId,
    generation: u32,
    fields: &mut PackAttributionFields,
) {
    match store.env.read_txn() {
        Ok(rtxn) => drain_in_txn(store, &rtxn, attempt, generation, fields),
        Err(error) => {
            tracing::warn!(%error, ?attempt, "a run's derivation witnesses were not read as it bound");
        }
    }
}

fn live_pairs_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    generation: u32,
) -> Result<Vec<(EntityId, EntityId)>> {
    let mut prefix = DERIVATION.to_vec();
    prefix.extend_from_slice(attempt.as_bytes());
    prefix.extend_from_slice(&generation.to_be_bytes());
    let mut pairs = Vec::new();
    for row in WITNESS.iter_raw_from(store, txn, &prefix)? {
        let (_, value) = row?;
        if let Ok(WitnessRow::Derivation(DerivationWitness {
            derived: Some(derived),
            source: Some(source),
            live: true,
            ..
        })) = WITNESS.decode_value(&value)
        {
            pairs.push((derived, source));
        }
    }
    Ok(pairs)
}

/// Appends each of `pairs` that `fields`' used chain lacks; whether any was.
fn extend_used(
    fields: &mut PackAttributionFields,
    pairs: impl IntoIterator<Item = (EntityId, EntityId)>,
) -> bool {
    let mut seen: BTreeSet<(EntityId, EntityId)> = fields
        .used_edges
        .iter()
        .map(|edge| (edge.derived, edge.source))
        .collect();
    let before = fields.used_edges.len();
    for (derived, source) in pairs {
        if derived != source && seen.insert((derived, source)) {
            fields.used_edges.push(UsedProvenanceEdge {
                derived,
                source,
                check: None,
            });
        }
    }
    fields.used_edges.len() != before
}

fn derivation_key(token: &RunWriteToken, derived: EntityId, source: EntityId) -> WitnessKey {
    let mut pair = blake3::Hasher::new_derive_key("oneiron derivation witness pair v1");
    pair.update(derived.as_bytes());
    pair.update(source.as_bytes());
    let mut rest = token.generation().to_be_bytes().to_vec();
    rest.extend_from_slice(pair.finalize().as_bytes());
    (DERIVATION, *token.attempt().as_bytes(), rest)
}

/// Keeps, in a scope-summary request's own `wtxn`, that the leased run whose
/// envelope is open on this thread asked for the summary Dreamer attempt
/// `summary` mints, while its lease holds. Asking again keeps one row; a
/// request no run's envelope covers keeps none. Capture-only
/// ([`capture_in_txn`]).
pub(crate) fn note_summary_request_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    summary: AttemptId,
) {
    let Some(token) = current_run_write_token() else {
        return;
    };
    if !token.lease_holds_in_txn(store, wtxn) {
        return;
    }
    let mut rest = token.attempt().as_bytes().to_vec();
    rest.extend_from_slice(&token.generation().to_be_bytes());
    let key = (REQUEST, *summary.as_bytes(), rest);
    let request = SummaryRequest {
        owner: token.owner().to_owned(),
        at: store.clock.now_recorded_at(),
    };
    capture_in_txn(store, wtxn, "summary request", |txn| {
        if WITNESS.contains(store, txn, &key)? {
            return Ok(());
        }
        WITNESS.put(store, txn, &key, &WitnessRow::Request(request))
    });
}

/// Records, in the landing's `txn`, `summary`'s stored DerivedFrom edges as
/// derivations of every run that asked for the summary Dreamer attempt
/// `attempt` lands, minted or reused, with that attempt as their producer.
/// Capture-only ([`capture_in_txn`]).
pub(crate) fn note_summary_landing_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    summary: EntityId,
) {
    capture_in_txn(&vault.store, txn, "summary landing", |txn| {
        summary_landing_in_txn(vault, txn, attempt, summary)
    });
}

fn summary_landing_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    summary: EntityId,
) -> Result<()> {
    let requesters = summary_requesters_in_txn(&vault.store, txn, attempt)?;
    if requesters.is_empty() {
        return Ok(());
    }
    let pairs: Vec<_> = vault
        .port_edge_neighbors(
            txn,
            &summary,
            EdgeDirection::Out,
            Some(EdgeKind::DerivedFrom),
            usize::MAX,
        )?
        .into_iter()
        .map(|edge| (summary, edge.target))
        .collect();
    for token in &requesters {
        record_pairs_in_txn(
            &vault.store,
            txn,
            token,
            &pairs,
            WitnessProducer::Summary(Some(attempt)),
        )?;
    }
    Ok(())
}

/// The runs that asked for the summary Dreamer attempt `summary` mints, read
/// only through `txn`. A row that no longer decodes names no run.
fn summary_requesters_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    summary: AttemptId,
) -> Result<Vec<RunWriteToken>> {
    let mut prefix = REQUEST.to_vec();
    prefix.extend_from_slice(summary.as_bytes());
    let mut requesters = Vec::new();
    for row in WITNESS.iter_raw_from(store, txn, &prefix)? {
        let (key, value) = row?;
        let Some((attempt, generation)) = key
            .get(prefix.len()..)
            .and_then(|rest| rest.split_at_checked(16))
            .and_then(|(attempt, generation)| {
                Some((
                    AttemptId::from_bytes(attempt).ok()?,
                    u32::from_be_bytes(generation.try_into().ok()?),
                ))
            })
        else {
            continue;
        };
        if let Ok(WitnessRow::Request(request)) = WITNESS.decode_value(&value) {
            requesters.push(RunWriteToken::of(attempt, request.owner, generation));
        }
    }
    Ok(requesters)
}

/// Keeps every witness naming erased `entity` in erased form (FIX 8988).
///
/// - A derivation clears each end and the summary producer it names, and
///   moves from its key, whose digest a known id would confirm, to a fresh
///   opaque one ([`WitnessKey`]); a derivation of an erased run loses its
///   run as well. It keeps its producer kind, liveness, time and any other
///   end.
/// - A summary request whose summary attempt, asking run or lease owner
///   names `entity` goes: an owner can spell an actor's id, and a request
///   is only good to rebuild that run's token.
///
/// A row that no longer decodes is deleted and counted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_derivation_witness_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let id = *entity.as_bytes();
    let spelled = entity.to_hex().to_ascii_lowercase();
    for (key, row) in super::skill_erase::erase_scan_in_txn(vault, wtxn, WITNESS)? {
        let (kind, held, rest) = &key;
        match row {
            WitnessRow::Derivation(mut witness) => {
                let run_erased = *kind == DERIVATION && *held == id;
                let mut named = run_erased;
                for end in [&mut witness.derived, &mut witness.source] {
                    if *end == Some(*entity) {
                        *end = None;
                        named = true;
                    }
                }
                if let WitnessProducer::Summary(producer) = &mut witness.producer
                    && producer.is_some_and(|attempt| *attempt.as_bytes() == id)
                {
                    *producer = None;
                    named = true;
                }
                if !named {
                    continue;
                }
                let fresh = vault.store.clock.ulid()?;
                let moved = match rest.get(..4).filter(|_| *kind == DERIVATION && !run_erased) {
                    Some(generation) => {
                        (DERIVATION, *held, [generation, fresh.as_slice()].concat())
                    }
                    None => (ERASED, fresh, Vec::new()),
                };
                WITNESS.delete(&vault.store, wtxn, &key)?;
                WITNESS.put(&vault.store, wtxn, &moved, &WitnessRow::Derivation(witness))?;
            }
            WitnessRow::Request(request) => {
                let named = *held == id
                    || rest.get(..16).is_some_and(|asking| asking == id.as_slice())
                    || request.owner.to_ascii_lowercase().contains(&spelled);
                if named {
                    WITNESS.delete(&vault.store, wtxn, &key)?;
                }
            }
        }
    }
    Ok(())
}
