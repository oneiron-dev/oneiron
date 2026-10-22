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
//! lands as it would: a witness never holds or fails a write.

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

/// `(kind, attempt, rest)`: a derivation is [`DERIVATION`], the run's
/// attempt, its lease generation and a digest of the pair; a request is
/// [`REQUEST`], the summary's Dreamer attempt, the asking run's attempt and
/// its generation.
type WitnessKey = ([u8; 1], [u8; 16], Vec<u8>);

const WITNESS: SideTable<WitnessKey, WitnessRow, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_DERIVATION_WITNESS);

const DERIVATION: [u8; 1] = *b"d";
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
    /// attempt.
    Summary(AttemptId),
}

impl WitnessProducer {
    /// Whether this producer lands a run's edge after the run's own write:
    /// its token held as it was captured, so the edge stays the run's once
    /// the lease has ended.
    const fn lands_late(self) -> bool {
        matches!(self, Self::Promotion | Self::Summary(_))
    }
}

/// Records `pairs`, the DerivedFrom edges `token`'s run wrote through
/// `producer`, in the writer's `wtxn`: only edges it left stored, each once
/// per run try. A live run's bound attribution gains them now. A producer
/// that lands late records them once the lease has ended; any other write
/// whose lease no longer holds records nothing.
pub(super) fn record_in_txn(
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
/// `fields`' used chain, reading only through `txn`; whether it grew. A row
/// with an erased end, or that no longer decodes, projects nothing.
pub(super) fn drain_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    generation: u32,
    fields: &mut PackAttributionFields,
) -> Result<bool> {
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
    Ok(extend_used(fields, pairs))
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
/// request no run's envelope covers keeps none.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn note_summary_request_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    summary: AttemptId,
) -> Result<()> {
    let Some(token) = current_run_write_token() else {
        return Ok(());
    };
    if !token.lease_holds_in_txn(store, wtxn) {
        return Ok(());
    }
    let mut rest = token.attempt().as_bytes().to_vec();
    rest.extend_from_slice(&token.generation().to_be_bytes());
    let key = (REQUEST, *summary.as_bytes(), rest);
    if WITNESS.contains(store, wtxn, &key)? {
        return Ok(());
    }
    let request = SummaryRequest {
        owner: token.owner().to_owned(),
        at: store.clock.now_recorded_at(),
    };
    WITNESS.put(store, wtxn, &key, &WitnessRow::Request(request))
}

/// Records, in the landing's `txn`, `summary`'s stored DerivedFrom edges as
/// derivations of every run that asked for the summary Dreamer attempt
/// `attempt` lands, minted or reused, with that attempt as their producer.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn note_summary_landing_in_txn(
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
        record_in_txn(
            &vault.store,
            txn,
            token,
            &pairs,
            WitnessProducer::Summary(attempt),
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

/// Keeps every witness naming erased `entity` in erased form (FIX 8988): the
/// end it names is cleared, and the row keeps its run, producer, time and
/// other end. Its key spells only a digest of the pair, and a summary request
/// names no entity. A row that no longer decodes is deleted and counted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_derivation_witness_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (key, row) in super::skill_erase::erase_scan_in_txn(vault, wtxn, WITNESS)? {
        let WitnessRow::Derivation(mut witness) = row else {
            continue;
        };
        let mut named = false;
        for end in [&mut witness.derived, &mut witness.source] {
            if *end == Some(*entity) {
                *end = None;
                named = true;
            }
        }
        if named {
            WITNESS.put(&vault.store, wtxn, &key, &WitnessRow::Derivation(witness))?;
        }
    }
    Ok(())
}
