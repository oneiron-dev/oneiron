//! Doors for `tests/promotion_cited_source_dependency_backfill.rs` (S1b): strip a
//! CLAIM's cited-source dependencies to the pre-S1 state, reset and read the
//! one-time marker, and plant the fixtures S1 cannot produce.

use crate::dreamer_consolidation::{
    ConsolidationEvidenceEnvelope, SwarmEvidenceRef, encode_consolidation_evidence_with_locators,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::{TimeRange, Vault};

/// The backfill marker this door resets and reads.
const MARKER: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::CITED_SOURCE_DEPENDENCY_BACKFILL);

/// Strips `citing`'s dependency rows, both directions, to the pre-S1 state.
pub fn forget_cited_source_dependencies(vault: &Vault, citing: EntityId) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        crate::ports::remove_dependency_rows_for_dependent_in_txn(&vault.store, txn, &citing)
    })
}

/// The sources `citing` is registered as derived from.
pub fn cited_source_dependency_sources(vault: &Vault, citing: EntityId) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::ports::dependency_sources_in(&vault.store, &txn, &citing)
}

/// Deletes the backfill marker so the next open runs the pass again.
pub fn reset_cited_source_dependency_backfill(vault: &Vault) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        MARKER.delete(&vault.store, txn, &())?;
        Ok(())
    })
}

/// The Complete counters (scanned, linked, withdrawn, undecodable,
/// missing_without_marker, archived, stale_source, untrusted_writer,
/// rewritten_source), or None while incomplete.
pub fn cited_source_dependency_backfill_counts(vault: &Vault) -> Result<Option<[u64; 9]>> {
    let txn = vault.store.env.read_txn()?;
    let Some(raw) = MARKER.get_bytes(&vault.store, &txn, &())? else {
        return Ok(None);
    };
    if raw.len() != 73 || raw[0] != 2 {
        return Ok(None);
    }
    let mut counts = [0u64; 9];
    for (slot, chunk) in counts.iter_mut().zip(raw[1..].chunks_exact(8)) {
        *slot = u64::from_be_bytes(
            chunk
                .try_into()
                .map_err(|_| crate::error::Error::CorruptedIndex("backfill marker"))?,
        );
    }
    Ok(Some(counts))
}

/// A CLAIM about `subject` citing a never-stored id: the CLAIM and the source.
/// Observed, Auto and active, with one Claim-shaped locator and no spans.
pub fn write_claim_citing_missing_source(
    vault: &Vault,
    subject: EntityId,
) -> Result<(EntityId, EntityId)> {
    let missing = EntityId::now();
    let id = EntityId::now();
    write_claim_citing_source_at(vault, subject, id, missing)?;
    Ok((id, missing))
}

/// A CLAIM about `subject` at `id` citing `source`, written as
/// [`write_claim_citing_missing_source`] writes its CLAIM: no dependency row.
/// The caller picks `id`, so a test orders the pass's visits.
pub fn write_claim_citing_source_at(
    vault: &Vault,
    subject: EntityId,
    id: EntityId,
    source: EntityId,
) -> Result<()> {
    put_claim_with_inner(
        vault,
        subject,
        id,
        consolidation_inner_with_locators(source),
    )
}

/// A CLAIM about `subject` at `id` citing `source`'s CURRENT body, written
/// as [`write_claim_citing_source_at`] writes its CLAIM but with the binding
/// the verifier computes over the source as stored now (for T10: redact the
/// source after, and the citation no longer names it). The source must be
/// stored; the CLAIM carries no dependency row.
pub fn write_claim_citing_source_with_current_binding(
    vault: &Vault,
    subject: EntityId,
    id: EntityId,
    source: EntityId,
) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &source)?
        .ok_or(crate::error::Error::EntityNotFound)?;
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .ok_or(crate::error::Error::CorruptedIndex("cited source row"))?;
    let hash = crate::dreamer_consolidation::swarm_evidence_content_hash(body);
    drop(txn);
    put_claim_with_inner(
        vault,
        subject,
        id,
        consolidation_inner_with_locators_and_hash(source, hash),
    )
}

/// The same CLAIM with a `locators` entry the strict decoder rejects; its id.
pub fn write_claim_with_undecodable_locators(vault: &Vault, subject: EntityId) -> Result<EntityId> {
    let missing = EntityId::now();
    let mut inner = consolidation_inner_with_locators(missing);
    if let rmpv::Value::Map(fields) = &mut inner {
        if let Some((_, locators)) = fields
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("locators"))
        {
            *locators = rmpv::Value::from("undecodable");
        }
    }
    let id = EntityId::now();
    put_claim_with_inner(vault, subject, id, inner)?;
    Ok(id)
}

/// Evidence with `refs = [source]` and one Claim-shaped locator, `[0; 32]`
/// hash and no MESSAGE spans.
fn consolidation_inner_with_locators(source: EntityId) -> rmpv::Value {
    consolidation_inner_with_locators_and_hash(source, [0; 32])
}

/// Evidence with `refs = [source]` and one Claim-shaped locator, `hash` and
/// no MESSAGE spans.
fn consolidation_inner_with_locators_and_hash(source: EntityId, hash: [u8; 32]) -> rmpv::Value {
    use crate::claim::ClaimSource;

    encode_consolidation_evidence_with_locators(
        &ConsolidationEvidenceEnvelope {
            refs: vec![source],
            chain: Vec::new(),
            source_meet: ClaimSource::Observed,
        },
        &[(
            SwarmEvidenceRef {
                source_id: source,
                claim_id: Some(source),
                byte_range: None,
            },
            hash,
            Vec::new(),
        )],
    )
}

/// A `profile.note` CLAIM about `subject` at `id` with the envelope around
/// `inner`, S1-writer-shaped: the Dreamer authority's stamp and machine
/// signature (review 10625 round 1 P1-1: the backfill trusts only a base
/// agent's stamp). It lands as the other Dreamer doors land theirs: signed,
/// then a `claim_candidate` with its envelope in one write transaction, so
/// the write chokepoint verifies the first birth against that envelope (a
/// raw `put_claim` carries no envelope, and a signed first birth without one
/// is refused). Proposed, as those doors write; the backfill never reads
/// approval. The fixture retains the Dreamer signer
/// (`provision_engine_machine_identities`), so without one this errors
/// instead of landing an unsigned Dreamer row.
fn put_claim_with_inner(
    vault: &Vault,
    subject: EntityId,
    id: EntityId,
    inner: rmpv::Value,
) -> Result<()> {
    use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
    use crate::write_envelope::{ClaimCandidate, SourceLineage, WriteEnvelope, WriteProvenance};

    let mut envelope = WriteEnvelope::with_lineage(
        vault.dreamer_authority()?,
        ClaimSource::Observed,
        WriteProvenance::new(rmpv::Value::Map(vec![(
            rmpv::Value::from("door"),
            rmpv::Value::from("cited_source_dependency_backfill"),
        )]))?,
        ClaimApprovalStatus::Proposed,
        SourceLineage::of(ClaimSource::Generated).with(ClaimSource::Observed),
    );
    let candidate = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("the cited note"),
        1.0,
    )
    .with_evidence(inner)
    .with_scope(crate::dreamer_promotion::scope_with_taint(
        None,
        ClaimSource::Observed,
    ));
    let at = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        vault.sign_retained_machine_claim_in_txn(&*txn, &id, &candidate, &mut envelope)?;
        vault
            .batch_in()
            .claim_candidate(
                &id,
                candidate,
                &envelope,
                TimeRange { start: at, end: at },
                at,
            )
            .apply_recording_gate_decisions(txn)
    })?;
    Ok(())
}
