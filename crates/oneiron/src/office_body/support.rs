//! Shared office body storage, validation and projection helpers.
//! Entry: `erase_in_txn`.
//! Definitions live here; office_body forwards their original names.

use super::*;

/// Removes `artifact`'s office rows: its format record, its deck forks'
/// office records, its proposals and its export records. The body itself, a Loro document in
/// every format, goes with its forks in the typed body's own eraser.
/// Registered in `deletion/derived_rows.rs`.
pub(crate) fn erase_in_txn(store: &Store, txn: &mut RwTxn<'_>, entity: &EntityId) -> Result<()> {
    FORKS.delete_from(store, txn, entity.as_bytes())?;
    consent::erase_in_txn(store, txn, entity)?;
    EXPORTS.delete_from(store, txn, entity.as_bytes())?;
    SOURCES.delete(store, txn, entity)?;
    Ok(())
}

pub(super) fn claim_source(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    artifact: &EntityId,
    source: &OfficeBodySource,
) -> Result<()> {
    if SOURCES.contains(store, wtxn, artifact)? {
        return Err(invalid("the artifact already has a live body"));
    }
    SOURCES.put(store, wtxn, artifact, source)
}

pub(super) fn source(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
) -> Result<OfficeBodySource> {
    SOURCES
        .get(store, txn, artifact)?
        .ok_or(Error::EntityNotFound)
}

/// A Loro body's kind; a deck has its own fork doors.
pub(super) fn loro_kind(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
) -> Result<OfficeBodyKind> {
    match source(store, txn, artifact)?.kind {
        OfficeBodyKind::Pptx => Err(invalid(
            "a deck fork reviews and lands through vault.artifacts.body.deck.review and .deck.merge",
        )),
        kind => Ok(kind),
    }
}

/// An open fork's record and proposal document.
pub(super) fn open_fork(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    fork: &EntityId,
) -> Result<(TypedBodyFork, LoroDoc)> {
    let (record, proposal) =
        typed_body_fork_in_txn(store, txn, artifact, fork)?.ok_or(Error::EntityNotFound)?;
    Ok((
        record,
        proposal.ok_or_else(|| invalid("the fork is not open"))?,
    ))
}

pub(super) fn fork_view(record: TypedBodyFork) -> OfficeBodyFork {
    OfficeBodyFork {
        id: record.fork,
        artifact: record.entity,
        opener: record.opener,
        base: record.base,
        commits: record.commits,
        opened_at: record.opened_at,
        state: match record.state {
            TypedForkState::Open => ForkState::Open,
            TypedForkState::Merged { by, at, head } => ForkState::Merged { by, at, head },
            TypedForkState::Discarded { by, at } => ForkState::Discarded { by, at },
        },
        run_root: None,
        origin: None,
    }
}

pub(super) fn writer(
    kind: OfficeBodyKind,
    actor: WriteActor,
    made_by: &MadeBy,
) -> TypedBodyWriter<'_> {
    TypedBodyWriter {
        schema: kind.schema(),
        actor,
        made_by,
    }
}

pub(super) fn check_made_by(actor: WriteActor, made_by: &MadeBy) -> Result<()> {
    if made_by.process.actor != actor.entity_ref() || !made_by.process.is_valid() {
        return Err(invalid(
            "the MadeBy envelope does not name this actor's process",
        ));
    }
    Ok(())
}

pub(super) fn apply_all(doc: &LoroDoc, ops: &[DocxBodyOp]) -> Result<Vec<String>> {
    let mut minted = Vec::new();
    for op in ops {
        docx::apply(doc, op, &mut minted)?;
    }
    Ok(minted)
}

pub(super) fn apply_xlsx(
    doc: &LoroDoc,
    ops: &[XlsxBodyOp],
    effects: &mut Vec<String>,
) -> Result<Vec<String>> {
    for op in ops {
        xlsx::apply(doc, op, effects)?;
    }
    Ok(Vec::new())
}

/// Fail closed on a document that no longer reads as its kind.
pub(super) fn validate(kind: OfficeBodyKind, doc: &LoroDoc) -> Result<()> {
    match kind {
        OfficeBodyKind::Docx => docx::read(doc).map(drop),
        OfficeBodyKind::Xlsx => xlsx::read(doc).map(drop),
        OfficeBodyKind::Pptx => pptx::validate(doc),
    }
}

pub(super) fn three_way(
    kind: OfficeBodyKind,
    live: &LoroDoc,
    proposal: &LoroDoc,
    base: &[u8],
    head: &[u8],
) -> Result<OfficeBodyDiff> {
    let frontier = loro::Frontiers::decode(base).map_err(|_| invalid("invalid body frontier"))?;
    let before = live
        .fork_at(&frontier)
        .map_err(|_| invalid("unknown body frontier"))?;
    let frontiers = (
        base.to_vec(),
        head.to_vec(),
        proposal.oplog_frontiers().encode(),
    );
    Ok(match kind {
        OfficeBodyKind::Docx => fork::diff(
            &docx::read(&before)?,
            &docx::read(live)?,
            &docx::read(proposal)?,
            frontiers,
        ),
        OfficeBodyKind::Xlsx => xlsx::diff(
            &xlsx::read(&before)?,
            &xlsx::read(live)?,
            &xlsx::read(proposal)?,
            frontiers,
        ),
        OfficeBodyKind::Pptx => {
            return Err(invalid(
                "a deck fork reviews and lands through vault.artifacts.body.deck.review and .deck.merge",
            ));
        }
    })
}

/// Recalculate a projected workbook in process at `at`, read in `zone`'s
/// local time, seeded by the projected package, so the result is
/// deterministic in all three and no vault frontier reaches the file
/// (OF-491). A workbook the engine refuses is marked to recalculate when it
/// is opened instead.
pub(super) fn recalc_xlsx(
    bytes: &[u8],
    limits: Limits,
    at: u64,
    zone: &OfficeRecalcZone,
) -> Result<(Vec<u8>, Option<CalcEngineStamp>)> {
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&blake3::hash(bytes).as_bytes()[..8]);
    let clock = RecalcClock::new(
        timestamp(at)?,
        zone.utc_offset_minutes,
        u64::from_le_bytes(seed),
    )
    .ok_or_else(|| invalid("office body recalc clock"))?;
    match FormualizerEngine::new().recalculate_xlsx(bytes, limits, &clock, None) {
        Ok(report) => Ok((
            report.bytes,
            Some(CalcEngineStamp::new(
                report.engine.engine,
                report.engine.version,
            )?),
        )),
        Err(_) => Ok((
            mark_full_calc(bytes, limits, &crate::office_body::document_resources()).map_err(
                |_| invalid("the projected workbook could not be marked to recalculate"),
            )?,
            None,
        )),
    }
}

/// The calculator and the local time it read, as the export record and the
/// preview name them: `formualizer 0.5.1 at UTC+09:00 (Asia/Tokyo)`.
pub(super) fn recalc_label(stamp: &CalcEngineStamp, zone: &OfficeRecalcZone) -> String {
    let sign = if zone.utc_offset_minutes < 0 {
        '-'
    } else {
        '+'
    };
    let minutes = zone.utc_offset_minutes.unsigned_abs();
    let mut label = format!(
        "{} {} at UTC{sign}{:02}:{:02}",
        stamp.engine(),
        stamp.version(),
        minutes / 60,
        minutes % 60
    );
    if let Some(name) = &zone.iana_timezone {
        label.push_str(&format!(" ({name})"));
    }
    label
}

pub(super) fn timestamp(at: u64) -> Result<chrono::DateTime<chrono::Utc>> {
    i64::try_from(at)
        .ok()
        .and_then(|at| chrono::DateTime::from_timestamp(at, 0))
        .ok_or_else(|| invalid("office body export time"))
}

/// An office body call names at least one operation, and takes any number
/// of them (FIX 6600, Rule 5).
pub(super) fn bounded_ops(count: usize) -> Result<()> {
    if count == 0 {
        return Err(invalid("an office body call takes at least one operation"));
    }
    Ok(())
}

/// An id16 followed by a big-endian sequence or version number.
pub(super) fn version_key(owner: &EntityId, number: u64) -> Vec<u8> {
    let mut key = owner.as_bytes().to_vec();
    key.extend_from_slice(&number.to_be_bytes());
    key
}

/// The refusal of a fork nothing answers, which waits in `proposal`.
/// `refused` is the ask admission's refusal when no holder could be asked.
pub(crate) fn fork_waits(proposal: &EntityId, refused: Option<&str>) -> Error {
    let asked = match refused {
        None => "so its holders are asked".to_owned(),
        Some(reason) => format!("and asking its holders was refused: {reason}"),
    };
    Error::InvalidConfig(format!(
        "the fork waits in proposal {} for a person outside its opener's lineage; no grant covers it, {asked}",
        proposal.to_hex()
    ))
}
