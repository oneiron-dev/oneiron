//! The transactional epoch mint: one SUMMARY, its lineage and its
//! dependencies in one write (FIX 5029: a chat epoch re-proves its
//! conversation's turn order and reads its prior in its own lineage there).

use crate::compaction::driver::{CompactionProduct, CompactionRequest, WindowLog};
use crate::compaction::withdrawn::WithdrawnKeyframe;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::registry::ENTITY_TYPE_SUMMARY;
use crate::store::{ManifestDbs, Store};
use crate::temporal::TimeRange;
use crate::tokenizer::count_context_pack_tokens;
use crate::vault::Vault;
use crate::write_envelope::WriteActor;

use super::codec::{
    EPOCH_SUMMARY_BODY_VERSION, EPOCH_SUMMARY_LEVEL, EpochSummaryBody, encode_epoch_summary_body,
};
use super::lineage::{
    next_epoch, prior_epoch_in_txn, validate_epoch_boundary, validate_window_span,
};

/// Mints ONE session-kind SUMMARY entity for a finished compaction.
///
/// Everything that decides what the row IS happens inside a single write
/// transaction: the H-S3 probe over every covered turn, the epoch derivation
/// from durable prior summaries, the body encode, the put, its
/// pending-embedding marker and the `DerivedFrom` edge set. A refusal
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
    /// The conversation whose lineage the epoch counts in (FIX 5029); `None`
    /// for the SESSION's own log.
    conversation: Option<EntityId>,
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
    pub(crate) const fn conversation(self) -> Option<EntityId> {
        self.conversation
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
/// operation rolls back both, leaving the driver request retryable. A
/// self-written summary's `writer` receipt (FIX 4465) is linked from its
/// birth; the byline stays the agent's.
pub(in crate::compaction) fn mint_epoch_summary_with(
    vault: &Vault,
    session_ref: &EntityId,
    byline: WriteActor,
    request: &CompactionRequest,
    product: &CompactionProduct,
    writer: Option<&crate::compaction::CompactionExecution>,
    extra: impl FnOnce(&mut heed::RwTxn<'_>, &EpochMint) -> Result<()>,
) -> Result<(u64, EntityId)> {
    mint_epoch_summary_guarded(
        vault,
        session_ref,
        byline,
        request,
        product,
        writer,
        |_| Ok(()),
        extra,
    )
}

/// [`mint_epoch_summary_with`] whose `landing` runs FIRST in the mint's own
/// transaction (Docs Q17): a session-bound run on a route that went on
/// record lands its summary in base only while its participant, its saver
/// and its route still stand, exactly as its other base writes do. A refused
/// landing writes nothing. A chat window (FIX 5029) re-proves, in the same
/// transaction, that each of its turns stands at its number in its
/// conversation's order within the SESSION, then reads its prior in that
/// conversation's lineage.
#[expect(
    clippy::too_many_arguments,
    reason = "the mint's arguments plus its landing guard and a self-written receipt"
)]
pub(in crate::compaction) fn mint_epoch_summary_guarded(
    vault: &Vault,
    session_ref: &EntityId,
    byline: WriteActor,
    request: &CompactionRequest,
    product: &CompactionProduct,
    writer: Option<&crate::compaction::CompactionExecution>,
    landing: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
    extra: impl FnOnce(&mut heed::RwTxn<'_>, &EpochMint) -> Result<()>,
) -> Result<(u64, EntityId)> {
    let (turn_start, turn_end) = check_mint(session_ref, request, product)?;

    // `DerivedFrom` targets are the sealed request's sources: every record
    // the window was read from (a conversation window's TURNs and MESSAGEs,
    // or what a host-numbered log names), and for a self-written summary
    // each home part its call wore (FIX 4465 B, Engine 10-19).
    let derived = &summary_dependencies(request, writer);

    // The keyframe's temporal position IS the compaction moment: the recorded
    // watermark. Wall-clock would make an otherwise byte-stable row depend on
    // when it happened to be minted.
    let at = request.watermark.learned_at;
    let summary_id = vault.store.clock.entity_id()?;
    let intent_id = vault.store.clock.entity_id()?;

    let epoch = vault.with_write_txn_grouped(|wtxn| {
        landing(wtxn)?;
        refuse_overlay_derived_mint(
            &vault.store,
            request
                .window
                .iter()
                .map(|message| message.turn_id)
                .filter(|_| matches!(request.log, WindowLog::Conversation(_)))
                .chain(request.sources.iter().copied()),
        )?;
        let scope = request.epoch_scope();
        let prior = match request.log {
            WindowLog::Conversation(binding) => {
                if let Some(binding) = binding {
                    crate::compaction::conversation::validate_conversation_window_in_txn(
                        &vault.store,
                        &*wtxn,
                        *session_ref,
                        binding,
                        &request.window,
                    )?;
                }
                prior_epoch_in_txn(&vault.store, &*wtxn, &scope)?
            }
            // The host's own rows re-check this position in `extra`.
            WindowLog::Host { prior, .. } => prior,
        };
        validate_epoch_boundary(prior, turn_start)?;
        let epoch = next_epoch(prior)?;
        let body = encode_epoch_summary_body(&EpochSummaryBody {
            v: EPOCH_SUMMARY_BODY_VERSION,
            session: session_ref.to_hex(),
            conversation: scope.conversation.as_ref().map(EntityId::to_hex),
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
        let mut live = Vec::with_capacity(derived.len());
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
                live.push(*target);
            }
        }
        // Rule A: the pass's intent NOTE is the prompt the summary is born
        // from, and the run that sealed it, while its record stands here,
        // the trigger.
        let intent = crate::compaction::epoch_intent::intent_note_body(
            request,
            byline.entity_ref(),
            summary_id,
            born_withdrawn.is_some(),
        )?;
        batch = crate::compaction::epoch_intent::stage_intent(
            batch,
            intent_id,
            byline.entity_ref(),
            summary_id,
            at,
            &intent,
            &live,
        );
        let trigger = crate::compaction::epoch_intent::run_trigger_in(&vault.store, wtxn, request)?;
        let birth =
            crate::compaction::epoch_intent::epoch_birth(request, byline, at, intent_id, trigger)
                .map(|birth| crate::compaction::self_writer::link_writer(birth, writer))
                .transpose()?;
        batch = batch.made_by(&summary_id, birth);
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
        // Every host's window names its covered TURNs the same way, so a
        // host-numbered log's mint folds its turns' boards here too; this
        // mint is the one landing every production host's epochs pass
        // through.
        crate::context_board::fold_board_turns_in_txn(
            vault,
            wtxn,
            request.window.iter().map(|message| message.turn_id),
        )?;
        extra(
            wtxn,
            &EpochMint {
                summary_id,
                session_ref: *session_ref,
                conversation: scope.conversation,
                epoch,
                turn_start,
                turn_end,
            },
        )?;
        if let Some(worlds) = &born_withdrawn {
            crate::ports::record_withdrawn_in_txn(&vault.store, wtxn, &summary_id, worlds)?;
            crate::ports::RetrievalIndex::port_retrieval_mark_stale(vault, wtxn, &summary_id)?;
            crate::compaction::withdrawn::scrub_withdrawn_epoch_in_txn(
                &vault.store,
                wtxn,
                &summary_id,
            )?;
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

/// [`mint_epoch_summary_with`] for a run in an off-record room
/// (agent-runtime-v1 §d7): the compactor read the room's overlay over base,
/// and the summary lands through the run's own session handle, on the route
/// the run captured at entry. The SUMMARY, its `DerivedFrom` lineage, its
/// text and `extra`'s rows stage in one overlay segment and drop with the
/// overlay at close; a room closed or flipped since the pass began refuses
/// the landing.
///
/// Nothing reaches base: no pending embedding (a room has no `pe:`
/// keyspace) and no withdrawal marker; the pass's intent NOTE and the
/// summary's birth (Rule A) stamp in the overlay, and export and sync stay
/// base-only. The `vector` the pass embedded inline (K6) stages beside the
/// summary's text. Each op is journaled under the run's compaction session
/// and the summary itself, a turn no promotion names, so promoting the
/// room's turns never carries it.
///
/// A source erased, withdrawn or purged before the mint takes no edge, as a
/// dependency needs its row (FIX 3448): the summary is born withdrawn in the
/// room, its keyframe only, marked stale there, with no text and no vector.
#[expect(
    clippy::too_many_arguments,
    reason = "the base mint's arguments plus the room's route, inline vector and a self-written \
              receipt"
)]
pub(in crate::compaction) fn mint_epoch_summary_in_overlay(
    session: &crate::off_record::OffRecordSession<'_>,
    route: &crate::session_overlay::SessionWriteRoute,
    session_ref: &EntityId,
    byline: WriteActor,
    request: &CompactionRequest,
    product: &CompactionProduct,
    vector: Option<&crate::compaction::epoch_vector::EpochVector>,
    writer: Option<&crate::compaction::CompactionExecution>,
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
    let intent_id = session.read_view()?.clock().entity_id()?;
    let summary = EpochSummaryBody {
        v: EPOCH_SUMMARY_BODY_VERSION,
        session: session_ref.to_hex(),
        conversation: None,
        epoch,
        turn_start,
        turn_end,
        level: EPOCH_SUMMARY_LEVEL,
        text: product.summary_text.clone(),
        actor: byline.entity_ref().to_hex(),
    };
    let scope = JournalScope::new(*session_ref, summary_id);
    // A self-written summary's home parts are its sources too (FIX 4465 B).
    let derived = summary_dependencies(request, writer);
    // FIX 3103: the mint keeps the run whose envelope it runs under.
    let source_run = crate::skill_attribution::current_run_write_token();
    let entry = |role, op| JournalEntry {
        scope,
        role,
        learned_at: at,
        occurred,
        op,
        source_run: source_run.clone(),
    };
    session.overlay_write_routed(route, |wtxn, apply| {
        let view = session.read_view()?;
        let live = crate::compaction::epoch_intent::standing_in(&view, wtxn, &derived)?;
        let withdrawn = live.len() < derived.len();
        let data = if withdrawn {
            WithdrawnKeyframe::of_body(&summary)?.encode()?
        } else {
            encode_epoch_summary_body(&summary)?
        };
        apply(
            wtxn,
            entry(
                JournalRole::SummaryDerivedFrom,
                BatchOp::Put {
                    id: summary_id,
                    entity_type: ENTITY_TYPE_SUMMARY,
                    occurred,
                    learned_at: at,
                    row_version: None,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                },
            ),
        )?;
        for target in &live {
            apply(
                wtxn,
                entry(
                    JournalRole::SummaryDerivedFrom,
                    BatchOp::Edge {
                        src: summary_id,
                        kind: EdgeKind::DerivedFrom,
                        tgt: *target,
                        weight: 1.0,
                        vad: oneiron_contracts::affect::Vad::NEUTRAL,
                    },
                ),
            )?;
        }
        if withdrawn {
            crate::ports::stage_stale_mark_in_txn(&view, wtxn, &summary_id, at)?;
        } else {
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
        }
        if let Some(op) =
            crate::compaction::epoch_vector::room_vector_op(vector, summary_id, withdrawn)
        {
            apply(wtxn, entry(JournalRole::TurnOwnedArtifact, op))?;
        }
        // Rule A, as the base mint names it: the pass's intent NOTE is the
        // summary's prompt, and the run its trigger while its record stands.
        let intent = crate::compaction::epoch_intent::intent_note_body(
            request,
            byline.entity_ref(),
            summary_id,
            withdrawn,
        )?;
        for op in crate::compaction::epoch_intent::intent_ops(
            intent_id,
            byline.entity_ref(),
            summary_id,
            at,
            intent,
            &live,
        ) {
            apply(wtxn, entry(JournalRole::TurnOwnedArtifact, op))?;
        }
        let trigger = crate::compaction::epoch_intent::run_trigger_in(&view, wtxn, request)?;
        if let Some(birth) =
            crate::compaction::epoch_intent::epoch_birth(request, byline, at, intent_id, trigger)
        {
            let birth = crate::compaction::self_writer::link_writer(birth, writer)?;
            crate::store::birth_record::stamp_row_birth_in_txn(&view, wtxn, &summary_id, &birth)?;
        }
        extra(
            &view,
            wtxn,
            &EpochMint {
                summary_id,
                session_ref: *session_ref,
                conversation: None,
                epoch,
                turn_start,
                turn_end,
            },
        )
    })?;
    Ok((epoch, summary_id))
}

/// What an epoch summary depends on for withdrawal: its request's sources,
/// then each home part a self-written one's call wore and each row its live
/// fork's prefix was read from (FIX 9463) that they do not name.
fn summary_dependencies(
    request: &CompactionRequest,
    writer: Option<&crate::compaction::CompactionExecution>,
) -> Vec<EntityId> {
    let mut derived = request.sources.clone();
    for row in writer
        .into_iter()
        .flat_map(crate::compaction::CompactionExecution::input_dependencies)
    {
        if !derived.contains(&row) {
            derived.push(row);
        }
    }
    derived
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
/// The probe covers EVERY covered turn: a room turn at window position 1000
/// refuses the mint. Membership is read from live registry state INSIDE the
/// applying transaction, which is the state the transaction applies against
/// — the same TOCTOU-free discipline the K4 guard uses.
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
