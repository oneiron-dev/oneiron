use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;

/// Semantic ownership tag on a typed journal entry (ARCH-0052 D4, K3).
///
/// This is the ONLY legal closure source for promotion (ONE-1730): promote
/// selects by role, never by inferring ownership from a type-index,
/// text-posting, short-id, temporal, or edge-index key. Index keys are shared
/// between turns by construction, so key-shaped selection drags siblings.
///
/// Role assignment is CLOSED — every staged op maps to exactly one role:
///
/// | role | staged op |
/// |---|---|
/// | [`Self::ConversationShell`] | the conversation shell put |
/// | [`Self::TurnPut`] | the TURN entity put |
/// | [`Self::MessagePartOf`] | each MESSAGE put and its `PartOf` edge |
/// | [`Self::SummaryDerivedFrom`] | the SUMMARY put and its `DerivedFrom` edge |
/// | [`Self::AttributionEdge`] | the `AuthoredBy` and `BelongsTo` edges |
/// | [`Self::TurnOwnedArtifact`] | every other turn-scoped op (BM25 `content` text ops, vector/HNSW rows) |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalRole {
    TurnPut,
    MessagePartOf,
    SummaryDerivedFrom,
    AttributionEdge,
    ConversationShell,
    TurnOwnedArtifact,
}

/// One typed journal operation.
///
/// `scope` carries the owning conversation + turn; `learned_at` and `occurred`
/// are preserved from the witnessing write and never restamped, so promote
/// replays into the correct month window (ARCH-0052 D4).
#[derive(Clone)]
pub(crate) struct JournalEntry {
    /// Read by [`OverlaySnapshot::plan_promotion`] to cut ONE turn's closure
    /// out of the journal — the whole reason the scope is recorded at staging
    /// time rather than reconstructed from index keys later.
    pub(crate) scope: JournalScope,
    pub(crate) role: JournalRole,
    pub(crate) learned_at: u64,
    pub(crate) occurred: TimeRange,
    pub(crate) op: BatchOp,
}

impl JournalEntry {
    pub(super) fn byte_size(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(batch_op_payload_bytes(&self.op))
    }
}

/// Turn/conversation scope carried by each typed journal operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JournalScope {
    conversation: EntityId,
    turn: EntityId,
}

impl JournalScope {
    pub(crate) const fn new(conversation: EntityId, turn: EntityId) -> Self {
        Self { conversation, turn }
    }

    /// The turn this op belongs to. Promotion moves ONE turn at a time, so
    /// this is how the closure is cut out of the journal.
    pub(crate) const fn turn(&self) -> EntityId {
        self.turn
    }

    /// The conversation shell owning this op.
    pub(crate) const fn conversation(&self) -> EntityId {
        self.conversation
    }
}

/// One turn's promotable closure, cut out of the typed journal by
/// [`OverlaySnapshot::plan_promotion`] (ARCH-0052 D4, ONE-1730).
///
/// The plan is pure data: it names WHAT to replay, and the promote
/// transaction decides how. Selection and durable commit are separate so the
/// caller can hold the per-session state lock across both and a failed commit
/// leaves the journal it was cut from untouched.
pub(crate) struct PromotePlan {
    /// The replay program, in journal-staging order — the shell put leads, so
    /// every later op refers to a row the base apply already materialized.
    pub(crate) ops: Vec<BatchOp>,
    /// Entity ids the replay materializes, in the same order.
    pub(crate) replayed: Vec<EntityId>,
    /// `(id, in-room alias)` for every promoted entity that carries one. The
    /// canonical half is read back from base after the replay.
    pub(crate) temporary_short_ids: Vec<(EntityId, String)>,
    /// Distinct journal `learned_at` values, ascending. These are the SOURCE
    /// windows the pickup markers are derived from — never a promote-time
    /// clock. Only the sync pickup-marker writer reads them, but the field is
    /// accumulated unconditionally so the plan shape stays feature-independent.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) source_learned_at: Vec<u64>,
    pub(super) turn: EntityId,
    pub(super) conversation: EntityId,
}

impl PromotePlan {
    /// The promoted turn — the receipt key and the pickup marker's id.
    pub(crate) const fn turn(&self) -> EntityId {
        self.turn
    }
}

/// The ONE closure-membership predicate, shared by selection and retirement so
/// the rows that were promoted are exactly the rows that retire.
pub(super) fn journal_entry_in_closure(
    entry: &JournalEntry,
    turn: EntityId,
    conversation: EntityId,
) -> bool {
    match entry.role {
        JournalRole::ConversationShell => entry.scope.conversation() == conversation,
        JournalRole::AttributionEdge => {
            entry.scope.turn() == turn && attribution_edge_is_closure_internal(&entry.op)
        }
        JournalRole::TurnPut
        | JournalRole::MessagePartOf
        | JournalRole::SummaryDerivedFrom
        | JournalRole::TurnOwnedArtifact => entry.scope.turn() == turn,
    }
}

/// Whether an [`JournalRole::AttributionEdge`] op belongs to the promotable
/// closure (ARCH-0052 D4, ONE-1730).
///
/// ONE-1728 stages TWO kinds under that one role, and they differ in where
/// they point:
///
/// * `BelongsTo(message -> conversation shell)` — the shell is a closure
///   member, so this edge is internal to the subgraph being published and is
///   one of the ratified three (`PartOf`, `DerivedFrom`, `BelongsTo`).
/// * `AuthoredBy(message -> actor)` — the actor is a BASE identity the room
///   neither staged nor owns. Promoting it would attach the consented subgraph
///   to an entity outside it, which is exactly the closure boundary promote
///   exists to hold.
///
/// The authorship edge is not discarded: it stays an overlay row and a journal
/// entry for the rest of the room's life (the in-room view still resolves it)
/// and evaporates at close with everything else the user did not promote.
fn attribution_edge_is_closure_internal(op: &BatchOp) -> bool {
    matches!(
        op,
        BatchOp::Edge {
            kind: crate::edge::EdgeKind::BelongsTo,
            ..
        }
    )
}

/// Rebuilds one journaled op as the base apply must see it.
///
/// The ENTRY's `occurred`/`learned_at` ride into the rebuilt op — never
/// `unix_seconds_now()` — so a promoted row lands in the month window the turn
/// actually happened in. Edges become the timestamped PUBLIC arm for the same
/// reason: the plain `Edge` arm stamps `created_at` at apply time, which would
/// restamp the whole attribution set to the promote clock.
pub(super) fn promotion_replay_op(entry: &JournalEntry) -> Result<BatchOp> {
    Ok(match &entry.op {
        BatchOp::Put {
            id,
            entity_type,
            data,
            allow_maintenance,
            allow_reserved_predicate,
            hub_sync_imported,
            ..
        } => BatchOp::Put {
            id: *id,
            entity_type: *entity_type,
            occurred: entry.occurred,
            learned_at: entry.learned_at,
            data: data.clone(),
            allow_maintenance: *allow_maintenance,
            allow_reserved_predicate: *allow_reserved_predicate,
            hub_sync_imported: *hub_sync_imported,
        },
        BatchOp::Edge {
            src,
            kind,
            tgt,
            weight,
            vad,
        } => BatchOp::PublicEdgeWithCreatedAt {
            src: *src,
            kind: *kind,
            tgt: *tgt,
            weight: *weight,
            created_at: entry.learned_at,
            vad: *vad,
        },
        // Text and Vector ride unchanged — only Put re-stamps the journaled
        // time range and only Edge re-arms, so these clone verbatim.
        BatchOp::Text { .. } | BatchOp::Vector { .. } => entry.op.clone(),
        BatchOp::ClaimCandidate { .. }
        | BatchOp::ReconcileLexicalQueryHints { .. }
        | BatchOp::Phonetic { .. }
        | BatchOp::PublicEdgeWithCreatedAt { .. }
        | BatchOp::EdgeWithCreatedAt { .. }
        | BatchOp::SetEdgeWeight { .. }
        | BatchOp::SetEdgeVad { .. }
        | BatchOp::Delete { .. }
        | BatchOp::DeleteEdge { .. }
        | BatchOp::CommitmentGapDecay { .. } => {
            return Err(Error::InvariantViolation(
                "promotion replay found a journal op the session write path cannot stage",
            ));
        }
    })
}

fn batch_op_payload_bytes(op: &BatchOp) -> usize {
    match op {
        BatchOp::Put { data, .. } => data.len(),
        BatchOp::ClaimCandidate {
            candidate,
            envelope,
            ..
        } => debug_bytes(candidate).saturating_add(debug_bytes(envelope)),
        BatchOp::ReconcileLexicalQueryHints { keep, .. } => {
            keep.len().saturating_mul(std::mem::size_of::<EntityId>())
        }
        BatchOp::Vector {
            vector,
            pending_embedding_token,
            ..
        } => vector
            .len()
            .saturating_mul(std::mem::size_of::<f32>())
            .saturating_add(pending_embedding_token.as_ref().map_or(0, Vec::len)),
        BatchOp::Text { fields, .. } => fields
            .iter()
            .map(|(name, value)| name.len().saturating_add(value.len()))
            .sum(),
        BatchOp::Phonetic { codes, .. } => codes.iter().map(String::len).sum(),
        BatchOp::Edge { .. }
        | BatchOp::PublicEdgeWithCreatedAt { .. }
        | BatchOp::EdgeWithCreatedAt { .. }
        | BatchOp::SetEdgeWeight { .. }
        | BatchOp::SetEdgeVad { .. }
        | BatchOp::Delete { .. }
        | BatchOp::DeleteEdge { .. } => 0,
        // The lapse op names ids and carries no body; the rows it rewrites are
        // derived inside the applying transaction, not staged here.
        BatchOp::CommitmentGapDecay { ids, .. } => {
            ids.len().saturating_mul(std::mem::size_of::<EntityId>())
        }
    }
}

fn debug_bytes(value: &impl std::fmt::Debug) -> usize {
    struct Counter(usize);

    impl std::fmt::Write for Counter {
        fn write_str(&mut self, value: &str) -> std::fmt::Result {
            self.0 = self.0.saturating_add(value.len());
            Ok(())
        }
    }

    let mut counter = Counter(0);
    let _ = std::fmt::write(&mut counter, format_args!("{value:?}"));
    counter.0
}
