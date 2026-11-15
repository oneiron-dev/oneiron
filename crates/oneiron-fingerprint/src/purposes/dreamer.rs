//! Purposes of the Dreamer (`crates/oneiron/src/dreamer_consolidation`, `dreamer_runner`).

purposes! {
    /// An intent ask's question (`dreamer_consolidation::gap::intent`). Parts: its TURN, the
    /// words it quotes.
    INTENT_ASK_QUESTION = "oneiron.dreamer.intent_ask.question.v1";

    /// The intent a yes lands (`dreamer_consolidation::gap::intent`). Parts: the ask.
    INTENT_ASK_CLAIM = "oneiron.dreamer.intent_ask.claim.v1";

    /// Each answer part's NOTE (`dreamer_consolidation::task_realize::landing`). Parts: the
    /// record, the part's index (u64 little-endian).
    TASK_REALIZE_NOTE = "oneiron.dreamer.task_realize.note.v1";

    /// A thing's host parent run (`dreamer_consolidation::thing_agent::proposals`). Parts:
    /// attempt, generation (big-endian).
    THING_PARENT_RUN = "oneiron:dreamer-thing-parent:v1";

    /// A staged draft candidate (`dreamer_consolidation::thing_agent::proposals`). Parts: step
    /// hash, index (big-endian).
    THING_DRAFT = "oneiron:dreamer-thing-draft:v1";

    /// An amendment label's source, one per settled cause row and label
    /// (`dreamer_runner::maintenance::agent_health::environment`). Parts: source, label.
    AGENT_HEALTH_AMENDMENT_CAUSE = "oneiron:agent-health-amendment-cause:v1";
}

legacy_purposes! {}
