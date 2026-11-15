//! Purposes of model decisions (`crates/oneiron/src/llm`).

purposes! {
    /// A question unit's ask (`llm::decision::questions::role_asks`). Parts: question,
    /// version (little-endian), principal, unit, source.
    QUESTION_UNIT_ASK = "oneiron:question-unit-ask:v1";
}

legacy_purposes! {}
