//! Purposes of agent dispatch (`crates/oneiron/src/agent_dispatch`).

purposes! {
    /// The wait an attempt's step key names (`agent_dispatch::agent_wait`). Parts: the
    /// parent attempt, the step key.
    CODE_AGENT_WAIT = "oneiron:code-agent-wait:v1";

    /// A completed agent run's result TURN (`agent_dispatch::resident::result`). Parts:
    /// attempt.
    RUN_RESULT = "oneiron:agent-run-result:v1";

    /// The run's answer body, as the result TURN holds it
    /// (`agent_dispatch::resident::result`). Parts: result TURN.
    RUN_RESULT_BODY = "oneiron:agent-run-result-body:v1";

    /// The body owner of a workflow tool wait's checkpoint
    /// (`agent_dispatch::workflow::tool_wait`). Parts: attempt.
    WORKFLOW_TOOL_CHECKPOINT = "oneiron:workflow-tool-checkpoint:v1";

    /// A workflow run's result (`agent_dispatch::workflow_host`). Parts: attempt.
    WORKFLOW_RUN_RESULT = "oneiron:workflow-run-result:v1";

    /// The body occurrence a workflow run's result holds
    /// (`agent_dispatch::workflow_host`). Parts: the result.
    WORKFLOW_RUN_RESULT_BODY = "oneiron:workflow-run-result-body:v1";
}

legacy_purposes! {
    /// The key a workflow wrapper's dedupe index is kept under
    /// (`agent_dispatch::workflow_record::dedupe_key_hash`): plain BLAKE3 of the dedupe key's
    /// bytes, with no tag. Today the same bytes as `learning::SKILL_CAUSE_RECEIPT_KEY` and
    /// `learning::AMENDMENT_CAUSE_RECEIPT_KEY` for one string; the three tables are never read
    /// together.
    WORKFLOW_DEDUPE_KEY = (Blake3, NotHashed, "oneiron.agent.workflow_dedupe_key.v1");
}
