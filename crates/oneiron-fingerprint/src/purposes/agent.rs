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

legacy_purposes! {}
