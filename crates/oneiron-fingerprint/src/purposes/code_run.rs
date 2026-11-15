//! Purposes of code runs (`crates/oneiron/src/code_run`, `store::result_manifest`).

purposes! {
    /// A member-funded run's root spend scope
    /// (`code_run::dispatcher::workflow_dispatch::operations`). Parts: person, task,
    /// workflow, intent key, cap, unit, the shown amount.
    MEMBER_FUNDING = "oneiron.workflow.member_funding.v1";

    /// The summary task a parent's memo key names: the same members by the same recipe are
    /// the same task (`code_run::reader`). Parts: parent run, memo key.
    READER_SUMMARY = "oneiron:code-reader-summary:v1";

    /// The child task a parent's spawn key names (`code_run::reader`). Parts: parent run,
    /// intent key.
    READER_TASK = "oneiron:code-reader-task:v1";

    /// The run a reader child task runs as (`code_run::reader`). Parts: task.
    READER_RUN = "oneiron:code-reader-run:v1";

    /// The attempt a reader child's spend scope is keyed by (OF-532; `code_run::reader`).
    /// Parts: task.
    READER_ATTEMPT = "oneiron:code-reader-attempt:v1";

    /// The wait set a parent's step key names (`code_run::reader`). Parts: parent run, step
    /// key.
    READER_WAIT = "oneiron:code-reader-wait:v1";

    /// A scoped child's task (`code_run::scoped_child_io`). Parts: parent run, intent key.
    SCOPED_CHILD_TASK = "oneiron:code-scoped-child-task:v1";

    /// The occurrence of a run output with no owner (`store::result_manifest`). Parts: the
    /// output's raw BLAKE3.
    OUTPUT_UNOWNED = "oneiron:code-run-output-unowned:v1";

    /// The occurrence of a run output its owner holds at a path (`store::result_manifest`).
    /// Parts: owner, path.
    OUTPUT_OCCURRENCE = "oneiron:code-run-output-occurrence:v1";

    /// The raw hold of a run output's bytes (`store::result_manifest`). Parts: owner, path,
    /// digest.
    OUTPUT_RAW_HOLD = "oneiron:code-run-output-raw-hold:v1";
}

legacy_purposes! {}
