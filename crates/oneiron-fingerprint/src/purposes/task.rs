//! Purposes of tasks (`crates/oneiron/src/task_verb`, `task_type`, `campaign`).

purposes! {
    /// A blocked TASK's question CLAIM, so a settlement finds its continuation from the group
    /// alone (`task_verb::highway_block`). Parts: the ask group.
    BLOCK_QUESTION = "oneiron.tasks.block_question.v1";

    /// An attendee entry (`task_verb::ask_record::attendee_entry`). Parts: container, then
    /// `person` and the person, or `speaker`, the session key and the speaker key.
    ATTENDEE_ENTRY = "oneiron.tasks.attendee_entry.v1";

    /// An attendee's late ask (`task_verb::ask_record::attendee_late_ask`). Parts: the entry.
    ATTENDEE_LATE_ASK = "oneiron.tasks.attendee_late_ask.v1";

    /// A browser workflow try's receipt NOTE (`task_verb::browser_workflow`). Parts:
    /// attempt.
    BROWSER_WORKFLOW_RECEIPT = "oneiron.tasks.browser_workflow.receipt.v1";

    /// A consult's assignee-fact wait (`task_verb::consult_assignee_wait`). Parts: the
    /// consult TASK.
    CONSULT_ASSIGNEE_WAIT = "oneiron.tasks.consult_assignee_wait.v1";

    /// The witness key a wave planning attempt derives (`task_verb::create_origin`). Parts:
    /// attempt.
    WAVE_PLAN_ORIGIN = "oneiron.tasks.create_origin.wave_plan.v1";

    /// A launch's ref: one launch per actor and plan (`task_verb::fanout_launch`). Parts:
    /// `wave`, actor, plan ref; or `ask_auto`, actor, intent key.
    FANOUT_LAUNCH = "oneiron.tasks.fanout.launch.v1";

    /// A workflow run's report NOTE (`task_verb::highway_runner::workflow_try`). Parts: the
    /// root.
    WORKFLOW_TASK_REPORT = "oneiron.workflow.task_report.v1";

    /// The lifecycle receipt of one call (`task_verb::lifecycle_receipt`). Parts: call name,
    /// then the call's identity parts.
    LIFECYCLE_RECEIPT = "oneiron.tasks.lifecycle_receipt.v1";

    /// A task type node's id spelling (`task_type`). Parts: the node id.
    TYPE_NODE = "oneiron.task_type.node.v1";

    /// A held campaign enrollment's call ref (`campaign::enrollment::held`). Parts: the key's
    /// first part, the sequence, the key's third part.
    CAMPAIGN_HELD_CALL_REF = "oneiron.campaign.enrollment.held.call_ref.v1";

    /// A held campaign enrollment's question (`campaign::enrollment::held`). Parts: call ref,
    /// approval digest.
    CAMPAIGN_HELD_QUESTION = "oneiron.campaign.enrollment.held.question.v1";
}

legacy_purposes! {}
