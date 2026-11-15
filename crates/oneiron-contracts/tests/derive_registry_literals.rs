//! PLAN-UC-04 2.1: `EntityId::derive` takes a `Purpose`, and every id keeps its bytes.
//!
//! Generated from the base 945f4ad28bcd by
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_derive_registry_literals.py` (vibe-build tree);
//! regenerate rather than edit. Each row is a purpose and the context bytes its site spelled
//! at the base: the 107 constants of `entity_id/derived_domains.rs` (now `purposes/ids.rs`),
//! and the 72 local constants and inline literals that moved into the registry.

use oneiron_contracts::entity_id::{EntityId, derived_domains};
use oneiron_contracts::fingerprint::{Purpose, purposes};

/// Each purpose, with the bytes its site passed to `EntityId::derive` at the base.
const MOVED: &[(Purpose, &[u8])] = &[
    // The 107 constants of entity_id/derived_domains.rs.
    (
        derived_domains::PERSON_SUBSTRATE_FACET,
        b"oneiron/person-substrate-facet/v1",
    ),
    (derived_domains::KEY_VALUE, b"oneiron.key_value.v1"),
    (
        derived_domains::EXECUTOR_SPEECH_TURN,
        b"oneiron:executor-speech-turn:v1",
    ),
    (
        derived_domains::EXECUTOR_COMPACTION_SESSION,
        b"oneiron:executor-compaction-session:v1",
    ),
    (
        derived_domains::EXECUTOR_SPEECH_CONVERSATION,
        b"oneiron:executor-speech-conversation:v1",
    ),
    (
        derived_domains::EXECUTOR_SPEECH_MESSAGE,
        b"oneiron:executor-speech-message:v1",
    ),
    (
        derived_domains::CODE_CONSENT_WAIT,
        b"oneiron:code-consent-wait:v1",
    ),
    (
        derived_domains::EXECUTOR_AGENT_VERB_RECEIPT,
        b"oneiron:executor-agent-verb-receipt:v1",
    ),
    (derived_domains::BOOTSTRAP_SKILL, b"oneiron/bootstrap/v1/"),
    (
        derived_domains::SUPERSESSION_COMPANION,
        b"oneiron.supersession.companion.v1",
    ),
    (
        derived_domains::CODE_SYMBOL_ENTITY,
        b"oneiron:code-symbol-entity:v1",
    ),
    (
        derived_domains::DREAMER_CLAIM,
        b"oneiron:dreamer-claim-id:v1",
    ),
    (
        derived_domains::DREAMER_PERSON,
        b"oneiron:dreamer-person:v1",
    ),
    (derived_domains::PROJECT_HOME_ROOM, b"project.home_room.v1/"),
    (
        derived_domains::COMM_PROJECTED_CLAIM,
        b"oneiron.comm.projected_claim.v1\0",
    ),
    (
        derived_domains::COMM_BORN_TOUCH_EVENT,
        b"oneiron.comm.born_touch_event.v1\0",
    ),
    (
        derived_domains::CONNECTOR_ACTOR,
        b"oneiron.connector_actor.v0\0",
    ),
    (
        derived_domains::AGENT_RUN_TASK,
        b"oneiron.agent_run_task.v0\0",
    ),
    (
        derived_domains::AGENT_RUN_SEND_TASK,
        b"oneiron.agent_run_send_task.v0\0",
    ),
    (
        derived_domains::EMBEDDED_OWNER_ACTOR,
        b"oneiron 2026-08 embedded-owner-actor v1",
    ),
    (
        derived_domains::AGENT_PRINCIPAL,
        b"oneiron/agent-principal/v1",
    ),
    (
        derived_domains::COMMITMENT_PROJECTION_ACTOR,
        b"oneiron.commitment.projection.actor.v1\0",
    ),
    (
        derived_domains::FACADE_UNBOUND_CALLER,
        b"oneiron:facade-unbound-caller:v1",
    ),
    (derived_domains::SHARED_ACTION, b"oneiron:shared-action:v1"),
    (
        derived_domains::COMMITMENT_INSTANCE,
        b"oneiron.commitment.instance.v1\0",
    ),
    (
        derived_domains::COMMITMENT_LAPSE_SUCCESSOR,
        b"oneiron.commitment.lapse_successor.v1\0",
    ),
    (
        derived_domains::COMMITMENT_WAKE_PROPOSAL,
        b"oneiron.commitment.wake_proposal.v1\0",
    ),
    (
        derived_domains::LINKEDIN_ENTITY,
        b"oneiron.linkedin.entity.v1",
    ),
    (
        derived_domains::LINKEDIN_CLAIM,
        b"oneiron.linkedin.claim.v1",
    ),
    (
        derived_domains::CALENDAR_SERIES_EXCEPTION,
        b"oneiron:calendar-series-exception:v1",
    ),
    (
        derived_domains::CALENDAR_ICS_FEED_EXCEPTION,
        b"oneiron:calendar-ics-feed-exception:v1:",
    ),
    (
        derived_domains::CALENDAR_ICS_IMPORT_ACTOR,
        b"oneiron:calendar-ics-import-actor:v1",
    ),
    (
        derived_domains::CONVERSATION_MIRROR_ACTOR,
        b"oneiron:conversation-mirror-actor:v1",
    ),
    (
        derived_domains::CALENDAR_ICS_FEED_BLOB,
        b"oneiron:calendar-ics-feed-blob:v1:",
    ),
    (
        derived_domains::CALENDAR_CONNECTOR_SOURCE_BLOB,
        b"oneiron:calendar-connector-source-blob:v1:",
    ),
    (
        derived_domains::SURFACE_PROVIDER_EVENT_BLOB,
        b"oneiron:surface-provider-event-blob:v1:",
    ),
    (
        derived_domains::SURFACE_PROVIDER_INBOUND_ACTOR,
        b"oneiron:surface-provider-inbound-actor:v1",
    ),
    (
        derived_domains::CONNECTOR_REPLY_BODY_BLOB,
        b"oneiron:connector-reply-body-blob:v1:",
    ),
    (
        derived_domains::CAMPAIGN_STEP_BODY_BLOB,
        b"oneiron:campaign-step-body-blob:v1:",
    ),
    (
        derived_domains::TASK_ASK_ORIGIN,
        b"oneiron.tasks.ask.origin.v1",
    ),
    (
        derived_domains::TASK_ASK_INTENT,
        b"oneiron.tasks.ask.intent.v1",
    ),
    (
        derived_domains::TASK_ASK_MEMBER,
        b"oneiron.tasks.ask.member.v1",
    ),
    (
        derived_domains::TASK_ASK_ANSWER,
        b"oneiron.tasks.ask.answer.v1",
    ),
    (
        derived_domains::TASK_ASK_SETTLEMENT,
        b"oneiron.tasks.ask.settlement",
    ),
    (
        derived_domains::TASK_ASK_SOFT_CONFIRM,
        b"oneiron.tasks.ask.soft_confirm.v1",
    ),
    (
        derived_domains::TASK_ASK_GUEST_GRANT,
        b"oneiron.tasks.ask.guest.v1",
    ),
    (
        derived_domains::TASK_ASK_FORWARD_INTENT,
        b"oneiron.tasks.ask.forward_intent.v1",
    ),
    (
        derived_domains::TASK_ASK_FORWARD_RESULT,
        b"oneiron.tasks.ask.forward_result.v1",
    ),
    (derived_domains::TASK_POST, b"oneiron.tasks.post.v1"),
    (
        derived_domains::PLAN_RUN_SESSION,
        b"oneiron.plans.run_session.v1",
    ),
    (derived_domains::TASK_SETTLE, b"oneiron.tasks.settle.v1"),
    (
        derived_domains::COMM_CONNECTOR_SEND_EVENT,
        b"oneiron.comm.connector_send_event.v1\0",
    ),
    (
        derived_domains::OUTBOUND_RECEIPT_RECORD,
        b"oneiron.outbound.receipt_record.v1\0",
    ),
    (
        derived_domains::FIRST_PARTY_SKILL_HUB,
        b"oneiron/first-party-skill-hub/v1",
    ),
    (
        derived_domains::CLAIM_CLASS_DESCRIPTOR,
        b"oneiron.comm.claim_class_descriptor.v1",
    ),
    (
        derived_domains::EMBEDDING_SETUP,
        b"oneiron/embedding-setup/v1/",
    ),
    (
        derived_domains::BUILTIN_CONNECTOR_PACK_HUB,
        b"oneiron/built-in-connector-packs/v1",
    ),
    (
        derived_domains::HISTORY_CONVERSATION,
        b"oneiron.ingest.history.conversation.v1",
    ),
    (
        derived_domains::HISTORY_TURN,
        b"oneiron.ingest.history.turn.v1",
    ),
    (
        derived_domains::HISTORY_MESSAGE,
        b"oneiron.ingest.history.message.v1",
    ),
    (
        derived_domains::MAIL_CONVERSATION,
        b"oneiron.mail_pack.conversation.v1",
    ),
    (derived_domains::MAIL_TURN, b"oneiron.mail_pack.turn.v1"),
    (
        derived_domains::MAIL_MESSAGE,
        b"oneiron.mail_pack.message.v1",
    ),
    (
        derived_domains::MAIL_ATTACHMENT,
        b"oneiron.mail_pack.attachment.v1",
    ),
    (
        derived_domains::MAIL_REPLY_DRAFT,
        b"oneiron.mail_pack.reply_draft.v1",
    ),
    (
        derived_domains::MAIL_CALENDAR_EVENT,
        b"oneiron.mail_pack.calendar_event.v1",
    ),
    (
        derived_domains::MAIL_CALENDAR_SOURCE_BLOB,
        b"oneiron.mail_pack.calendar_source_blob.v1",
    ),
    (
        derived_domains::IMPORTED_NOTE,
        b"oneiron.ingest.notes.note.v1",
    ),
    (
        derived_domains::IMPORT_AUDIENCE_TOPIC,
        b"oneiron.ingest.import_audience.topic.v1",
    ),
    (
        derived_domains::PROJECT_REVISION,
        b"oneiron/project-revision-id/v1/",
    ),
    (
        derived_domains::DECISION_QUESTION,
        b"oneiron.decision.question.v1",
    ),
    (
        derived_domains::DECISION_HOST_RULE,
        b"oneiron.decision.host_rule.v1",
    ),
    (
        derived_domains::COORDINATION_PATTERN,
        b"oneiron/coordination-pattern/v1/",
    ),
    (
        derived_domains::SIDE_ROW_MASK,
        b"oneiron.side_row.mask.v1\0",
    ),
    (
        derived_domains::GLOBAL_SETTING_SUBJECT,
        b"oneiron.learning.setting.global_subject.v1\0",
    ),
    (
        derived_domains::TASK_SUBPROJECT,
        b"oneiron/task-subproject/v1/",
    ),
    (
        derived_domains::AGENT_PACK_TRAVEL,
        b"oneiron/agent-pack-travel/v1/",
    ),
    (
        derived_domains::CONNECT_GUEST_ACTOR,
        b"oneiron/connect-guest-actor/v1",
    ),
    (
        derived_domains::FOREIGN_WORLD,
        b"oneiron.federation.foreign-world.v1",
    ),
    (
        derived_domains::INQUIRY_COPY_CLAIM,
        b"oneiron.inquiry.copy-claim.v1",
    ),
    (
        derived_domains::ASSET_BODY_FILE,
        b"oneiron/asset-body-file/v1",
    ),
    (
        derived_domains::ASSET_BODY_HELD,
        b"oneiron/asset-body-held/v1",
    ),
    (
        derived_domains::ASSET_BODY_REVISION,
        b"oneiron/asset-body-revision/v1",
    ),
    (
        derived_domains::REMOVAL_ARCHIVE_OWNER,
        b"oneiron/removal-archive-owner/v1",
    ),
    (
        derived_domains::REPO_SECRET_MARK,
        b"oneiron:repo-secret-mark:v1",
    ),
    (derived_domains::FILES_WORLD, b"oneiron.files.world.v1"),
    (
        derived_domains::CLIPBOARD_WORLD,
        b"oneiron.clipboard.world.v1",
    ),
    (derived_domains::FILES_SOURCE, b"oneiron.files.source.v1"),
    (
        derived_domains::SYNC_TEXT_BIRTH_INCARNATION,
        b"oneiron.sync-text.birth-incarnation.v1",
    ),
    (
        derived_domains::VAD_ANNOTATION_CLAIM,
        b"oneiron:vad-annotation-claim:v1",
    ),
    (
        derived_domains::STORAGE_SERVICE_PRINCIPAL,
        b"oneiron:storage-service-principal:v1",
    ),
    (
        derived_domains::CHANNEL_IDENTITY_AUTONOMY,
        b"oneiron/channel-identity-autonomy/v1",
    ),
    (
        derived_domains::PACK_SOURCE_ASSET,
        b"oneiron.pack-source.asset.v1\0",
    ),
    (
        derived_domains::COMMITMENT_REMINDER_WORDING_BLOB,
        b"oneiron:commitment-reminder-wording:v1:",
    ),
    (
        derived_domains::ESIGN_SEAL_ACTOR,
        b"oneiron.esign.seal.actor.v1",
    ),
    (
        derived_domains::ESIGN_DOCUMENT_COMMITMENT,
        b"oneiron.esign.document.commitment.v1",
    ),
    (
        derived_domains::SCOPE_SUMMARY_LANDING_ACTOR,
        b"oneiron.scope-summary.landing.actor.v1",
    ),
    (
        derived_domains::PLUGIN_SECTION_FIT_INSTALL_ACTOR,
        b"oneiron.plugin-section.fit-install.actor.v1",
    ),
    (
        derived_domains::COMMITMENT_LAPSE_ACTOR,
        b"oneiron.commitment.lapse.actor.v1",
    ),
    (
        derived_domains::ORIGIN_CUT_TARGET,
        b"oneiron/origin-cut-target/v1",
    ),
    (
        derived_domains::DEVICE_SUCCESSION_TARGET,
        b"oneiron/device-succession-target/v1",
    ),
    (
        derived_domains::IDENTITY_TOPOLOGY_OPERATION_PART,
        b"oneiron/identity-topology/operation-part/v1",
    ),
    (
        derived_domains::LEXICAL_QUERY_HINT,
        b"oneiron.lexical-query-hint.v1",
    ),
    (
        derived_domains::EXECUTOR_COMPACTION_STEP,
        b"oneiron:executor-compaction-step:v1",
    ),
    (
        derived_domains::EXECUTOR_FOLD_REQUEST,
        b"oneiron:executor-fold-request:v1",
    ),
    (
        derived_domains::EXECUTOR_CONTINUATION_CHECKPOINT,
        b"oneiron:executor-continuation-checkpoint:v1",
    ),
    (
        derived_domains::RESIDENT_MESSAGE_ASK,
        b"oneiron.agent_dispatch.resident_message_ask.v1\0",
    ),
    // The sites that named no registry constant: file under src/, then the old name.
    // world_pad_codec.rs PAD_ROW_DOMAIN
    (
        purposes::world::KEY_PAD_ROW,
        b"oneiron/world-key-pad-row/v1",
    ),
    // agent_dispatch/resident/result.rs RUN_RESULT
    (purposes::agent::RUN_RESULT, b"oneiron:agent-run-result:v1"),
    // agent_dispatch/resident/result.rs RUN_RESULT_BODY
    (
        purposes::agent::RUN_RESULT_BODY,
        b"oneiron:agent-run-result-body:v1",
    ),
    // agent_dispatch/workflow_host.rs RESULT
    (
        purposes::agent::WORKFLOW_RUN_RESULT,
        b"oneiron:workflow-run-result:v1",
    ),
    // agent_dispatch/workflow_host.rs BODY
    (
        purposes::agent::WORKFLOW_RUN_RESULT_BODY,
        b"oneiron:workflow-run-result-body:v1",
    ),
    // batch/secret_scan/mask/carrier.rs CARRIER_ORIGIN
    (
        purposes::secret::LIFT_CARRIER,
        b"oneiron:secret-lift:carrier:v1",
    ),
    // blob_artifact/erase.rs ERASED_PRODUCER_DOMAIN
    (
        purposes::blob::ERASED_PRODUCER,
        b"oneiron:erased-producer:v1",
    ),
    // campaign/enrollment/held.rs HELD_CALL_REF_DOMAIN
    (
        purposes::task::CAMPAIGN_HELD_CALL_REF,
        b"oneiron.campaign.enrollment.held.call_ref.v1",
    ),
    // campaign/enrollment/held.rs HELD_QUESTION_DOMAIN
    (
        purposes::task::CAMPAIGN_HELD_QUESTION,
        b"oneiron.campaign.enrollment.held.question.v1",
    ),
    // channel_identity_lifecycle/approval.rs LIFECYCLE_REQUEST_REF_DOMAIN
    (
        purposes::channel_identity::LIFECYCLE_REQUEST_REF,
        b"oneiron:channel-identity-lifecycle-request-ref:v1",
    ),
    // channel_identity_provider/workspace_connector/invocation.rs WORKSPACE_WRITE_INVOCATION_DOMAIN
    (
        purposes::channel_identity::WORKSPACE_WRITE_INVOCATION,
        b"oneiron.workspace_write_invocation.v1",
    ),
    // claim/scoped_read/served_forms/session.rs ROOM_SERVED_FORM_ID
    (
        purposes::claim::ROOM_SERVED_FORM,
        b"oneiron/room-served-form/v1",
    ),
    // code_run/dispatcher/workflow_dispatch/operations.rs MEMBER_FUNDING_DOMAIN
    (
        purposes::code_run::MEMBER_FUNDING,
        b"oneiron.workflow.member_funding.v1",
    ),
    // connector_key/credential_binding.rs BINDING_DOMAIN
    (
        purposes::connector::CREDENTIAL_BINDING,
        b"oneiron:connector-credential-binding:v1",
    ),
    // connector_key/slate_scope_signal.rs SCOPE_SIGNAL_DOMAIN
    (
        purposes::connector::SCOPE_SIGNAL,
        b"oneiron:connector-scope-signal:v1",
    ),
    // consent/contact_clearance/engine_offer.rs ENGINE_OFFER_FILER
    (
        purposes::people::CONTACT_DISCLOSURE_ENGINE_FILER,
        b"oneiron:contact-disclosure-engine-filer:v1",
    ),
    // context_board/people.rs AGENT_PERSON_DOMAIN
    (
        purposes::people::AGENT_PERSON,
        b"oneiron.people.agent-person.v1",
    ),
    // context_board/people.rs SEEDED_SUBSTRATE_DOMAIN
    (
        purposes::people::SEEDED_SUBSTRATE,
        b"oneiron.people.seeded-substrate.v1",
    ),
    // context_board/people.rs SEEDED_ANCHOR_DOMAIN
    (
        purposes::people::SEEDED_ANCHOR,
        b"oneiron.people.seeded-anchor.v1",
    ),
    // dreamer_consolidation/gap/intent.rs INTENT_QUESTION_DOMAIN
    (
        purposes::dreamer::INTENT_ASK_QUESTION,
        b"oneiron.dreamer.intent_ask.question.v1",
    ),
    // dreamer_consolidation/gap/intent.rs INTENT_CLAIM_DOMAIN
    (
        purposes::dreamer::INTENT_ASK_CLAIM,
        b"oneiron.dreamer.intent_ask.claim.v1",
    ),
    // dreamer_consolidation/task_realize/landing.rs NOTE_ID_DOMAIN
    (
        purposes::dreamer::TASK_REALIZE_NOTE,
        b"oneiron.dreamer.task_realize.note.v1",
    ),
    // dreamer_consolidation/thing_agent/proposals.rs PARENT_RUN_DOMAIN
    (
        purposes::dreamer::THING_PARENT_RUN,
        b"oneiron:dreamer-thing-parent:v1",
    ),
    // dreamer_consolidation/thing_agent/proposals.rs DRAFT_ID_DOMAIN
    (
        purposes::dreamer::THING_DRAFT,
        b"oneiron:dreamer-thing-draft:v1",
    ),
    // dreamer_runner/maintenance/identity.rs ASK_ANSWER_CONTEXT
    (
        purposes::identity::ASK_ANSWER,
        b"oneiron/identity-ask/answer/v1",
    ),
    // edit_distance/attribution/causes.rs SOURCE_DOMAIN
    (
        purposes::learning::AMENDMENT_CAUSE,
        b"oneiron:amendment-cause:v1",
    ),
    // identity_topology/post_hoc_review/run.rs RECIPE_DOMAIN
    (
        purposes::identity::TOPOLOGY_AUDIT_RECIPE,
        b"oneiron/coach/topology-audit-recipe/v1",
    ),
    // ingest/connector_conversation.rs CONNECTOR_CONVERSATION_DOMAIN
    (
        purposes::connector::CONVERSATION,
        b"oneiron.ingest.connector.conversation.v1",
    ),
    // ingest/connector_conversation.rs CONNECTOR_TURN_DOMAIN
    (
        purposes::connector::TURN,
        b"oneiron.ingest.connector.turn.v1",
    ),
    // ingest/connector_conversation.rs CONNECTOR_MESSAGE_DOMAIN
    (
        purposes::connector::MESSAGE,
        b"oneiron.ingest.connector.message.v1",
    ),
    // ingest/connector_witness_grant.rs CONNECTOR_WITNESS_READ_GRANT_DOMAIN
    (
        purposes::connector::WITNESS_READ_GRANT,
        b"oneiron.ingest.connector.witness_read_grant.v1",
    ),
    // linear_sync/custody.rs BODY_OCCURRENCE
    (
        purposes::connector::LINEAR_MIRROR_BODY,
        b"oneiron:linear-mirror-body:v1",
    ),
    // llm/decision/questions/role_asks.rs QUESTION_UNIT_ASK_DOMAIN
    (
        purposes::llm::QUESTION_UNIT_ASK,
        b"oneiron:question-unit-ask:v1",
    ),
    // memory/people_verbs.rs LEADER_DIRECT_ROOM_DOMAIN
    (
        purposes::people::LEADER_ROOM,
        b"oneiron.people.leader-room.v1",
    ),
    // memory/people_verbs.rs DIRECT_ROOM_DOMAIN
    (
        purposes::people::DIRECT_ROOM,
        b"oneiron.people.direct-room.v1",
    ),
    // note/brief_view.rs REDACTED_CITATION
    (
        purposes::note::BRIEF_REDACTED_CITATION,
        b"oneiron.note.brief.redacted_citation.v1",
    ),
    // origin/smart_http/protected_ref_confirm.rs ASK_DOMAIN
    (
        purposes::origin::PROTECTED_REF_MOVE_ASK,
        b"oneiron:origin-protected-ref-move-ask:v1",
    ),
    // outbound/reply_job.rs CONNECTOR_REPLY_RESULT_DOMAIN
    (
        purposes::connector::REPLY_JOB_RESULT,
        b"oneiron:connector-reply-job-result:v1",
    ),
    // outbound_chokepoint/ordinary_slate.rs ASK_DOMAIN
    (
        purposes::outbound_intent_ledger::INTENT_APPROVAL_ASK,
        b"oneiron:outbound-intent-approval-ask:v1",
    ),
    // outbound_consent/connector_call.rs CONNECTOR_CALL_REF_DOMAIN
    (
        purposes::connector::CALL_REF,
        b"oneiron:connector-call-ref:v1",
    ),
    // outbound_consent/connector_elicitation_asks.rs ELICITATION_ASK_DOMAIN
    (
        purposes::connector::ELICITATION_ASK,
        b"oneiron:connector-elicitation-ask:v1",
    ),
    // outbound_consent/connector_elicitation_asks.rs ELICITATION_ASK_PART_DOMAIN
    (
        purposes::connector::ELICITATION_ASK_PART,
        b"oneiron:connector-elicitation-ask-part:v1",
    ),
    // outbound_consent/connector_elicitation_asks.rs ANSWER_CHECK_DOMAIN
    (
        purposes::connector::ELICITATION_ANSWER_CHECK,
        b"oneiron:connector-elicitation-answer-check:v1",
    ),
    // outbound_intent_ledger/remote_task_input/owner_ask.rs ASK_DOMAIN
    (
        purposes::outbound_intent_ledger::REMOTE_TASK_INPUT_ASK,
        b"oneiron:outbound-remote-task-input-ask:v1",
    ),
    // skill_attribution/causes.rs SOURCE_DOMAIN
    (
        purposes::learning::SKILL_ATTRIBUTION_CAUSE,
        b"oneiron:skill-attribution-cause:v1",
    ),
    // task_verb/ask_record/attendee_entry.rs ENTRY_ID_DOMAIN
    (
        purposes::task::ATTENDEE_ENTRY,
        b"oneiron.tasks.attendee_entry.v1",
    ),
    // task_verb/ask_record/attendee_late_ask.rs LATE_ASK_ID_DOMAIN
    (
        purposes::task::ATTENDEE_LATE_ASK,
        b"oneiron.tasks.attendee_late_ask.v1",
    ),
    // task_verb/browser_workflow.rs RECEIPT_NOTE_DOMAIN
    (
        purposes::task::BROWSER_WORKFLOW_RECEIPT,
        b"oneiron.tasks.browser_workflow.receipt.v1",
    ),
    // task_verb/consult_assignee_wait.rs CONSULT_ASSIGNEE_WAIT_DOMAIN
    (
        purposes::task::CONSULT_ASSIGNEE_WAIT,
        b"oneiron.tasks.consult_assignee_wait.v1",
    ),
    // task_verb/consts.rs TASK_BLOCK_QUESTION_ID_DOMAIN
    (
        purposes::task::BLOCK_QUESTION,
        b"oneiron.tasks.block_question.v1",
    ),
    // task_verb/create_origin.rs WAVE_PLAN_ORIGIN_DOMAIN
    (
        purposes::task::WAVE_PLAN_ORIGIN,
        b"oneiron.tasks.create_origin.wave_plan.v1",
    ),
    // task_verb/fanout_launch.rs LAUNCH_REF_DOMAIN
    (
        purposes::task::FANOUT_LAUNCH,
        b"oneiron.tasks.fanout.launch.v1",
    ),
    // task_verb/highway_runner/workflow_try.rs REPORT_NOTE_DOMAIN
    (
        purposes::task::WORKFLOW_TASK_REPORT,
        b"oneiron.workflow.task_report.v1",
    ),
    // task_verb/lifecycle_receipt.rs RECEIPT_ID_DOMAIN
    (
        purposes::task::LIFECYCLE_RECEIPT,
        b"oneiron.tasks.lifecycle_receipt.v1",
    ),
    // dreamer_runner/maintenance/agent_health/environment.rs AMENDMENT_SOURCE_DOMAIN
    (
        purposes::dreamer::AGENT_HEALTH_AMENDMENT_CAUSE,
        b"oneiron:agent-health-amendment-cause:v1",
    ),
    // task_type/mod.rs TYPE_NODE_ID_DOMAIN
    (purposes::task::TYPE_NODE, b"oneiron.task_type.node.v1"),
    // agent_dispatch/agent_wait.rs inline
    (
        purposes::agent::CODE_AGENT_WAIT,
        b"oneiron:code-agent-wait:v1",
    ),
    // agent_dispatch/workflow/tool_wait.rs inline
    (
        purposes::agent::WORKFLOW_TOOL_CHECKPOINT,
        b"oneiron:workflow-tool-checkpoint:v1",
    ),
    // channel_identity_provider/native_mail/mailbox.rs inline
    (
        purposes::channel_identity::NATIVE_MAIL_MAILBOX,
        b"oneiron.native_mail.mailbox.v1",
    ),
    // channel_identity_provider/stalwart/reputation.rs inline
    (
        purposes::channel_identity::NATIVE_MAIL_REPUTATION,
        b"oneiron.native_mail.reputation.v1",
    ),
    // code_run/reader.rs inline
    (
        purposes::code_run::READER_SUMMARY,
        b"oneiron:code-reader-summary:v1",
    ),
    // code_run/reader.rs inline
    (
        purposes::code_run::READER_TASK,
        b"oneiron:code-reader-task:v1",
    ),
    // code_run/reader.rs inline
    (
        purposes::code_run::READER_RUN,
        b"oneiron:code-reader-run:v1",
    ),
    // code_run/reader.rs inline
    (
        purposes::code_run::READER_ATTEMPT,
        b"oneiron:code-reader-attempt:v1",
    ),
    // code_run/reader.rs inline
    (
        purposes::code_run::READER_WAIT,
        b"oneiron:code-reader-wait:v1",
    ),
    // code_run/scoped_child_io.rs inline
    (
        purposes::code_run::SCOPED_CHILD_TASK,
        b"oneiron:code-scoped-child-task:v1",
    ),
    // edit_distance/publisher/signature_store.rs inline
    (
        purposes::learning::ISSUE_SIGNATURE,
        b"oneiron:issue-signature:v1",
    ),
    // identity_topology/op_apply.rs inline
    (
        purposes::identity::FACET_FORK,
        b"oneiron/identity-topology/facet-fork/v1",
    ),
    // skill_hub/pack_catalog/hooks/author.rs inline
    (
        purposes::skill_hub::PACK_HOOK_FOREIGN_PUBLISHER,
        b"oneiron.pack-hook.foreign-publisher.v1",
    ),
    // store/result_manifest.rs inline
    (
        purposes::code_run::OUTPUT_UNOWNED,
        b"oneiron:code-run-output-unowned:v1",
    ),
    // store/result_manifest.rs inline
    (
        purposes::code_run::OUTPUT_OCCURRENCE,
        b"oneiron:code-run-output-occurrence:v1",
    ),
    // store/result_manifest.rs inline
    (
        purposes::code_run::OUTPUT_RAW_HOLD,
        b"oneiron:code-run-output-raw-hold:v1",
    ),
];

/// Part lists for the id check: none, one, and two whose boundary moves.
const PARTS: [&[&[u8]]; 4] = [&[], &[b"part"], &[b"ab", b"c"], &[b"a", b"bc"]];

#[test]
fn every_moved_purpose_keeps_its_base_context() {
    assert_eq!(MOVED.len(), 179);
    for (purpose, base) in MOVED {
        assert_eq!(
            purpose.context().as_bytes(),
            *base,
            "{}",
            String::from_utf8_lossy(base)
        );
    }
}

#[test]
fn every_moved_purpose_derives_the_base_id() {
    for (purpose, base) in MOVED {
        for parts in PARTS {
            let id = EntityId::derive(*purpose, parts).expect("a derived id is never reserved");
            let kept = EntityId::derive_unregistered(base, parts).expect("the base rule derives");
            assert_eq!(id, kept, "{} {parts:?}", String::from_utf8_lossy(base));
        }
    }
}

#[test]
fn the_id_file_holds_the_old_registry_whole() {
    assert_eq!(derived_domains::ALL.len(), 107);
    for (purpose, _) in &MOVED[..107] {
        assert!(
            derived_domains::ALL.contains(purpose),
            "{}",
            purpose.context()
        );
    }
}
