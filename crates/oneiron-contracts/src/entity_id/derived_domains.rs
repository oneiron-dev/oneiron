//! Every domain string [`EntityId::derive`](super::EntityId::derive) is called with.
//!
//! One constant per derivation site, its bytes exactly as the site spelled them
//! before the one derived-id rule. The bytes are the id's context string: changing
//! one changes every id already derived under it.

/// The `substrate` FACET of a PERSON (`claim::substrate_facet_id`). Parts: person.
pub const PERSON_SUBSTRATE_FACET: &[u8] = b"oneiron/person-substrate-facet/v1";

/// A keyed-value revision claim (`memory::key_value`). Parts: actor, actor class,
/// JSON address, request id.
pub const KEY_VALUE: &[u8] = b"oneiron.key_value.v1";

/// The speech TURN of one durable executor run
/// (`executor_speech_identity::executor_speech_turn_id`, FIX 9711). Parts: the
/// run ref, then the run id when one is known.
pub const EXECUTOR_SPEECH_TURN: &[u8] = b"oneiron:executor-speech-turn:v1";

/// The compaction session of one durable executor run
/// (`executor_speech_identity::executor_compaction_session_id`, FIX 9711).
/// Parts: the run ref, the run id.
pub const EXECUTOR_COMPACTION_SESSION: &[u8] = b"oneiron:executor-compaction-session:v1";

/// The conversation an executor run's speech lands in
/// (`code_run::storage::speech_identity`, FIX 9711). Parts: the run ref, then
/// the run id when one is known.
pub const EXECUTOR_SPEECH_CONVERSATION: &[u8] = b"oneiron:executor-speech-conversation:v1";

/// One executor speech MESSAGE (`code_run::storage::speech_identity`, FIX
/// 9711). Parts: the run ref, the run id when one is known, the bubble's
/// order (u32 little-endian).
pub const EXECUTOR_SPEECH_MESSAGE: &[u8] = b"oneiron:executor-speech-message:v1";

/// A held code call's consent wait (`code_run::consent_wait::binding`, FIX
/// 9711). Parts: the write receipt, the request digest.
pub const CODE_CONSENT_WAIT: &[u8] = b"oneiron:code-consent-wait:v1";

/// The write receipt of one executor agent-verb call
/// (`code_run::dispatcher::agent_verb`, FIX 9711). Parts: the run ref, the
/// run id, the step start and the ordinal (u64 little-endian each).
pub const EXECUTOR_AGENT_VERB_RECEIPT: &[u8] = b"oneiron:executor-agent-verb-receipt:v1";

/// A built-in bootstrap skill (`skill_hub::bootstrap`). Parts: skill name.
pub const BOOTSTRAP_SKILL: &[u8] = b"oneiron/bootstrap/v1/";

/// A supersession companion claim (`claim::supersession_provenance`). Parts: new
/// head, old head, predicate.
pub const SUPERSESSION_COMPANION: &[u8] = b"oneiron.supersession.companion.v1";

/// A code-symbol entity (`code_symbol::code_symbol_entity_id`). Parts: repo identity
/// key, path, name, kind, fingerprint.
pub const CODE_SYMBOL_ENTITY: &[u8] = b"oneiron:code-symbol-entity:v1";

/// A consolidation claim (`dreamer_consolidation`). Parts: attempt, subject,
/// predicate, canonical value, then world, facet, relationship and topic, each
/// empty when absent and `0x01` followed by its bytes when present.
pub const DREAMER_CLAIM: &[u8] = b"oneiron:dreamer-claim-id:v1";

/// A PERSON the Dreamer's extraction declares (`dreamer_consolidation`, FIX
/// 7506). Parts: the extraction namespace attempt, then world, facet,
/// relationship and the anchor's project (each empty when absent, `0x01` and
/// its bytes when present), the normalized name, the anchor source, and the
/// name's byte range in it (empty, or `0x01`, start and end as u64 big-endian).
pub const DREAMER_PERSON: &[u8] = b"oneiron:dreamer-person:v1";

/// A project's home room (`workspace_roster::project`). Parts: project.
pub const PROJECT_HOME_ROOM: &[u8] = b"project.home_room.v1/";

/// A projector-created `comm.*` claim (`comm`). Parts: source event, predicate,
/// conflict key.
pub const COMM_PROJECTED_CLAIM: &[u8] = b"oneiron.comm.projected_claim.v1\0";

/// The MACHINE assignee of one connector class (`outbound::connector_actor_id`).
/// Parts: normalized connector class.
pub const CONNECTOR_ACTOR: &[u8] = b"oneiron.connector_actor.v0\0";

/// The embedded default owner actor (`vault::embedded_owner_actor_id`, ONE-1441
/// WIRE-P1). No parts. It must stay the same text as the domain behind
/// `oneiron_vault_contract::embedded_owner_holder_hex`, the supervisor's copy
/// of this id: managed boot refuses to start when the two ids disagree.
pub const EMBEDDED_OWNER_ACTOR: &[u8] = b"oneiron 2026-08 embedded-owner-actor v1";

/// A named agent principal the owner mints a credential for
/// (`oneiron token agent`). Parts: agent name.
pub const AGENT_PRINCIPAL: &[u8] = b"oneiron/agent-principal/v1";

/// The System actor that owns engine projection writes
/// (`commitment_schedule::commitment_projection_actor`). No parts.
pub const COMMITMENT_PROJECTION_ACTOR: &[u8] = b"oneiron.commitment.projection.actor.v1\0";

/// The System actor a facade row's verb hooks name for a scoped credential
/// bound to no actor (`api::facade::hooks`, FIX 1439). No parts.
pub const FACADE_UNBOUND_CALLER: &[u8] = b"oneiron:facade-unbound-caller:v1";

/// The run id of one shared agent action (`code_run::actions::execution`,
/// FIX 9702). Parts: the actor, the verb id, the idempotency key, then for a
/// live run's action `live-run`, the attempt id and its try count (u32
/// big-endian).
pub const SHARED_ACTION: &[u8] = b"oneiron:shared-action:v1";

/// One occurrence of one commitment series
/// (`commitment_schedule::commitment_instance_id`). Parts: series, due-at, window
/// start, window end (u64 big-endian each), ordinal (u32 big-endian).
pub const COMMITMENT_INSTANCE: &[u8] = b"oneiron.commitment.instance.v1\0";

/// The successor claim that carries one commitment's batched lapse
/// (`commitment::lapse_claim_id`, FIX 9726). Parts: the commitment (16 bytes).
pub const COMMITMENT_LAPSE_SUCCESSOR: &[u8] = b"oneiron.commitment.lapse_successor.v1\0";

/// The proposal claim one commitment wake attempt writes
/// (`commitment_wake::commitment_wake_proposal_claim_id`, FIX 9731). Parts: the
/// attempt id (16 bytes).
pub const COMMITMENT_WAKE_PROPOSAL: &[u8] = b"oneiron.commitment.wake_proposal.v1\0";

/// A person or company bound to an external lead source (`linkedin_lead_preload`).
/// Parts: source ref.
pub const LINKEDIN_ENTITY: &[u8] = b"oneiron.linkedin.entity.v1";

/// An imported fact about a lead-source entity (`linkedin_lead_preload`). Parts:
/// source ref, predicate.
pub const LINKEDIN_CLAIM: &[u8] = b"oneiron.linkedin.claim.v1";

/// A series-exception claim (`calendar::ingest::admission`). Parts: master event,
/// original start (u64 big-endian).
pub const CALENDAR_SERIES_EXCEPTION: &[u8] = b"oneiron:calendar-series-exception:v1";

/// The inbox-exception ref of one ICS feed (`calendar::ingest::poll`). Parts: feed
/// identity.
pub const CALENDAR_ICS_FEED_EXCEPTION: &[u8] = b"oneiron:calendar-ics-feed-exception:v1:";

/// The ICS import write actor (`calendar::ics_import_actor_id`). No parts.
pub const CALENDAR_ICS_IMPORT_ACTOR: &[u8] = b"oneiron:calendar-ics-import-actor:v1";

/// The conversation-mirror write actor (`reaction::conversation_mirror_actor_id`).
/// No parts.
pub const CONVERSATION_MIRROR_ACTOR: &[u8] = b"oneiron:conversation-mirror-actor:v1";

/// The raw-feed BLOB artifact of one ICS feed (`calendar::ingest::fetch`). Parts:
/// feed dedupe key.
pub const CALENDAR_ICS_FEED_BLOB: &[u8] = b"oneiron:calendar-ics-feed-blob:v1:";

/// The archived remote copy of one calendar connector resource
/// (`calendar::connectors::resource`). Parts: system, calendar ref, UID.
pub const CALENDAR_CONNECTOR_SOURCE_BLOB: &[u8] = b"oneiron:calendar-connector-source-blob:v1:";

/// The BLOB artifact holding one verified provider event's body
/// (`surface_event::provider_payload`). Parts: channel, provider event id.
pub const SURFACE_PROVIDER_EVENT_BLOB: &[u8] = b"oneiron:surface-provider-event-blob:v1:";

/// The write actor provider event bodies are archived under
/// (`surface_event::provider_payload`). No parts.
pub const SURFACE_PROVIDER_INBOUND_ACTOR: &[u8] = b"oneiron:surface-provider-inbound-actor:v1";

/// The BLOB artifact holding one agent's reply body to one connector event
/// (`outbound::reply_content`). Parts: event id, agent, reply ref.
pub const CONNECTOR_REPLY_BODY_BLOB: &[u8] = b"oneiron:connector-reply-body-blob:v1:";

/// The BLOB artifact holding one campaign program step's filed outbound body
/// (`campaign::step_body`, FIX 11513). Parts: program ref, step ref, call_seq
/// (u64 big-endian).
pub const CAMPAIGN_STEP_BODY_BLOB: &[u8] = b"oneiron:campaign-step-body-blob:v1:";

/// An asking actor's origin (`task_verb::ask_record`). Parts: vault ask origin, actor.
pub const TASK_ASK_ORIGIN: &[u8] = b"oneiron.tasks.ask.origin.v1";

/// An ask group (`task_verb::ask_record`). Parts: actor origin, intent key.
pub const TASK_ASK_INTENT: &[u8] = b"oneiron.tasks.ask.intent.v1";

/// An ask group member (`task_verb::ask_record`). Parts: group, actor.
pub const TASK_ASK_MEMBER: &[u8] = b"oneiron.tasks.ask.member.v1";

/// An ask answer (`task_verb::ask_record`). Parts: group, encoded answer.
pub const TASK_ASK_ANSWER: &[u8] = b"oneiron.tasks.ask.answer.v1";

/// An ask group's settlement receipt (`task_verb::ask_settlement`). Parts: group,
/// `receipt`.
pub const TASK_ASK_SETTLEMENT: &[u8] = b"oneiron.tasks.ask.settlement";

/// An ask's soft-confirm notice (`task_verb::ask_soft_confirm`). Parts: group, person.
pub const TASK_ASK_SOFT_CONFIRM: &[u8] = b"oneiron.tasks.ask.soft_confirm.v1";

/// A guest's federation grant on one ask (`task_verb::ask_guest`). Parts: group,
/// person.
pub const TASK_ASK_GUEST_GRANT: &[u8] = b"oneiron.tasks.ask.guest.v1";

/// A replica's relayed word or void on an ask another node admitted
/// (`task_verb::ask_forward`, FIX 7494). Parts: group, holder, intent key.
pub const TASK_ASK_FORWARD_INTENT: &[u8] = b"oneiron.tasks.ask.forward_intent.v1";

/// The admitting node's result for one relayed intent
/// (`task_verb::ask_forward`, FIX 7494). Parts: intent.
pub const TASK_ASK_FORWARD_RESULT: &[u8] = b"oneiron.tasks.ask.forward_result.v1";

/// The TASK an Auto post names (`task_verb::highway_post`). Parts: actor,
/// intent key. The store-local vault id is left out on purpose: every replica
/// of one vault holds its own, and one post must name one TASK on all of them.
pub const TASK_POST: &[u8] = b"oneiron.tasks.post.v1";

/// The TASK a settled create proposal names (`task_verb::proposal_create`).
/// Parts: the proposal claim id.
pub const TASK_SETTLE: &[u8] = b"oneiron.tasks.settle.v1";

/// The CONNECTOR_SEND event a delivered connector receipt projects
/// (`comm::projector`). Parts: task.
pub const COMM_CONNECTOR_SEND_EVENT: &[u8] = b"oneiron.comm.connector_send_event.v1\0";

/// The terminal RECEIPT_RECORD of one outbound intent (`receipt::record`). Parts:
/// intent id.
pub const OUTBOUND_RECEIPT_RECORD: &[u8] = b"oneiron.outbound.receipt_record.v1\0";

/// The first-party library hub every vault shares (`skill_hub::default_hub`). No
/// parts.
pub const FIRST_PARTY_SKILL_HUB: &[u8] = b"oneiron/first-party-skill-hub/v1";

/// A claim-class descriptor (`comm::descriptor`, ARCH-0057). Parts: the
/// predicate the class describes.
pub const CLAIM_CLASS_DESCRIPTOR: &[u8] = b"oneiron.comm.claim_class_descriptor.v1";

/// An embedding setup row (`embed::space`, OF-370). Parts: `space` and the
/// space id, or `slot` and the kind slot's byte.
pub const EMBEDDING_SETUP: &[u8] = b"oneiron/embedding-setup/v1/";

/// The engine hub of the built-in connector packs
/// (`skill_hub::pack_catalog::builtin`). No parts.
pub const BUILTIN_CONNECTOR_PACK_HUB: &[u8] = b"oneiron/built-in-connector-packs/v1";

/// An imported conversation (`ingest::history`). Parts: source, native
/// conversation id.
pub const HISTORY_CONVERSATION: &[u8] = b"oneiron.ingest.history.conversation.v1";

/// An imported TURN (`ingest::history`). Parts: source, native conversation id,
/// native id of the turn's first message.
pub const HISTORY_TURN: &[u8] = b"oneiron.ingest.history.turn.v1";

/// An imported MESSAGE (`ingest::history`). Parts: source, native message id,
/// content hash.
pub const HISTORY_MESSAGE: &[u8] = b"oneiron.ingest.history.message.v1";

/// A mail thread's CONVERSATION (`mail_pack`). Parts: mail source id (hex),
/// the source's own thread key.
pub const MAIL_CONVERSATION: &[u8] = b"oneiron.mail_pack.conversation.v1";

/// One provider message's TURN (`mail_pack`). Parts: mail source id (hex),
/// the provider's message id.
pub const MAIL_TURN: &[u8] = b"oneiron.mail_pack.turn.v1";

/// One revision of a provider message (`mail_pack`). Parts: mail source id
/// (hex), the provider's message id, the revision's content hash.
pub const MAIL_MESSAGE: &[u8] = b"oneiron.mail_pack.message.v1";

/// An attachment a reader opened, stored once (`mail_pack`). Parts: mail
/// source id, the provider's message id, the attachment's MIME part id.
pub const MAIL_ATTACHMENT: &[u8] = b"oneiron.mail_pack.attachment.v1";

/// One drafted mail reply (`mail_pack`, FIX 15420). Parts: the drafter's id
/// (hex), the thread's CONVERSATION id (hex), the drafter's request key.
pub const MAIL_REPLY_DRAFT: &[u8] = b"oneiron.mail_pack.reply_draft.v1";

/// A pack calendar source's EVENT (`mail_pack`): one per source and
/// provider UID, so two people's copies of one meeting never share a row.
/// Parts: calendar source id, the event's UID.
pub const MAIL_CALENDAR_EVENT: &[u8] = b"oneiron.mail_pack.calendar_event.v1";

/// The archived resource a pack calendar source pulled (`mail_pack`).
/// Parts: the source's calendar system, the event's UID.
pub const MAIL_CALENDAR_SOURCE_BLOB: &[u8] = b"oneiron.mail_pack.calendar_source_blob.v1";

/// A NOTE imported from a folder of markdown notes (`note::import`). Parts:
/// folder, the file's path under it.
pub const IMPORTED_NOTE: &[u8] = b"oneiron.ingest.notes.note.v1";

/// An import-audience topic cluster (`ingest::audience`). Parts: the
/// canonical bytes of the extractor's `topic_key`.
pub const IMPORT_AUDIENCE_TOPIC: &[u8] = b"oneiron.ingest.import_audience.topic.v1";

/// A project revision companion (`workspace_roster::project::revision`).
/// Parts: the revision's 32-byte logical hash.
pub const PROJECT_REVISION: &[u8] = b"oneiron/project-revision-id/v1/";

/// A typed decision question an engine caller asks (`self_heal::tiered`). Parts: the
/// question's registered name, then the caller's instance parts.
pub const DECISION_QUESTION: &[u8] = b"oneiron.decision.question.v1";

/// A host rule row: the owner's reason on one answered decision ask
/// (`llm::decision::rules`). Parts: the question's id, its version (u32be), then
/// each evidence id in the order it was asked.
pub const DECISION_HOST_RULE: &[u8] = b"oneiron.decision.host_rule.v1";

/// A coordination pattern's context and a team run's decision on a pack
/// attribution (`skill_attribution::host`). Parts: `pattern` and the pattern's
/// token, or `decider` and the team reference.
pub const COORDINATION_PATTERN: &[u8] = b"oneiron/coordination-pattern/v1/";

/// The row a mask on write found a secret in outside the entity tables
/// (`batch::secret_scan::mask::side_row`): a side-table row, an attempt
/// record's payload and notes, or an intake event. Parts: place, row key.
pub const SIDE_ROW_MASK: &[u8] = b"oneiron.side_row.mask.v1\0";

/// The one subject a learned setting's vault-wide fit is learned on
/// (`learning_setting::global_setting_subject`). Parts: the catalog key.
pub const GLOBAL_SETTING_SUBJECT: &[u8] = b"oneiron.learning.setting.global_subject.v1\0";

/// The subproject a TASK wraps when its leader splits it
/// (`code_run::dispatcher::leader`): one child per wrapper, so a retried split
/// names the child the first try linked. Parts: the wrapper TASK.
pub const TASK_SUBPROJECT: &[u8] = b"oneiron/task-subproject/v1/";

/// What a received AgentPack mints (`skill_hub::pack_catalog::agent_admission`).
/// Parts: `agent` and the pack source's content hash, so a reinstall of the
/// same bytes finds the agent it minted; or `knowledge`, the agent and the
/// row's index (u32be).
pub const AGENT_PACK_TRAVEL: &[u8] = b"oneiron/agent-pack-travel/v1/";

/// The vault-resident guest actor a Connect peer's grants name
/// (`federation::connect_grant`, FIX 3016). Parts: this vault's id, the peer
/// vault's id (32 bytes each), and the actor generation (u64 big-endian; a
/// deleted actor moves the next mint to the next generation, FIX 3685).
pub const CONNECT_GUEST_ACTOR: &[u8] = b"oneiron/connect-guest-actor/v1";
/// The foreign WORLD a federation peer's world lands in on the recipient
/// (`federation::foreign_world_for`, FIX 3497). Parts: the source vault id (32
/// bytes), the sender's world id (its reserved base scope id for base reality),
/// and a counter (u64 little-endian) from 0; the first id in the foreign range
/// is the one.
pub const FOREIGN_WORLD: &[u8] = b"oneiron.federation.foreign-world.v1";

/// The occurrence of an ASSET's current body file (`store::asset_body`, FIX
/// 3677): one per ASSET, moved as its row changes. Parts: the ASSET.
pub const ASSET_BODY_FILE: &[u8] = b"oneiron/asset-body-file/v1";

/// The occurrence a legal hold keeps an ASSET's superseded body file under
/// (`store::asset_body`, FIX 3677). Parts: the ASSET, the file's BLAKE3 (32
/// bytes) and its length (u64 big-endian).
pub const ASSET_BODY_HELD: &[u8] = b"oneiron/asset-body-held/v1";

/// The owner one kept removal archive row's files are held under
/// (`federation::shared_act::removal_file`, FIX 3679): a namespace of its own,
/// so a release of one row reaches no other row's bodies, another member's
/// archive of the same receipt included, whatever ids an imported copy names.
/// Parts: the receipt, then the removed member.
pub const REMOVAL_ARCHIVE_OWNER: &[u8] = b"oneiron/removal-archive-owner/v1";

/// One mark of a key a retained repository blob holds (`origin::secret_marks`,
/// FIX 7608). Parts: schema (u16be), operation, store identity, tagged source,
/// blob OID, tagged path, detector reason, content kind, tagged placement. No
/// key byte, custody id, handle or time is a part.
pub const REPO_SECRET_MARK: &[u8] = b"oneiron:repo-secret-mark:v1";

/// The Files world of one install (`note::files`, FIX 6942). Parts: the
/// install's MACHINE id, then a u64 little-endian counter: the first whose id
/// is outside the foreign-world range.
pub const FILES_WORLD: &[u8] = b"oneiron.files.world.v1";

/// The Clipboard role in each isolated vault (`clipboard`, FIX 12583). Parts:
/// a u64 little-endian counter, selecting the first non-base local-world id.
/// Imported worlds still acquire their source-vault-bound foreign identity.
pub const CLIPBOARD_WORLD: &[u8] = b"oneiron.clipboard.world.v1";

/// One folder source of a Files world (`note::files`, FIX 6942). Parts: the
/// source install's MACHINE id, its Files world, the canonical folder.
pub const FILES_SOURCE: &[u8] = b"oneiron.files.source.v1";

/// The incarnation of a record's lazy sync-text birth (`entity_doc::sync`,
/// FIX 11795): every machine's lazy birth of one row is one document. Parts:
/// the record's id.
pub const SYNC_TEXT_BIRTH_INCARNATION: &[u8] = b"oneiron.sync-text.birth-incarnation.v1";

/// A turn or message VAD annotation claim (`affect::vad_annotation_claim_id`,
/// FIX 9554). Parts: the annotated row's entity type, its id.
pub const VAD_ANNOTATION_CLAIM: &[u8] = b"oneiron:vad-annotation-claim:v1";

/// The storage service principal (`ports::storage_service_principal`, FIX
/// 10043): the actor a write no actor made is stamped with. No parts.
pub const STORAGE_SERVICE_PRINCIPAL: &[u8] = b"oneiron:storage-service-principal:v1";

/// A channel-identity autonomy handle (`channel_identity_autonomy::codec::address`,
/// FIX 9675): a read or action envelope, a read or action grant, an autonomy
/// mode, a graduation scope or evidence row, a space-posting envelope. Parts:
/// the row kind, the MessagePack bytes of the row's value.
pub const CHANNEL_IDENTITY_AUTONOMY: &[u8] = b"oneiron/channel-identity-autonomy/v1";

/// The source-bearing ASSET of one pack source (`skill_hub::pack_catalog::codec`,
/// FIX 10125). Parts: the source's canonical tree content hash (32 bytes).
pub const PACK_SOURCE_ASSET: &[u8] = b"oneiron.pack-source.asset.v1\0";

/// The filed wording of one commitment reminder (`commitment_wake::reminder_wording`,
/// FIX 12000). Parts: the reminder's content ref.
pub const COMMITMENT_REMINDER_WORDING_BLOB: &[u8] = b"oneiron:commitment-reminder-wording:v1:";

/// The target of an owner's origin cut act (`authority::origin_cut_target`,
/// FIX 15740). Parts: the repository's 32-byte portable id.
pub const ORIGIN_CUT_TARGET: &[u8] = b"oneiron/origin-cut-target/v1";
/// The target of the owner's naming of a device key's successor (FIX 11135):
/// derived from the predecessor's client id and device key.
pub const DEVICE_SUCCESSION_TARGET: &[u8] = b"oneiron/device-succession-target/v1";
/// One bounded part of an identity-topology decision too large for one record
/// (`identity_topology::operation_parts`, FIX 10188). Parts: the decision's
/// manifest id, the part index as u32 big-endian.
pub const IDENTITY_TOPOLOGY_OPERATION_PART: &[u8] = b"oneiron/identity-topology/operation-part/v1";

/// A lexical query hint CLAIM (`claim::lexical_query_hint_claim_id`, FIX 9597).
/// Parts: the target claim (16 bytes), the normalized query (UTF-8).
pub const LEXICAL_QUERY_HINT: &[u8] = b"oneiron.lexical-query-hint.v1";

/// The window identity of one executor step a compaction reads
/// (`engine_executor::compaction::step_message_id`, FIX 9838). Parts: the run,
/// the step (u64 big-endian).
pub const EXECUTOR_COMPACTION_STEP: &[u8] = b"oneiron:executor-compaction-step:v1";

/// The request identity of one executor fold's pass
/// (`engine_executor::compaction::fold_request_id`, FIX 9838). Parts: the run,
/// the fold (u64 big-endian).
pub const EXECUTOR_FOLD_REQUEST: &[u8] = b"oneiron:executor-fold-request:v1";

/// An executor continuation checkpoint (`engine_executor::continuation`,
/// `ExecutorCheckpointRef::id`, FIX 9838). Parts: the source run, the step
/// (u64 little-endian).
pub const EXECUTOR_CONTINUATION_CHECKPOINT: &[u8] = b"oneiron:executor-continuation-checkpoint:v1";

/// Every derived-id domain, one entry per constant above.
#[cfg(test)]
pub(crate) const ALL: [&[u8]; 67] = [
    PERSON_SUBSTRATE_FACET,
    KEY_VALUE,
    BOOTSTRAP_SKILL,
    SUPERSESSION_COMPANION,
    CODE_SYMBOL_ENTITY,
    DREAMER_CLAIM,
    PROJECT_HOME_ROOM,
    COMM_PROJECTED_CLAIM,
    CONNECTOR_ACTOR,
    EMBEDDED_OWNER_ACTOR,
    AGENT_PRINCIPAL,
    COMMITMENT_PROJECTION_ACTOR,
    COMMITMENT_INSTANCE,
    LINKEDIN_ENTITY,
    LINKEDIN_CLAIM,
    CALENDAR_SERIES_EXCEPTION,
    CALENDAR_ICS_FEED_EXCEPTION,
    CALENDAR_ICS_IMPORT_ACTOR,
    CONVERSATION_MIRROR_ACTOR,
    CALENDAR_ICS_FEED_BLOB,
    SURFACE_PROVIDER_EVENT_BLOB,
    SURFACE_PROVIDER_INBOUND_ACTOR,
    CONNECTOR_REPLY_BODY_BLOB,
    CAMPAIGN_STEP_BODY_BLOB,
    TASK_ASK_ORIGIN,
    TASK_ASK_INTENT,
    TASK_ASK_MEMBER,
    TASK_ASK_ANSWER,
    TASK_ASK_SETTLEMENT,
    TASK_ASK_SOFT_CONFIRM,
    TASK_ASK_GUEST_GRANT,
    TASK_ASK_FORWARD_INTENT,
    TASK_ASK_FORWARD_RESULT,
    TASK_POST,
    TASK_SETTLE,
    COMM_CONNECTOR_SEND_EVENT,
    OUTBOUND_RECEIPT_RECORD,
    FIRST_PARTY_SKILL_HUB,
    CLAIM_CLASS_DESCRIPTOR,
    EMBEDDING_SETUP,
    BUILTIN_CONNECTOR_PACK_HUB,
    HISTORY_CONVERSATION,
    HISTORY_TURN,
    HISTORY_MESSAGE,
    MAIL_CONVERSATION,
    MAIL_TURN,
    MAIL_MESSAGE,
    MAIL_ATTACHMENT,
    MAIL_REPLY_DRAFT,
    MAIL_CALENDAR_EVENT,
    MAIL_CALENDAR_SOURCE_BLOB,
    IMPORTED_NOTE,
    PROJECT_REVISION,
    DECISION_QUESTION,
    DECISION_HOST_RULE,
    COORDINATION_PATTERN,
    SIDE_ROW_MASK,
    GLOBAL_SETTING_SUBJECT,
    TASK_SUBPROJECT,
    AGENT_PACK_TRAVEL,
    CONNECT_GUEST_ACTOR,
    FOREIGN_WORLD,
    ASSET_BODY_FILE,
    ASSET_BODY_HELD,
    REMOVAL_ARCHIVE_OWNER,
    REPO_SECRET_MARK,
    VAD_ANNOTATION_CLAIM,
];
