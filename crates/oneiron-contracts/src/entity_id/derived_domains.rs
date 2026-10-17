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

/// A project's home room (`workspace_roster::project`). Parts: project.
pub const PROJECT_HOME_ROOM: &[u8] = b"project.home_room.v1/";

/// A projector-created `comm.*` claim (`comm`). Parts: source event, predicate,
/// conflict key.
pub const COMM_PROJECTED_CLAIM: &[u8] = b"oneiron.comm.projected_claim.v1\0";

/// The MACHINE assignee of one connector class (`outbound::connector_actor_id`).
/// Parts: normalized connector class.
pub const CONNECTOR_ACTOR: &[u8] = b"oneiron.connector_actor.v0\0";

/// The embedded default owner actor (`vault::embedded_owner_actor_id`, ONE-1441
/// WIRE-P1). No parts.
pub const EMBEDDED_OWNER_ACTOR: &[u8] = b"oneiron 2026-08 embedded-owner-actor v1";

/// A named agent principal the owner mints a credential for
/// (`oneiron token agent`). Parts: agent name.
pub const AGENT_PRINCIPAL: &[u8] = b"oneiron/agent-principal/v1";

/// The System actor that owns engine projection writes
/// (`commitment_schedule::commitment_projection_actor`). No parts.
pub const COMMITMENT_PROJECTION_ACTOR: &[u8] = b"oneiron.commitment.projection.actor.v1\0";

/// One occurrence of one commitment series
/// (`commitment_schedule::commitment_instance_id`). Parts: series, due-at, window
/// start, window end (u64 big-endian each), ordinal (u32 big-endian).
pub const COMMITMENT_INSTANCE: &[u8] = b"oneiron.commitment.instance.v1\0";

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

/// The BLOB artifact holding one verified provider event's body
/// (`surface_event::provider_payload`). Parts: channel, provider event id.
pub const SURFACE_PROVIDER_EVENT_BLOB: &[u8] = b"oneiron:surface-provider-event-blob:v1:";

/// The write actor provider event bodies are archived under
/// (`surface_event::provider_payload`). No parts.
pub const SURFACE_PROVIDER_INBOUND_ACTOR: &[u8] = b"oneiron:surface-provider-inbound-actor:v1";

/// The BLOB artifact holding one agent's reply body to one connector event
/// (`outbound::reply_content`). Parts: event id, agent, reply ref.
pub const CONNECTOR_REPLY_BODY_BLOB: &[u8] = b"oneiron:connector-reply-body-blob:v1:";

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

/// A NOTE imported from a folder of markdown notes (`note::import`). Parts:
/// folder, the file's path under it.
pub const IMPORTED_NOTE: &[u8] = b"oneiron.ingest.notes.note.v1";

/// A project revision companion (`workspace_roster::project::revision`).
/// Parts: the revision's 32-byte logical hash.
pub const PROJECT_REVISION: &[u8] = b"oneiron/project-revision-id/v1/";

/// A typed decision question an engine caller asks (`self_heal::tiered`). Parts: the
/// question's registered name, then the caller's instance parts.
pub const DECISION_QUESTION: &[u8] = b"oneiron.decision.question.v1";

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

/// Every derived-id domain, one entry per constant above.
#[cfg(test)]
pub(crate) const ALL: [&[u8]; 47] = [
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
    TASK_ASK_ORIGIN,
    TASK_ASK_INTENT,
    TASK_ASK_MEMBER,
    TASK_ASK_ANSWER,
    TASK_ASK_SETTLEMENT,
    TASK_ASK_SOFT_CONFIRM,
    TASK_ASK_GUEST_GRANT,
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
    IMPORTED_NOTE,
    PROJECT_REVISION,
    DECISION_QUESTION,
    COORDINATION_PATTERN,
    SIDE_ROW_MASK,
    GLOBAL_SETTING_SUBJECT,
];
