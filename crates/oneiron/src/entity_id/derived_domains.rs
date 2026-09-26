//! Every domain string [`EntityId::derive`](super::EntityId::derive) is called with.
//!
//! One constant per derivation site, its bytes exactly as the site spelled them
//! before the one derived-id rule. The bytes are the id's context string: changing
//! one changes every id already derived under it.

/// The `substrate` FACET of a PERSON (`claim::substrate_facet_id`). Parts: person.
pub(crate) const PERSON_SUBSTRATE_FACET: &[u8] = b"oneiron/person-substrate-facet/v1";

/// A keyed-value revision claim (`memory::key_value`). Parts: actor, actor class,
/// JSON address, request id.
pub(crate) const KEY_VALUE: &[u8] = b"oneiron.key_value.v1";

/// A built-in bootstrap skill (`skill_hub::bootstrap`). Parts: skill name.
pub(crate) const BOOTSTRAP_SKILL: &[u8] = b"oneiron/bootstrap/v1/";

/// A supersession companion claim (`claim::supersession_provenance`). Parts: new
/// head, old head, predicate.
pub(crate) const SUPERSESSION_COMPANION: &[u8] = b"oneiron.supersession.companion.v1";

/// A code-symbol entity (`code_symbol::code_symbol_entity_id`). Parts: repo identity
/// key, path, name, kind, fingerprint.
pub(crate) const CODE_SYMBOL_ENTITY: &[u8] = b"oneiron:code-symbol-entity:v1";

/// A consolidation claim (`dreamer_consolidation`). Parts: attempt, subject,
/// predicate, canonical value, then world, facet, relationship and topic, each
/// empty when absent and `0x01` followed by its bytes when present.
pub(crate) const DREAMER_CLAIM: &[u8] = b"oneiron:dreamer-claim-id:v1";

/// A project's home room (`workspace_roster::project`). Parts: project.
pub(crate) const PROJECT_HOME_ROOM: &[u8] = b"project.home_room.v1/";

/// A projector-created `comm.*` claim (`comm`). Parts: source event, predicate,
/// conflict key.
pub(crate) const COMM_PROJECTED_CLAIM: &[u8] = b"oneiron.comm.projected_claim.v1\0";

/// The MACHINE assignee of one connector class (`outbound::connector_actor_id`).
/// Parts: normalized connector class.
pub(crate) const CONNECTOR_ACTOR: &[u8] = b"oneiron.connector_actor.v0\0";

/// The embedded default owner actor (`vault::embedded_owner_actor_id`, ONE-1441
/// WIRE-P1). No parts.
pub(crate) const EMBEDDED_OWNER_ACTOR: &[u8] = b"oneiron 2026-08 embedded-owner-actor v1";

/// The System actor that owns engine projection writes
/// (`commitment_schedule::commitment_projection_actor`). No parts.
pub(crate) const COMMITMENT_PROJECTION_ACTOR: &[u8] = b"oneiron.commitment.projection.actor.v1\0";

/// One occurrence of one commitment series
/// (`commitment_schedule::commitment_instance_id`). Parts: series, due-at, window
/// start, window end (u64 big-endian each), ordinal (u32 big-endian).
pub(crate) const COMMITMENT_INSTANCE: &[u8] = b"oneiron.commitment.instance.v1\0";

/// A person or company bound to an external lead source (`linkedin_lead_preload`).
/// Parts: source ref.
pub(crate) const LINKEDIN_ENTITY: &[u8] = b"oneiron.linkedin.entity.v1";

/// An imported fact about a lead-source entity (`linkedin_lead_preload`). Parts:
/// source ref, predicate.
pub(crate) const LINKEDIN_CLAIM: &[u8] = b"oneiron.linkedin.claim.v1";

/// A series-exception claim (`calendar::ingest::admission`). Parts: master event,
/// original start (u64 big-endian).
pub(crate) const CALENDAR_SERIES_EXCEPTION: &[u8] = b"oneiron:calendar-series-exception:v1";

/// The inbox-exception ref of one ICS feed (`calendar::ingest::poll`). Parts: feed
/// identity.
pub(crate) const CALENDAR_ICS_FEED_EXCEPTION: &[u8] = b"oneiron:calendar-ics-feed-exception:v1:";

/// The ICS import write actor (`calendar::ics_import_actor_id`). No parts.
pub(crate) const CALENDAR_ICS_IMPORT_ACTOR: &[u8] = b"oneiron:calendar-ics-import-actor:v1";

/// The raw-feed BLOB artifact of one ICS feed (`calendar::ingest::fetch`). Parts:
/// feed dedupe key.
pub(crate) const CALENDAR_ICS_FEED_BLOB: &[u8] = b"oneiron:calendar-ics-feed-blob:v1:";

/// An asking actor's origin (`task_verb::ask_record`). Parts: vault ask origin, actor.
pub(crate) const TASK_ASK_ORIGIN: &[u8] = b"oneiron.tasks.ask.origin.v1";

/// An ask group (`task_verb::ask_record`). Parts: actor origin, intent key.
pub(crate) const TASK_ASK_INTENT: &[u8] = b"oneiron.tasks.ask.intent.v1";

/// An ask group member (`task_verb::ask_record`). Parts: group, actor.
pub(crate) const TASK_ASK_MEMBER: &[u8] = b"oneiron.tasks.ask.member.v1";

/// An ask answer (`task_verb::ask_record`). Parts: group, encoded answer.
pub(crate) const TASK_ASK_ANSWER: &[u8] = b"oneiron.tasks.ask.answer.v1";

/// An ask group's settlement receipt (`task_verb::ask_settlement`). Parts: group,
/// `receipt`.
pub(crate) const TASK_ASK_SETTLEMENT: &[u8] = b"oneiron.tasks.ask.settlement";

/// Every derived-id domain, one entry per constant above.
#[cfg(test)]
pub(crate) const ALL: [&[u8]; 23] = [
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
    COMMITMENT_PROJECTION_ACTOR,
    COMMITMENT_INSTANCE,
    LINKEDIN_ENTITY,
    LINKEDIN_CLAIM,
    CALENDAR_SERIES_EXCEPTION,
    CALENDAR_ICS_FEED_EXCEPTION,
    CALENDAR_ICS_IMPORT_ACTOR,
    CALENDAR_ICS_FEED_BLOB,
    TASK_ASK_ORIGIN,
    TASK_ASK_INTENT,
    TASK_ASK_MEMBER,
    TASK_ASK_ANSWER,
    TASK_ASK_SETTLEMENT,
];
