//! Static entity-type to section-label lookup used by every writer.

use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT,
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_COUNTERPARTY_CONTACT,
    ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_MACHINE,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTE, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_ORG,
    ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSON, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
    ENTITY_TYPE_PLACE, ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_RELATIONSHIP, ENTITY_TYPE_SESSION,
    ENTITY_TYPE_SKILL, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TASK, ENTITY_TYPE_TASK_LIST,
    ENTITY_TYPE_TURN, ENTITY_TYPE_WORLD,
};

use super::types::GroupKey;

#[derive(Clone, Copy)]
pub(super) struct GroupLabels {
    pub(super) key: &'static str,
    pub(super) name: &'static str,
    pub(super) title: &'static str,
}

pub(super) const OTHER_GROUP_LABELS: GroupLabels = GroupLabels {
    key: "other",
    name: "OTHER",
    title: "Other",
};

pub(super) fn group_labels(key: GroupKey) -> GroupLabels {
    match key {
        GroupKey::Kind(entity_type) => {
            known_group_labels(entity_type).unwrap_or(OTHER_GROUP_LABELS)
        }
        GroupKey::Other => OTHER_GROUP_LABELS,
    }
}

pub(super) fn known_group_labels(entity_type: u8) -> Option<GroupLabels> {
    match entity_type {
        ENTITY_TYPE_CLAIM => Some(GroupLabels {
            key: "claims",
            name: "CLAIMS",
            title: "Claims",
        }),
        ENTITY_TYPE_TURN => Some(GroupLabels {
            key: "turns",
            name: "TURNS",
            title: "Turns",
        }),
        ENTITY_TYPE_SESSION => Some(GroupLabels {
            key: "sessions",
            name: "SESSIONS",
            title: "Sessions",
        }),
        ENTITY_TYPE_MESSAGE => Some(GroupLabels {
            key: "messages",
            name: "MESSAGES",
            title: "Messages",
        }),
        ENTITY_TYPE_PERSON => Some(GroupLabels {
            key: "persons",
            name: "PERSONS",
            title: "Persons",
        }),
        ENTITY_TYPE_RELATIONSHIP => Some(GroupLabels {
            key: "relationships",
            name: "RELATIONSHIPS",
            title: "Relationships",
        }),
        ENTITY_TYPE_EVENT => Some(GroupLabels {
            key: "events",
            name: "EVENTS",
            title: "Events",
        }),
        ENTITY_TYPE_SKILL => Some(GroupLabels {
            key: "skills",
            name: "SKILLS",
            title: "Skills",
        }),
        ENTITY_TYPE_AGENT_DEF => Some(GroupLabels {
            key: "agent_definitions",
            name: "AGENT_DEFINITIONS",
            title: "Agent Definitions",
        }),
        ENTITY_TYPE_SUMMARY => Some(GroupLabels {
            key: "summaries",
            name: "SUMMARIES",
            title: "Summaries",
        }),
        ENTITY_TYPE_PLACE => Some(GroupLabels {
            key: "places",
            name: "PLACES",
            title: "Places",
        }),
        ENTITY_TYPE_ASSET_TEXT => Some(GroupLabels {
            key: "texts",
            name: "TEXTS",
            title: "Texts",
        }),
        ENTITY_TYPE_CONVERSATION => Some(GroupLabels {
            key: "conversations",
            name: "CONVERSATIONS",
            title: "Conversations",
        }),
        ENTITY_TYPE_ORG => Some(GroupLabels {
            key: "organizations",
            name: "ORGANIZATIONS",
            title: "Organizations",
        }),
        ENTITY_TYPE_FACET => Some(GroupLabels {
            key: "facets",
            name: "FACETS",
            title: "Facets",
        }),
        ENTITY_TYPE_WORLD => Some(GroupLabels {
            key: "worlds",
            name: "WORLDS",
            title: "Worlds",
        }),
        ENTITY_TYPE_ASSET => Some(GroupLabels {
            key: "assets",
            name: "ASSETS",
            title: "Assets",
        }),
        ENTITY_TYPE_NOTIFICATION => Some(GroupLabels {
            key: "notifications",
            name: "NOTIFICATIONS",
            title: "Notifications",
        }),
        // Productivity (80-99)
        ENTITY_TYPE_TASK_LIST => Some(GroupLabels {
            key: "task_lists",
            name: "TASK_LISTS",
            title: "Task Lists",
        }),
        ENTITY_TYPE_TASK => Some(GroupLabels {
            key: "tasks",
            name: "TASKS",
            title: "Tasks",
        }),
        ENTITY_TYPE_MACHINE => Some(GroupLabels {
            key: "machines",
            name: "MACHINES",
            title: "Machines",
        }),
        // ARCH-0032 takes get their OWN group. Folding them into CLAIMS would
        // reprint an actor's opinion as if it were a neutral claim — the exact
        // conflation `author_take` exists to prevent.
        ENTITY_TYPE_NOTE => Some(GroupLabels {
            key: "notes",
            name: "NOTES",
            title: "Notes",
        }),
        ENTITY_TYPE_FEDERATION_GRANT => Some(GroupLabels {
            key: "federation_grants",
            name: "FEDERATION_GRANTS",
            title: "Federation Grants",
        }),
        ENTITY_TYPE_ACCESS_GRANT => Some(GroupLabels {
            key: "access_grants",
            name: "ACCESS_GRANTS",
            title: "Access Grants",
        }),
        ENTITY_TYPE_COUNTERPARTY_CONTACT => Some(GroupLabels {
            key: "counterparty_contacts",
            name: "COUNTERPARTY_CONTACTS",
            title: "Counterparty Contacts",
        }),
        ENTITY_TYPE_OUTBOUND_GRANT => Some(GroupLabels {
            key: "outbound_grants",
            name: "OUTBOUND_GRANTS",
            title: "Outbound Grants",
        }),
        ENTITY_TYPE_COMPANION_REGISTER => Some(GroupLabels {
            key: "companion_records",
            name: "COMPANION_RECORDS",
            title: "Companion Records",
        }),
        ENTITY_TYPE_PSYCH_PROFILE => Some(GroupLabels {
            key: "psych_profiles",
            name: "PSYCH_PROFILES",
            title: "Psych Profiles",
        }),
        ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT => Some(GroupLabels {
            key: "persona_snapshot_exports",
            name: "PERSONA_SNAPSHOT_EXPORTS",
            title: "Persona Snapshot Exports",
        }),
        _ => None,
    }
}

pub(super) fn group_key(key: GroupKey) -> &'static str {
    group_labels(key).key
}

pub(super) fn group_name(key: GroupKey) -> &'static str {
    group_labels(key).name
}

pub(super) fn group_title(key: GroupKey) -> &'static str {
    group_labels(key).title
}
