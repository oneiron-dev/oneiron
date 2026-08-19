//! Static entity-type x [`FieldProfile`] to allowed-field-slice table.

use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::context_pack::FieldProfile;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_EVENT, ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_MACHINE, ENTITY_TYPE_NOTE, ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_SKILL,
    ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TASK, ENTITY_TYPE_TASK_LIST, ENTITY_TYPE_TURN,
};

pub(super) fn fields_for_profile(
    entity_type: u8,
    profile: FieldProfile,
) -> &'static [&'static str] {
    match (entity_type, profile) {
        // CLAIM profiles are prefixes of the pinned on-disk key set (D11) —
        // sourced from `claim::CLAIM_BODY_KEYS` so the read projection can
        // never drift from the storage ABI:
        //   Minimal  = pred val
        //   Standard = pred val conf sal evid
        //   Full     = pred val conf sal evid from to src world rel subj scope
        (ENTITY_TYPE_CLAIM, FieldProfile::Minimal) => crate::claim::CLAIM_FIELDS_MINIMAL,
        (ENTITY_TYPE_CLAIM, FieldProfile::Standard) => crate::claim::CLAIM_FIELDS_STANDARD,
        (ENTITY_TYPE_CLAIM, FieldProfile::Full) => crate::claim::CLAIM_FIELDS_FULL,

        (ENTITY_TYPE_TURN, FieldProfile::Minimal) => &["txt"],
        (ENTITY_TYPE_TURN, FieldProfile::Standard) => &["txt", "spkr", "at"],
        (ENTITY_TYPE_TURN, FieldProfile::Full) => &["txt", "spkr", "at", "sess"],

        (ENTITY_TYPE_SUMMARY, FieldProfile::Minimal) => &["txt"],
        (ENTITY_TYPE_SUMMARY, FieldProfile::Standard) => &["txt", "lvl", "at"],
        (ENTITY_TYPE_SUMMARY, FieldProfile::Full) => &["txt", "lvl", "at", "src"],

        (ENTITY_TYPE_EVENT, FieldProfile::Minimal) => &["name"],
        (ENTITY_TYPE_EVENT, FieldProfile::Standard) => &["name", "at", "ppl"],
        (ENTITY_TYPE_EVENT, FieldProfile::Full) => &["name", "at", "ppl", "place", "desc"],

        (ENTITY_TYPE_PERSON, FieldProfile::Minimal) => &["name"],
        (ENTITY_TYPE_PERSON, FieldProfile::Standard) => &["name"],
        (ENTITY_TYPE_PERSON, FieldProfile::Full) => &["name", "role", "rel"],

        (ENTITY_TYPE_SKILL, FieldProfile::Minimal) => &["skillId"],
        (ENTITY_TYPE_SKILL, FieldProfile::Standard) => &["skillId", "desc", "approvalStatus"],
        (ENTITY_TYPE_SKILL, FieldProfile::Full) => &crate::skill::SKILL_RECORD_BODY_KEYS,

        // AGENT_DEF mirrors SKILL: identity-only Minimal, identity + summary in
        // Standard, and the full pinned body only at Full — the 16 KiB
        // `instructions` prompt must never surface in Minimal/Standard packs.
        (ENTITY_TYPE_AGENT_DEF, FieldProfile::Minimal) => &["agentId"],
        (ENTITY_TYPE_AGENT_DEF, FieldProfile::Standard) => &["agentId", "desc", "approvalStatus"],
        (ENTITY_TYPE_AGENT_DEF, FieldProfile::Full) => &crate::agent_def::AGENT_DEF_BODY_KEYS,

        // TaskList (project container)
        (ENTITY_TYPE_TASK_LIST, FieldProfile::Minimal) => &["name"],
        (ENTITY_TYPE_TASK_LIST, FieldProfile::Standard) => &["name", "goal", "status"],
        (ENTITY_TYPE_TASK_LIST, FieldProfile::Full) => {
            &["name", "goal", "status", "icon", "color", "repoUrl"]
        }

        // Task (universal work unit)
        (ENTITY_TYPE_TASK, FieldProfile::Minimal) => &["title", "role"],
        (ENTITY_TYPE_TASK, FieldProfile::Standard) => {
            &["title", "role", "status", "priority", "dueDate"]
        }
        (ENTITY_TYPE_TASK, FieldProfile::Full) => &[
            "title",
            "role",
            "status",
            "priority",
            "dueDate",
            "frequency",
            "frequencyDetail",
            "currentStreak",
            "longestStreak",
            "parentId",
            "listId",
            "position",
        ],

        // Machine: schema-reserved, no fields yet. Explicit empty arms so
        // future field additions don't silently fall through to alphabetical order.
        (ENTITY_TYPE_MACHINE, _) => &[],

        // NOTE (ARCH-0032 take): Minimal carries the attribution pair a
        // renderer needs to label the row "{actor} take" and nothing else —
        // `markdown` is unbounded prose and only earns its tokens once the
        // profile is already paying for body text.
        (ENTITY_TYPE_NOTE, FieldProfile::Minimal) => &["kind", "author_ref"],
        (ENTITY_TYPE_NOTE, FieldProfile::Standard | FieldProfile::Full) => {
            &["kind", "author_ref", "markdown"]
        }

        (ENTITY_TYPE_FEDERATION_GRANT, FieldProfile::Minimal) => {
            crate::federation::FEDERATION_GRANT_FIELDS_MINIMAL
        }
        (ENTITY_TYPE_FEDERATION_GRANT, FieldProfile::Standard) => {
            crate::federation::FEDERATION_GRANT_FIELDS_STANDARD
        }
        (ENTITY_TYPE_FEDERATION_GRANT, FieldProfile::Full) => {
            crate::federation::FEDERATION_GRANT_FIELDS_FULL
        }
        (ENTITY_TYPE_ACCESS_GRANT, FieldProfile::Minimal) => {
            crate::access_grant::ACCESS_GRANT_FIELDS_MINIMAL
        }
        (ENTITY_TYPE_ACCESS_GRANT, FieldProfile::Standard) => {
            crate::access_grant::ACCESS_GRANT_FIELDS_STANDARD
        }
        (ENTITY_TYPE_ACCESS_GRANT, FieldProfile::Full) => {
            crate::access_grant::ACCESS_GRANT_FIELDS_FULL
        }
        (ENTITY_TYPE_COUNTERPARTY_CONTACT, FieldProfile::Minimal) => {
            crate::counterparty_contact::COUNTERPARTY_CONTACT_FIELDS_MINIMAL
        }
        (ENTITY_TYPE_COUNTERPARTY_CONTACT, FieldProfile::Standard) => {
            crate::counterparty_contact::COUNTERPARTY_CONTACT_FIELDS_STANDARD
        }
        (ENTITY_TYPE_COUNTERPARTY_CONTACT, FieldProfile::Full) => {
            crate::counterparty_contact::COUNTERPARTY_CONTACT_FIELDS_FULL
        }
        (ENTITY_TYPE_OUTBOUND_GRANT, FieldProfile::Minimal) => {
            crate::outbound_grant::OUTBOUND_GRANT_FIELDS_MINIMAL
        }
        (ENTITY_TYPE_OUTBOUND_GRANT, FieldProfile::Standard) => {
            crate::outbound_grant::OUTBOUND_GRANT_FIELDS_STANDARD
        }
        (ENTITY_TYPE_OUTBOUND_GRANT, FieldProfile::Full) => {
            crate::outbound_grant::OUTBOUND_GRANT_FIELDS_FULL
        }
        (ENTITY_TYPE_PSYCH_PROFILE, FieldProfile::Minimal) => {
            crate::psych_profile::PSYCH_PROFILE_FIELDS_MINIMAL
        }
        (ENTITY_TYPE_PSYCH_PROFILE, FieldProfile::Standard) => {
            crate::psych_profile::PSYCH_PROFILE_FIELDS_STANDARD
        }
        (ENTITY_TYPE_PSYCH_PROFILE, FieldProfile::Full) => {
            crate::psych_profile::PSYCH_PROFILE_FIELDS_FULL
        }
        (ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, FieldProfile::Minimal) => {
            crate::persona_snapshot::PERSONA_SNAPSHOT_EXPORT_FIELDS_MINIMAL
        }
        (ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, FieldProfile::Standard) => {
            crate::persona_snapshot::PERSONA_SNAPSHOT_EXPORT_FIELDS_STANDARD
        }
        (ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, FieldProfile::Full) => {
            crate::persona_snapshot::PERSONA_SNAPSHOT_EXPORT_FIELDS_FULL
        }
        (ENTITY_TYPE_COMPANION_REGISTER, FieldProfile::Minimal) => &["kind", "scope", "subject"],
        (ENTITY_TYPE_COMPANION_REGISTER, FieldProfile::Standard) => {
            &["kind", "scope", "subject", "lifecycle", "export"]
        }
        (ENTITY_TYPE_COMPANION_REGISTER, FieldProfile::Full) => &[
            "schema_version",
            "kind",
            "scope",
            "subject",
            "lifecycle",
            "export",
            "lifecycle_events",
            "provenance",
        ],

        _ => &[],
    }
}
