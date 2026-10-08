//! What a restore over a live vault does with each canonical row: one table,
//! deny by default.
//!
//! ARCH-0038 (RD-20, amended 2026-09-26): a historical restore gives content as
//! it stood and never resets live authority, freshness pins or destroyed
//! identity keys. Every canonical side-table family (the declarations in
//! `side_table::decls`, one part file per declaration file below) and every
//! entity kind has exactly one [`Class`] here. A row the table does not name,
//! by an undeclared prefix or an unregistered kind, is refused if it differs
//! from the live vault's, never restored silently. `every_canonical_family_and_kind_has_one_class`
//! fails when a declaration or kind is added without a class.

mod sync_state;
mod vault_meta_a_c;
mod vault_meta_d_l;
mod vault_meta_m_r;
mod vault_meta_s_z;

use crate::batch::EntityMetadataHeader;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT,
    ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CHANNEL_IDENTITY,
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR, ENTITY_TYPE_CODE_ARTIFACT,
    ENTITY_TYPE_CODE_SYMBOL, ENTITY_TYPE_COMM_RECORD, ENTITY_TYPE_CONNECTOR_KEY,
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_DIAGNOSTIC,
    ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT,
    ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, ENTITY_TYPE_MACHINE, ENTITY_TYPE_MESSAGE,
    ENTITY_TYPE_MODEL, ENTITY_TYPE_NOTE, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_ORG,
    ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSON, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
    ENTITY_TYPE_PLACE, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_PSYCH_PROFILE,
    ENTITY_TYPE_RECEIPT_RECORD, ENTITY_TYPE_REDACTION_AUDIT, ENTITY_TYPE_RELATIONSHIP,
    ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_SESSION, ENTITY_TYPE_SKILL,
    ENTITY_TYPE_SKILL_CONTENT_ANCHOR, ENTITY_TYPE_SKILL_HUB, ENTITY_TYPE_SUMMARY,
    ENTITY_TYPE_SUSPICIOUS_WAKE, ENTITY_TYPE_TASK, ENTITY_TYPE_TASK_LIST, ENTITY_TYPE_TURN,
    ENTITY_TYPE_WORKFLOW, ENTITY_TYPE_WORLD,
};
use crate::side_table::{SideDb, SideTableDecl};

/// What a restore over a live vault does with one family's rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    /// Historical content: the image's rows come back.
    Content,
    /// Authority, consent, policy, access, credential or erasure state, and
    /// the record of acts that already left the vault (a send, an export, a
    /// materialized secret), that stands on its own: the live vault's rows
    /// replace the image's, and a row the live vault no longer holds stays
    /// absent.
    Live,
    /// Authority entangled with content, which cannot be carried without it:
    /// the restore refuses, before creating anything, when the image's rows
    /// differ from the live vault's. `what` names it in the refusal.
    Refuse { what: &'static str, scope: Scope },
}

/// Which rows of a refused family are compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scope {
    /// Every row.
    Family,
    /// Rows keyed by an entity the image holds (the key leads with its id16).
    /// The rows of an entity the image does not hold leave with it, as
    /// content: a room or document made after the checkpoint does not block
    /// restoring it, and any change to one the checkpoint holds does.
    ImageEntities,
    /// Entity bodies that are content but carry authority: only the
    /// authority the [`Projection`] names is compared.
    Authority(Projection),
}

/// The authority a content body carries. It is compared for each entity
/// both vaults hold, the live vault not having deleted it; one only the image
/// holds is content unless its absence is itself authority, as noted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Projection {
    /// A room's members, roles and effective history default.
    Room,
    /// A relationship's participants, who read its scoped records.
    Relationship,
    /// A skill's approval, whether the owner quarantined it, and its
    /// governance tier.
    Skill,
    /// What bounds an agent: approval, lifecycle, its on switch, ceiling,
    /// scope, connectors, tools, skills, model, memory and waking.
    Agent,
    /// Whether a counterparty contact is live, and the party's opt-out and
    /// promotional consent.
    Contact,
    /// A NOTE's kind, which decides who reads it, and its author. A body
    /// that does not decode is content.
    Note,
    /// A claim's relationship scope and privacy, and the whole of a claim in
    /// an [`AUTHORITY_CLAIMS`] family. Such a claim only one vault holds
    /// counts as changed. Skill scan verdicts are compared as the activation
    /// posture each skill's bytes take from them, not claim by claim, so a
    /// refreshed scan with the same result changes nothing.
    Claim,
    /// A project's authority (parents, claims scope, slice, depth, leader,
    /// board), roster, role and budget.
    Project,
    /// A TASK authority fact (owner, cancellation, acknowledgement, human
    /// assignment), one added since the image to a task the image holds
    /// counting as changed; or a task's owner, assignee and ask class, which
    /// authorize the asks bound to it. The rest of a TASK body is content.
    Task,
    /// Every outbound grant, without the stamp each use writes. One only one
    /// side holds counts as changed.
    OutboundGrant,
}

const CONTENT: Class = Class::Content;
const LIVE: Class = Class::Live;

const fn refuse(what: &'static str) -> Class {
    Class::Refuse {
        what,
        scope: Scope::Family,
    }
}

const POLICY_MANIFESTS: Class = refuse("policy manifests");
const FEDERATION_GRANTS: Class = refuse("federation grants");
const ACCESS_GRANTS: Class = refuse("access grants");
const SECRET_CUSTODY: Class = refuse("secret custody");
const CONNECTOR_KEYS: Class = refuse("connector keys");
const CHANNEL_IDENTITIES: Class = refuse("channel identities");
const OUTBOUND_GRANTS: Class = Class::Refuse {
    what: "outbound grants",
    scope: Scope::Authority(Projection::OutboundGrant),
};
const MACHINE_IDENTITIES: Class = refuse("machine identities");
const SKILL_HUB_CONFIGURATION: Class = refuse("skill hub configuration");
const STANDING_GRANTS: Class = refuse("standing consent grants");
const STANDING_BLOCKS: Class = refuse("standing blocks");
const DISCLOSURE_SCOPES: Class = refuse("disclosure scopes");
const ORG_ADMIN_GRANTS: Class = refuse("org admin grants");
const SHARED_VAULT_MEMBERSHIP: Class = refuse("shared vault membership");
const ESIGN_CAPABILITIES: Class = refuse("e-sign capabilities");
const SHARE_ADMISSIONS: Class = refuse("share admissions");
const PUBLIC_BOOKING_PAGES: Class = refuse("public booking pages");
const PUBLISHED_ARTIFACTS: Class = refuse("published artifacts");
const ORIGIN_AUTHORITY: Class = refuse("repository origin authority");
const ROOMS: Class = Class::Refuse {
    what: "room roles and membership",
    scope: Scope::ImageEntities,
};
const ROOM_BODIES: Class = Class::Refuse {
    what: "room roles and membership",
    scope: Scope::Authority(Projection::Room),
};
const SKILLS: Class = Class::Refuse {
    what: "skill approvals and quarantines",
    scope: Scope::Authority(Projection::Skill),
};
const AGENT_DEFINITIONS: Class = Class::Refuse {
    what: "agent permissions",
    scope: Scope::Authority(Projection::Agent),
};
const RELATIONSHIPS: Class = Class::Refuse {
    what: "relationship participants",
    scope: Scope::Authority(Projection::Relationship),
};
const PROJECTS: Class = Class::Refuse {
    what: "project authority",
    scope: Scope::Authority(Projection::Project),
};
const TASKS: Class = Class::Refuse {
    what: "task authority",
    scope: Scope::Authority(Projection::Task),
};
const CONTACTS: Class = Class::Refuse {
    what: "counterparty contacts and their consents",
    scope: Scope::Authority(Projection::Contact),
};
const NOTES: Class = Class::Refuse {
    what: "note privacy",
    scope: Scope::Authority(Projection::Note),
};
const CLAIMS: Class = Class::Refuse {
    what: "claim privacy",
    scope: Scope::Authority(Projection::Claim),
};

/// Claim families that carry authority, consent, disclosure, or a restriction
/// on who is reached, what is served or what an agent may do: a predicate, or
/// a namespace ending in `.`, with the name a refusal gives it. Each claim of
/// one is compared whole; one only one vault holds counts as changed, so
/// neither a permission withdrawn nor a restriction added since the image is
/// undone. Every other claim is content.
pub(super) const AUTHORITY_CLAIMS: &[(&str, &str)] = &[
    (
        "agent.connector_subscription",
        "agent connector subscriptions",
    ),
    ("agent.resident", "resident agents"),
    ("booking.public_page", "public booking pages"),
    ("booking.submission_quarantine", "booking quarantines"),
    ("campaign.member", "campaign enrollment"),
    ("comm.do_not_contact", "communication consent"),
    ("comm.opt_out", "communication consent"),
    ("comm.send_override", "communication consent"),
    (
        "core.coreference.share_consent",
        "coreference sharing consent",
    ),
    ("core.relationship.person_ref", "relationship membership"),
    ("core.world_access.", "world access"),
    ("crm.compliance.", "compliance evidence"),
    ("delivery_window.", "delivery windows"),
    ("disclosure.", "disclosure"),
    ("federation.admin_ruling", "federation rulings"),
    ("plugin.section_install", "board plugins"),
    ("project.leader_chat", "leader chat rules"),
    ("vault.default_facet", "the default facet"),
];

/// The [`AUTHORITY_CLAIMS`] family `predicate` belongs to, by name.
pub(super) fn authority_claim(predicate: &str) -> Option<&'static str> {
    AUTHORITY_CLAIMS
        .iter()
        .find(|(family, _)| {
            predicate == *family || (family.ends_with('.') && predicate.starts_with(family))
        })
        .map(|(_, name)| *name)
}

/// Kinds a vault registers at run time, by their pack and short-id prefix,
/// the identity their own readers check: the engine registers each of these
/// itself. A registered kind not named here, including one that reuses a
/// prefix under another pack, is refused when it differs.
const RUNTIME_KINDS: &[(&str, &str, Class)] = &[
    (
        crate::workspace_roster::PROJECT_PACK,
        crate::workspace_roster::PROJECT_SHORT_ID_PREFIX,
        PROJECTS,
    ),
    (
        crate::campaign::CRM_PACK_ID,
        crate::saved_query::SAVED_QUERY_SHORT_ID_PREFIX,
        CONTENT,
    ),
    (
        crate::campaign::CRM_PACK_ID,
        crate::campaign::CAMPAIGN_SHORT_ID_PREFIX,
        CONTENT,
    ),
];
const ESIGN_CEREMONIES: Class = Class::Refuse {
    what: "e-sign ceremonies",
    scope: Scope::ImageEntities,
};
const UNCLASSIFIED_ROWS: Class = refuse("rows of an undeclared family");
const UNCLASSIFIED_KINDS: Class = refuse("entities of an unregistered kind");

/// Every entity kind. Most are content; the kinds that hold the authority
/// root, grants, policy, custody or machine identities are live or refused,
/// and a few content kinds have their authority compared.
const ENTITY_KINDS: &[(u8, Class)] = &[
    (ENTITY_TYPE_CLAIM, CLAIMS),
    (ENTITY_TYPE_TURN, CONTENT),
    (ENTITY_TYPE_SESSION, CONTENT),
    // A MESSAGE id stays bound to its first body, and a SUMMARY carries no
    // privacy of its own (a `scope` key makes it a scope summary): neither
    // body can narrow who reads it after the fact.
    (ENTITY_TYPE_MESSAGE, CONTENT),
    (ENTITY_TYPE_CONVERSATION, ROOM_BODIES),
    (ENTITY_TYPE_SUMMARY, CONTENT),
    (ENTITY_TYPE_PERSON, CONTENT),
    (ENTITY_TYPE_RELATIONSHIP, RELATIONSHIPS),
    (ENTITY_TYPE_ORG, CONTENT),
    (ENTITY_TYPE_FACET, CONTENT),
    (ENTITY_TYPE_WORKFLOW, CONTENT),
    (ENTITY_TYPE_EVENT, CONTENT),
    (ENTITY_TYPE_PLACE, CONTENT),
    (ENTITY_TYPE_WORLD, CONTENT),
    (ENTITY_TYPE_ASSET, CONTENT),
    (ENTITY_TYPE_ASSET_TEXT, CONTENT),
    (ENTITY_TYPE_SKILL, SKILLS),
    (ENTITY_TYPE_AGENT_DEF, AGENT_DEFINITIONS),
    (ENTITY_TYPE_NOTIFICATION, CONTENT),
    (ENTITY_TYPE_AUTHORITY_LOG, LIVE),
    (ENTITY_TYPE_POLICY_MANIFEST, POLICY_MANIFESTS),
    (ENTITY_TYPE_FEDERATION_GRANT, FEDERATION_GRANTS),
    (ENTITY_TYPE_ACCESS_GRANT, ACCESS_GRANTS),
    (ENTITY_TYPE_SECRET_CUSTODY, SECRET_CUSTODY),
    (ENTITY_TYPE_REDACTION_AUDIT, CONTENT),
    // Never in an image: the snapshot leaves diagnostics out.
    (ENTITY_TYPE_DIAGNOSTIC, CONTENT),
    (ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT, CONTENT),
    (ENTITY_TYPE_SUSPICIOUS_WAKE, CONTENT),
    (ENTITY_TYPE_CONNECTOR_KEY, CONNECTOR_KEYS),
    (ENTITY_TYPE_CHANNEL_IDENTITY, CHANNEL_IDENTITIES),
    (ENTITY_TYPE_COUNTERPARTY_CONTACT, CONTACTS),
    (ENTITY_TYPE_OUTBOUND_GRANT, OUTBOUND_GRANTS),
    (ENTITY_TYPE_COMM_RECORD, CONTENT),
    (ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT, CONTENT),
    (ENTITY_TYPE_RECEIPT_RECORD, CONTENT),
    (ENTITY_TYPE_MODEL, CONTENT),
    (ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR, CONTENT),
    (ENTITY_TYPE_SKILL_HUB, SKILL_HUB_CONFIGURATION),
    (ENTITY_TYPE_SKILL_CONTENT_ANCHOR, CONTENT),
    (ENTITY_TYPE_PSYCH_PROFILE, CONTENT),
    (ENTITY_TYPE_TASK_LIST, CONTENT),
    (ENTITY_TYPE_TASK, TASKS),
    (ENTITY_TYPE_MACHINE, MACHINE_IDENTITIES),
    (ENTITY_TYPE_CODE_ARTIFACT, CONTENT),
    (ENTITY_TYPE_CODE_SYMBOL, CONTENT),
    (ENTITY_TYPE_BLOB_ARTIFACT, CONTENT),
    (ENTITY_TYPE_NOTE, NOTES),
    (crate::companion::ENTITY_TYPE_COMPANION_REGISTER, CONTENT),
];

/// How each database's canonical rows are classed.
#[derive(Clone, Copy, Debug)]
enum Rows {
    /// By declared family ([`SIDE_TABLES`]).
    ByFamily,
    /// By entity kind ([`ENTITY_KINDS`]).
    ByKind,
    /// One class for the whole database.
    Whole(Class),
    /// No canonical rows: rebuilt after every restore, never in an image.
    Rebuilt,
}

/// Every database a vault opens.
const DATABASES: &[(&str, Rows)] = &[
    ("entities", Rows::ByKind),
    ("vault_meta", Rows::ByFamily),
    ("sync_state", Rows::ByFamily),
    // Presentation ids and graph links of the content they name.
    ("short_ids", Rows::Whole(CONTENT)),
    ("short_ids_reverse", Rows::Whole(CONTENT)),
    ("edges_out", Rows::Whole(CONTENT)),
    ("edges_in", Rows::Whole(CONTENT)),
    // Index compatibility pins of the content the image carries.
    ("hnsw_meta", Rows::Whole(CONTENT)),
    // Durable job intents (unleased at snapshot) and the sync send queue.
    ("job_records", Rows::Whole(CONTENT)),
    ("sync_queue", Rows::Whole(CONTENT)),
    ("type_index", Rows::Rebuilt),
    ("vectors", Rows::Rebuilt),
    ("hnsw_neighbors", Rows::Rebuilt),
    ("text_postings", Rows::Rebuilt),
    ("text_meta", Rows::Rebuilt),
    ("text_forward", Rows::Rebuilt),
    ("text_bm25_field_stats", Rows::Rebuilt),
    ("text_doc_field_lengths", Rows::Rebuilt),
    ("ppr_cache", Rows::Rebuilt),
    ("ppr_cache_deps", Rows::Rebuilt),
    ("temporal_occurred_start", Rows::Rebuilt),
    ("temporal_occurred_end", Rows::Rebuilt),
    ("temporal_learned", Rows::Rebuilt),
    ("temporal_long_intervals", Rows::Rebuilt),
    ("phonetic_index", Rows::Rebuilt),
    ("phonetic_forward", Rows::Rebuilt),
    ("job_ready", Rows::Rebuilt),
    ("job_dedupe", Rows::Rebuilt),
];

/// Every canonical side-table family, one part per declaration file.
static SIDE_TABLES: [&[(&SideTableDecl, Class)]; 5] = [
    sync_state::PART,
    vault_meta_a_c::PART,
    vault_meta_d_l::PART,
    vault_meta_m_r::PART,
    vault_meta_s_z::PART,
];

/// The table as a lookup: the class of any canonical row.
pub(super) struct Classes {
    /// `(prefix, class)` per side-table database, in prefix order. Declared
    /// prefixes are disjoint, so the one that can cover a key is the
    /// greatest prefix not above it.
    vault_meta: Vec<(&'static [u8], Class)>,
    sync_state: Vec<(&'static [u8], Class)>,
    kinds: [Option<Class>; 256],
}

impl Classes {
    /// The table, with the kinds `current` registered at run time.
    pub(super) fn new(current: &crate::Vault) -> Self {
        let mut vault_meta = Vec::new();
        let mut sync_state = Vec::new();
        for (decl, class) in SIDE_TABLES.iter().copied().flatten() {
            match decl.db {
                SideDb::VaultMeta => vault_meta.push((decl.prefix, *class)),
                SideDb::SyncState => sync_state.push((decl.prefix, *class)),
            }
        }
        vault_meta.sort_unstable_by_key(|(prefix, _)| *prefix);
        sync_state.sort_unstable_by_key(|(prefix, _)| *prefix);
        let mut kinds = [None; 256];
        for (kind, class) in ENTITY_KINDS {
            kinds[usize::from(*kind)] = Some(*class);
        }
        for registration in current.structural_kind_registrations() {
            let class = RUNTIME_KINDS
                .iter()
                .find(|(pack, prefix, _)| {
                    registration.pack == *pack && registration.short_id_prefix == *prefix
                })
                .map(|(_, _, class)| *class);
            let slot = &mut kinds[usize::from(registration.type_byte)];
            if slot.is_none() {
                *slot = class;
            }
        }
        Self {
            vault_meta,
            sync_state,
            kinds,
        }
    }

    /// The class of one canonical row of `database`, and the length of the
    /// declared prefix its key starts with (0 outside the side tables).
    pub(super) fn row(&self, database: &str, key: &[u8], value: &[u8]) -> (Class, usize) {
        let rows = DATABASES
            .iter()
            .find(|(name, _)| *name == database)
            .map(|(_, rows)| *rows);
        match rows {
            Some(Rows::ByKind) => (
                EntityMetadataHeader::parse(value)
                    .and_then(|header| self.kinds[usize::from(header.entity_type)])
                    .unwrap_or(UNCLASSIFIED_KINDS),
                0,
            ),
            Some(Rows::ByFamily) => {
                let families = if database == "vault_meta" {
                    &self.vault_meta
                } else {
                    &self.sync_state
                };
                let below = families.partition_point(|(prefix, _)| *prefix <= key);
                match below.checked_sub(1).map(|index| families[index]) {
                    Some((prefix, class)) if key.starts_with(prefix) => (class, prefix.len()),
                    _ => (UNCLASSIFIED_ROWS, 0),
                }
            }
            Some(Rows::Whole(class)) => (class, 0),
            Some(Rows::Rebuilt) | None => (UNCLASSIFIED_ROWS, 0),
        }
    }

    /// Whether any row of `database` can be other than content.
    pub(super) fn has_authority(database: &str) -> bool {
        DATABASES
            .iter()
            .find(|(name, _)| *name == database)
            .is_none_or(|(_, rows)| {
                matches!(rows, Rows::ByKind | Rows::ByFamily)
                    || matches!(rows, Rows::Whole(class) if *class != CONTENT)
            })
    }
}

#[cfg(test)]
mod tests;
