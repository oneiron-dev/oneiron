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

use std::collections::{BTreeMap, BTreeSet};

use crate::batch::EntityMetadataHeader;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus};
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
    ENTITY_TYPE_WORKFLOW, ENTITY_TYPE_WORLD, ENTITY_TYPE_WORLD_KEY_PAD,
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
    /// Which party on which identity a counterparty contact binds (the pair a
    /// sender resolves to the contact and its disclosure standing), how it
    /// was first met (a public first touch holds a send for the owner),
    /// whether it is live, and the party's opt-out and promotional consent.
    /// One only one vault holds counts as changed when it is revoked, opted
    /// out or first met in public, or when the send gate would read it before
    /// another contact of the same party with a different first touch.
    Contact,
    /// A NOTE's kind, which decides who reads it, and its author. A body
    /// that does not decode is content.
    Note,
    /// A claim's relationship scope and privacy, and the whole of a claim in
    /// an [`AUTHORITY_CLAIMS`] family. Such a claim only one vault holds
    /// counts as changed. Skill scan verdicts are compared as the activation
    /// posture the bytes of each skill the image holds take from them, not
    /// claim by claim, so a refreshed scan with the same result, or a scan of
    /// bytes the image does not hold, changes nothing. Recipient jurisdiction
    /// observations are compared the same way, as the jurisdiction the
    /// campaign gate selects for each subject the image holds and a campaign
    /// enrolls. Either kind's read scope is still compared claim by claim.
    Claim,
    /// A project's authority (parents, claims scope, slice, depth, leader,
    /// board), roster, role and budget.
    Project,
    /// A TASK authority fact, one added since the image to a task the image
    /// holds counting as changed unless it is an acknowledgement; or a task's
    /// owner, assignee and ask class, which authorize the asks bound to it. A
    /// TASK body that binds no ask compares equal to any other such body, and
    /// differs from one that does. The rest of a TASK body is content.
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
/// An owner's own-device grant (FIX 3134) is the access a paired device
/// stands on, not vault content: it stays as the live vault holds it, so a
/// device paired after a checkpoint never blocks restoring that checkpoint
/// (FIX 3293).
const OWN_DEVICE_GRANTS: Class = LIVE;

/// Whether the entity row `value` holds an own-device grant.
fn own_device_grant_row(value: &[u8]) -> bool {
    value
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .and_then(|body| crate::federation::decode_federation_grant_body(body).ok())
        .is_some_and(|grant| crate::federation::is_own_device_grant(&grant))
}
/// An owner's grant to a named agent (FIX 5628) is his standing will,
/// durable until he revokes it, not vault content: it stays as the live
/// vault holds it, so a grant he made after a checkpoint never blocks
/// restoring that checkpoint, and one he revoked since stays revoked: its
/// bodyless shell is Live too, by his revoke act (FIX 5732).
const OWNER_AGENT_GRANTS: Class = LIVE;

/// Whether the entity row `value` is a bodyless shell: a deleted entity's
/// header, its body scrubbed.
fn bodyless_row(value: &[u8]) -> bool {
    value
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .is_some_and(<[u8]>::is_empty)
}

/// Whether the entity row `value` holds an owner's agent grant: its body
/// carries the `owner_agent` mark.
fn owner_agent_grant_row(value: &[u8]) -> bool {
    value
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .and_then(|body| crate::federation::decode_federation_grant_body(body).ok())
        .is_some_and(|grant| grant.owner_agent)
}

/// Whether the `vault_meta` family declared at `prefix` is keyed by one
/// try's bare attempt id and goes with that try (FIX 6577): the resident's
/// stamp the try runs as, and its run-tree row.
fn keyed_by_try(prefix: &[u8]) -> bool {
    [
        crate::side_table::DREAMER_RESIDENT_ATTEMPT.prefix,
        crate::side_table::DREAMER_RUN_TREE.prefix,
    ]
    .contains(&prefix)
}
const ACCESS_GRANTS: Class = refuse("access grants");
const SECRET_CUSTODY: Class = refuse("secret custody");
const CONNECTOR_KEYS: Class = refuse("connector keys");
const CHANNEL_IDENTITIES: Class = refuse("channel identities");
const OUTBOUND_GRANTS: Class = Class::Refuse {
    what: "outbound grants",
    scope: Scope::Authority(Projection::OutboundGrant),
};
const MACHINE_IDENTITIES: Class = refuse("machine identities");
/// This install's own serving MACHINE row (FIX 4728; Engine 10-19 15:0x):
/// the one machine row an authority-preserving restore keeps as the live
/// vault holds it, so the profile a start ensured never refuses a restore of
/// an image taken before it. Every other machine row stays refused.
const SERVING_MACHINE: Class = LIVE;
const SKILL_HUB_CONFIGURATION: Class = refuse("skill hub configuration");
const STANDING_GRANTS: Class = refuse("standing consent grants");
/// A code consent wait (DOOR-079) entangles a one-shot answer, an external
/// effect's admission and settlement, and (1b) the replay that consumed it:
/// a rollback could unspend it, and keeping it live alone would point into
/// a rolled-back replay. Its family refuses a restore instead (CALLS: restore
/// Refuse).
const CODE_CONSENT_WAITS: Class = refuse("code consent waits");
const STANDING_BLOCKS: Class = refuse("standing blocks");
const DISCLOSURE_SCOPES: Class = refuse("disclosure scopes");
const ORG_ADMIN_GRANTS: Class = refuse("org admin grants");
const SHARED_VAULT_MEMBERSHIP: Class = refuse("shared vault membership");
const ESIGN_CAPABILITIES: Class = refuse("e-sign capabilities");
const SHARE_ADMISSIONS: Class = refuse("share admissions");
const PUBLIC_BOOKING_PAGES: Class = refuse("public booking pages");
const PUBLISHED_ARTIFACTS: Class = refuse("published artifacts");
const ORIGIN_AUTHORITY: Class = refuse("repository origin authority");
/// An authority row whose writer an actor's erase replaced (FIX 3877): the
/// erase changes who it names and nothing else, so the row stays as the live
/// vault holds it, and a checkpoint that holds it naming that writer still
/// restores. A cutover moves the epoch, so it still refuses.
const ERASED_ORIGIN_AUTHORITY: Class = LIVE;
const ORIGIN_MIRRORS: Class = refuse("repository mirror targets");
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

/// [`AUTHORITY_CLAIMS`] families whose readers act only on an approved,
/// active claim. One awaiting approval, rejected or retracted authorizes
/// nothing, so it is content. A stale one still counts: the install executor
/// accepts it, so withdrawing it is a narrowing.
const APPROVED_AUTHORITY_CLAIMS: &[&str] = &["plugin.section_install"];

/// The [`AUTHORITY_CLAIMS`] family `claim` carries authority in, by name.
pub(super) fn authority_claim(claim: &ClaimBody) -> Option<&'static str> {
    let predicate = claim.predicate.as_str();
    let in_effect = !APPROVED_AUTHORITY_CLAIMS.contains(&predicate)
        || (claim.approval == ClaimApprovalStatus::Approved
            && claim.lifecycle == ClaimLifecycleStatus::Active);
    AUTHORITY_CLAIMS
        .iter()
        .find(|(family, _)| {
            predicate == *family || (family.ends_with('.') && predicate.starts_with(family))
        })
        .filter(|_| in_effect)
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
    // Signed project history is live authority: a restore never rolls it back.
    (
        crate::workspace_roster::PROJECT_PACK,
        crate::workspace_roster::PROJECT_REVISION_SHORT_ID_PREFIX,
        LIVE,
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
/// A STOP's send hold before this replica projected it, keyed by the event:
/// it leaves with an event made after the checkpoint, and a changed one for
/// an event both vaults hold refuses.
const PENDING_COMM_STOPS: Class = Class::Refuse {
    what: "pending communication STOP",
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
    // A pad the live vault erased must not come back from an image.
    (ENTITY_TYPE_WORLD_KEY_PAD, LIVE),
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
];

/// How each database's canonical rows are classed.
#[derive(Clone, Copy, Debug)]
enum Rows {
    /// By declared family ([`SIDE_TABLES`]).
    ByFamily,
    /// By entity kind ([`ENTITY_KINDS`]).
    ByKind,
    /// By attempt (FIX 6577): a free-time try [`Classes`] names is live, as
    /// the item binding it runs under is; every other attempt is content.
    Attempts,
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
    // Durable job intents (unleased at snapshot): the free-time tries follow
    // their live bindings, every other attempt is content.
    ("job_records", Rows::Attempts),
    // The sync send queue.
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
    /// The live vault's origin authority rows an erase rewrote, by key. A
    /// read that fails keeps none, so those rows refuse as before.
    erased_authority: BTreeMap<Vec<u8>, crate::origin::residence::OriginAuthority>,
    /// The live vault's own serving machine ([`SERVING_MACHINE`]), read in
    /// one snapshot of `current` (`Vault::serving_machine_in_txn`).
    serving_machine: Option<crate::EntityId>,
    /// The agent grants the live vault's owner revoked, by key: each one a
    /// GrantRevoke act in its authority log names (FIX 5732). A read that
    /// fails keeps none, so those shells refuse as before.
    revoked_agent_grants: BTreeSet<Vec<u8>>,
    /// The rows of the tables a home move carries, by database (FIX 5661
    /// C2b): each table's live keys in `current` and the image's keys it
    /// manages. They restore live, so an old export never comes back over
    /// later spend.
    home_managed: BTreeMap<&'static str, BTreeSet<Vec<u8>>>,
    /// The home tables whose live rows did not read or decode: each keeps
    /// its own class, so the image wins where that is content.
    home_unreadable: Vec<&'static str>,
    /// The `job_records` keys of every free-time try in `current` or the
    /// image (FIX 6577): they restore live, following the item bindings a
    /// home move carries, and so do the rows keyed by them
    /// ([`keyed_by_try`]). Empty when the live rows did not read: the
    /// image's tries and their rows then stand, noted as `job_records`.
    free_time_attempts: BTreeSet<Vec<u8>>,
}

impl Classes {
    /// The table, with the kinds `current` registered at run time, its own
    /// serving machine, and the home tables' rows and the free-time tries
    /// over `image`'s.
    pub(super) fn new(
        current: &crate::Vault,
        image: &BTreeMap<String, Vec<(Vec<u8>, Vec<u8>)>>,
    ) -> crate::Result<Self> {
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
        let txn = current.store.env.read_txn()?;
        let serving_machine = current.serving_machine_in_txn(&txn)?;
        let revoked_agent_grants: BTreeSet<Vec<u8>> = current
            .revoked_agent_grants_in_txn(&txn)
            .map(|revoked| revoked.iter().map(|id| id.as_bytes().to_vec()).collect())
            .unwrap_or_default();
        drop(txn);
        #[cfg(feature = "sync")]
        let crate::sync::home_handoff::HomeManaged {
            keys: home_managed,
            unreadable: mut home_unreadable,
        } = crate::sync::home_handoff::restore_managed_keys(current, image)?;
        // The free-time tries, with their stamps and run-tree rows, follow
        // their live bindings (FIX 6577). Live rows that do not read leave
        // them content, noted as a home table's.
        #[cfg(feature = "sync")]
        let free_time_attempts = crate::dreamer_runner::free_time_attempt_restore_keys(
            current, image,
        )
        .unwrap_or_else(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "the free-time attempts' live rows did not read; they restore from the image"
            );
            home_unreadable.push("job_records");
            BTreeSet::new()
        });
        #[cfg(not(feature = "sync"))]
        let (home_managed, home_unreadable, free_time_attempts) = {
            let _ = image;
            (BTreeMap::new(), Vec::new(), BTreeSet::new())
        };
        Ok(Self {
            vault_meta,
            sync_state,
            kinds,
            erased_authority: crate::origin::residence::erased_writer_rows(current)
                .unwrap_or_default(),
            serving_machine,
            revoked_agent_grants,
            home_managed,
            home_unreadable,
            free_time_attempts,
        })
    }

    /// The restore's note for each home table whose live rows did not read
    /// (FIX 5661 C2b): it came from the image.
    pub(super) fn home_notes(&self) -> Vec<super::HomeTableNote> {
        self.home_unreadable
            .iter()
            .map(|table| super::HomeTableNote::Unreadable {
                table: (*table).to_owned(),
            })
            .collect()
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
                    .and_then(|header| {
                        if header.entity_type == ENTITY_TYPE_MACHINE
                            && self
                                .serving_machine
                                .is_some_and(|machine| key == machine.as_bytes())
                        {
                            return Some(SERVING_MACHINE);
                        }
                        if header.entity_type == ENTITY_TYPE_FEDERATION_GRANT
                            && own_device_grant_row(value)
                        {
                            return Some(OWN_DEVICE_GRANTS);
                        }
                        if header.entity_type == ENTITY_TYPE_FEDERATION_GRANT
                            && owner_agent_grant_row(value)
                        {
                            return Some(OWNER_AGENT_GRANTS);
                        }
                        // A revoked agent grant's shell holds no mark; his
                        // revoke act names it (FIX 5732).
                        if header.entity_type == ENTITY_TYPE_FEDERATION_GRANT
                            && bodyless_row(value)
                            && self.revoked_agent_grants.contains(key)
                        {
                            return Some(OWNER_AGENT_GRANTS);
                        }
                        self.kinds[usize::from(header.entity_type)]
                    })
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
                    Some((prefix, _))
                        if database == "vault_meta"
                            && self.erased_authority.get(key).is_some_and(|live| {
                                crate::origin::residence::erased_writer_row(live, value)
                            }) =>
                    {
                        (ERASED_ORIGIN_AUTHORITY, prefix.len())
                    }
                    Some((prefix, _))
                        if key.starts_with(prefix)
                            && self
                                .home_managed
                                .get(database)
                                .is_some_and(|keys| keys.contains(key)) =>
                    {
                        (LIVE, prefix.len())
                    }
                    Some((prefix, _))
                        if database == "vault_meta"
                            && keyed_by_try(prefix)
                            && key.strip_prefix(prefix).is_some_and(|attempt| {
                                self.free_time_attempts.contains(attempt)
                            }) =>
                    {
                        (LIVE, prefix.len())
                    }
                    Some((prefix, class)) if key.starts_with(prefix) => {
                        (self.binding_class(database, key, class), prefix.len())
                    }
                    _ => (UNCLASSIFIED_ROWS, 0),
                }
            }
            Some(Rows::Attempts) if self.free_time_attempts.contains(key) => (LIVE, 0),
            Some(Rows::Attempts) => (CONTENT, 0),
            Some(Rows::Whole(class)) => (class, 0),
            Some(Rows::Rebuilt) | None => (UNCLASSIFIED_ROWS, 0),
        }
    }

    /// A row-held response's binding goes with its carrier (KS-2B2): one
    /// whose row is a Live family's, a media job's or clip's, is the live
    /// vault's with the row, and one the live vault no longer holds stays
    /// absent. Every other row keeps its family's `class`.
    fn binding_class(&self, database: &str, key: &[u8], class: Class) -> Class {
        if database != "vault_meta" {
            return class;
        }
        let Some((db, row)) = key
            .strip_prefix(crate::side_table::PROVENANCE_BODY_RESPONSE.prefix)
            .and_then(crate::store::carrier_row)
        else {
            return class;
        };
        if db == crate::store::ResponseDb::SyncState && self.row(db.name(), row, &[]).0 == LIVE {
            LIVE
        } else {
            class
        }
    }

    /// Whether any row of `database` can be other than content.
    pub(super) fn has_authority(database: &str) -> bool {
        DATABASES
            .iter()
            .find(|(name, _)| *name == database)
            .is_none_or(|(_, rows)| {
                matches!(rows, Rows::ByKind | Rows::ByFamily | Rows::Attempts)
                    || matches!(rows, Rows::Whole(class) if *class != CONTENT)
            })
    }
}

#[cfg(test)]
mod tests;
