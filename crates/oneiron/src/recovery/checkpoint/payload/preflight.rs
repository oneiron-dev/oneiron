//! The payload registry's preflight (KS7-6, Engine 10-30 11:12): what the
//! registry ([`super::rows`]) misses or names twice, and the owner families
//! no compartment may seal, found before a capture places a row. Nothing
//! here refuses a capture. Each finding is logged and named on the capture
//! receipt, a family by its name, database and prefix, and the capture rides
//! past it: a family or entity kind a finding names is not compartmented,
//! so its rows stay in the image under the vault-wide seal, as before KS-7;
//! a database one names is not read, so the rows no getter places stay
//! there too.
//!
//! A compartment holds the getter's live value. An owner family must not be
//! sealed when the snapshot writes it otherwise than it rests (a row-held
//! response as its stub, KS-2B1; an inline body without its bytes, KS-2A; a
//! window's pads by reference, KS-5; a queue row unleased, FIX 7115), or
//! when a restore reads references from it in the image's rows alone,
//! before any compartment lands (a body's instance, file or descriptor,
//! KS-2A; the known-value history, KS-3; an agent id pin, H215; a world key
//! pad, KS-5; a credential, KS-6).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::LazyLock;

use super::keep_owner_parts;
use super::rows::{self, Class, DbClass};
use super::super::{StorageTier, storage_tier};
use crate::batch::EntityMetadataHeader;
use crate::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_REGISTRY, ENTITY_TYPE_SECRET_CUSTODY, ENTITY_TYPE_WORLD_KEY_PAD,
    entity_type_registry_entry,
};
use crate::side_table::{self, SideDb, SideTableDecl};
use crate::store::DB_MANIFEST;
use crate::store::checkpoint_payload::rows::{Captured, RowDb};

/// The families the snapshot writes otherwise than they rest: each row-held
/// response's carrier, which goes as its stub, and its binding, which a
/// stale one leaves (KS-2B1); an inline result body's row, which goes
/// without its bytes (KS-2A); and a window snapshot, which goes by its pads'
/// references (FIX 7107).
static REWRITTEN: &[&SideTableDecl] = &[
    &side_table::DREAMER_TURN_PROGRAM_STEP,
    &side_table::DREAMER_STEP_STATE,
    &side_table::CODE_RUN_REPLAY,
    &side_table::COACH_BLOCKED_SOURCE,
    &side_table::CODE_RUN_WAIT_DELIVERY,
    &side_table::CODE_RUN_WAIT_INDEX,
    &side_table::MODEL_STEP_SUBMISSION,
    &side_table::SAVED_QUERY_MEMO,
    &side_table::SELF_HEAL_CENTROID_EVIDENCE,
    &side_table::MESSAGE_REPLY_ASSERTIONS,
    &side_table::FEEDBACK_REPORT_CLUSTER,
    &side_table::VOICE_OWNER_REF,
    &side_table::VOICE_OWNER_REF_OWNER_INDEX,
    &side_table::VOICE_REF_IDENTITY,
    &side_table::VOICE_REF_INCARNATION,
    &side_table::VOICE_REF_RENDER_CONSENT,
    &side_table::VOICE_REF_RENDER_EVENT,
    &side_table::VOICE_REF_TARGET,
    &side_table::HTTP_IDEMPOTENCY_REPLY,
    &side_table::MODEL_MEDIA_JOB,
    &side_table::PROVENANCE_BODY_RESPONSE,
    &side_table::CODE_RUN_RAW_OUTPUT,
    &side_table::WINDOW_SNAPSHOT,
];

/// The entity kinds it writes otherwise: an inline ASSET without its bytes
/// (KS-2A) and a world key pad by its reference (KS-5). A dreamer step's
/// CLAIM goes as its stub too, but its getter places it by its predicate,
/// as the response client's, never by its kind.
static REWRITTEN_KINDS: &[u8] = &[ENTITY_TYPE_ASSET, ENTITY_TYPE_WORLD_KEY_PAD];

/// The databases it writes otherwise: every queue row, unleased (FIX 7115).
static REWRITTEN_DATABASES: &[&str] = &["job_records"];

/// The families a restore reads references from in the image's rows alone:
/// body instances, files, descriptors and holders, which a retired body's
/// prune rewrites, and a step response's pins (KS-2A,
/// `carried_bodies::require`); the known-value history (KS-3); agent id pins
/// (H215).
static REFERENCES: &[&SideTableDecl] = &[
    &side_table::PROVENANCE_BODY_KEY,
    &side_table::PROVENANCE_BODY_INLINE,
    &side_table::PROVENANCE_BODY_RESPONSE,
    &side_table::PROVENANCE_BODY,
    &side_table::PROVENANCE_BODY_DIGEST,
    &side_table::PROVENANCE_BODY_RELEASED,
    &side_table::CODE_RUN_RAW_OUTPUT,
    &side_table::DREAMER_STEP_RESPONSE_PIN,
    &side_table::SECRET_KNOWN_HISTORY,
    &side_table::SECRET_KNOWN_INDEX,
    &side_table::AGENT_DEF_ID_PIN,
];

/// The entity kinds it does: an ASSET's body file (KS-2A), a world key pad
/// (KS-5) and a credential (KS-6).
static REFERENCE_KINDS: &[u8] = &[
    ENTITY_TYPE_ASSET,
    ENTITY_TYPE_WORLD_KEY_PAD,
    ENTITY_TYPE_SECRET_CUSTODY,
];

/// What a finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gap {
    /// Declared, registered or in the manifest, but not in the registry.
    Unregistered,
    /// In the registry more than once.
    NamedTwice,
    /// In the registry, but declared, registered or in the manifest nowhere.
    Unknown,
    /// Classed not imaged, but the image takes it.
    Imaged,
    /// An owner's, which the snapshot writes otherwise than it rests.
    Rewritten,
    /// An owner's, which a restore reads references from before it lands.
    References,
    /// Classed for the projection to read, which has no reader for it.
    Unread,
}

impl Gap {
    const fn says(self) -> &'static str {
        match self {
            Self::Unregistered => "the payload registry does not name it",
            Self::NamedTwice => "the payload registry names it more than once",
            Self::Unknown => "the payload registry names it, but nothing declares it",
            Self::Imaged => "classed not imaged, but the image takes it",
            Self::Rewritten => "an owner's, but the snapshot writes it otherwise than it rests",
            Self::References => {
                "an owner's, but a restore reads references from it before any compartment lands"
            }
            Self::Unread => "the projection has no reader for it",
        }
    }
}

/// What a finding names.
#[derive(Clone, Copy, Debug)]
enum Place {
    Family(&'static SideTableDecl),
    Database(&'static str),
    Kind(&'static str),
}

/// One registry gap a capture rides past.
#[derive(Clone, Copy, Debug)]
pub(super) struct Finding {
    place: Place,
    gap: Gap,
}

impl Finding {
    /// A database the projection has no reader for.
    pub(super) fn unread(database: &'static str) -> Self {
        Self {
            place: Place::Database(database),
            gap: Gap::Unread,
        }
    }

    /// Logs it, a family by its name, database and prefix.
    pub(super) fn log(&self) {
        tracing::warn!(
            finding = %self,
            "checkpoint payload preflight: a registry gap rides in the image, not compartmented"
        );
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.place {
            Place::Family(decl) => write!(
                f,
                "family {} ({}, prefix \"{}\")",
                decl.name,
                rows::db_name(decl.db),
                decl.prefix.escape_ascii()
            )?,
            Place::Database(name) => write!(f, "database {name}")?,
            Place::Kind(kind) => write!(f, "entity kind {kind}")?,
        }
        let rides = match (self.place, self.gap) {
            (_, Gap::Unknown) => "no row is compartmented under it",
            (Place::Database(_), _) => {
                "the projection does not read it, and the rows no getter places stay in the image, \
                 not compartmented"
            }
            _ => "its rows stay in the image, not compartmented",
        };
        write!(f, ": {}; {rides}", self.gap.says())
    }
}

/// What the preflight found, and what a capture keeps out of compartments
/// for it.
pub(super) struct Preflight {
    findings: Vec<Finding>,
    /// The families a finding names, by identity.
    families: BTreeMap<(bool, &'static [u8]), &'static SideTableDecl>,
    /// The entity kinds a finding names.
    kinds: BTreeSet<&'static str>,
    /// The manifest databases the projection reads, each once, in the
    /// registry's order.
    databases: Vec<(&'static str, DbClass)>,
}

static PREFLIGHT: LazyLock<Preflight> = LazyLock::new(Preflight::run);

/// The registry's preflight, read once: the registry is static.
pub(super) fn preflight() -> &'static Preflight {
    &PREFLIGHT
}

impl Preflight {
    fn run() -> Self {
        let mut preflight = Self {
            findings: Vec::new(),
            families: BTreeMap::new(),
            kinds: BTreeSet::new(),
            databases: Vec::new(),
        };
        preflight.check_families();
        preflight.check_kinds();
        preflight.check_databases();
        preflight
    }

    fn family(&mut self, decl: &'static SideTableDecl, gap: Gap) {
        self.findings.push(Finding {
            place: Place::Family(decl),
            gap,
        });
        self.families.insert(rows::identity(decl), decl);
    }

    fn kind(&mut self, kind: &'static str, gap: Gap) {
        self.findings.push(Finding {
            place: Place::Kind(kind),
            gap,
        });
        self.kinds.insert(kind);
    }

    /// Every declared family once, every family the registry names
    /// declared, each not-imaged one left out by tier filtering, and no
    /// owner family one the snapshot rewrites or a restore reads references
    /// from.
    fn check_families(&mut self) {
        let mut named: BTreeMap<(bool, &[u8]), (&'static SideTableDecl, Vec<Class>)> =
            BTreeMap::new();
        for (class, decls) in rows::families() {
            for decl in *decls {
                let entry = named.entry(rows::identity(decl));
                entry.or_insert_with(|| (*decl, Vec::new())).1.push(*class);
            }
        }
        let declared: BTreeMap<(bool, &[u8]), &'static SideTableDecl> = side_table::declared()
            .map(|decl| (rows::identity(decl), decl))
            .collect();
        for (identity, decl) in &declared {
            if !named.contains_key(identity) {
                self.family(*decl, Gap::Unregistered);
            }
        }
        for (identity, (decl, classes)) in &named {
            let canonical =
                storage_tier(rows::db_name(decl.db), decl.prefix) == StorageTier::Canonical;
            let gap = match classes[..] {
                _ if !declared.contains_key(identity) => Gap::Unknown,
                [_, _, ..] => Gap::NamedTwice,
                [Class::NotImaged] if canonical => Gap::Imaged,
                _ => continue,
            };
            self.family(*decl, gap);
        }
        let owned = |decl: &SideTableDecl| {
            named
                .get(&rows::identity(decl))
                .is_some_and(|(_, classes)| matches!(classes[..], [Class::Owner(_)]))
        };
        for (decls, gap) in [
            (REWRITTEN, Gap::Rewritten),
            (REFERENCES, Gap::References),
        ] {
            for decl in decls {
                if owned(*decl) {
                    self.family(*decl, gap);
                }
            }
        }
    }

    /// Every registered entity kind once, every kind the registry names
    /// registered, and no owner kind one the snapshot rewrites or a restore
    /// reads references from.
    fn check_kinds(&mut self) {
        let mut named: BTreeMap<&'static str, Vec<Class>> = BTreeMap::new();
        for (class, kinds) in rows::kinds() {
            for kind in *kinds {
                named.entry(*kind).or_default().push(*class);
            }
        }
        let registered: BTreeSet<&'static str> = ENTITY_TYPE_REGISTRY
            .iter()
            .map(|entry| entry.kind)
            .collect();
        for kind in &registered {
            if !named.contains_key(kind) {
                self.kind(*kind, Gap::Unregistered);
            }
        }
        for (kind, classes) in &named {
            if !registered.contains(kind) {
                self.kind(*kind, Gap::Unknown);
            } else if classes.len() > 1 {
                self.kind(*kind, Gap::NamedTwice);
            }
        }
        let owned = |type_byte: u8| {
            entity_type_registry_entry(type_byte)
                .map(|entry| entry.kind)
                .filter(|kind| {
                    named
                        .get(kind)
                        .is_some_and(|classes| matches!(classes[..], [Class::Owner(_)]))
                })
        };
        for (kinds, gap) in [
            (REWRITTEN_KINDS, Gap::Rewritten),
            (REFERENCE_KINDS, Gap::References),
        ] {
            for type_byte in kinds {
                if let Some(kind) = owned(*type_byte) {
                    self.kind(kind, gap);
                }
            }
        }
    }

    /// Every manifest database once and none besides, each not-imaged one
    /// left out by tier filtering (by its database alone), and no owner
    /// database one the snapshot rewrites: the rest are what the projection
    /// reads.
    fn check_databases(&mut self) {
        let manifest: BTreeSet<&'static str> = DB_MANIFEST.iter().map(|entry| entry.name).collect();
        let mut times: BTreeMap<&'static str, usize> = BTreeMap::new();
        for (name, _) in rows::DATABASES {
            *times.entry(*name).or_default() += 1;
        }
        let mut gaps: Vec<(&'static str, Gap)> = manifest
            .iter()
            .filter(|name| !times.contains_key(*name))
            .map(|name| (*name, Gap::Unregistered))
            .collect();
        for &(name, class) in rows::DATABASES {
            let not_imaged = matches!(class, DbClass::Rows(Class::NotImaged));
            let gap = if !manifest.contains(name) {
                Gap::Unknown
            } else if times.get(name).is_some_and(|times| *times > 1) {
                Gap::NamedTwice
            } else if not_imaged && storage_tier(name, &[]) == StorageTier::Canonical {
                Gap::Imaged
            } else if matches!(class, DbClass::Rows(Class::Owner(_)))
                && REWRITTEN_DATABASES.contains(&name)
            {
                Gap::Rewritten
            } else {
                if !not_imaged {
                    self.databases.push((name, class));
                }
                continue;
            };
            if !gaps.contains(&(name, gap)) {
                gaps.push((name, gap));
            }
        }
        self.findings.extend(gaps.into_iter().map(|(name, gap)| Finding {
            place: Place::Database(name),
            gap,
        }));
    }

    /// Every finding, in the order the preflight made them.
    pub(super) fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// The manifest databases the projection reads, each once, by class.
    pub(super) fn databases(&self) -> &[(&'static str, DbClass)] {
        &self.databases
    }

    /// Whether a finding names `decl`: its rows stay in the image.
    pub(super) fn holds_out(&self, decl: &SideTableDecl) -> bool {
        self.families.contains_key(&rows::identity(decl))
    }

    /// The family a finding names that the row `key` of `db` falls under:
    /// how the receipt names a row the registry places under no family.
    pub(super) fn family_of(&self, db: SideDb, key: &[u8]) -> Option<&'static SideTableDecl> {
        self.families
            .values()
            .copied()
            .find(|decl| decl.db == db && key.starts_with(decl.prefix))
    }

    /// Whether a compartment may hold the image row `key` of `db`, holding
    /// `value`: one of no family or entity kind a finding names.
    fn compartments(&self, db: RowDb, key: &[u8], value: &[u8]) -> bool {
        let db = match db {
            RowDb::VaultMeta => SideDb::VaultMeta,
            RowDb::SyncState => SideDb::SyncState,
            RowDb::Entities => {
                return !EntityMetadataHeader::parse(value)
                    .and_then(|header| entity_type_registry_entry(header.entity_type))
                    .is_some_and(|entry| self.kinds.contains(entry.kind));
            }
            RowDb::EdgesOut | RowDb::EdgesIn | RowDb::SyncQueue => return true,
        };
        self.family_of(db, key).is_none()
    }

    /// `captured` with no owner part of a family or entity kind a finding
    /// names: those rows stay in the image, as before KS-7.
    pub(super) fn hold_out(&self, captured: Captured) -> Captured {
        if self.families.is_empty() && self.kinds.is_empty() {
            return captured;
        }
        keep_owner_parts(captured, &|db, key, value| self.compartments(db, key, value))
    }
}
