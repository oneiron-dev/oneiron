//! The declaration list: every prefix a module keeps rows under in `vault_meta` or `sync_state`,
//! one entry each. A module declares its own tables in its `tables.rs`, with [`side_tables!`]
//! (core split slice 1); the few rows no single module owns stay in the files included here. The
//! crate's build script reads every row and writes [`CATALOGUE`], all of them sorted by database
//! and prefix, and a `use` of each module's rows, so `side_table::NAME` names every table.
//! `assert_disjoint` pins at compile time that no entry is a byte prefix of another in the same
//! database, so two tables never read each other's rows.
//!
//! An entry names the database, the prefix bytes (unchanged from the rows already on disk) and
//! the codec. `Named` is the codec; entries on a legacy codec (`LegacyJson`, `LegacyCompact`,
//! `Raw`) keep the bytes they had and move with the next storage ABI bump. The key note on each
//! entry spells what follows the prefix.
//!
//! An entry may end with what its rows carry, a [`SidePayload`] (OF-067). A table classed
//! `Authored` is admitted at every write by the side-row wall; an entry with no class is written
//! as given. The class changes no stored byte.
//!
//! An `Authored` entry whose rows keep structural references names them after its class, in
//! `[refs: LIST]`, a list of [`RefPath`]s the side-row wall reads with no known-value sweep (FIX
//! 6634); an entry that names none keeps every field under the sweep.
//!
//! An entry whose rows record an actor ends with `=> scrub`, the [`ActorScrub`] an actor's erase
//! runs over its rows (FIX 3520); the erase walks every entry that names one.
//!
//! An `Authored` entry may name `[accepts: path]`, its owner's
//! [`MaskedAccepts`](super::MaskedAccepts) (FIX 2680): the typed check the historical lift sweep
//! runs over a masked copy of a row, in place of its shape check.
//!
//! Every entry then says what a checkpoint does with its rows, in three fields a row cannot
//! leave out (the macro does not read a row without them):
//! - `[restore: ..]`, its [`RestoreClass`]: `content`, `live`, `refuse "what"`,
//!   `refuse_image_entities "what"`, `not_imaged` for a derived or runtime table, or `none` for a
//!   canonical table with no class yet;
//! - `[family: ..]`, its payload family: `unclassified`, `not_imaged`, `structure`,
//!   `owner GETTER`, `dispatch CLIENT`, `sealed CUSTODY_KIND`, `mixed CARRIER`, or `unregistered`
//!   while it has none;
//! - `[tier: ..]`, its [`StorageTier`]: `canonical`, `derived` or `runtime`. A key range in another
//!   tier follows as `, runtime for b"bytes after the prefix"`; one table has such ranges,
//!   `BOOKING_ANTI_ABUSE`, whose rate counters and slot-list caches are runtime.
//!
//! A key no table declares is canonical (`recovery::checkpoint::storage_tier`).
//!
//! `none` and `unregistered` mark gaps (FIX-LIST rows 22408-22423), which a fix closes in the
//! owner's own row.

use super::RefStep::{Field, Json};
use super::{ActorScrub, RefPath, RestoreClass, SideDb, SidePayload, SideTableDecl, StorageTier};

/// Declares side tables: each row becomes a `pub(crate) static` [`SideTableDecl`] in the module
/// that invokes it. Only the crate's build script lists them, in [`CATALOGUE`], so a row lives in
/// its owner module's `tables.rs` (or in a file included here) and nowhere else.
///
/// Both rules hold at compile time, whether or not the build script reran: an invocation in any
/// other module fails [`row_module_allowed`], and each row names its `side_table::NAME`
/// re-export, which exists only for a row the build script has read.
macro_rules! side_tables {
    ($($(#[$doc:meta])* $name:ident: $db:ident $prefix:literal $codec:ident $($payload:ident)? $([refs: $refs:expr])? $([accepts: $accepts:path])?
        [restore: $($restore:tt)+] [family: $($family:tt)+] [tier: $tier:ident $(, $key_tier:ident for $key:literal)*]
        $(=> $scrub:path)?;)+) => {
        const _: () = assert!(
            $crate::side_table::row_module_allowed(module_path!()),
            "side_tables! rows live in a module's tables.rs or in side_table/decls: the build script reads only those files"
        );
        $(
            const _: &$crate::side_table::SideTableDecl = &$crate::side_table::$name;
            $(#[$doc])*
            pub(crate) static $name: $crate::side_table::SideTableDecl = $crate::side_table::SideTableDecl {
                name: stringify!($name),
                db: $crate::side_table::SideDb::$db,
                prefix: $prefix,
                codec: $crate::side_table::CodecName::$codec,
                payload: $crate::side_table::side_payload!($($payload)?),
                references: $crate::side_table::side_references!($($refs)?),
                actor: $crate::side_table::side_actor!($($scrub)?),
                accepts: $crate::side_table::side_accepts!($($accepts)?),
                restore: $crate::side_table::side_restore!($($restore)+),
                family: $crate::side_table::side_family!($($family)+),
                tier: $crate::side_table::side_tier!($tier),
                key_tiers: &[$(($key, $crate::side_table::side_tier!($key_tier))),*],
            };
        )+
    };
}
pub(crate) use side_tables;

/// Whether `side_tables!` may expand in the module at `path` (its `module_path!()`): a module's
/// `tables`, or `side_table::decls`, which includes the shared decl files.
pub(crate) const fn row_module_allowed(path: &str) -> bool {
    ends_with(path.as_bytes(), b"::tables") || ends_with(path.as_bytes(), b"::side_table::decls")
}

const fn ends_with(text: &[u8], tail: &[u8]) -> bool {
    if text.len() < tail.len() {
        return false;
    }
    let start = text.len() - tail.len();
    let mut at = 0;
    while at < tail.len() {
        if text[start + at] != tail[at] {
            return false;
        }
        at += 1;
    }
    true
}

/// An entry's restore class, from its `[restore: ..]`.
macro_rules! side_restore {
    (content) => {
        $crate::side_table::RestoreClass::Content
    };
    (live) => {
        $crate::side_table::RestoreClass::Live
    };
    (refuse $what:literal) => {
        $crate::side_table::RestoreClass::Refuse($what)
    };
    (refuse_image_entities $what:literal) => {
        $crate::side_table::RestoreClass::RefuseImageEntities($what)
    };
    (not_imaged) => {
        $crate::side_table::RestoreClass::NotImaged
    };
    (none) => {
        $crate::side_table::RestoreClass::None
    };
}
pub(crate) use side_restore;

/// An entry's payload family, from its `[family: ..]`: none while it is `unregistered`.
macro_rules! side_family {
    (unregistered) => {
        ::core::option::Option::None
    };
    (unclassified) => {
        Some($crate::store::checkpoint_payload::rows::Class::Unclassified)
    };
    (not_imaged) => {
        Some($crate::store::checkpoint_payload::rows::Class::NotImaged)
    };
    (structure) => {
        Some($crate::store::checkpoint_payload::rows::Class::Structure)
    };
    (owner $getter:ident) => {
        Some($crate::store::checkpoint_payload::rows::Class::Owner(
            $crate::store::checkpoint_payload::rows::Getter::$getter,
        ))
    };
    (dispatch $client:ident) => {
        Some($crate::store::checkpoint_payload::rows::Class::Other(
            $crate::store::checkpoint_payload::rows::Client::Dispatch(
                $crate::store::checkpoint_payload::rows::OtherClient::$client,
            ),
        ))
    };
    (sealed $kind:ident) => {
        Some($crate::store::checkpoint_payload::rows::Class::Other(
            $crate::store::checkpoint_payload::rows::Client::Sealed(
                $crate::store::CustodyKind::$kind,
            ),
        ))
    };
    (mixed $carrier:ident) => {
        Some($crate::store::checkpoint_payload::rows::Class::Mixed(
            $crate::store::checkpoint_payload::rows::Carrier::$carrier,
        ))
    };
}
pub(crate) use side_family;

/// An entry's storage tier, from its `[tier: ..]`.
macro_rules! side_tier {
    (canonical) => {
        $crate::side_table::StorageTier::Canonical
    };
    (derived) => {
        $crate::side_table::StorageTier::Derived
    };
    (runtime) => {
        $crate::side_table::StorageTier::Runtime
    };
}
pub(crate) use side_tier;

/// An entry's class: [`SidePayload::Unclassed`] when it names none.
macro_rules! side_payload {
    () => {
        $crate::side_table::SidePayload::Unclassed
    };
    ($payload:ident) => {
        $crate::side_table::SidePayload::$payload
    };
}
pub(crate) use side_payload;

/// An entry's actor scrub: `None` when it names none.
macro_rules! side_actor {
    () => {
        None
    };
    ($scrub:path) => {
        Some($scrub)
    };
}
pub(crate) use side_actor;

/// An entry's masked-copy acceptance: `None` when it names none.
macro_rules! side_accepts {
    () => {
        None::<$crate::side_table::MaskedAccepts>
    };
    ($accepts:path) => {
        Some($accepts as $crate::side_table::MaskedAccepts)
    };
}
pub(crate) use side_accepts;

/// An entry's structural references: none when it names none.
macro_rules! side_references {
    () => {
        &[]
    };
    ($refs:expr) => {
        $refs
    };
}
pub(crate) use side_references;

include!("sync_state.rs");
include!("vault_meta_a_b.rs");
include!("vault_meta_c.rs");
include!("vault_meta_d_e.rs");
include!("vault_meta_f_l.rs");
include!("vault_meta_n_r.rs");
include!("vault_meta_s.rs");
include!("vault_meta_t_z.rs");

/// One [`RefPath`], written as a dotted path: each name steps into the member under it, and
/// `json` into the JSON a string member spells.
macro_rules! ref_path {
    ($($step:ident).+) => {
        &[$(ref_step!($step)),+]
    };
}

/// One step of a `ref_path!`.
macro_rules! ref_step {
    (json) => {
        Json
    };
    ($name:ident) => {
        Field(stringify!($name))
    };
}

/// The structural references an inert workflow's record keeps (FIX 6634): every id or label the
/// engine resolves by its exact bytes, read from the top of the row and of each frozen step its
/// writer admits as a body of the row (FIX 6637). The two shapes share only `launch`, an object
/// in the row and JSON text in a step, so neither's paths name anything in the other. Free text
/// (a briefing, objectives, a healer case) stays under the sweep.
const WORKFLOW_RECORD_REFS: &[RefPath] = &[
    // The row: its intent, launch statement and step results.
    ref_path!(intent.workflow_ref),
    ref_path!(intent.run_id),
    ref_path!(intent.context_spec.layers),
    ref_path!(intent.context_spec.memory.domains),
    ref_path!(intent.context_from),
    ref_path!(intent.project_ref),
    ref_path!(intent.type_ref.node_id),
    ref_path!(intent.spend),
    ref_path!(intent.room),
    ref_path!(intent.task.task_ref),
    ref_path!(intent.task.bound_by),
    ref_path!(launch.scope),
    ref_path!(launch.parent_scope),
    ref_path!(results),
    // A frozen step: a dispatch input's pinned-key MessagePack map.
    ref_path!(target),
    ref_path!(agent_def),
    ref_path!(definition),
    ref_path!(context_spec.json.layers),
    ref_path!(context_spec.json.memory.domains),
    ref_path!(context_from),
    ref_path!(project_ref),
    ref_path!(spawn_intent),
    ref_path!(scope),
    ref_path!(task_type_ref),
    ref_path!(launch.json.scope),
    ref_path!(launch.json.parent_scope),
    ref_path!(origin_conversation),
    ref_path!(room),
    ref_path!(join),
    ref_path!(team.json.team_ref),
    ref_path!(plan.json.asked.type_ref.node_id),
    ref_path!(plan.json.asked.model),
    ref_path!(plan.json.plan.agent_def),
    ref_path!(plan.json.plan.model),
];

/// The structural references a context-widen proposal keeps (FIX 6634): every id or label of its
/// intent the engine resolves by its exact bytes, the target fingerprint approval compares, the
/// labels and domains of the parent slice and the widened slice its request names (approval
/// compares the first with the parent's live slice and narrows the board's by the second), and
/// the decliner's id. Free text (a briefing, objectives, a healer case) stays under the sweep.
const WIDEN_INTENT_REFS: &[RefPath] = &[
    ref_path!(request.intent.target),
    ref_path!(request.intent.dedupe_key),
    ref_path!(request.intent.run_id),
    ref_path!(request.intent.spec.layers),
    ref_path!(request.intent.spec.memory.domains),
    ref_path!(request.intent.context_from),
    ref_path!(request.intent.project_ref),
    ref_path!(request.intent.scope),
    ref_path!(request.intent.type_ref.node_id),
    ref_path!(request.intent.room),
    ref_path!(request.intent.team.team_ref),
    ref_path!(request.intent.plan.asked.type_ref.node_id),
    ref_path!(request.intent.plan.asked.model),
    ref_path!(request.intent.plan.plan.agent_def),
    ref_path!(request.intent.plan.plan.model),
    ref_path!(request.intent.task.task_ref),
    ref_path!(request.intent.task.bound_by),
    ref_path!(request.target_fingerprint),
    ref_path!(request.parent_spec.layers),
    ref_path!(request.parent_spec.memory.domains),
    ref_path!(request.widened_spec.layers),
    ref_path!(request.widened_spec.memory.domains),
    ref_path!(declined.by),
];

/// The structural references a frozen callable case keeps (FIX 12093): its receipt, the revision
/// that answered, its caller and its source rows. Its arguments and answer stay under the sweep.
const CALLABLE_CASE_REFS: &[RefPath] = &[
    ref_path!(receipt),
    ref_path!(version),
    ref_path!(caller.actor),
    ref_path!(source_rows),
];

// `CATALOGUE`: every row, sorted by database and prefix, written by the crate's build script.
include!(concat!(env!("OUT_DIR"), "/side_table_catalogue.rs"));

/// Every declared table, in catalogue order: the restore-class census walks it, and so does a
/// left shared vault's purge (`store::local_replica`, `sync`-only).
pub(crate) fn declared() -> impl Iterator<Item = &'static SideTableDecl> {
    CATALOGUE.iter().copied()
}

/// Every `vault_meta` table the catalog classes `Authored`, in prefix order:
/// the historical lift sweep walks their rows (OF-067).
pub(crate) fn authored_vault_meta() -> impl Iterator<Item = &'static SideTableDecl> {
    declared().filter(|decl| decl.db == SideDb::VaultMeta && decl.payload == SidePayload::Authored)
}

/// The scrub of every table whose entry names one, in catalog order: an actor's erase runs
/// them all (FIX 3520).
pub(crate) fn actor_scrubs() -> impl Iterator<Item = (&'static SideTableDecl, ActorScrub)> {
    declared().filter_map(|decl| decl.actor.map(|scrub| (decl, scrub)))
}

/// The declared table whose prefix `key` falls under, in `db`, or `None` when
/// no declared prefix matches. Declared prefixes are disjoint within one
/// database (`assert_disjoint`), so at most one table can match: the last
/// [`CATALOGUE`] entry at or before `(db, key)`, which is sorted by database
/// and prefix. This is the production door a caller-chosen key (a host's
/// `sync_state` row) is checked against before it is allowed to write, and
/// the storage tier of every side-table row a checkpoint reads.
pub(crate) fn declared_for(db: SideDb, key: &[u8]) -> Option<&'static SideTableDecl> {
    let below = CATALOGUE.partition_point(|decl| {
        (catalogue_rank(decl.db), decl.prefix) <= (catalogue_rank(db), key)
    });
    below
        .checked_sub(1)
        .map(|index| CATALOGUE[index])
        .filter(|decl| decl.db == db && key.starts_with(decl.prefix))
}

/// A database's place in [`CATALOGUE`]'s order, as the build script sorts it: `sync_state` first.
const fn catalogue_rank(db: SideDb) -> u8 {
    match db {
        SideDb::SyncState => 0,
        SideDb::VaultMeta => 1,
    }
}

/// Whether `prefix` (in `db`) overlaps a declared table: either it extends a
/// declared prefix ([`declared_for`] would find one) or it is itself a
/// leading substring of one — a family or whole-table scan, e.g. `"rm:"`
/// covers both `SYNC_REMAT_MARKER` (`rm:w:`) and
/// `SYNC_REPLAY_REMAT_MARKER_PROVENANCE` (`rmp:w:`). A scan can only surface
/// rows a declared door already wrote, so either direction is a read over
/// declared territory; only the exact-key doors ([`declared_for`]) and the
/// write doors need the one-directional check.
pub(crate) fn declared_overlaps(db: SideDb, prefix: &[u8]) -> bool {
    declared().any(|decl| {
        decl.db == db && (prefix.starts_with(decl.prefix) || decl.prefix.starts_with(prefix))
    })
}

// A declaration list with an overlap, or out of database and prefix order, does not compile.
const _: () = assert_disjoint(&CATALOGUE);

// A canonical table with no restore class, other than one marked `none`, or a derived or runtime
// table with one, does not compile.
const _: () = assert_restore_tiers(&CATALOGUE);

// The session overlay keeps these tables' rows outside a room's byte budget by
// the prefixes in `oneiron_store::overlay_bookkeeping`. A lower prefix that
// differs from its declaration does not compile.
const _: () = {
    use oneiron_store::overlay_bookkeeping as bookkeeping;
    assert!(
        same_bytes(SCOPE_RECORD.prefix, bookkeeping::SCOPE_RECORD_PREFIX),
        "overlay bookkeeping prefix differs from SCOPE_RECORD"
    );
    assert!(
        same_bytes(
            PROVENANCE_ROW_BIRTH.prefix,
            bookkeeping::PROVENANCE_ROW_BIRTH_PREFIX
        ),
        "overlay bookkeeping prefix differs from PROVENANCE_ROW_BIRTH"
    );
    assert!(
        same_bytes(
            PROVENANCE_BIRTH_BY_TRIGGER.prefix,
            bookkeeping::PROVENANCE_BIRTH_BY_TRIGGER_PREFIX
        ),
        "overlay bookkeeping prefix differs from PROVENANCE_BIRTH_BY_TRIGGER"
    );
};

/// The list runs by database, `sync_state` first ([`declared_for`] searches it in that order).
/// Within one database, the declared prefixes in list order must be strictly ascending and no
/// prefix may be a byte prefix of its successor. In a sorted list a prefix of any later entry is
/// a prefix of its immediate successor, so the adjacent check covers every pair.
const fn assert_disjoint(catalogue: &[&SideTableDecl]) {
    let mut previous: Option<&SideTableDecl> = None;
    let mut index = 0;
    while index < catalogue.len() {
        let current = catalogue[index];
        assert!(!current.prefix.is_empty(), "a declared prefix is empty");
        if let Some(before) = previous {
            assert!(
                catalogue_rank(before.db) <= catalogue_rank(current.db),
                "the declared tables are out of database order"
            );
        }
        if let Some(before) = previous
            && before.db as u8 == current.db as u8
        {
            assert!(
                ascending(before.prefix, current.prefix),
                "declared prefixes are out of order within one database"
            );
            assert!(
                !starts_with(current.prefix, before.prefix),
                "a declared prefix is a byte prefix of another"
            );
        }
        previous = Some(current);
        index += 1;
    }
}

/// A table is `not_imaged` exactly when its tier is derived or runtime: no image carries its rows,
/// so no restore class applies to them, and every canonical table names one (or `none`).
const fn assert_restore_tiers(catalogue: &[&SideTableDecl]) {
    let mut index = 0;
    while index < catalogue.len() {
        let decl = catalogue[index];
        let canonical = decl.tier as u8 == StorageTier::Canonical as u8;
        let not_imaged = matches!(decl.restore, RestoreClass::NotImaged);
        assert!(
            canonical != not_imaged,
            "a canonical table is not_imaged, or a derived or runtime table has a restore class"
        );
        index += 1;
    }
}

const fn starts_with(bytes: &[u8], prefix: &[u8]) -> bool {
    if prefix.len() > bytes.len() {
        return false;
    }
    let mut index = 0;
    while index < prefix.len() {
        if bytes[index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn same_bytes(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && starts_with(left, right)
}

const fn ascending(before: &[u8], after: &[u8]) -> bool {
    let mut index = 0;
    while index < before.len() && index < after.len() {
        if before[index] != after[index] {
            return before[index] < after[index];
        }
        index += 1;
    }
    before.len() < after.len()
}
