//! The declaration list: every prefix a module keeps rows under in `vault_meta` or `sync_state`,
//! one entry each. The entries sit in seven included files (by database, then leading byte) so
//! no file outgrows the size bar; they are one list in one module.
//! `no_declared_prefix_is_a_byte_prefix_of_another` pins that no entry is a byte prefix of another
//! in the same database, so two tables never read each other's rows.
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

use super::RefStep::{Field, Json};
use super::{ActorScrub, CodecName, RefPath, SideDb, SidePayload, SideTableDecl};

macro_rules! side_tables {
    ($list:ident; $($(#[$doc:meta])* $name:ident: $db:ident $prefix:literal $codec:ident $($payload:ident)? $([refs: $refs:expr])? $(=> $scrub:path)?;)+) => {
        $(
            $(#[$doc])*
            pub(crate) static $name: SideTableDecl = SideTableDecl {
                name: stringify!($name),
                db: SideDb::$db,
                prefix: $prefix,
                codec: CodecName::$codec,
                payload: side_payload!($($payload)?),
                references: side_references!($($refs)?),
                actor: side_actor!($($scrub)?),
            };
        )+

        /// One file's declarations, in prefix order.
        static $list: &[&SideTableDecl] = &[$(&$name),+];
    };
}

/// An entry's class: [`SidePayload::Unclassed`] when it names none.
macro_rules! side_payload {
    () => {
        SidePayload::Unclassed
    };
    ($payload:ident) => {
        SidePayload::$payload
    };
}

/// An entry's actor scrub: `None` when it names none.
macro_rules! side_actor {
    () => {
        None
    };
    ($scrub:path) => {
        Some($scrub)
    };
}

/// An entry's structural references: none when it names none.
macro_rules! side_references {
    () => {
        &[]
    };
    ($refs:expr) => {
        $refs
    };
}

include!("sync_state.rs");
include!("vault_meta_a_b.rs");
include!("vault_meta_c.rs");
include!("vault_meta_d_e.rs");
include!("vault_meta_f_l.rs");
include!("vault_meta_m_r.rs");
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

/// Every declared table: the restore-class census walks it, and so does a
/// left shared vault's purge (`store::local_replica`, `sync`-only).
pub(crate) fn declared() -> impl Iterator<Item = &'static SideTableDecl> {
    PARTS.into_iter().flatten().copied()
}

/// Every `vault_meta` table the catalog classes `Authored`, in prefix order:
/// the historical lift sweep walks their rows (OF-067).
pub(crate) fn authored_vault_meta() -> impl Iterator<Item = &'static SideTableDecl> {
    PARTS
        .into_iter()
        .flatten()
        .copied()
        .filter(|decl| decl.db == SideDb::VaultMeta && decl.payload == SidePayload::Authored)
}

/// The scrub of every table whose entry names one, in catalog order: an actor's erase runs
/// them all (FIX 3520).
pub(crate) fn actor_scrubs() -> impl Iterator<Item = ActorScrub> {
    PARTS.into_iter().flatten().filter_map(|decl| decl.actor)
}

/// The declared table whose prefix `key` falls under, in `db`, or `None` when
/// no declared prefix matches. Declared prefixes are disjoint within one
/// database (`assert_disjoint`), so at most one table can match; this is the
/// production door a caller-chosen key (a host's `sync_state` row) is checked
/// against before it is allowed to write, over the same [`PARTS`] list the
/// disjointness check walks at compile time. Gated with its only callers
/// (the generic host doors, `sync`-only) so a featureless build does not
/// carry an unused production function.
#[cfg(feature = "sync")]
pub(crate) fn declared_for(db: SideDb, key: &[u8]) -> Option<&'static SideTableDecl> {
    PARTS
        .iter()
        .flat_map(|part| part.iter())
        .find(|decl| decl.db == db && key.starts_with(decl.prefix))
        .copied()
}

/// Whether `prefix` (in `db`) overlaps a declared table: either it extends a
/// declared prefix ([`declared_for`] would find one) or it is itself a
/// leading substring of one — a family or whole-table scan, e.g. `"rm:"`
/// covers both `SYNC_REMAT_MARKER` (`rm:w:`) and
/// `SYNC_REPLAY_REMAT_MARKER_PROVENANCE` (`rmp:w:`). A scan can only surface
/// rows a declared door already wrote, so either direction is a read over
/// declared territory; only the exact-key doors ([`declared_for`]) and the
/// write doors need the one-directional check.
#[cfg(feature = "sync")]
pub(crate) fn declared_overlaps(db: SideDb, prefix: &[u8]) -> bool {
    PARTS.iter().flat_map(|part| part.iter()).any(|decl| {
        decl.db == db && (prefix.starts_with(decl.prefix) || decl.prefix.starts_with(prefix))
    })
}

/// The files in byte order of their prefixes: `sync_state`, then `vault_meta` by leading byte.
static PARTS: [&[&SideTableDecl]; 8] = [
    SYNC_STATE,
    VAULT_META_A_B,
    VAULT_META_C,
    VAULT_META_D_E,
    VAULT_META_F_L,
    VAULT_META_M_R,
    VAULT_META_S,
    VAULT_META_T_Z,
];

// A declaration list with an overlap does not compile.
const _: () = assert_disjoint(&PARTS);

/// Within one database, the declared prefixes in list order must be strictly ascending and no
/// prefix may be a byte prefix of its successor. In a sorted list a prefix of any later entry is
/// a prefix of its immediate successor, so the adjacent check covers every pair.
const fn assert_disjoint(parts: &[&[&SideTableDecl]]) {
    let mut previous: Option<&SideTableDecl> = None;
    let mut part = 0;
    while part < parts.len() {
        let mut index = 0;
        while index < parts[part].len() {
            let current = parts[part][index];
            assert!(!current.prefix.is_empty(), "a declared prefix is empty");
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
        part += 1;
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
