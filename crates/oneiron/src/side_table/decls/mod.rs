//! The declaration list: every prefix a module keeps rows under in `vault_meta` or `sync_state`,
//! one entry each. The entries sit in five included files (by database, then leading byte) so
//! no file outgrows the size bar; they are one list in one module.
//! `no_declared_prefix_is_a_byte_prefix_of_another` pins that no entry is a byte prefix of another
//! in the same database, so two tables never read each other's rows.
//!
//! An entry names the database, the prefix bytes (unchanged from the rows already on disk) and
//! the codec. `Named` is the codec; entries on a legacy codec (`LegacyJson`, `LegacyCompact`,
//! `Raw`) keep the bytes they had and move with the next storage ABI bump. The key note on each
//! entry spells what follows the prefix.

use super::{CodecName, SideDb, SideTableDecl};

macro_rules! side_tables {
    ($list:ident; $($(#[$doc:meta])* $name:ident: $db:ident $prefix:literal $codec:ident;)+) => {
        $(
            $(#[$doc])*
            pub(crate) static $name: SideTableDecl = SideTableDecl {
                name: stringify!($name),
                db: SideDb::$db,
                prefix: $prefix,
                codec: CodecName::$codec,
            };
        )+

        /// One file's declarations, in prefix order.
        static $list: &[&SideTableDecl] = &[$(&$name),+];
    };
}

include!("sync_state.rs");
include!("vault_meta_a_c.rs");
include!("vault_meta_d_l.rs");
include!("vault_meta_m_r.rs");
include!("vault_meta_s_z.rs");

/// Every declared table.
#[cfg(test)]
pub(crate) fn declared() -> impl Iterator<Item = &'static SideTableDecl> {
    PARTS.into_iter().flatten().copied()
}

/// The files in byte order of their prefixes: `sync_state`, then `vault_meta` by leading byte.
static PARTS: [&[&SideTableDecl]; 5] = [
    SYNC_STATE,
    VAULT_META_A_C,
    VAULT_META_D_L,
    VAULT_META_M_R,
    VAULT_META_S_Z,
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
