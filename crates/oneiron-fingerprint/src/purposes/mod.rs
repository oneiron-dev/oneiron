//! The purpose registry: every [`Purpose`] and every [`LegacyPurpose`] the engine uses,
//! one file per engine area.
//!
//! A site declares its purpose with one entry in its area file:
//!
//! ```text
//! purposes! {
//!     /// Replay digest of `tasks.post`. Parts: actor, key, brief digest, assignee.
//!     POST_REQUEST = "oneiron.tasks.post.request.v1";
//! }
//! legacy_purposes! {
//!     /// Saved-query evidence hash. SHA-256: the tag, then each field as a u64-BE
//!     /// length and its bytes. Stored in memo rows (`VerdictMemoKey.evidence_hash`).
//!     SAVED_QUERY_EVIDENCE = (Sha256, HashedFirst, "oneiron.saved_query.evidence.v2");
//! }
//! ```
//!
//! Every area file writes both blocks (an empty block is fine), and the one `areas!`
//! line below both declares the file's module and adds its purposes to the
//! distinctness assertion, so no area can be left out of it. Two purposes with one
//! context string, of either kind, do not compile.
//!
//! Rules for a string:
//! - a moved site keeps its literal exactly, with no respelling;
//! - a site that has no tag gets `oneiron.<area>.<thing>.v1`;
//! - one constant per site: a purpose is for an id or for a 32-byte fingerprint, not both;
//! - a change to what is hashed is a new version (`.v2`), declared as a new constant.

use crate::{LegacyPurpose, Purpose};

/// Declares v1 purposes, and the file's `ALL` slice for the distinctness assertion.
macro_rules! purposes {
    ($($(#[$doc:meta])* $name:ident = $context:literal;)*) => {
        $($(#[$doc])* pub const $name: $crate::Purpose = $crate::Purpose::new($context);)*
        /// Every v1 purpose this file declares.
        pub const ALL: &[$crate::Purpose] = &[$($name),*];
    };
}

/// Declares legacy purposes as `NAME = (hash, tag mode, "tag");`, and the file's
/// `LEGACY` slice for the distinctness assertion.
macro_rules! legacy_purposes {
    ($($(#[$doc:meta])* $name:ident = ($hash:ident, $tag_mode:ident, $tag:literal);)*) => {
        $($(#[$doc])* pub const $name: $crate::LegacyPurpose = $crate::LegacyPurpose::new(
            $tag,
            $crate::LegacyHash::$hash,
            $crate::TagMode::$tag_mode,
        );)*
        /// Every legacy purpose this file declares.
        pub const LEGACY: &[$crate::LegacyPurpose] = &[$($name),*];
    };
}

/// Declares each area file and collects its purposes of both kinds.
macro_rules! areas {
    ($($area:ident),* $(,)?) => {
        $(pub mod $area;)*
        const PURPOSE_FILES: &[&[Purpose]] = &[$($area::ALL),*];
        const LEGACY_FILES: &[&[LegacyPurpose]] = &[$($area::LEGACY),*];
    };
}

areas! { broker, restore, testing, web_fetch }

const _: () = assert_distinct_registry(PURPOSE_FILES, LEGACY_FILES);

/// Slots of the open-addressing table the assertion fills: a power of two, at least
/// twice the number of strings it holds.
const SLOTS: usize = 8192;

/// Two context strings in the registry, of either kind, are never equal.
const fn assert_distinct_registry(purposes: &[&[Purpose]], legacy: &[&[LegacyPurpose]]) {
    let mut table = ContextTable::new();
    let mut file = 0;
    while file < purposes.len() {
        let mut at = 0;
        while at < purposes[file].len() {
            table.insert(purposes[file][at].context());
            at += 1;
        }
        file += 1;
    }
    let mut file = 0;
    while file < legacy.len() {
        let mut at = 0;
        while at < legacy[file].len() {
            table.insert(legacy[file][at].tag());
            at += 1;
        }
        file += 1;
    }
}

/// Fails to build when two strings in `groups` are equal. The registry runs the same
/// check over every purpose; this form takes plain strings.
///
/// ```
/// const _: () = oneiron_fingerprint::assert_distinct_contexts(&[
///     &["oneiron.example.a.v1"],
///     &["oneiron.example.b.v1", "oneiron.example.c.v1"],
/// ]);
/// ```
///
/// Two equal strings, even in two groups, do not compile:
///
/// ```compile_fail
/// const _: () = oneiron_fingerprint::assert_distinct_contexts(&[
///     &["oneiron.example.a.v1"],
///     &["oneiron.example.b.v1", "oneiron.example.a.v1"],
/// ]);
/// ```
pub const fn assert_distinct_contexts(groups: &[&[&str]]) {
    let mut table = ContextTable::new();
    let mut group = 0;
    while group < groups.len() {
        let mut at = 0;
        while at < groups[group].len() {
            table.insert(groups[group][at]);
            at += 1;
        }
        group += 1;
    }
}

/// An open-addressing set of strings, filled at compile time.
struct ContextTable<'a> {
    slots: [&'a str; SLOTS],
    len: usize,
}

impl<'a> ContextTable<'a> {
    const fn new() -> Self {
        Self {
            slots: [""; SLOTS],
            len: 0,
        }
    }

    const fn insert(&mut self, context: &'a str) {
        assert!(!context.is_empty(), "a context string must not be empty");
        assert!(
            self.len < SLOTS / 2,
            "the registry holds more than half of SLOTS strings: double SLOTS"
        );
        let mut slot = fnv1a(context.as_bytes()) as usize & (SLOTS - 1);
        while !self.slots[slot].is_empty() {
            assert!(
                !bytes_equal(self.slots[slot].as_bytes(), context.as_bytes()),
                "two purposes share one context string"
            );
            slot = (slot + 1) & (SLOTS - 1);
        }
        self.slots[slot] = context;
        self.len += 1;
    }
}

/// 64-bit FNV-1a: a slot index only, never a digest.
const fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut at = 0;
    while at < bytes.len() {
        hash ^= bytes[at] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        at += 1;
    }
    hash
}

const fn bytes_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut at = 0;
    while at < left.len() {
        if left[at] != right[at] {
            return false;
        }
        at += 1;
    }
    true
}
