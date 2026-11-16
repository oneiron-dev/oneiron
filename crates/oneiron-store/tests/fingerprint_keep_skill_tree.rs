//! K-proof (oracle) for PLAN-UC-04 stage 6.3a: the canonical skill tree hash keeps its bytes.
//!
//! The canonical skill tree hash (`purposes::skill::TREE_HASH`) now starts through the
//! fingerprint crate's K door. It is a skill's content identity: every skill record stores
//! it, a hub index declares it per skill, a fetch compares a Git subtree or a package with
//! the pinned or declared one, and an import compares it with a source-tree proof. So it
//! must give main's bytes for every tree, and refuse every tree main refuses. The `base`
//! module holds main's lines at 3db42b3bc550, copied by range (each range is named above its
//! copy; the generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and
//! differing from them only in indentation; one accessor below the copies reads the
//! private digest bytes.
//!
//! `cargo test --locked -p oneiron-store --test fingerprint_keep_skill_tree`.

use oneiron_contracts::fingerprint::{LegacyHash, TagMode, purposes};
use oneiron_store::write_envelope::skill_record::identity::{
    SKILL_TREE_HASH_DOMAIN, canonical_skill_tree_hash,
};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base {
    use std::collections::HashSet;

    use oneiron_contracts::error::{ArtifactError, Error, Result};
    use sha2::{Digest, Sha256};

    // main 3db42b3bc550: crates/oneiron-store/src/write_envelope/skill_record/identity.rs:15-16
    /// Upper bound on one canonicalized skill-tree path (relative, `/`-joined).
    pub const SKILL_TREE_PATH_MAX_BYTES: usize = 1024;

    // main 3db42b3bc550: crates/oneiron-store/src/write_envelope/skill_record/identity.rs:18-21
    /// Domain-separation tag for the canonical skill-tree hash. Versioned so a
    /// future canonicalization change mints a new tag instead of silently
    /// re-keying every stored identity.
    pub const SKILL_TREE_HASH_DOMAIN: &[u8] = b"oneiron.skill.tree.v1\0";

    // main 3db42b3bc550: crates/oneiron-store/src/write_envelope/skill_record/identity.rs:23-28
    /// Canonical skill identity: SHA-256 over the canonicalized file tree
    /// (ARCH-0053 §7, ONE-1735). Recomputable from any source, so the same
    /// content fetched via two hubs is ONE entity — hub refs live in the
    /// separate mutable alias/provenance layer, never in this hash.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SkillContentHash([u8; 32]);

    // main 3db42b3bc550: crates/oneiron-store/src/write_envelope/skill_record/identity.rs:58-119
    /// Computes the canonical identity of a skill file tree (ARCH-0053 §7):
    /// SHA-256 over a domain-tagged, length-prefixed, path-sorted encoding of
    /// every `(relative path, content)` pair. Input order never matters; the
    /// encoding is injective (lengths are prefixed), so no two distinct trees
    /// collide by concatenation tricks.
    ///
    /// Path canonicalization is strict and fail-closed: relative, `/`-joined,
    /// no empty / `.` / `..` segments, no backslashes, colons (kills `C:/…`
    /// drive-absolute paths), or NULs, at most [`SKILL_TREE_PATH_MAX_BYTES`]
    /// bytes, no file/directory collisions or duplicates — detection ASCII-case-folds (`Foo` vs
    /// `foo` alias on default Windows/macOS filesystems; full Unicode folding
    /// is out of scope). An empty tree has no identity.
    pub fn canonical_skill_tree_hash<'a, I>(files: I) -> Result<SkillContentHash>
    where
        I: IntoIterator<Item = (&'a str, &'a [u8])>,
    {
        let mut entries: Vec<(&str, &[u8])> = Vec::new();
        for (path, content) in files {
            validate_skill_tree_path(path)?;
            entries.push((path, content));
        }
        if entries.is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "skill tree must contain at least one file",
            )));
        }
        entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        // ASCII case-fold duplicate rejection (subsumes exact duplicates):
        // `Foo` and `foo` alias on default Windows/macOS filesystems, so
        // hashing both could authenticate a different tree from the one that
        // executes.
        let mut folded = HashSet::new();
        for (path, _) in &entries {
            if !folded.insert(path.to_ascii_lowercase()) {
                return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                    "duplicate skill tree path",
                )));
            }
        }

        for path in &folded {
            if path
                .match_indices('/')
                .any(|(index, _)| folded.contains(&path[..index]))
            {
                return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                    "skill tree path is both a file and a directory",
                )));
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(SKILL_TREE_HASH_DOMAIN);
        hasher.update((entries.len() as u64).to_be_bytes());
        for (path, content) in entries {
            hasher.update((path.len() as u64).to_be_bytes());
            hasher.update(path.as_bytes());
            hasher.update((content.len() as u64).to_be_bytes());
            hasher.update(content);
        }
        Ok(SkillContentHash(hasher.finalize().into()))
    }

    // main 3db42b3bc550: crates/oneiron-store/src/write_envelope/skill_record/identity.rs:121-139
    fn validate_skill_tree_path(path: &str) -> Result<()> {
        const CONTEXT: &str = "skill tree paths must be relative, `/`-joined, without empty/dot segments, backslashes, colons, or NULs";
        if path.is_empty()
            || path.len() > SKILL_TREE_PATH_MAX_BYTES
            || path.starts_with('/')
            || path.contains('\\')
            || path.contains(':')
            || path.contains('\0')
        {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(CONTEXT)));
        }
        if path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(CONTEXT)));
        }
        Ok(())
    }

    impl SkillContentHash {
        pub(crate) fn bytes(self) -> [u8; 32] {
            self.0
        }
    }
}

/// Main's pinned vectors: `crates/oneiron/src/skill/tests.rs` `TWO_FILE_TREE_HASH` and
/// `ONE_FILE_TREE_HASH` (`canonical_tree_hash_is_order_independent_with_pinned_vector`).
const TWO_FILE_TREE_HASH: &str = "c4f2fad6eeab4789a4560a3ee555ad9be4384b57c55f3a72b9244351a7508460";
const ONE_FILE_TREE_HASH: &str = "7e070ad60eac3f513daa2777987ec08ddcc2c8a9eaf3e42e204729c787a9cfb3";

type Tree = Vec<(String, Vec<u8>)>;

/// Main's hash and the head's of one tree; a refusal is its error's Debug text.
fn both(tree: &Tree) -> (Result<[u8; 32], String>, Result<[u8; 32], String>) {
    let files = || {
        tree.iter()
            .map(|(path, content)| (path.as_str(), content.as_slice()))
    };
    let main = base::canonical_skill_tree_hash(files())
        .map(base::SkillContentHash::bytes)
        .map_err(|error| format!("{error:?}"));
    let head = canonical_skill_tree_hash(files())
        .map(|hash| *hash.as_bytes())
        .map_err(|error| format!("{error:?}"));
    (main, head)
}

fn file(path: &str, content: &[u8]) -> (String, Vec<u8>) {
    (path.to_owned(), content.to_vec())
}

/// Trees of every shape a skill has: one file, nested paths, Unicode paths, empty and long
/// contents (on each side of SHA-256's 64-byte block), a NUL inside a content, and 300
/// generated trees of 1 to 12 files in shuffled order.
fn valid_trees() -> Vec<Tree> {
    let mut out = vec![
        vec![file("SKILL.md", b"# demo skill\n")],
        vec![
            file("SKILL.md", b"# demo skill\n"),
            file("scripts/run.sh", b"echo hi\n"),
        ],
        vec![
            file("scripts/run.sh", b"echo hi\n"),
            file("SKILL.md", b"# demo skill\n"),
        ],
        vec![file("SKILL.md", b"")],
        vec![file("a", b"\0"), file("b", b"nul \0 inside")],
        vec![
            file("docs/Überblick.md", "日本語 — 🦀".as_bytes()),
            file("SKILL.md", b"x"),
        ],
        vec![
            file("a/b/c/d/e.txt", b"deep"),
            file("a/b/f.txt", b"less deep"),
            file("z", b""),
        ],
        vec![
            file("B", b"upper"),
            file("a", b"lower"),
            file("_", b"underscore"),
        ],
        vec![file(&"p".repeat(1024), b"the longest path")],
    ];
    for len in [1, 55, 56, 63, 64, 65, 127, 128, 1000, 65_537] {
        out.push(vec![file("SKILL.md", &vec![b'm'; len])]);
        out.push(vec![
            file(&"q".repeat(len.min(1024)), b"body"),
            file("SKILL.md", b"x"),
        ]);
    }
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move |bound: u64| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) % bound
    };
    for round in 0..300_u64 {
        let files = 1 + next(12);
        let mut tree = Tree::new();
        for at in 0..files {
            let depth = next(3);
            let mut path = String::new();
            for level in 0..depth {
                path.push_str(&format!("dir{}_{level}/", next(4)));
            }
            path.push_str(&format!(
                "f{round}_{at}.{}",
                ["md", "sh", "json", "txt"][next(4) as usize]
            ));
            let content: Vec<u8> = (0..next(300)).map(|_| next(256) as u8).collect();
            tree.push((path, content));
        }
        out.push(tree);
    }
    out
}

/// Trees main refuses: no file, and each path rule, the duplicate rule (ASCII case folded)
/// and the file and directory rule.
fn invalid_trees() -> Vec<Tree> {
    let mut out = vec![Tree::new()];
    for path in [
        "", "/abs", "a\\b", "C:/x", "a:b", "a\0b", "a//b", "./a", "a/./b", "a/..", "../a", "a/",
    ] {
        out.push(vec![file("SKILL.md", b"x"), file(path, b"y")]);
    }
    out.push(vec![file(&"p".repeat(1025), b"one byte too long")]);
    out.push(vec![file("SKILL.md", b"x"), file("SKILL.md", b"x")]);
    out.push(vec![file("Foo", b"x"), file("foo", b"y")]);
    out.push(vec![file("a", b"x"), file("a/b", b"y")]);
    out.push(vec![file("A", b"x"), file("a/b", b"y")]);
    out
}

#[test]
fn the_skill_purpose_keeps_main_s_tag() {
    let purpose = purposes::skill::TREE_HASH;
    assert_eq!(purpose.tag().as_bytes(), base::SKILL_TREE_HASH_DOMAIN);
    assert_eq!(purpose.hash(), LegacyHash::Sha256);
    assert_eq!(purpose.tag_mode(), TagMode::HashedFirst);
    assert_eq!(SKILL_TREE_HASH_DOMAIN, base::SKILL_TREE_HASH_DOMAIN);
}

#[test]
fn the_skill_tree_hash_keeps_its_bytes() {
    let trees = valid_trees();
    assert_eq!(trees.len(), 329);
    for tree in &trees {
        let (main, head) = both(tree);
        let main = main.unwrap_or_else(|error| panic!("main refuses a valid tree: {error}"));
        assert_eq!(head, Ok(main), "{} files", tree.len());
    }
}

#[test]
fn the_pinned_vectors_keep_their_values() {
    let two = vec![
        file("SKILL.md", b"# demo skill\n"),
        file("scripts/run.sh", b"echo hi\n"),
    ];
    let one = vec![file("SKILL.md", b"# demo skill\n")];
    for (tree, pinned) in [(two, TWO_FILE_TREE_HASH), (one, ONE_FILE_TREE_HASH)] {
        let (main, head) = both(&tree);
        assert_eq!(oneiron_hex::encode(&main.expect("main hashes it")), pinned);
        assert_eq!(
            oneiron_hex::encode(&head.expect("the head hashes it")),
            pinned
        );
    }
}

#[test]
fn an_invalid_tree_is_refused_alike() {
    let trees = invalid_trees();
    assert_eq!(trees.len(), 18);
    for tree in &trees {
        let (main, head) = both(tree);
        assert!(main.is_err(), "main hashes an invalid tree: {tree:?}");
        assert_eq!(head, main);
    }
}
