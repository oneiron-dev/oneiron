//! K-proof (oracle) for PLAN-UC-04 stage 6.1a: four generic digest helpers keep their bytes.
//!
//! A Coach site-skill candidate's fingerprint (`purposes::dreamer::SITE_SKILL_DISTILL`), a
//! candidate browser program's input fingerprint (`purposes::browser_library::PROGRAM_CANDIDATE`,
//! which the diagnostic pass now computes through the same helper), a feedback triage part's
//! and item's digests (`purposes::feedback::{TRIAGE_PART, TRIAGE_ITEM}`) and a claim conflict
//! packet's content address (`purposes::claim::CONFLICT_PACKET`) now start their BLAKE3
//! through the fingerprint crate's K door. Each is a stored key or a stored value that is
//! recomputed and compared: the two fingerprints key the Coach's seen markers, the triage
//! digests sit on the handoff row's work graph and every answer is checked against them, and
//! the packet row is keyed by its content address, which every load recomputes. So each
//! must give main's bytes for every input. The `base_*` modules hold main's lines at 38f343f5bacb,
//! copied by range (each range is named above its copy; the generator is
//! `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing from them only
//! in indentation. The few lines around the copies are wrappers that carry main's private
//! fns and tags to the tests, the diagnostic pass's inline lines wrapped in a function of
//! the two values they read, and stand-ins for the packet type, its codec and its error
//! that hand main's packet digest a packet's stripped bytes.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_generic_helpers`.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::fingerprint_keep_generic_helpers as door;
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_distill {
    /// Main's tag, which is private there.
    // main 38f343f5bacb: crates/oneiron/src/dreamer_runner/maintenance/site_skills/distill.rs:24-24
    const SITE_SKILL_DISTILL_DOMAIN: &[u8] = b"oneiron:coach-site-skill-distill:v1";

    // main 38f343f5bacb: crates/oneiron/src/dreamer_runner/maintenance/site_skills/distill.rs:737-746
    fn digest(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SITE_SKILL_DISTILL_DOMAIN);
        for part in parts {
            let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
            hasher.update(&len.to_be_bytes());
            hasher.update(part);
        }
        *hasher.finalize().as_bytes()
    }

    /// Main's site-skill fingerprint, which is private there.
    pub(crate) fn main_site_skill_digest(parts: &[&[u8]]) -> [u8; 32] {
        digest(parts)
    }

    /// The tag's bytes, for the tag test outside this module.
    pub(crate) const MAIN_SITE_SKILL_DISTILL_DOMAIN: &[u8] = SITE_SKILL_DISTILL_DOMAIN;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_induction {
    // main 38f343f5bacb: crates/oneiron/src/dreamer_runner/maintenance/browser_candidate.rs:6-6
    pub const CANDIDATE_DOMAIN: &[u8] = b"oneiron:browser-program-induction:v1";

    // main 38f343f5bacb: crates/oneiron/src/dreamer_runner/maintenance/browser_programs/induction/mod.rs:27-27
    pub(super) const INDUCTION_VERSION: u32 = 1;

    // main 38f343f5bacb: crates/oneiron/src/dreamer_runner/maintenance/browser_programs/induction/mod.rs:472-481
    fn digest(parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CANDIDATE_DOMAIN);
        for part in parts {
            let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
            hasher.update(&len.to_be_bytes());
            hasher.update(part);
        }
        *hasher.finalize().as_bytes()
    }

    /// Main's program candidate fingerprint, which is private there.
    pub(crate) fn main_program_candidate_digest(parts: &[&[u8]]) -> [u8; 32] {
        digest(parts)
    }

    /// The diagnostic pass's inline fingerprint of a solved group's `digest` and a
    /// diagnostic's JSON `bytes`.
    pub(crate) fn main_diagnostic_fingerprint(digest: [u8; 32], bytes: Vec<u8>) -> [u8; 32] {
        // main 38f343f5bacb: crates/oneiron/src/dreamer_runner/maintenance/browser_programs/diagnostic.rs:77-85
                    let version = INDUCTION_VERSION.to_be_bytes();
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(CANDIDATE_DOMAIN);
                    for part in [version.as_slice(), digest.as_slice(), bytes.as_slice()] {
                        let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
                        hasher.update(&len.to_be_bytes());
                        hasher.update(part);
                    }
                    let fingerprint = *hasher.finalize().as_bytes();
        fingerprint
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_work {
    /// Main's tags, which are private there.
    // main 38f343f5bacb: crates/oneiron/src/feedback/triage/work.rs:23-23
    const PART_DOMAIN: &[u8] = b"oneiron:feedback-triage:part:v1";
    // main 38f343f5bacb: crates/oneiron/src/feedback/triage/work.rs:27-27
    const ITEM_DOMAIN: &[u8] = b"oneiron:feedback-triage:item:v1";

    // main 38f343f5bacb: crates/oneiron/src/feedback/triage/work.rs:173-178
    fn digest(domain: &[u8], bytes: &[u8]) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(bytes);
        hasher.finalize().to_hex().to_string()
    }

    /// Main's part digest and item digest of `bytes`, which are private there.
    pub(crate) fn main_triage_digests(bytes: &[u8]) -> (String, String) {
        (digest(PART_DOMAIN, bytes), digest(ITEM_DOMAIN, bytes))
    }

    /// The tags' bytes, for the tag test outside this module.
    pub(crate) const MAIN_PART_DOMAIN: &[u8] = PART_DOMAIN;
    pub(crate) const MAIN_ITEM_DOMAIN: &[u8] = ITEM_DOMAIN;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_claim_conflict {
    /// A stand-in for main's packet: its own id, and the bytes main's codec writes for it
    /// once its members' raw rows are cleared.
    #[derive(Clone)]
    pub(crate) struct ClaimConflictBundle {
        pub(crate) bundle_id: [u8; 32],
        pub(crate) stripped: Vec<u8>,
    }

    /// A stand-in for main's error.
    #[derive(Debug)]
    pub(crate) struct Error;

    /// A stand-in for main's codec: the packet's stripped bytes.
    fn encode(bundle: &ClaimConflictBundle) -> Result<Vec<u8>, Error> {
        Ok(bundle.stripped.clone())
    }

    // main 38f343f5bacb: crates/oneiron/src/memory/claim_conflict.rs:60-67
    fn digest(bundle: &ClaimConflictBundle) -> Result<[u8; 32], Error> {
        let mut input = bundle.clone();
        input.bundle_id = [0; 32];
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron.consent_bundle.claim_conflict.v1\0");
        hash.update(&encode(&input)?);
        Ok(*hash.finalize().as_bytes())
    }

    /// Main's content address of a packet, which is private there.
    pub(crate) fn main_claim_conflict_digest(bundle: &ClaimConflictBundle) -> [u8; 32] {
        digest(bundle).expect("the stand-in codec never fails")
    }
}

/// Byte strings with the edge rows: empty, a NUL, one byte, an inner NUL, non-ASCII text,
/// a string and its extension, JSON, bytes that are not UTF-8, and a long run.
fn texts() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        vec![0],
        b"a".to_vec(),
        b"a\0b".to_vec(),
        "na\u{ef}ve \u{6f22}\u{5b57} \u{1f642}".as_bytes().to_vec(),
        b"part".to_vec(),
        b"part:1".to_vec(),
        br#"{"origins":["https://a.example"],"routes":[]}"#.to_vec(),
        vec![0xff; 255],
        vec![b'x'; 4096],
    ]
}

/// The parts a fingerprint frames: empty, a NUL, a version (u32 big-endian), a site and a
/// 32-byte digest.
fn part_values() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        vec![0],
        1_u32.to_be_bytes().to_vec(),
        b"a.example".to_vec(),
        vec![0xff; 32],
    ]
}

/// Every list of zero to three of `part_values()` (1 + 5 + 25 + 125 = 156 lists), and three
/// lists with a long part.
fn part_lists() -> Vec<Vec<Vec<u8>>> {
    let values = part_values();
    let mut lists = vec![Vec::new()];
    for a in &values {
        lists.push(vec![a.clone()]);
        for b in &values {
            lists.push(vec![a.clone(), b.clone()]);
            for c in &values {
                lists.push(vec![a.clone(), b.clone(), c.clone()]);
            }
        }
    }
    let long = vec![b'x'; 4096];
    lists.push(vec![long.clone()]);
    lists.push(vec![
        1_u32.to_be_bytes().to_vec(),
        b"a.example".to_vec(),
        long.clone(),
    ]);
    lists.push(vec![long, Vec::new()]);
    lists
}

/// 32-byte values with the edge rows: all zero, all `0xFF`, a counting run and a constant.
fn digests() -> [[u8; 32]; 4] {
    let mut counting = [0_u8; 32];
    for (at, byte) in counting.iter_mut().enumerate() {
        *byte = u8::try_from(at).expect("32 fits a byte");
    }
    [[0; 32], [0xff; 32], counting, [0x5a; 32]]
}

fn purpose_shape(purpose: LegacyPurpose) -> (LegacyHash, TagMode) {
    (purpose.hash(), purpose.tag_mode())
}

#[test]
fn the_generic_helper_purposes_keep_main_s_tags() {
    assert_eq!(
        purposes::dreamer::SITE_SKILL_DISTILL.tag().as_bytes(),
        base_distill::MAIN_SITE_SKILL_DISTILL_DOMAIN
    );
    assert_eq!(
        purposes::browser_library::PROGRAM_CANDIDATE
            .tag()
            .as_bytes(),
        base_induction::CANDIDATE_DOMAIN
    );
    assert_eq!(
        oneiron::browser_library::CANDIDATE_DOMAIN,
        base_induction::CANDIDATE_DOMAIN
    );
    assert_eq!(
        purposes::feedback::TRIAGE_PART.tag().as_bytes(),
        base_work::MAIN_PART_DOMAIN
    );
    assert_eq!(
        purposes::feedback::TRIAGE_ITEM.tag().as_bytes(),
        base_work::MAIN_ITEM_DOMAIN
    );
    for purpose in [
        purposes::dreamer::SITE_SKILL_DISTILL,
        purposes::browser_library::PROGRAM_CANDIDATE,
        purposes::feedback::TRIAGE_PART,
        purposes::feedback::TRIAGE_ITEM,
        purposes::claim::CONFLICT_PACKET,
    ] {
        assert_eq!(
            purpose_shape(purpose),
            (LegacyHash::Blake3, TagMode::HashedFirst)
        );
    }
}

#[test]
fn the_seen_marker_fingerprints_keep_their_bytes() {
    let lists = part_lists();
    assert_eq!(lists.len(), 159);
    for list in &lists {
        let parts: Vec<&[u8]> = list.iter().map(Vec::as_slice).collect();
        assert_eq!(
            door::site_skill_digest(&parts),
            base_distill::main_site_skill_digest(&parts)
        );
        assert_eq!(
            door::program_candidate_digest(&parts),
            base_induction::main_program_candidate_digest(&parts)
        );
    }
}

#[test]
fn the_diagnostic_fingerprint_keeps_its_bytes() {
    let mut rows = 0;
    let version = base_induction::INDUCTION_VERSION.to_be_bytes();
    for digest in digests() {
        for bytes in texts() {
            assert_eq!(
                door::program_candidate_digest(&[&version, &digest, &bytes]),
                base_induction::main_diagnostic_fingerprint(digest, bytes.clone())
            );
            rows += 1;
        }
    }
    assert_eq!(rows, 40);
}

#[test]
fn the_triage_digests_keep_their_bytes() {
    for bytes in texts() {
        let (part, item) = base_work::main_triage_digests(&bytes);
        assert_eq!(
            door::triage_digest(purposes::feedback::TRIAGE_PART, &bytes),
            part
        );
        assert_eq!(
            door::triage_digest(purposes::feedback::TRIAGE_ITEM, &bytes),
            item
        );
        assert_eq!(part.len(), 64);
    }
}

#[test]
fn the_claim_conflict_packet_digest_keeps_its_bytes() {
    let mut rows = 0;
    for bundle_id in digests() {
        for stripped in texts() {
            let bundle = base_claim_conflict::ClaimConflictBundle {
                bundle_id,
                stripped: stripped.clone(),
            };
            assert_eq!(
                door::claim_conflict_packet_digest(&stripped),
                base_claim_conflict::main_claim_conflict_digest(&bundle)
            );
            rows += 1;
        }
    }
    assert_eq!(rows, 40);
}
