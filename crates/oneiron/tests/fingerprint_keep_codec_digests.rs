//! K-proof (oracle) for PLAN-UC-04 stage 6.1c: four codec digests keep their bytes.
//!
//! A calendar connector literal's digest (`purposes::calendar::CONNECTOR_LITERAL`), a
//! section manifest's digest (`purposes::plugin::SECTION_MANIFEST`), the plugin suggestion
//! key that hashes it (`purposes::plugin::SUGGESTION_KEY`) and a project revision's
//! logical hash (`purposes::workspace_roster::PROJECT_REVISION_HASH`) now start their hash
//! through the fingerprint crate's K door. Each is sealed, stored or compared against a
//! stored value: the literal digests are sealed in the calendar connector's custody
//! envelope and compared when it is opened, an install claim carries the manifest digest
//! beside the manifest's bytes, an answered suggestion stays quiet by its key, and a
//! revision's companion id and its children's parent links derive from its hash on every
//! replica. So each must give main's bytes for every input. The `base_*` modules hold
//! main's lines at 4988be7d9f3e, copied by range (each range is named above its copy; the
//! generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`) and differing
//! from them only in indentation. The few lines around the copies are wrappers that carry
//! main's private fns and tags to the tests, the imports main's lines name, and a stand-in
//! for main's `crate::Result`.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_codec_digests`.
#![cfg(oneiron_test_support)]

use oneiron::EntityId;
use oneiron::context_board::{
    AuthorityLaneRef, BudgetPolicyRef, PLUGIN_SECTION_BUDGET_POLICY_REF,
    SECTION_MANIFEST_SCHEMA_VERSION, SectionId, SectionManifest, SectionManifestEnvelope,
    SectionManifestProvenance, SectionVerbRef, StateFamilyRef, encode_section_manifest,
    section_manifest_digest,
};
use oneiron::dreamer_plugin_suggest::{
    PackCandidate, WorkflowPatternNotice, plugin_suggestion_key,
};
use oneiron::skill_hub::{HubPin, HubRef};
use oneiron::test_doors::fingerprint_keep_codec_digests as door;
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};
use oneiron_records::workspace_roster::project::revision::hash_of;

/// A stand-in for main's `crate::Result`, which main's literal digest names.
type Result<T> = oneiron::Result<T>;

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_literal {
    use oneiron_records::calendar::connectors::literal::encode;
    use serde::Serialize;

    // main 4988be7d9f3e: crates/oneiron/src/calendar/connectors/literal.rs:47-49
    pub(super) fn digest<T: Serialize>(value: &T) -> crate::Result<[u8; 32]> {
        Ok(*blake3::hash(&encode(value)?).as_bytes())
    }

    /// Main's literal digest of `value`, which is private there.
    pub(crate) fn main_literal_digest<T: Serialize>(value: &T) -> [u8; 32] {
        digest(value).expect("the stand-in value encodes")
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_manifest {
    use sha2::{Digest, Sha256};

    // main 4988be7d9f3e: crates/oneiron/src/context_board/plugin/codec.rs:22-28
    /// SHA-256 over the canonical manifest bytes.
    #[must_use]
    pub fn section_manifest_digest(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().into()
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_suggest {
    use super::base_manifest::section_manifest_digest;
    use oneiron::context_board::{PluginResult, PluginSuggestionKey, encode_section_manifest};
    use oneiron::dreamer_plugin_suggest::{PackCandidate, WorkflowPatternNotice};
    use sha2::{Digest, Sha256};

    // main 4988be7d9f3e: crates/oneiron/src/dreamer_plugin_suggest/mod.rs:71-73
    /// Domain separator for the suggestion key. Pinned: changing it renames every
    /// suggestion and would un-suppress everything already answered.
    const PLUGIN_SUGGESTION_KEY_DOMAIN: &[u8] = b"oneiron.plugin_suggestion.v1";

    // main 4988be7d9f3e: crates/oneiron/src/dreamer_plugin_suggest/mod.rs:284-303
    pub fn plugin_suggestion_key(
        notice: &WorkflowPatternNotice,
        candidate: &PackCandidate,
    ) -> PluginResult<PluginSuggestionKey> {
        let manifest_bytes = encode_section_manifest(&candidate.manifest)?;
        let manifest_digest = section_manifest_digest(&manifest_bytes);

        let mut hasher = Sha256::new();
        hasher.update(PLUGIN_SUGGESTION_KEY_DOMAIN);
        for field in [
            notice.pattern_key.as_str(),
            candidate.pack_id.as_str(),
            candidate.version.as_str(),
        ] {
            hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(field.as_bytes());
        }
        hasher.update(manifest_digest);
        Ok(PluginSuggestionKey::from_digest(hasher.finalize().into()))
    }

    /// Main's tag, which is private there, for the tag test outside this module.
    pub(crate) const MAIN_SUGGESTION_TAG: &[u8] = PLUGIN_SUGGESTION_KEY_DOMAIN;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_revision {
    use oneiron_records::workspace_roster::project::revision::ProjectRevisionHash;

    // main 4988be7d9f3e: crates/oneiron-records/src/workspace_roster/project/revision.rs:8-17
    /// Domain of a revision's logical hash; distinct from every authority-log,
    /// slip, challenge, resolution and seal domain.
    pub const REVISION_HASH_DOMAIN: &[u8] = b"oneiron/project-revision/v1/";

    pub fn hash_of(canonical: &[u8]) -> ProjectRevisionHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(REVISION_HASH_DOMAIN);
        hasher.update(canonical);
        ProjectRevisionHash(*hasher.finalize().as_bytes())
    }
}

/// A stand-in seat configuration with the shapes main's carries: text, an optional
/// text, a list and a number.
#[derive(serde::Serialize)]
struct SeatConfig {
    seat_ref: String,
    calendar: Option<String>,
    scopes: Vec<String>,
    window_days: u32,
}

/// A stand-in outbox action: a unit, a struct and a newtype variant.
#[derive(serde::Serialize)]
enum Action {
    Create,
    Move { sequence: u32 },
    Cancel(String),
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

/// The texts as strings (bytes that are not UTF-8 become U+FFFD).
fn strings() -> Vec<String> {
    texts()
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .collect()
}

/// A section manifest named `name`, with `name` in its verbs and provenance too.
fn manifest(name: &str, pack_id: &str, version: &str) -> SectionManifestEnvelope {
    SectionManifestEnvelope {
        schema_version: SECTION_MANIFEST_SCHEMA_VERSION,
        manifest: SectionManifest {
            section_id: SectionId(format!("section.{name}")),
            name: name.to_owned(),
            state_family: StateFamilyRef {
                family: format!("family.{name}"),
                version: 1,
            },
            verbs: vec![
                SectionVerbRef("self.focus.refresh".to_owned()),
                SectionVerbRef(name.to_owned()),
            ],
            authority_lane: AuthorityLaneRef(format!("plugin.{name}")),
            budget_policy: BudgetPolicyRef(PLUGIN_SECTION_BUDGET_POLICY_REF.to_owned()),
            provenance: SectionManifestProvenance {
                pack_id: pack_id.to_owned(),
                skill_id: format!("skill.{name}"),
                skill_version: version.to_owned(),
                content_hash_hex: "ab".repeat(32),
            },
        },
    }
}

/// A pack candidate for `pack_id` at `version` whose manifest is named `name`.
fn candidate(pack_id: &str, version: &str, name: &str) -> PackCandidate {
    PackCandidate {
        hub_ref: HubRef {
            hub_id: EntityId::from_bytes_unchecked([7; 16]),
            ref_string: format!("{pack_id}@{version}"),
            pin: HubPin::ContentHash("ab".repeat(32)),
        },
        target_skill_ref: EntityId::from_bytes_unchecked([9; 16]),
        pack_id: pack_id.to_owned(),
        label: name.to_owned(),
        description: String::new(),
        version: version.to_owned(),
        content_hash_hex: "ab".repeat(32),
        manifest: manifest(name, pack_id, version),
    }
}

/// A notice of the workflow pattern `pattern_key`.
fn notice(pattern_key: &str) -> WorkflowPatternNotice {
    WorkflowPatternNotice {
        pattern_key: pattern_key.to_owned(),
        summary: "tracking contacts by hand across notes".to_owned(),
        evidence_refs: vec![EntityId::from_bytes_unchecked([3; 16])],
        observed_at: 1_600,
    }
}

/// Notices and candidates: each text as the pattern key with the next two as the pack id
/// and the version, then two that differ only where their first two fields split.
fn suggestions() -> Vec<(WorkflowPatternNotice, PackCandidate)> {
    let strings = strings();
    let mut out = Vec::new();
    for at in 0..strings.len() {
        let pack_id = &strings[(at + 1) % strings.len()];
        let version = &strings[(at + 2) % strings.len()];
        out.push((
            notice(&strings[at]),
            candidate(pack_id, version, &strings[at]),
        ));
    }
    out.push((notice("ab"), candidate("c", "1.0.0", "crm")));
    out.push((notice("a"), candidate("bc", "1.0.0", "crm")));
    out
}

fn purpose_shape(purpose: LegacyPurpose) -> (LegacyHash, TagMode) {
    (purpose.hash(), purpose.tag_mode())
}

#[test]
fn the_codec_digest_purposes_keep_main_s_tags() {
    assert_eq!(
        purposes::plugin::SUGGESTION_KEY.tag().as_bytes(),
        base_suggest::MAIN_SUGGESTION_TAG
    );
    assert_eq!(
        purpose_shape(purposes::plugin::SUGGESTION_KEY),
        (LegacyHash::Sha256, TagMode::HashedFirst)
    );
    assert_eq!(
        purposes::workspace_roster::PROJECT_REVISION_HASH
            .tag()
            .as_bytes(),
        base_revision::REVISION_HASH_DOMAIN
    );
    assert_eq!(
        purpose_shape(purposes::workspace_roster::PROJECT_REVISION_HASH),
        (LegacyHash::Blake3, TagMode::HashedFirst)
    );
    assert_eq!(
        purpose_shape(purposes::calendar::CONNECTOR_LITERAL),
        (LegacyHash::Blake3, TagMode::NotHashed)
    );
    assert_eq!(
        purpose_shape(purposes::plugin::SECTION_MANIFEST),
        (LegacyHash::Sha256, TagMode::NotHashed)
    );
}

#[test]
fn the_calendar_literal_digest_keeps_its_bytes() {
    let mut rows = 0;
    for (at, text) in (0_u32..).zip(strings()) {
        let scope = (
            &text,
            &SeatConfig {
                seat_ref: String::new(),
                calendar: (at % 2 == 0).then(|| text.clone()),
                scopes: vec![text.clone(), "read".to_owned()],
                window_days: at,
            },
        );
        let action = match at % 3 {
            0 => Action::Create,
            1 => Action::Move { sequence: at },
            _ => Action::Cancel(text.clone()),
        };
        let byte = u8::try_from(at).expect("ten texts");
        let outbox = (
            action,
            [byte; 16],
            u64::from(at),
            [0xab_u8; 32],
            vec![[byte; 32]; at as usize],
            u64::MAX - u64::from(at),
        );
        let cursor = (
            u64::from(at),
            [byte; 32],
            u64::MAX - u64::from(at),
            (at % 2 == 1).then(|| text.clone()),
        );
        assert_eq!(
            door::calendar_literal_digest(&scope).expect("the stand-in value encodes"),
            base_literal::main_literal_digest(&scope)
        );
        assert_eq!(
            door::calendar_literal_digest(&outbox).expect("the stand-in value encodes"),
            base_literal::main_literal_digest(&outbox)
        );
        assert_eq!(
            door::calendar_literal_digest(&cursor).expect("the stand-in value encodes"),
            base_literal::main_literal_digest(&cursor)
        );
        rows += 3;
    }
    assert_eq!(rows, 30);
}

#[test]
fn the_section_manifest_digest_keeps_its_bytes() {
    let mut rows = 0;
    for bytes in texts() {
        assert_eq!(
            section_manifest_digest(&bytes),
            base_manifest::section_manifest_digest(&bytes)
        );
        rows += 1;
    }
    for (_, candidate) in suggestions() {
        let bytes = encode_section_manifest(&candidate.manifest).expect("the manifest encodes");
        assert_eq!(
            section_manifest_digest(&bytes),
            base_manifest::section_manifest_digest(&bytes)
        );
        rows += 1;
    }
    assert_eq!(rows, 22);
}

#[test]
fn the_plugin_suggestion_key_keeps_its_bytes() {
    let suggestions = suggestions();
    assert_eq!(suggestions.len(), 12);
    for (notice, candidate) in &suggestions {
        assert_eq!(
            plugin_suggestion_key(notice, candidate).expect("the manifest encodes"),
            base_suggest::plugin_suggestion_key(notice, candidate).expect("the manifest encodes")
        );
    }
}

#[test]
fn the_project_revision_hash_keeps_its_bytes() {
    for bytes in texts() {
        assert_eq!(hash_of(&bytes).0, base_revision::hash_of(&bytes).0);
    }
}
