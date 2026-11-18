//! K-proof (oracle) for PLAN-UC-04 stage 6.2c: the emergency reschedule's digests, a
//! proactivity digest's locator and content hash, and a free-time policy's digest keep their
//! bytes.
//!
//! The emergency reschedule's one hash helper
//! (`oneiron_records::booking::emergency_reschedule::content_hash`) now takes a legacy purpose,
//! one per stored use (`purposes::booking::EMERGENCY_*`); a proactivity digest's locator and
//! content hash (`purposes::dreamer::PROACTIVITY_DIGEST_{LOCATOR,CONTENT_HASH}`) and a free-time
//! policy's digest (`purposes::dreamer::FREE_TIME_POLICY_DIGEST`) start through the fingerprint
//! crate's K door. Each is stored or compared: the request hash in the instruction row, three row
//! keys, the intent reference outbound effects are frozen under, the plan's and the pick's content
//! hashes, the digest's row key and its checked content hash, and the policy's `prior` with the
//! signed policy setting act that cites it. So each must give main's bytes for every input.
//! The `base_*` modules hold main's lines at 28a0ed385015, copied by range (each range is named
//! above its copy; the generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`)
//! and differing from them only in indentation. The few lines around the copies are the
//! imports main's lines name and wrappers for main's private functions.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_booking_dreamer_digests`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;

use oneiron::booking::emergency_reschedule::{
    EmergencyActionPolicy, EmergencyRescheduleRequest, OwnerInstructionRecord,
    canonical_emergency_request_hash,
};
use oneiron::dreamer_runner::maintenance::digest::{
    DigestOffer, DigestProposal, ProactivityDigest, ProactivityPresentation,
};
use oneiron::test_doors::fingerprint_keep_booking_dreamer_digests as door;
use oneiron::{AttemptId, EntityId, TimeRange};
use oneiron_authority::authority::ActSurface;
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};
use oneiron_records::booking::emergency_reschedule::content_hash;
use oneiron_records::dreamer_runner::free_time::policy::{
    FreeTimeCadence, FreeTimePolicy, FreeTimeSchedule, FreeTimeSplit,
};
use serde_json::{Value, json};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_records {
    use oneiron::booking::BookingError;
    use serde::Serialize;

    // main 28a0ed385015: crates/oneiron-records/src/booking/emergency_reschedule.rs:43-46
    pub fn content_hash(value: &impl Serialize) -> Result<[u8; 32], BookingError> {
        let bytes = serde_json::to_vec(value).map_err(storage_failure)?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    // main 28a0ed385015: crates/oneiron-records/src/booking/emergency_reschedule.rs:63-65
    pub fn storage_failure(error: impl std::fmt::Display) -> BookingError {
        BookingError::SlotOracle(format!("emergency reschedule: {error}"))
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_reschedule {
    use oneiron::booking::BookingError;
    use oneiron::booking::emergency_reschedule::{EmergencyActionPolicy, EmergencyRescheduleRequest};
    use oneiron::{EntityId, TimeRange};
    use serde::Serialize;

    use super::base_records::content_hash;

    // main 28a0ed385015: crates/oneiron/src/booking/emergency_reschedule.rs:25-25
    pub const EMERGENCY_INSTRUCTION_META_PREFIX: &[u8] = b"booking:emergency_instruction:v1:";

    // main 28a0ed385015: crates/oneiron/src/booking/emergency_reschedule/planning.rs:10-10
    pub const EMERGENCY_ITEM_META_PREFIX: &[u8] = b"booking:emergency_item:v1:";

    // main 28a0ed385015: crates/oneiron/src/booking/lifecycle/token.rs:46-48
    pub(crate) fn hex_lower(bytes: &[u8]) -> String {
        oneiron_hex::encode(bytes)
    }

    // main 28a0ed385015: crates/oneiron/src/booking/emergency_reschedule.rs:49-118
    #[derive(Serialize)]
    struct WindowFields {
        start: u64,
        end: u64,
    }

    #[derive(Serialize)]
    struct RequestFields<'a> {
        window: WindowFields,
        reason: &'a str,
        action_policy: EmergencyActionPolicy,
    }

    #[derive(Serialize)]
    struct InstructionFields<'a> {
        owner_ref: String,
        #[serde(flatten)]
        request: RequestFields<'a>,
        recorded_at: u64,
    }

    fn request_fields(
        window: TimeRange,
        reason: &str,
        action_policy: EmergencyActionPolicy,
    ) -> Result<RequestFields<'_>, BookingError> {
        if window.start > window.end || reason.trim().is_empty() || reason.len() > 4096 {
            return Err(BookingError::InvalidConstraint(
                "instruction requires an ordered window and a 1..=4096 byte reason".to_owned(),
            ));
        }
        Ok(RequestFields {
            window: WindowFields {
                start: window.start,
                end: window.end,
            },
            reason,
            action_policy,
        })
    }

    /// Canonical hash of exactly `{window, reason, action_policy}` in that order.
    /// Whitespace in the reason is preserved, never normalized into another request.
    ///
    /// # Errors
    /// Refuses an inverted window, blank/oversized reason, or encoding failure.
    pub fn canonical_emergency_request_hash(
        window: TimeRange,
        reason: &str,
        action_policy: EmergencyActionPolicy,
    ) -> Result<[u8; 32], BookingError> {
        content_hash(&request_fields(window, reason, action_policy)?)
    }

    fn instruction_key(
        owner_ref: EntityId,
        window: TimeRange,
        reason: &str,
        action_policy: EmergencyActionPolicy,
        recorded_at: u64,
    ) -> Result<Vec<u8>, BookingError> {
        let digest = content_hash(&InstructionFields {
            owner_ref: owner_ref.to_hex(),
            request: request_fields(window, reason, action_policy)?,
            recorded_at,
        })?;
        let mut key = EMERGENCY_INSTRUCTION_META_PREFIX.to_vec();
        key.extend_from_slice(hex_lower(&digest).as_bytes());
        Ok(key)
    }

    // main 28a0ed385015: crates/oneiron/src/booking/emergency_reschedule.rs:256-264
    fn request_instruction_key(request: &EmergencyRescheduleRequest) -> Result<Vec<u8>, BookingError> {
        instruction_key(
            request.owner_ref,
            request.affected_window,
            &request.reason,
            request.action_policy,
            request.authority.recorded_at,
        )
    }

    // main 28a0ed385015: crates/oneiron/src/booking/emergency_reschedule/lookup.rs:39-43
    pub(super) fn request_plan_hash(
        request: &EmergencyRescheduleRequest,
    ) -> Result<[u8; 32], BookingError> {
        content_hash(&request_instruction_key(request)?)
    }

    // main 28a0ed385015: crates/oneiron/src/booking/emergency_reschedule/planning.rs:117-130
    pub(crate) fn item_key(
        request: &EmergencyRescheduleRequest,
        event: EntityId,
    ) -> Result<Vec<u8>, BookingError> {
        let mut key = EMERGENCY_ITEM_META_PREFIX.to_vec();
        key.extend_from_slice(
            hex_lower(&content_hash(&(
                request_instruction_key(request)?,
                event.to_hex(),
            ))?)
            .as_bytes(),
        );
        Ok(key)
    }

    /// Main's instruction key, which is private there.
    pub(crate) fn main_instruction_key(
        owner_ref: EntityId,
        window: TimeRange,
        reason: &str,
        action_policy: EmergencyActionPolicy,
        recorded_at: u64,
    ) -> Result<Vec<u8>, BookingError> {
        instruction_key(owner_ref, window, reason, action_policy, recorded_at)
    }
}

#[rustfmt::skip]
mod base_digest {
    use oneiron::dreamer_runner::maintenance::digest::ProactivityDigest;
    use oneiron::{Error, Result};
    use serde::Serialize;

    // main 28a0ed385015: crates/oneiron/src/dreamer_runner/maintenance/mod.rs:97-99
    fn invalid() -> Error {
        Error::InvalidConfig("invalid Dreamer maintenance row".into())
    }

    // main 28a0ed385015: crates/oneiron/src/dreamer_runner/maintenance/digest/view.rs:154-195
    /// FIX 2332: the digest's stable locator, the hash of every field it shows
    /// as assembled, before the side-row wall reads it. It is chosen once, the
    /// digest is admitted and stored under it, and every notification and the
    /// board pointer name it. It is never checked against what the digest shows
    /// now, which the wall may have masked: [`content_hash`] is.
    pub(super) fn digest_id(digest: &ProactivityDigest) -> Result<[u8; 32]> {
        hash(&shown(digest))
    }

    /// FIX 2332: the digest's integrity check, the hash of its locator and of
    /// every field it stores as admitted; the content hash alone is left out.
    pub(super) fn content_hash(digest: &ProactivityDigest) -> Result<[u8; 32]> {
        hash(&(digest.id, shown(digest)))
    }

    /// Every field of `digest` but its locator and its content hash.
    fn shown(digest: &ProactivityDigest) -> impl Serialize + '_ {
        (
            digest.created_at,
            digest.recipient,
            digest.urgent,
            &digest.groups,
            &digest.judge_asks,
            &digest.eval_label_asks,
            &digest.offers,
            &digest.cleanup,
            &digest.note_tombstones,
            &digest.applied,
            &digest.drafter,
            &digest.health_cards,
            &digest.rendered,
            &digest.voice_style,
            &digest.presentation,
            &digest.witness,
        )
    }

    /// BLAKE3 over `value`'s JSON.
    fn hash(value: &impl Serialize) -> Result<[u8; 32]> {
        let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}

#[rustfmt::skip]
mod base_policy {
    use oneiron::{Error, Result};
    use oneiron_records::dreamer_runner::free_time::policy::FreeTimePolicy;

    // main 28a0ed385015: crates/oneiron/src/dreamer_runner/free_time/policy.rs:183-189
    /// BLAKE3 over a policy as JSON (`null` for none): the one a write
    /// replaces, or the one it leaves.
    fn policy_digest(policy: Option<&FreeTimePolicy>) -> Result<[u8; 32]> {
        let bytes = serde_json::to_vec(&policy)
            .map_err(|_| Error::InvariantViolation("free-time policy act encoding"))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    /// Main's policy digest, which is private there.
    pub(crate) fn main_policy_digest(policy: Option<&FreeTimePolicy>) -> Result<[u8; 32]> {
        policy_digest(policy)
    }
}

const BOOKING_PURPOSES: [(LegacyPurpose, &str); 7] = [
    (
        purposes::booking::EMERGENCY_REQUEST_HASH,
        "oneiron.booking.emergency_request_hash.v1",
    ),
    (
        purposes::booking::EMERGENCY_INSTRUCTION_KEY,
        "oneiron.booking.emergency_instruction_key.v1",
    ),
    (
        purposes::booking::EMERGENCY_REQUEST_PLAN_INDEX_KEY,
        "oneiron.booking.emergency_request_plan_index_key.v1",
    ),
    (
        purposes::booking::EMERGENCY_ITEM_KEY,
        "oneiron.booking.emergency_item_key.v1",
    ),
    (
        purposes::booking::EMERGENCY_EFFECT_REF,
        "oneiron.booking.emergency_effect_ref.v1",
    ),
    (
        purposes::booking::EMERGENCY_PLAN_CONTENT_HASH,
        "oneiron.booking.emergency_plan_content_hash.v1",
    ),
    (
        purposes::booking::EMERGENCY_PICK_CONTENT_HASH,
        "oneiron.booking.emergency_pick_content_hash.v1",
    ),
];

fn id(n: u8) -> EntityId {
    EntityId::from_hex(&format!("{n:02x}{}", "ab".repeat(15))).expect("a valid id")
}

fn values() -> Vec<Value> {
    vec![
        Value::Null,
        json!(true),
        json!(1),
        json!(-2.5),
        json!(u64::MAX),
        json!(""),
        json!("words with \"quotes\", ünïcode and a \u{0} byte"),
        json!({"window": {"start": 1, "end": 2}, "reason": "sick", "action_policy": "cancel"}),
        json!({"b": 1, "a": [true, null, {"nested": "x"}]}),
        json!([]),
        json!([[0, 255, 7], "0123abcd"]),
    ]
}

fn windows() -> Vec<TimeRange> {
    vec![
        TimeRange { start: 0, end: 0 },
        TimeRange { start: 0, end: 1 },
        TimeRange { start: 5, end: 4 },
        TimeRange {
            start: 1_700_000_000,
            end: 1_700_086_400,
        },
        TimeRange {
            start: u64::MAX - 1,
            end: u64::MAX,
        },
    ]
}

fn reasons() -> Vec<String> {
    vec![
        String::new(),
        "   ".into(),
        "sick".into(),
        " leading and trailing whitespace \n".into(),
        "ünïcode — 日本語 🦀".into(),
        "quote \" and \\ backslash".into(),
        "a".repeat(4096),
        "a".repeat(4097),
    ]
}

const POLICIES: [EmergencyActionPolicy; 2] = [
    EmergencyActionPolicy::Cancel,
    EmergencyActionPolicy::RequestUpdate,
];

#[test]
fn the_booking_dreamer_purposes_keep_main_s_recipes() {
    let dreamer = [
        (
            purposes::dreamer::PROACTIVITY_DIGEST_LOCATOR,
            "oneiron.dreamer.proactivity_digest_locator.v1",
        ),
        (
            purposes::dreamer::PROACTIVITY_DIGEST_CONTENT_HASH,
            "oneiron.dreamer.proactivity_digest_content_hash.v1",
        ),
        (
            purposes::dreamer::FREE_TIME_POLICY_DIGEST,
            "oneiron.dreamer.free_time_policy_digest.v1",
        ),
    ];
    for (purpose, name) in BOOKING_PURPOSES.into_iter().chain(dreamer) {
        // Main's hashes write no tag: the tag is the registry name only.
        assert_eq!(purpose.tag(), name);
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), TagMode::NotHashed);
    }
}

#[test]
fn the_emergency_content_hash_keeps_its_bytes_under_each_purpose() {
    let values = values();
    for (purpose, name) in BOOKING_PURPOSES {
        for value in &values {
            assert_eq!(
                content_hash(purpose, value).expect("the value encodes"),
                base_records::content_hash(value).expect("the value encodes"),
                "{name} {value}"
            );
        }
        // The shapes main's callers hash: a row key with an event, an item key with a content
        // hash, and a content hash with a proposal index.
        let row_key = (
            b"booking:emergency_instruction:v1:00ff".to_vec(),
            id(7).to_hex(),
        );
        let effect = (b"booking:emergency_item:v1:abcd".to_vec(), [9_u8; 32]);
        let pick = ([3_u8; 32], 2_usize, "organizer@example.test");
        assert_eq!(
            content_hash(purpose, &row_key).expect("encodes"),
            base_records::content_hash(&row_key).expect("encodes"),
            "{name}"
        );
        assert_eq!(
            content_hash(purpose, &effect).expect("encodes"),
            base_records::content_hash(&effect).expect("encodes"),
            "{name}"
        );
        assert_eq!(
            content_hash(purpose, &pick).expect("encodes"),
            base_records::content_hash(&pick).expect("encodes"),
            "{name}"
        );
    }
}

#[test]
fn the_emergency_request_hash_keeps_its_bytes() {
    let mut hashed = 0;
    for window in windows() {
        for reason in reasons() {
            for policy in POLICIES {
                let head = canonical_emergency_request_hash(window, &reason, policy).ok();
                let main =
                    base_reschedule::canonical_emergency_request_hash(window, &reason, policy).ok();
                assert_eq!(head, main, "{window:?} {reason:?} {policy:?}");
                hashed += usize::from(head.is_some());
            }
        }
    }
    // 4 ordered windows x 5 accepted reasons x 2 policies; the rest are refused on both.
    assert_eq!(hashed, 40);
}

#[test]
fn the_emergency_row_keys_keep_their_bytes() {
    let mut keyed = 0;
    for owner in [id(1), id(2)] {
        for window in windows() {
            for reason in reasons() {
                for policy in POLICIES {
                    for recorded_at in [0, 1_700_000_000, u64::MAX] {
                        let head =
                            door::instruction_key(owner, window, &reason, policy, recorded_at);
                        let main = base_reschedule::main_instruction_key(
                            owner,
                            window,
                            &reason,
                            policy,
                            recorded_at,
                        );
                        assert_eq!(
                            head.as_ref().ok(),
                            main.as_ref().ok(),
                            "{window:?} {reason:?}"
                        );
                        if head.is_err() {
                            continue;
                        }
                        keyed += 1;
                        let request = EmergencyRescheduleRequest {
                            owner_ref: owner,
                            affected_window: window,
                            reason: reason.clone(),
                            action_policy: policy,
                            authority: OwnerInstructionRecord {
                                owner_ref: owner,
                                request_hash: [0x5a; 32],
                                recorded_at,
                            },
                        };
                        assert_eq!(
                            door::request_plan_hash(&request).expect("an accepted request"),
                            base_reschedule::request_plan_hash(&request)
                                .expect("an accepted request"),
                        );
                        for event in [id(0x30), id(0x31)] {
                            assert_eq!(
                                door::item_key(&request, event).expect("an accepted request"),
                                base_reschedule::item_key(&request, event)
                                    .expect("an accepted request"),
                            );
                        }
                    }
                }
            }
        }
    }
    // 2 owners x 4 ordered windows x 5 accepted reasons x 2 policies x 3 times.
    assert_eq!(keyed, 240);
}

fn presentations() -> Vec<ProactivityPresentation> {
    vec![
        ProactivityPresentation {
            group_aliases: BTreeMap::new(),
            group_template: "{group}".into(),
            item_template: "- {summary} ({ref})".into(),
            voice_style: "plain".into(),
            urgent_groups: Vec::new(),
        },
        ProactivityPresentation {
            group_aliases: BTreeMap::from([
                ("dreamer.cleanup".into(), "Cleanup".into()),
                ("note.tombstone".into(), "Notes — 日本語".into()),
            ]),
            group_template: "## {group}\n".into(),
            item_template: "* {summary} [{ref}]".into(),
            voice_style: "warm \"quoted\"".into(),
            urgent_groups: vec!["dreamer.cleanup".into()],
        },
    ]
}

fn proactivity_digests() -> Vec<ProactivityDigest> {
    let mut out = Vec::new();
    for (n, presentation) in presentations().into_iter().enumerate() {
        for proposals in 0..=2_u8 {
            for (recipient, witness) in [
                (None, None),
                (
                    Some(id(0x40)),
                    Some(AttemptId::from_bytes(&[7; 16]).expect("16 bytes")),
                ),
            ] {
                let mut groups = BTreeMap::new();
                if proposals > 0 {
                    groups.insert(
                        "dreamer.cleanup".to_owned(),
                        (0..proposals)
                            .map(|p| DigestProposal {
                                claim_ref: id(0x50 + p),
                                revision: [p; 32],
                                summary: format!("proposal {p} — ünïcode"),
                                private_sources: Vec::new(),
                                unverified: p % 2 == 1,
                            })
                            .collect::<Vec<_>>(),
                    );
                }
                let n8 = u8::try_from(n).expect("small");
                out.push(ProactivityDigest {
                    id: [0x11 + n8 + proposals; 32],
                    content_hash: [0x22; 32],
                    created_at: 1_700_000_000 + u64::from(proposals),
                    recipient,
                    urgent: proposals == 1,
                    groups,
                    judge_asks: Vec::new(),
                    eval_label_asks: Vec::new(),
                    offers: (0..proposals)
                        .map(|p| DigestOffer {
                            offer: id(0x60 + p),
                            digest: format!("{p:064x}"),
                            summary: format!("offer {p}"),
                        })
                        .collect(),
                    cleanup: None,
                    note_tombstones: None,
                    applied: None,
                    drafter: None,
                    health_cards: Vec::new(),
                    rendered: format!("digest {n}\n{}", "line ".repeat(usize::from(proposals))),
                    voice_style: presentation.voice_style.clone(),
                    presentation: presentation.clone(),
                    witness,
                });
            }
        }
    }
    out
}

#[test]
fn the_proactivity_digest_hashes_keep_their_bytes() {
    let digests = proactivity_digests();
    assert_eq!(digests.len(), 12);
    for digest in &digests {
        assert_eq!(
            door::digest_id(digest).expect("the digest encodes"),
            base_digest::digest_id(digest).expect("the digest encodes"),
            "{digest:?}"
        );
        assert_eq!(
            door::digest_content_hash(digest).expect("the digest encodes"),
            base_digest::content_hash(digest).expect("the digest encodes"),
            "{digest:?}"
        );
    }
}

fn free_time_policies() -> Vec<FreeTimePolicy> {
    let surfaces = [
        None,
        Some(ActSurface::ThisInstall),
        Some(ActSurface::LinkedDevice { machine: id(0x70) }),
        Some(ActSurface::HostedConsole),
    ];
    let mut out = Vec::new();
    for (n, surface) in surfaces.into_iter().enumerate() {
        for agent_set in [false, true] {
            let n8 = u8::try_from(n).expect("small");
            out.push(FreeTimePolicy {
                agent: id(0x80 + n8),
                revision: [1, 2, 7, u64::MAX][n],
                total_units: 100 * u64::from(n8),
                schedule: FreeTimeSchedule {
                    cadence: if n % 2 == 0 {
                        FreeTimeCadence::Daily
                    } else {
                        FreeTimeCadence::Nightly
                    },
                    hour: [0, 3, 12, 23][n],
                    minute: [0, 15, 30, 59][n],
                    zone: ["Asia/Tokyo", "America/New_York", "UTC", "Europe/Berlin"][n].into(),
                },
                pinned_split: (n % 2 == 1).then_some(FreeTimeSplit {
                    for_human_units: 40,
                    own_time_units: 60,
                }),
                cap_shown_at_ms: 1_700_000_000_000 + u64::from(n8),
                set_by: (!agent_set).then(|| id(0x90)),
                set_by_agent: agent_set.then(|| id(0x91)),
                set_grant: agent_set.then(|| id(0x92)),
                set_at: 1_700_000_000,
                holder_not_before: (n == 3).then_some(1_700_100_000),
                surface,
                prior: [n8; 32],
            });
        }
    }
    out
}

#[test]
fn the_free_time_policy_digest_keeps_its_bytes() {
    assert_eq!(
        door::free_time_policy_digest(None).expect("no policy encodes"),
        base_policy::main_policy_digest(None).expect("no policy encodes"),
    );
    let policies = free_time_policies();
    assert_eq!(policies.len(), 8);
    for policy in &policies {
        assert_eq!(
            door::free_time_policy_digest(Some(policy)).expect("the policy encodes"),
            base_policy::main_policy_digest(Some(policy)).expect("the policy encodes"),
            "{policy:?}"
        );
    }
}
