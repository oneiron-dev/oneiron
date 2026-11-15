//! K-proof (oracle) for PLAN-UC-04 stage 5a: the keys local vault tables are indexed and
//! deduplicated by keep their bytes.
//!
//! A channel assignment's slots (`purposes::channel_identity::ASSIGNMENT_INDEX_KEY`), a wave
//! plan's seal and per-task rows and its frozen statement
//! (`purposes::task::{WAVE_PLAN_INDEX_KEY, WAVE_PLAN_STATEMENT_KEY}`), a policy change's
//! follow-up index (`purposes::task::POLICY_CHANGE_FOLLOWUP_INDEX_KEY`), a skill or amendment
//! receipt's causes (`purposes::learning::{SKILL_CAUSE_RECEIPT_KEY,
//! AMENDMENT_CAUSE_RECEIPT_KEY}`), a workflow wrapper's dedupe row
//! (`purposes::agent::WORKFLOW_DEDUPE_KEY`), a graduation threshold row
//! (`purposes::learning::GRADUATION_PATTERN_KEY`) and a booking lifecycle receipt, confirm or
//! revision (`purposes::booking::LIFECYCLE_RECEIPT_KEY`), now start their BLAKE3 through the
//! fingerprint crate's K door. Each is the key of a stored row: a changed key would miss
//! every row a vault already holds. So each must give main's bytes for every value. The
//! `base_*` modules hold main's lines at 65fca8fefceb, copied by range (each range is named above
//! its copy; the generator is `lanes/kimi/OPUS-UC04-FINGERPRINT/check/gen_keep_oracle.py`)
//! and differing from them only in indentation. The few lines around the copies are
//! wrappers and aliases that carry main's private fns and tags to the tests.
//!
//! The door builds only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_index_keys`.
#![cfg(oneiron_test_support)]

use oneiron::channel_identity::AssignmentKey;
use oneiron::test_doors::fingerprint_keep_index_keys as door;
use oneiron::{EntityId, TimeRange};
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};

// Not formatted, so each copy stays line for line equal to main's.
#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_channel {
    use oneiron::channel_identity::AssignmentKey;

    // main 65fca8fefceb: crates/oneiron/src/channel_identity/assignment.rs:69-78
    fn index_key(key: &AssignmentKey) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        let channel = key.channel().as_bytes();
        let address = key.address_or_handle().as_bytes();
        hasher.update(&(channel.len() as u64).to_be_bytes());
        hasher.update(channel);
        hasher.update(&(address.len() as u64).to_be_bytes());
        hasher.update(address);
        *hasher.finalize().as_bytes()
    }

    /// Main's assignment index key, which is private there.
    pub(crate) fn main_assignment_index_key(key: &AssignmentKey) -> [u8; 32] {
        index_key(key)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_wave {
    // main 65fca8fefceb: crates/oneiron/src/task_verb/wave_port.rs:115-128
    fn index_key(plan: &str, local: &str) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(&(plan.len() as u64).to_be_bytes());
        hash.update(plan.as_bytes());
        hash.update(local.as_bytes());
        *hash.finalize().as_bytes()
    }
    /// The cut's frozen statement row. A derived-key hash, so it never collides
    /// with a seal or a per-task key.
    fn statement_key(plan: &str) -> [u8; 32] {
        let mut hash = blake3::Hasher::new_derive_key("oneiron wave plan statement v1");
        hash.update(plan.as_bytes());
        *hash.finalize().as_bytes()
    }

    /// Main's wave plan index key, which is private there.
    pub(crate) fn main_wave_plan_index_key(plan: &str, local: &str) -> [u8; 32] {
        index_key(plan, local)
    }

    /// Main's wave plan statement key, which is private there.
    pub(crate) fn main_wave_plan_statement_key(plan: &str) -> [u8; 32] {
        statement_key(plan)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_policy {
    use oneiron::EntityId;

    /// Main's index prefix, which is private there.
    // main 65fca8fefceb: crates/oneiron/src/task_verb/policy_change_followup.rs:19-19
    const INDEX_PREFIX: &[u8] = b"task.policy_change_followup.v1:";

    // main 65fca8fefceb: crates/oneiron/src/task_verb/policy_change_followup.rs:29-36
    fn index_key(receipt_id: &str, recipient: EntityId) -> Vec<u8> {
        let mut hash = blake3::Hasher::new();
        hash.update(INDEX_PREFIX);
        hash.update(&(receipt_id.len() as u64).to_be_bytes());
        hash.update(receipt_id.as_bytes());
        hash.update(recipient.as_bytes());
        [INDEX_PREFIX, hash.finalize().as_bytes()].concat()
    }

    /// Main's follow-up index key, which is private there.
    pub(crate) fn main_policy_change_followup_index_key(receipt_id: &str, recipient: EntityId) -> Vec<u8> {
        index_key(receipt_id, recipient)
    }

    /// The prefix's bytes, for the tag test outside this module.
    pub(crate) const MAIN_INDEX_PREFIX: &[u8] = INDEX_PREFIX;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_skill {
    // main 65fca8fefceb: crates/oneiron/src/skill_attribution/causes.rs:152-154
    fn receipt_key(receipt: &str) -> [u8; 32] {
        *blake3::hash(receipt.as_bytes()).as_bytes()
    }

    /// Main's skill cause receipt key, which is private there.
    pub(crate) fn main_skill_cause_receipt_key(receipt: &str) -> [u8; 32] {
        receipt_key(receipt)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_amendment {
    // main 65fca8fefceb: crates/oneiron/src/edit_distance/attribution/causes.rs:272-274
    fn receipt_key(receipt: &str) -> [u8; 32] {
        *blake3::hash(receipt.as_bytes()).as_bytes()
    }

    /// Main's amendment cause receipt key, which is private there.
    pub(crate) fn main_amendment_cause_receipt_key(receipt: &str) -> [u8; 32] {
        receipt_key(receipt)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_workflow {
    // main 65fca8fefceb: crates/oneiron/src/agent_dispatch/workflow_record.rs:202-204
    pub(super) fn dedupe_key_hash(key: &str) -> [u8; 32] {
        *blake3::hash(key.as_bytes()).as_bytes()
    }

    /// Main's workflow dedupe key hash, which is visible only to its parent there.
    pub(crate) fn main_workflow_dedupe_key_hash(key: &str) -> [u8; 32] {
        dedupe_key_hash(key)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_graduation {
    use oneiron_contracts::entity_id::ENTITY_ID_LEN;

    /// Main's tag, which is private there.
    // main 65fca8fefceb: crates/oneiron/src/edit_distance/graduation/mod.rs:97-98
    /// Domain separator for the threshold-pattern digest.
    const PATTERN_DIGEST_DOMAIN: &[u8] = b"oneiron.edit_distance.graduation.pattern.v1";

    // main 65fca8fefceb: crates/oneiron/src/edit_distance/graduation/threshold_policy.rs:160-168
    /// The 16-byte storage handle of a threshold pattern.
    pub(super) fn pattern_key(pattern: &str) -> [u8; ENTITY_ID_LEN] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PATTERN_DIGEST_DOMAIN);
        hasher.update(pattern.as_bytes());
        let mut key = [0_u8; ENTITY_ID_LEN];
        key.copy_from_slice(&hasher.finalize().as_bytes()[..ENTITY_ID_LEN]);
        key
    }

    /// Main's graduation pattern key, which is visible only to its parent there.
    pub(crate) fn main_graduation_pattern_key(pattern: &str) -> [u8; ENTITY_ID_LEN] {
        pattern_key(pattern)
    }

    /// The tag's bytes, for the tag test outside this module.
    pub(crate) const MAIN_PATTERN_DIGEST_DOMAIN: &[u8] = PATTERN_DIGEST_DOMAIN;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_booking {
    use oneiron::booking::LifecycleTokenScope;
    use oneiron::{EntityId, TimeRange};

    // main 65fca8fefceb: crates/oneiron/src/booking/lifecycle/storage.rs:80-87
    /// something only the holder can present and never an advisory input.
    pub(super) fn confirm_receipt_key(hold_hash: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(RECEIPT_KEY_DOMAIN);
        hasher.update(b"confirm\0");
        hasher.update(hold_hash);
        *hasher.finalize().as_bytes()
    }

    // main 65fca8fefceb: crates/oneiron/src/booking/lifecycle/storage.rs:102-122
    pub(super) fn revision_receipt_key(
        event_ref: &EntityId,
        target_slot: Option<TimeRange>,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(RECEIPT_KEY_DOMAIN);
        match target_slot {
            Some(slot) => {
                hasher.update(LifecycleTokenScope::Reschedule.tag());
                hasher.update(&slot.start.to_be_bytes());
                hasher.update(&slot.end.to_be_bytes());
            }
            None => {
                hasher.update(LifecycleTokenScope::Cancel.tag());
            }
        }
        hasher.update(event_ref.as_bytes());
        *hasher.finalize().as_bytes()
    }

    const RECEIPT_KEY_DOMAIN: &[u8] = b"oneiron.booking.receipt.v1\0";

    /// Main's confirm receipt key, which is visible only to its parent there.
    pub(crate) fn main_booking_confirm_receipt_key(hold_hash: &[u8; 32]) -> [u8; 32] {
        confirm_receipt_key(hold_hash)
    }

    /// Main's revision receipt key, which is visible only to its parent there.
    pub(crate) fn main_booking_revision_receipt_key(event_ref: &EntityId, target_slot: Option<TimeRange>) -> [u8; 32] {
        revision_receipt_key(event_ref, target_slot)
    }

    /// The tag's bytes, for the tag test outside this module.
    pub(crate) const MAIN_RECEIPT_KEY_DOMAIN: &[u8] = RECEIPT_KEY_DOMAIN;
}

/// Strings with the edge rows: empty, one byte, a NUL, non-ASCII, a separator, a prefix of
/// another row, and a long run.
fn strings() -> Vec<String> {
    let mut rows: Vec<String> = [
        "",
        "a",
        "\0",
        "\u{ff}\u{1F600}\u{e9}",
        "plan:7",
        "plan:",
        "receipt:0123456789abcdef",
        "gate:ffffffffffffffffffffffffffffffff",
        "skill.writing/*",
        "*",
        " spaced \t",
    ]
    .iter()
    .map(|row| (*row).to_string())
    .collect();
    rows.push("x".repeat(10_000));
    rows
}

/// Entity ids with the edge rows: all zero, all `0xFF` (reserved at the public layer, so
/// built unchecked) and two ordinary ids.
fn entity_ids() -> Vec<EntityId> {
    [[0_u8; 16], [0xff; 16], *b"0123456789abcdef", [7; 16]]
        .into_iter()
        .map(EntityId::from_bytes_unchecked)
        .collect()
}

fn purpose_shape(purpose: LegacyPurpose) -> (LegacyHash, TagMode) {
    (purpose.hash(), purpose.tag_mode())
}

#[test]
fn the_index_key_purposes_keep_main_s_tags() {
    assert_eq!(
        purposes::task::POLICY_CHANGE_FOLLOWUP_INDEX_KEY
            .tag()
            .as_bytes(),
        base_policy::MAIN_INDEX_PREFIX
    );
    assert_eq!(
        purposes::learning::GRADUATION_PATTERN_KEY.tag().as_bytes(),
        base_graduation::MAIN_PATTERN_DIGEST_DOMAIN
    );
    assert_eq!(
        purposes::booking::LIFECYCLE_RECEIPT_KEY.tag().as_bytes(),
        base_booking::MAIN_RECEIPT_KEY_DOMAIN
    );
    for purpose in [
        purposes::task::POLICY_CHANGE_FOLLOWUP_INDEX_KEY,
        purposes::learning::GRADUATION_PATTERN_KEY,
        purposes::booking::LIFECYCLE_RECEIPT_KEY,
    ] {
        assert_eq!(
            purpose_shape(purpose),
            (LegacyHash::Blake3, TagMode::HashedFirst)
        );
    }
    assert_eq!(
        purpose_shape(purposes::task::WAVE_PLAN_STATEMENT_KEY),
        (LegacyHash::Blake3, TagMode::DeriveKeyContext)
    );
    for purpose in [
        purposes::channel_identity::ASSIGNMENT_INDEX_KEY,
        purposes::task::WAVE_PLAN_INDEX_KEY,
        purposes::learning::SKILL_CAUSE_RECEIPT_KEY,
        purposes::learning::AMENDMENT_CAUSE_RECEIPT_KEY,
        purposes::agent::WORKFLOW_DEDUPE_KEY,
    ] {
        assert_eq!(
            purpose_shape(purpose),
            (LegacyHash::Blake3, TagMode::NotHashed)
        );
    }
}

#[test]
fn the_assignment_index_key_keeps_its_bytes() {
    let channels = ["email", " EMAIL ", "sms", "phone", "slack", "", "\u{1F600}"];
    let addresses = [
        "alice@example.com",
        "Alice@Example.COM",
        " bob@example.com ",
        "+15551234567",
        "@handle",
        "not an address",
        "",
    ];
    let mut rows = 0;
    for channel in channels {
        for address in addresses {
            let key = AssignmentKey::of(channel, address);
            assert_eq!(
                door::assignment_index_key(&key),
                base_channel::main_assignment_index_key(&key),
                "channel {channel:?}, address {address:?}"
            );
            rows += 1;
        }
    }
    assert_eq!(rows, 49);
}

#[test]
fn the_wave_plan_keys_keep_their_bytes() {
    let rows = strings();
    for plan in &rows {
        assert_eq!(
            door::wave_plan_statement_key(plan),
            base_wave::main_wave_plan_statement_key(plan),
            "plan {plan:?}"
        );
        for local in &rows {
            assert_eq!(
                door::wave_plan_index_key(plan, local),
                base_wave::main_wave_plan_index_key(plan, local),
                "plan {plan:?}, local {local:?}"
            );
        }
    }
}

#[test]
fn the_policy_change_followup_index_key_keeps_its_bytes() {
    for receipt in strings() {
        for recipient in entity_ids() {
            let key = door::policy_change_followup_index_key(&receipt, recipient);
            assert_eq!(
                key,
                base_policy::main_policy_change_followup_index_key(&receipt, recipient),
                "receipt {receipt:?}, recipient {recipient:?}"
            );
            assert!(key.starts_with(base_policy::MAIN_INDEX_PREFIX));
        }
    }
}

#[test]
fn the_cause_receipt_keys_keep_their_bytes() {
    for receipt in strings() {
        let skill = door::skill_cause_receipt_key(&receipt);
        let amendment = door::amendment_cause_receipt_key(&receipt);
        let workflow = door::workflow_dedupe_key_hash(&receipt);
        assert_eq!(
            skill,
            base_skill::main_skill_cause_receipt_key(&receipt),
            "{receipt:?}"
        );
        assert_eq!(
            amendment,
            base_amendment::main_amendment_cause_receipt_key(&receipt),
            "{receipt:?}"
        );
        assert_eq!(
            workflow,
            base_workflow::main_workflow_dedupe_key_hash(&receipt),
            "{receipt:?}"
        );
        // Three purpose names, one recipe: the three tables keep main's identical bytes.
        assert_eq!(skill, amendment);
        assert_eq!(skill, workflow);
    }
}

#[test]
fn the_graduation_pattern_key_keeps_its_bytes() {
    for pattern in strings() {
        assert_eq!(
            door::graduation_pattern_key(&pattern),
            base_graduation::main_graduation_pattern_key(&pattern),
            "{pattern:?}"
        );
    }
}

#[test]
fn the_booking_receipt_keys_keep_their_bytes() {
    let holds = [[0_u8; 32], [0xff; 32], *b"0123456789abcdef0123456789abcdef"];
    for hold in &holds {
        assert_eq!(
            door::booking_confirm_receipt_key(hold),
            base_booking::main_booking_confirm_receipt_key(hold),
            "hold {hold:?}"
        );
    }
    let slots = [
        None,
        Some(TimeRange { start: 0, end: 0 }),
        Some(TimeRange {
            start: 0,
            end: u64::MAX,
        }),
        Some(TimeRange {
            start: u64::MAX,
            end: u64::MAX,
        }),
        Some(TimeRange {
            start: 1_799_000_000,
            end: 1_799_003_600,
        }),
        Some(TimeRange {
            start: 1_799_003_600,
            end: 1_799_000_000,
        }),
    ];
    for event in entity_ids() {
        for slot in slots {
            assert_eq!(
                door::booking_revision_receipt_key(&event, slot),
                base_booking::main_booking_revision_receipt_key(&event, slot),
                "event {event:?}, slot {slot:?}"
            );
        }
    }
}
