//! Companion preset and proposal test suite.

use std::sync::Mutex;

use super::*;
use crate::booking::config::{HostAvailabilityConfig, RoutingMode, WeeklyWallWindow};
use crate::booking::{SolveRequest as SeamSolveRequest, SolveResult};
use crate::test_util::entity as id;

/// `2026-03-02T00:00:00Z`, a Monday clear of any northern DST transition.
const MONDAY: u64 = 1_772_409_600;
/// Request time: 08:00Z that Monday.
const NOW: u64 = MONDAY + 8 * 3_600;
const HOUR: u64 = 3_600;

const OWNER: u8 = 0x71;
const COMPANION: u8 = 0x72;
const HOST: u8 = 0x73;
const CALENDAR: u8 = 0x74;

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).expect("open booking vault");
    (dir, vault)
}

fn synthetic_config() -> EventTypeConfig {
    EventTypeConfig {
        key: EventTypeKey("friend-hangout".to_owned()),
        duration_min: 60,
        slot_step_min: 60,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 14 * 24 * 3_600,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: id(HOST),
            calendar_refs: vec![id(CALENDAR)],
            host_tz: "UTC".to_owned(),
            working_hours: vec![WeeklyWallWindow {
                weekday: 0,
                start_minute: 9 * 60,
                end_minute: 17 * 60,
            }],
            preferred_hours: Vec::new(),
        }],
        // The generous flex pool the preset declares.
        flex_windows: vec![WeeklyWallWindow {
            weekday: 5,
            start_minute: 10 * 60,
            end_minute: 22 * 60,
        }],
    }
}

/// The preset, loaded through the product binding — so every oracle below
/// runs against the pack-data path a caller actually uses.
fn preset() -> CompanionPresetRow {
    friend_hangout_preset(synthetic_config()).expect("friend hangout preset loads")
}

fn monday() -> TimeRange {
    TimeRange {
        start: MONDAY,
        end: MONDAY + 86_399,
    }
}

fn slot(hour: u64, rank: f32) -> RankedSlot {
    RankedSlot {
        start_utc: MONDAY + hour * HOUR,
        end_utc: MONDAY + hour * HOUR + HOUR,
        rank,
    }
}

/// Three slots whose rank order is deliberately NOT their time order, so a
/// pick by rank and a pick by "first offered" cannot be confused.
fn scripted_slots() -> Vec<RankedSlot> {
    vec![slot(15, 0.5), slot(10, 0.9), slot(12, 0.7)]
}

/// An oracle whose answer can change between calls — a new busy interval
/// arriving after the message was sent is exactly that.
struct ScriptedOracle {
    slots: Mutex<Vec<RankedSlot>>,
    seen: Mutex<Vec<SeamSolveRequest>>,
}

impl ScriptedOracle {
    fn new(slots: Vec<RankedSlot>) -> Self {
        Self {
            slots: Mutex::new(slots),
            seen: Mutex::new(Vec::new()),
        }
    }
}

impl SlotOracle for ScriptedOracle {
    fn solve(&self, req: &SeamSolveRequest) -> Result<SolveResult, BookingError> {
        self.seen.lock().expect("recorded solves").push(req.clone());
        Ok(SolveResult {
            slots: self.slots.lock().expect("scripted slots").clone(),
            flex_used: false,
            host_bindings: Vec::new(),
        })
    }
}

/// Creates a proposal for `participants` people, expiring an hour out.
fn propose(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    participants: usize,
) -> CompanionProposalCreation {
    create_companion_proposal(
        vault,
        oracle,
        id(OWNER),
        &preset(),
        monday(),
        None,
        "UTC".to_owned(),
        participants,
        NOW + HOUR,
    )
    .expect("proposal is created")
}

fn tap(vault: &Vault, token: &str, proposal_id: ProposalId, choice: u16) -> TapAggregate {
    record_proposal_tap(vault, token, proposal_id, ChoiceId(choice), NOW).expect("tap is recorded")
}

fn confirm(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    proposal_id: ProposalId,
) -> Option<CompanionSoftConfirmation> {
    soft_confirm_highest_common_on_home_node(vault, oracle, proposal_id, id(COMPANION), NOW)
        .expect("confirm runs")
}

/// Every byte in `vault_meta`, so a search for a raw secret cannot miss a
/// row by looking under the wrong prefix.
fn all_meta_bytes(vault: &Vault) -> Vec<u8> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut bytes = Vec::new();
    for entry in vault.store.vault_meta.iter(&rtxn).expect("meta scan") {
        let (key, value) = entry.expect("meta row");
        bytes.extend_from_slice(&key);
        bytes.extend_from_slice(&value);
    }
    bytes
}

/// The persisted row, read back through the production decode path.
fn stored_row(vault: &Vault, proposal_id: ProposalId) -> CompanionProposalRow {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    storage::PROPOSAL
        .get(&vault.store, &rtxn, &proposal_id.0)
        .expect("the proposal row decodes")
        .expect("the proposal row is persisted")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|slice| slice == needle)
}

// ---------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------

#[test]
fn proposal_creation_returns_raw_tokens_once_and_stores_only_hashes() {
    let (_dir, vault) = open_vault();
    let oracle = ScriptedOracle::new(scripted_slots());
    let created = propose(&vault, &oracle, 3);

    assert_eq!(created.participant_tokens.len(), 3);
    let ordinals: Vec<u16> = created
        .participant_tokens
        .iter()
        .map(|token| token.participant_ordinal)
        .collect();
    assert_eq!(ordinals, [0, 1, 2], "exactly one token per participant");
    let mut distinct: Vec<&str> = created
        .participant_tokens
        .iter()
        .map(|token| token.raw_token.as_str())
        .collect();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), 3, "no two participants share a credential");
    assert_eq!(created.proposal.participant_token_hashes.len(), 3);

    // At rest there are hashes and nothing else — and a tap, which is the
    // only other read path, does not put a raw value back on disk either.
    tap(
        &vault,
        &created.participant_tokens[0].raw_token,
        created.proposal.id,
        0,
    );
    let stored = all_meta_bytes(&vault);
    for token in &created.participant_tokens {
        assert!(
            !contains(&stored, token.raw_token.as_bytes()),
            "a raw participant token must never be at rest"
        );
    }
    // What IS at rest is the proposal-scoped hash set, and only that: the
    // row has no field a raw value could travel in.
    let row = stored_row(&vault, created.proposal.id);
    assert_eq!(
        row.proposal.participant_token_hashes,
        created.proposal.participant_token_hashes
    );
    assert_eq!(row.taps.len(), 1);
    assert!(
        created
            .proposal
            .participant_token_hashes
            .contains(&row.taps[0].participant_token_hash),
        "a tap is recorded against the issued hash, not the credential"
    );
}

#[test]
fn participant_links_are_opaque_and_proposal_scoped() {
    let (_dir, vault) = open_vault();
    let oracle = ScriptedOracle::new(scripted_slots());
    let first = propose(&vault, &oracle, 1);
    let second = propose(&vault, &oracle, 1);

    let token = first.participant_tokens[0].raw_token.clone();
    let link =
        opaque_proposal_message_link(first.proposal.id, &token).expect("a link is assembled");

    // Opaque: no identity of any kind travels in the reference.
    assert!(!link.contains(&id(OWNER).to_hex()));
    assert!(!link.contains(&id(COMPANION).to_hex()));
    assert!(!link.contains(&id(HOST).to_hex()));
    assert!(!link.contains('@'), "a link carries no address");
    assert!(!link.contains(&preset().id), "not even the preset name");
    assert!(link.starts_with(COMPANION_PROPOSAL_LINK_PREFIX));

    // Proposal-scoped: the same raw token is meaningless elsewhere, because
    // the persisted hash binds the proposal it was issued for.
    assert!(
        record_proposal_tap(&vault, &token, second.proposal.id, ChoiceId(0), NOW).is_err(),
        "a token cannot be replayed against another proposal"
    );
    let elsewhere = opaque_proposal_message_link(second.proposal.id, &token)
        .expect("the link function is pure formatting");
    assert_ne!(link, elsewhere);

    // A link position cannot be used to smuggle something that is not a
    // credential.
    assert!(opaque_proposal_message_link(first.proposal.id, "friend@example.com").is_err());
    assert!(opaque_proposal_message_link(first.proposal.id, "").is_err());
}

// ---------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------

#[test]
fn tap_after_expires_at_fails_lazily() {
    let (_dir, vault) = open_vault();
    let oracle = ScriptedOracle::new(scripted_slots());
    let created = propose(&vault, &oracle, 1);
    let token = created.participant_tokens[0].raw_token.clone();
    let expires_at = created.proposal.expires_at;

    assert!(
        record_proposal_tap(
            &vault,
            &token,
            created.proposal.id,
            ChoiceId(0),
            expires_at - 1
        )
        .is_ok(),
        "a live proposal accepts a tap"
    );
    assert!(
        record_proposal_tap(&vault, &token, created.proposal.id, ChoiceId(0), expires_at).is_err(),
        "the deadline itself is already too late"
    );
    assert!(
        record_proposal_tap(
            &vault,
            &token,
            created.proposal.id,
            ChoiceId(0),
            expires_at + 1
        )
        .is_err()
    );
    // Confirm applies the same check.
    assert!(
        soft_confirm_highest_common_on_home_node(
            &vault,
            &oracle,
            created.proposal.id,
            id(COMPANION),
            expires_at,
        )
        .is_err(),
        "confirm refuses an expired proposal too"
    );
}

// ---------------------------------------------------------------------
// Soft confirm
// ---------------------------------------------------------------------

#[test]
fn confirm_recomputes_and_picks_highest_ranked_common_choice() {
    let (_dir, vault) = open_vault();
    let oracle = ScriptedOracle::new(scripted_slots());
    let created = propose(&vault, &oracle, 2);

    // Choice 0 ranks highest overall, but only choice 1 is agreed: a union,
    // a plurality, or "the best slot on offer" would all answer 0.
    tap(
        &vault,
        &created.participant_tokens[0].raw_token,
        created.proposal.id,
        0,
    );
    tap(
        &vault,
        &created.participant_tokens[0].raw_token,
        created.proposal.id,
        1,
    );
    tap(
        &vault,
        &created.participant_tokens[1].raw_token,
        created.proposal.id,
        1,
    );
    tap(
        &vault,
        &created.participant_tokens[1].raw_token,
        created.proposal.id,
        2,
    );

    let answer = confirm(&vault, &oracle, created.proposal.id).expect("an answer");
    assert_eq!(answer.selected.id, ChoiceId(1));
    assert_eq!(answer.selected.slot, slot(12, 0.7));
    assert_eq!(answer.confirmed_by_companion, id(COMPANION));
    assert_eq!(answer.proposal_id, created.proposal.id);

    // Reloaded from stored state, not from the caller: a retry lands on the
    // very answer the first confirm recorded.
    let retry = confirm(&vault, &oracle, created.proposal.id).expect("a retry");
    assert_eq!(retry, answer);
}
