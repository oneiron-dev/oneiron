//! Companion preset and proposal test suite.

use std::sync::Mutex;

use super::*;
use crate::booking::config::{HostAvailabilityConfig, RoutingMode, WeeklyWallWindow};
use crate::booking::lifecycle::{
    BOOKING_HOLD_META_PREFIX, BOOKING_PASSPORT_SYSTEM, BOOKING_RECEIPT_META_PREFIX,
    BOOKING_TOKEN_META_PREFIX, mint_raw_token,
};
use crate::booking::solver::{BookingSolver, NoActiveHolds};
use crate::booking::{SolveRequest as SeamSolveRequest, SolveResult};
use crate::calendar::query::CalendarSel;
use crate::lens::SelfUiControl;
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
/// A subject that carries NO `booking.event_type` claim, on purpose.
const PAGELESS: u8 = 0x75;

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

    fn offer(&self, slots: Vec<RankedSlot>) {
        *self.slots.lock().expect("scripted slots") = slots;
    }

    fn seen(&self) -> Vec<SeamSolveRequest> {
        self.seen.lock().expect("recorded solves").clone()
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
    let raw = read_meta_bytes(vault, &rtxn, &proposal_meta_key(proposal_id))
        .expect("meta read")
        .expect("the proposal row is persisted");
    decode_row(&raw).expect("the proposal row decodes")
}

fn entity_count(vault: &Vault) -> u64 {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault.store.entities.len(&rtxn).expect("entity count")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|slice| slice == needle)
}

// ---------------------------------------------------------------------
// Pack data, not a kind
// ---------------------------------------------------------------------

#[test]
fn preset_is_pack_data_not_an_entity_kind() {
    let preset = preset();
    assert_eq!(preset.id, FRIEND_HANGOUT_PRESET_ID);

    // The pack row declares behaviour and nothing else: no id, no type
    // byte, no claim subject, no page.
    let row: serde_json::Value =
        serde_json::from_str(include_str!("presets/friend_hangout_v1.json"))
            .expect("the pack row is JSON");
    let mut keys: Vec<&str> = row["preset"]
        .as_object()
        .expect("the pack row is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "carrier",
            "confirmation",
            "email_otp_enabled",
            "generous_flex",
            "group_intersection",
            "id",
            "personal_hours",
        ],
        "the pack row carries behaviour flags only"
    );
}

#[test]
fn preset_defaults_match_r9() {
    let preset = friend_hangout_preset(synthetic_config()).expect("friend hangout preset loads");
    assert!(matches!(
        preset.confirmation,
        CompanionConfirmationMode::SoftViaCompanion
    ));
    assert!(preset.group_intersection);
    assert!(!preset.email_otp_enabled);
}

#[test]
fn preset_supplies_synthetic_event_type_config_without_page() {
    let (_dir, vault) = open_vault();
    let preset = preset();
    let hosts: Vec<(EntityId, Vec<CalendarSel>)> = preset
        .synthetic_event_type_config
        .hosts
        .iter()
        .map(|host| (host.host_ref, vec![CalendarSel { system: None }]))
        .collect();
    let request = companion_solve_request(&preset, monday(), None, "UTC".to_owned());
    assert_eq!(
        request.event_type, preset.synthetic_event_type_config.key,
        "the request is keyed by the preset's own configuration"
    );

    let solved = BookingSolver {
        vault: &vault,
        page_ref: id(PAGELESS),
        calendars_by_host: &hosts,
        holds: &NoActiveHolds,
        now_utc: NOW,
        synthetic_config: Some(preset.synthetic_event_type_config),
    }
    .solve(&request)
    .expect("the shared solver runs on the preset's configuration");
    assert!(
        !solved.slots.is_empty(),
        "a page-less preset still gets slots"
    );

    // The control: the SAME solve with the synthetic arm off has to resolve
    // a `booking.event_type` claim, and that subject carries none. The
    // difference is the whole proof that no page was read.
    let page_lookup = BookingSolver {
        vault: &vault,
        page_ref: id(PAGELESS),
        calendars_by_host: &hosts,
        holds: &NoActiveHolds,
        now_utc: NOW,
        synthetic_config: None,
    }
    .solve(&request);
    assert!(
        page_lookup.is_err(),
        "without the preset there is no configuration to find"
    );
}

#[test]
fn proposal_choices_are_ranked_slot_oracle_results() {
    let (_dir, vault) = open_vault();
    let oracle = ScriptedOracle::new(scripted_slots());
    let created = propose(&vault, &oracle, 1);

    let offered = scripted_slots();
    for choice in &created.proposal.choices {
        assert!(
            offered.contains(&choice.slot),
            "every choice is a slot the oracle emitted, verbatim"
        );
        assert_eq!(
            choice.label,
            format!("{}-{}", choice.slot.start_utc, choice.slot.end_utc),
            "labels are derived from the oracle's own integers"
        );
    }
    // Highest-ranked first, and no time was invented in between.
    let ranks: Vec<f32> = created
        .proposal
        .choices
        .iter()
        .map(|choice| choice.slot.rank)
        .collect();
    assert_eq!(ranks, [0.9, 0.7, 0.5]);

    let seen = oracle.seen();
    assert_eq!(seen.len(), 1, "one solve, from the shared oracle");
    assert_eq!(seen[0].event_type, preset().synthetic_event_type_config.key);
}

// ---------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------

#[test]
fn participant_token_width_matches_the_shared_minter() {
    let raw = mint_raw_token();
    assert_eq!(raw.len(), PARTICIPANT_TOKEN_HEX_LEN);
    validate_participant_token(&raw).expect("the shared minter's output is a valid token");
}

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
// Surface
// ---------------------------------------------------------------------

#[test]
fn proposal_lens_is_ephemeral_and_button_only() {
    let (_dir, vault) = open_vault();
    let oracle = ScriptedOracle::new(scripted_slots());
    let created = propose(&vault, &oracle, 2);

    let before = all_meta_bytes(&vault);
    let lens = render_companion_proposal(&created.proposal).expect("the artifact renders");
    let again = render_companion_proposal(&created.proposal).expect("rendering is pure");
    assert_eq!(
        before,
        all_meta_bytes(&vault),
        "the artifact is ephemeral: rendering persists nothing"
    );
    assert_eq!(lens.root(), again.root(), "and is deterministic");

    let mut controls = 0_usize;
    let mut stack = vec![lens.root()];
    while let Some(node) = stack.pop() {
        if let LensAtom::SelfUi(control) = &node.atom {
            controls += 1;
            let SelfUiControl::Button(button) = control else {
                panic!("a proposal offers tap controls only, never {control:?}");
            };
            assert_eq!(
                button.action.command.as_str(),
                COMPANION_PROPOSAL_TAP_ACTION,
                "every control carries the one tap action"
            );
        }
        stack.extend(node.children.iter());
    }
    assert_eq!(
        controls,
        created.proposal.choices.len(),
        "one control per curated choice, and nothing else to press"
    );
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
// Aggregation
// ---------------------------------------------------------------------

#[test]
fn group_taps_compute_true_authorized_intersection() {
    let (_dir, vault) = open_vault();
    let oracle = ScriptedOracle::new(scripted_slots());

    // Two participants, overlapping on choice 1.
    let pair = propose(&vault, &oracle, 2);
    tap(
        &vault,
        &pair.participant_tokens[0].raw_token,
        pair.proposal.id,
        0,
    );
    tap(
        &vault,
        &pair.participant_tokens[0].raw_token,
        pair.proposal.id,
        1,
    );
    tap(
        &vault,
        &pair.participant_tokens[1].raw_token,
        pair.proposal.id,
        1,
    );
    let aggregate = tap(
        &vault,
        &pair.participant_tokens[1].raw_token,
        pair.proposal.id,
        2,
    );
    let common = ranked_authorized_common_intersection(&pair.proposal, &aggregate);
    assert_eq!(
        common.iter().map(|choice| choice.id).collect::<Vec<_>>(),
        [ChoiceId(1)],
        "the overlap, not the union"
    );

    // Three participants, one of them disjoint.
    let trio = propose(&vault, &oracle, 3);
    tap(
        &vault,
        &trio.participant_tokens[0].raw_token,
        trio.proposal.id,
        0,
    );
    tap(
        &vault,
        &trio.participant_tokens[1].raw_token,
        trio.proposal.id,
        0,
    );
    let aggregate = tap(
        &vault,
        &trio.participant_tokens[2].raw_token,
        trio.proposal.id,
        2,
    );
    assert!(
        ranked_authorized_common_intersection(&trio.proposal, &aggregate).is_empty(),
        "one disjoint answer empties the intersection"
    );

    // An unissued hash is refused at the door...
    let stranger = mint_raw_token();
    assert!(
        record_proposal_tap(&vault, &stranger, trio.proposal.id, ChoiceId(0), NOW).is_err(),
        "an unissued token cannot tap"
    );
    // ...and ignored even if one somehow reached an aggregate.
    let mut forged = aggregate;
    forged
        .choices_by_participant
        .insert([0x9E; 32], [ChoiceId(0), ChoiceId(2)].into_iter().collect());
    assert!(
        ranked_authorized_common_intersection(&trio.proposal, &forged).is_empty(),
        "an unauthorized voice constrains nothing"
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

#[test]
fn no_intersection_returns_followup_without_commit() {
    let (_dir, vault) = open_vault();
    let oracle = ScriptedOracle::new(scripted_slots());
    let created = propose(&vault, &oracle, 2);
    let entities_before = entity_count(&vault);

    tap(
        &vault,
        &created.participant_tokens[0].raw_token,
        created.proposal.id,
        0,
    );
    tap(
        &vault,
        &created.participant_tokens[1].raw_token,
        created.proposal.id,
        2,
    );
    assert!(
        confirm(&vault, &oracle, created.proposal.id).is_none(),
        "disjoint answers are a follow-up, not a booking"
    );
    assert_eq!(
        entity_count(&vault),
        entities_before,
        "nothing was created for a group that has not agreed"
    );

    // The proposal stays open: the companion follows up, a friend taps
    // again, and the same machinery answers.
    tap(
        &vault,
        &created.participant_tokens[1].raw_token,
        created.proposal.id,
        0,
    );
    let answer = confirm(&vault, &oracle, created.proposal.id).expect("the follow-up lands");
    assert_eq!(answer.selected.id, ChoiceId(0));
}

#[test]
fn soft_confirm_revalidates_on_home_node_writer() {
    let (_dir, vault) = open_vault();
    let oracle = ScriptedOracle::new(scripted_slots());
    let created = propose(&vault, &oracle, 2);

    // Both friends agree on choices 0 and 1.
    for participant in &created.participant_tokens {
        tap(&vault, &participant.raw_token, created.proposal.id, 0);
        tap(&vault, &participant.raw_token, created.proposal.id, 1);
    }
    render_companion_proposal(&created.proposal).expect("the page renders");

    // A new busy interval takes the top-ranked slot while the message sits
    // unread.
    oracle.offer(vec![slot(12, 0.7), slot(15, 0.5)]);
    let answer = confirm(&vault, &oracle, created.proposal.id).expect("an answer");
    assert_eq!(
        answer.selected.id,
        ChoiceId(1),
        "the stale pick is re-proposed, not double-booked"
    );

    // And when nothing agreed survives, there is no answer at all.
    let other = propose(&vault, &oracle, 1);
    tap(
        &vault,
        &other.participant_tokens[0].raw_token,
        other.proposal.id,
        0,
    );
    oracle.offer(Vec::new());
    assert!(
        confirm(&vault, &oracle, other.proposal.id).is_none(),
        "an agreement the solver no longer offers is not a booking"
    );
}

#[test]
fn soft_confirm_emits_no_imip_hard_commit() {
    let (_dir, vault) = open_vault();
    let oracle = ScriptedOracle::new(scripted_slots());
    let created = propose(&vault, &oracle, 1);
    let entities_before = entity_count(&vault);

    tap(
        &vault,
        &created.participant_tokens[0].raw_token,
        created.proposal.id,
        0,
    );
    let answer = confirm(&vault, &oracle, created.proposal.id).expect("a soft answer");
    assert_eq!(answer.selected.id, ChoiceId(0));

    // A tap produced an answer and nothing else: no booking entity, no
    // lifecycle hold, token, or receipt row, and no outbound identity.
    assert_eq!(entity_count(&vault), entities_before);
    let stored = all_meta_bytes(&vault);
    for prefix in [
        BOOKING_HOLD_META_PREFIX,
        BOOKING_TOKEN_META_PREFIX,
        BOOKING_RECEIPT_META_PREFIX,
    ] {
        assert!(
            !contains(&stored, prefix),
            "a soft confirmation writes no lifecycle row"
        );
    }
    assert!(
        !contains(&stored, BOOKING_PASSPORT_SYSTEM.as_bytes()),
        "and mints no outbound calendar identity"
    );
}

// ---------------------------------------------------------------------
// The binding
// ---------------------------------------------------------------------

#[test]
fn eiri_assembly_carries_existing_proposal_link() {
    let (_dir, vault) = open_vault();
    let oracle = ScriptedOracle::new(scripted_slots());
    let created = propose(&vault, &oracle, 1);
    let link = opaque_proposal_message_link(
        created.proposal.id,
        &created.participant_tokens[0].raw_token,
    )
    .expect("a link");

    let assembly = assemble_hangout_proposal_message(&created.proposal, link.clone());
    assert_eq!(assembly.proposal_id, created.proposal.id);
    assert_eq!(
        assembly.message_link, link,
        "the binding carries the existing link rather than minting one"
    );
    assert_eq!(
        assembly.choice_labels,
        created
            .proposal
            .choices
            .iter()
            .map(|choice| choice.label.clone())
            .collect::<Vec<_>>(),
        "and reads the proposal's own labels"
    );
}

// ---------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------

#[test]
fn loader_refuses_a_row_whose_flags_it_would_have_to_ignore() {
    let config = synthetic_config();
    let row = |body: &str| {
        load_companion_preset(
            format!(r#"{{"version":1,"preset":{body}}}"#).as_bytes(),
            config.clone(),
        )
    };
    let flags = |group: bool, otp: bool| {
        format!(
            r#"{{"id":"p.v1","carrier":"message_link","confirmation":"soft_via_companion",
                     "personal_hours":true,"generous_flex":true,"email_otp_enabled":{otp},
                     "group_intersection":{group}}}"#
        )
    };
    assert!(row(&flags(true, false)).is_ok());
    assert!(
        row(&flags(false, false)).is_err(),
        "an aggregation this module does not implement is refused, not ignored"
    );
    assert!(
        row(&flags(true, true)).is_err(),
        "an OTP step that does not exist is refused, not ignored"
    );

    // A declared flex pool with no windows behind it is a flag with no
    // effect.
    let mut flexless = synthetic_config();
    flexless.flex_windows.clear();
    assert!(
        load_companion_preset(
            format!(r#"{{"version":1,"preset":{}}}"#, flags(true, false)).as_bytes(),
            flexless,
        )
        .is_err()
    );

    // Version pinning and unknown keys both fail closed.
    assert!(
        load_companion_preset(
            format!(r#"{{"version":2,"preset":{}}}"#, flags(true, false)).as_bytes(),
            config.clone(),
        )
        .is_err()
    );
    assert!(
        load_companion_preset(
            br#"{"version":1,"preset":{"id":"p.v1","surprise":true}}"#,
            config,
        )
        .is_err()
    );
}
