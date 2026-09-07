//! ONE-1821 [BK-10] companion booking presets.
//!
//! A companion preset is a second set of *interaction* semantics over the SAME
//! solver, mask, and home-node writer the business booking page uses. It is not
//! a second booking system, and this module carries no product name: the
//! product binding is one small seam in `eiri.rs`, and the preset's behaviour
//! is pack data, not code and not an entity kind.
//!
//! # What a companion preset changes
//!
//! - the proposal page is ephemeral and companion-generated, not a hosted page;
//! - the configuration is supplied by the preset ([`CompanionPresetRow`]), so a
//!   solve performs no `booking.event_type` claim lookup — ONE-1823's
//!   `synthetic_config` arm is exactly this;
//! - the carrier is a message link, and each participant gets ONE opaque token,
//!   returned once at creation with only its hash persisted;
//! - a group answer is the intersection of the AUTHORIZED taps, recomputed at
//!   confirm time from stored state rather than trusted from a caller;
//! - the terminal step is a soft confirmation through the companion — no
//!   outbound calendar dispatch, no business inventory, no hard commitment.
//!
//! # Expiry is lazy
//!
//! `expires_at` is compared at tap and at confirm. There is no timer, wake, or
//! daemon, and correctness never depends on cleanup running: a proposal whose
//! deadline has passed is refused by the liveness test on the read path.
//!
//! # One state machine
//!
//! A single participant is a group of one. Creation, tap, intersection, and
//! confirm are the same four functions at every participant count — there is no
//! poll-style parallel implementation for groups.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::booking::constraint::validate_visitor_tz;
use crate::booking::lifecycle::{
    booking_writer, digest_with, hex_lower, mint_raw_token, put_meta, read_meta_bytes,
};
use crate::booking::{
    BookingError, ConstraintObject, EventTypeConfig, EventTypeKey, RankedSlot, SlotOracle,
    SolveRequest,
};
use crate::error::Error;
use crate::lens::{
    ButtonControl, CollectionAtom, GeneratedLens, LensAtom, LensAtomId, LensNode, LensText,
    SelfUiAction, SelfUiActionId, SelfUiControl, SelfUiControlId, SelfUiOptionValue, SelfUiValue,
};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

// -------------------------------------------------------------------------
// Ratified constants
// -------------------------------------------------------------------------

/// `vault_meta` prefix for the ephemeral proposal row.
pub const COMPANION_PROPOSAL_META_PREFIX: &[u8] = b"booking:companion_proposal:v1:";

/// The only action a proposal choice can carry. Air Canada law, restated for
/// the companion carrier: a tap is ALWAYS a button, never text.
pub const COMPANION_PROPOSAL_TAP_ACTION: &str = "booking.companion.tap_choice";

/// Prefix on the carrier reference a companion pastes into a message.
///
/// It names no origin, host, or path on purpose: ONE-1815 owns the serving
/// surface, so choosing one here would be this module deciding something it
/// does not own. What it does own is that the reference carries two opaque
/// values and nothing else.
pub const COMPANION_PROPOSAL_LINK_PREFIX: &str = "oneiron-booking-proposal:";

/// Wire version of the preset manifest. A payload carrying any other version
/// fails closed rather than being coerced.
const COMPANION_PRESET_SCHEMA_VERSION: u8 = 1;

/// Row-format byte on the companion proposal `vault_meta` value.
const COMPANION_ROW_VERSION: u8 = 1;

/// Bound on a preset id.
const MAX_PRESET_ID_BYTES: usize = 64;

/// How many curated choices one proposal offers. A shortlist, not a grid: the
/// companion asks friends to tap, and a wall of buttons is a poll.
const MAX_PROPOSAL_CHOICES: u16 = 5;

/// How many participants one proposal may issue tokens for.
const MAX_PROPOSAL_PARTICIPANTS: u16 = 16;

/// Width of a raw participant token, in lower-hex characters. Pinned to what
/// the shared minter emits; `participant_token_width_matches_the_shared_minter`
/// is what keeps the two from drifting.
const PARTICIPANT_TOKEN_HEX_LEN: usize = 64;

/// How far either side of a chosen slot the confirm re-solve looks.
///
/// The pad widens the ASK so a slot with buffers is certain to fit inside the
/// window; it never widens the ANSWER, because acceptance is exact equality on
/// the oracle's own UTC bounds.
const CONFIRM_REVALIDATE_PAD_SECS: u64 = 24 * 60 * 60;

// Domain separators, in the discipline `lifecycle.rs` established: a companion
// digest can never be replayed as a hold token digest or a session key.
const PROPOSAL_ID_DOMAIN: &[u8] = b"oneiron.booking.companion_proposal_id.v1\0";
const PARTICIPANT_TOKEN_DOMAIN: &[u8] = b"oneiron.booking.companion_participant_token.v1\0";

// -------------------------------------------------------------------------
// The preset
// -------------------------------------------------------------------------

/// How a proposal reaches its participants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalCarrier {
    MessageLink,
}

/// How a proposal terminates. A soft confirmation is the companion saying "this
/// is the one" — distinct from a business hard commit, which this path has no
/// door onto.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionConfirmationMode {
    SoftViaCompanion,
}

/// The runtime preset: the pack-data row plus the caller-supplied synthetic
/// configuration it runs the shared solver against.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompanionPresetRow {
    pub id: String,
    pub carrier: ProposalCarrier,
    pub confirmation: CompanionConfirmationMode,
    pub synthetic_event_type_config: EventTypeConfig,
    pub personal_hours: bool,
    pub generous_flex: bool,
    pub email_otp_enabled: bool,
    pub group_intersection: bool,
}

/// The pack-data envelope, in the manifest idiom the seeded-roster loader
/// established: a pinned version and a `deny_unknown_fields` body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompanionPresetManifest {
    version: u8,
    preset: CompanionPresetSeed,
}

/// The pack-data row. It declares behaviour and nothing else — no entity id, no
/// type byte, no claim subject.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompanionPresetSeed {
    id: String,
    carrier: ProposalCarrier,
    confirmation: CompanionConfirmationMode,
    personal_hours: bool,
    generous_flex: bool,
    email_otp_enabled: bool,
    group_intersection: bool,
}

/// Parses a companion preset manifest and binds it to the configuration the
/// consumer supplies.
///
/// The row is refused when it declares behaviour this module does not
/// implement. A configuration flag that is silently ignored is a lie the solver
/// would go on to honour as its opposite, so each one is either enforced or
/// documented as un-enforceable:
///
/// - `group_intersection` — the only aggregation implemented here is the
///   authorized intersection, so `false` is refused rather than ignored;
/// - `email_otp_enabled` — there is no OTP path on the companion carrier, so
///   `true` is refused;
/// - `generous_flex` — checkable against the supplied configuration: a declared
///   flex pool with no flex windows is a flag with no effect;
/// - `personal_hours` — a statement about which availability profile the
///   consumer built its configuration from. It is carried as data because this
///   module cannot tell a personal profile from a business one by inspection.
pub fn load_companion_preset(
    json: &[u8],
    synthetic_event_type_config: EventTypeConfig,
) -> Result<CompanionPresetRow, BookingError> {
    let manifest: CompanionPresetManifest = serde_json::from_slice(json).map_err(|error| {
        BookingError::InvalidConfig(format!("companion preset does not parse: {error}"))
    })?;
    if manifest.version != COMPANION_PRESET_SCHEMA_VERSION {
        return Err(BookingError::InvalidConfig(format!(
            "companion preset version must be {COMPANION_PRESET_SCHEMA_VERSION}, got {}",
            manifest.version
        )));
    }
    let seed = manifest.preset;
    validate_preset_id(&seed.id)?;
    synthetic_event_type_config.validate()?;
    if !seed.group_intersection {
        return Err(BookingError::InvalidConfig(
            "companion presets aggregate taps as the authorized intersection only".to_owned(),
        ));
    }
    if seed.email_otp_enabled {
        return Err(BookingError::InvalidConfig(
            "companion presets carry no email OTP step".to_owned(),
        ));
    }
    if seed.generous_flex && synthetic_event_type_config.flex_windows.is_empty() {
        return Err(BookingError::InvalidConfig(
            "companion preset declares generous flex but its configuration has no flex windows"
                .to_owned(),
        ));
    }
    Ok(CompanionPresetRow {
        id: seed.id,
        carrier: seed.carrier,
        confirmation: seed.confirmation,
        synthetic_event_type_config,
        personal_hours: seed.personal_hours,
        generous_flex: seed.generous_flex,
        email_otp_enabled: seed.email_otp_enabled,
        group_intersection: seed.group_intersection,
    })
}

fn validate_preset_id(value: &str) -> Result<(), BookingError> {
    if value.is_empty() || value.len() > MAX_PRESET_ID_BYTES {
        return Err(BookingError::InvalidConfig(format!(
            "companion preset id must be 1..={MAX_PRESET_ID_BYTES} bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(BookingError::InvalidConfig(
            "companion preset id must use only ASCII alnum, '.', '_', or '-'".to_owned(),
        ));
    }
    Ok(())
}

// -------------------------------------------------------------------------
// Proposal state
// -------------------------------------------------------------------------

/// Opaque proposal identity: 32 unguessable bytes, minted from the CSPRNG and
/// domain-tagged so it cannot collide with any other digest booking persists.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ProposalId(pub [u8; 32]);

/// Index of a choice within one proposal's shortlist.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ChoiceId(pub u16);

/// One tappable choice. The slot is the oracle's, verbatim — nothing here
/// rounds, widens, or invents a time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProposalChoice {
    pub id: ChoiceId,
    pub slot: RankedSlot,
    pub label: String,
}

/// The ephemeral proposal. It stores participant token HASHES, never the raw
/// tokens: the raw values exist once, in the creation return value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompanionProposal {
    pub id: ProposalId,
    #[serde(with = "entity_ref_serde")]
    pub owner_ref: EntityId,
    pub preset_id: String,
    /// The configuration key the shortlist was solved under. Stored so confirm
    /// rebuilds its re-solve from the ROW and not from a caller argument.
    pub event_type: EventTypeKey,
    /// The visitor zone the shortlist was solved in, stored for the same
    /// reason.
    pub visitor_tz: String,
    pub choices: Vec<ProposalChoice>,
    pub participant_token_hashes: BTreeSet<[u8; 32]>,
    pub expires_at: u64,
}

/// One participant's raw credential. Deliberately not `Serialize` and not
/// `Debug`: a raw token has no wire form and no log form.
pub struct OneTimeParticipantToken {
    pub participant_ordinal: u16,
    pub raw_token: String,
}

/// What proposal creation returns. The raw tokens are handed over exactly once,
/// here; every later read of the proposal sees hashes only.
pub struct CompanionProposalCreation {
    pub proposal: CompanionProposal,
    pub participant_tokens: Vec<OneTimeParticipantToken>,
}

/// One recorded tap. This is the stored form: `(participant, choice)` is unique
/// within a proposal, so the tap log is bounded by participants x choices and
/// a re-tap is idempotent rather than growth.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProposalTap {
    pub proposal_id: ProposalId,
    pub participant_token_hash: [u8; 32],
    pub choice_id: ChoiceId,
    pub tapped_at: u64,
}

/// The folded view of a proposal's taps, keyed by participant.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TapAggregate {
    pub choices_by_participant: BTreeMap<[u8; 32], BTreeSet<ChoiceId>>,
}

impl TapAggregate {
    /// Folds a tap log. Taps from a hash the proposal never issued are dropped
    /// here as well as refused on the write path, so a row that somehow carried
    /// one could still not influence an intersection.
    fn fold(proposal: &CompanionProposal, taps: &[ProposalTap]) -> Self {
        let mut choices_by_participant: BTreeMap<[u8; 32], BTreeSet<ChoiceId>> = BTreeMap::new();
        for tap in taps {
            if !proposal
                .participant_token_hashes
                .contains(&tap.participant_token_hash)
            {
                continue;
            }
            choices_by_participant
                .entry(tap.participant_token_hash)
                .or_default()
                .insert(tap.choice_id);
        }
        Self {
            choices_by_participant,
        }
    }
}

/// The terminal artifact: the companion committed to one choice, softly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompanionSoftConfirmation {
    pub proposal_id: ProposalId,
    pub selected: ProposalChoice,
    #[serde(with = "entity_ref_serde")]
    pub confirmed_by_companion: EntityId,
    pub confirmed_at: u64,
}

/// The persisted row. Proposal, tap log, and confirmation share ONE row so a
/// tap and a confirm read exactly the same bytes under the same writer lease.
#[derive(Serialize, Deserialize)]
struct CompanionProposalRow {
    proposal: CompanionProposal,
    taps: Vec<ProposalTap>,
    confirmation: Option<CompanionSoftConfirmation>,
}

// -------------------------------------------------------------------------
// Solve
// -------------------------------------------------------------------------

/// Builds the request from the preset's own configuration key.
///
/// Free text may have helped a companion assemble `constraint`, but only the
/// typed [`ConstraintObject`] reaches the oracle: [`SolveRequest`] has no text
/// field to carry a sentence in.
#[must_use]
pub fn companion_solve_request(
    preset: &CompanionPresetRow,
    window: TimeRange,
    constraint: Option<ConstraintObject>,
    visitor_tz: String,
) -> SolveRequest {
    SolveRequest {
        event_type: preset.synthetic_event_type_config.key.clone(),
        window,
        constraint,
        visitor_tz,
    }
}

/// Asks the shared oracle and freezes a curated shortlist, one opaque token per
/// participant.
///
/// No booking page is read: the configuration travelled in on `preset`, which
/// is what ONE-1823's synthetic-configuration arm exists for.
// The nine parameters are the ratified seam signature. `oracle` is an injected
// host capability and the rest are independent inputs; bundling them would hide
// which of them the proposal actually stores.
#[allow(clippy::too_many_arguments)]
pub fn create_companion_proposal(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    owner_ref: EntityId,
    preset: &CompanionPresetRow,
    window: TimeRange,
    constraint: Option<ConstraintObject>,
    visitor_tz: String,
    participant_count: usize,
    expires_at: u64,
) -> Result<CompanionProposalCreation, BookingError> {
    // Narrowing to the ordinal's own width IS the admission check, so a count
    // that survives it cannot need a fallback further down.
    let participants = u16::try_from(participant_count)
        .ok()
        .filter(|count| (1..=MAX_PROPOSAL_PARTICIPANTS).contains(count))
        .ok_or_else(|| {
            refused(format!(
                "a proposal must issue 1..={MAX_PROPOSAL_PARTICIPANTS} participant tokens"
            ))
        })?;
    validate_visitor_tz(&visitor_tz)?;

    let request = companion_solve_request(preset, window, constraint, visitor_tz);
    let solved = oracle.solve(&request)?;
    let choices = curated_shortlist(&solved.slots);
    if choices.is_empty() {
        return Err(BookingError::SlotOracle(
            "the oracle offered no slot to propose in this window".to_owned(),
        ));
    }

    // The id is minted before the tokens because every participant hash binds
    // it: that binding is what stops a token from being replayed elsewhere.
    let id = ProposalId(digest_with(PROPOSAL_ID_DOMAIN, mint_raw_token().as_bytes()));
    let mut participant_tokens = Vec::with_capacity(participant_count);
    let mut participant_token_hashes = BTreeSet::new();
    for participant_ordinal in 0..participants {
        let raw_token = mint_raw_token();
        participant_token_hashes.insert(participant_token_hash(id, &raw_token));
        participant_tokens.push(OneTimeParticipantToken {
            participant_ordinal,
            raw_token,
        });
    }

    let proposal = CompanionProposal {
        id,
        owner_ref,
        preset_id: preset.id.clone(),
        event_type: request.event_type,
        visitor_tz: request.visitor_tz,
        choices,
        participant_token_hashes,
        expires_at,
    };
    let row = CompanionProposalRow {
        proposal: proposal.clone(),
        taps: Vec::new(),
        confirmation: None,
    };
    let key = proposal_meta_key(id);
    let encoded = encode_row(&row)?;
    booking_writer(vault, |wtxn| put_meta(vault, wtxn, &key, &encoded))?;

    Ok(CompanionProposalCreation {
        proposal,
        participant_tokens,
    })
}

/// The shortlist: highest-ranked first, ties broken by the earlier start so two
/// equally-ranked slots order deterministically. The oracle's ranks and times
/// are read, never rewritten.
fn curated_shortlist(slots: &[RankedSlot]) -> Vec<ProposalChoice> {
    let mut ordered = slots.to_vec();
    ordered.sort_by(|left, right| {
        right
            .rank
            .total_cmp(&left.rank)
            .then(left.start_utc.cmp(&right.start_utc))
    });
    ordered.truncate(usize::from(MAX_PROPOSAL_CHOICES));
    // Counting in the id's own width: the truncation above is what makes that
    // safe, so no conversion is needed and none can fail.
    ordered
        .into_iter()
        .zip(0_u16..)
        .map(|(slot, index)| ProposalChoice {
            id: ChoiceId(index),
            // The label is derived from the oracle's own UTC integers, so the
            // engine ships no user-facing prose and the surface owns formatting.
            label: format!("{}-{}", slot.start_utc, slot.end_utc),
            slot,
        })
        .collect()
}

// -------------------------------------------------------------------------
// Surface
// -------------------------------------------------------------------------

/// Renders the proposal as a curated list of tap controls.
///
/// Every control is a button. There is no text input anywhere in the tree, so
/// the artifact structurally cannot carry a free-text commitment: a friend taps
/// a time or does nothing.
pub fn render_companion_proposal(
    proposal: &CompanionProposal,
) -> Result<GeneratedLens, BookingError> {
    let reference = hex_lower(&proposal.id.0);
    let mut root = LensNode::new(
        surface(LensAtomId::new(format!("companion-proposal-{reference}")))?,
        LensAtom::Sheet(CollectionAtom {
            // The sheet names the proposal by its own opaque reference. No copy
            // is shipped from here: the labels below are the oracle's times.
            title: surface(LensText::new(reference))?,
            rows: Vec::new(),
        }),
    );
    for choice in &proposal.choices {
        root.children.push(choice_button(choice)?);
    }
    surface(GeneratedLens::new(root))
}

fn choice_button(choice: &ProposalChoice) -> Result<LensNode, BookingError> {
    let control_id = format!("companion-choice-{}", choice.id.0);
    Ok(LensNode::new(
        surface(LensAtomId::new(control_id.clone()))?,
        LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
            id: surface(SelfUiControlId::new(control_id))?,
            label: surface(LensText::new(choice.label.clone()))?,
            action: SelfUiAction {
                command: surface(SelfUiActionId::new(COMPANION_PROPOSAL_TAP_ACTION))?,
                args: vec![SelfUiValue::Token(surface(SelfUiOptionValue::new(
                    choice.id.0.to_string(),
                ))?)],
            },
        })),
    ))
}

/// The carrier reference for one participant: the proposal's opaque id and that
/// participant's opaque token, and nothing else.
///
/// Neither component is derived from an entity id, an address, or any other
/// identity, so a link discloses who is invited to no one — including to the
/// other participants.
pub fn opaque_proposal_message_link(
    proposal_id: ProposalId,
    participant_token: &str,
) -> Result<String, BookingError> {
    validate_participant_token(participant_token)?;
    Ok(format!(
        "{COMPANION_PROPOSAL_LINK_PREFIX}{}.{participant_token}",
        hex_lower(&proposal_id.0)
    ))
}

/// A raw token is exactly what the shared minter emits. Checking the shape here
/// is what stops an address or a name from being carried in a link's token
/// position.
fn validate_participant_token(value: &str) -> Result<(), BookingError> {
    if value.len() != PARTICIPANT_TOKEN_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refused(format!(
            "a participant token is {PARTICIPANT_TOKEN_HEX_LEN} lower-hex characters"
        )));
    }
    Ok(())
}

// -------------------------------------------------------------------------
// Taps
// -------------------------------------------------------------------------

/// Records one participant's tap and returns the folded aggregate.
///
/// Three things are refused: a proposal past `expires_at` (the lazy check), a
/// token the proposal never issued, and a choice the shortlist does not offer.
pub fn record_proposal_tap(
    vault: &Vault,
    opaque_participant_token: &str,
    proposal_id: ProposalId,
    choice_id: ChoiceId,
    now_utc: u64,
) -> Result<TapAggregate, BookingError> {
    validate_participant_token(opaque_participant_token)?;
    let hash = participant_token_hash(proposal_id, opaque_participant_token);
    let key = proposal_meta_key(proposal_id);

    booking_writer(vault, |wtxn| {
        let mut row = load_live_row(vault, &*wtxn, &key, now_utc)?;
        if !row.proposal.participant_token_hashes.contains(&hash) {
            return Err(refused("this token was not issued for this proposal"));
        }
        if !row
            .proposal
            .choices
            .iter()
            .any(|choice| choice.id == choice_id)
        {
            return Err(refused("this proposal offers no such choice"));
        }
        // `(participant, choice)` is unique, so a re-tap is a no-op rather than
        // another row: the log cannot outgrow participants x choices.
        let already = row
            .taps
            .iter()
            .any(|tap| tap.participant_token_hash == hash && tap.choice_id == choice_id);
        if !already {
            row.taps.push(ProposalTap {
                proposal_id,
                participant_token_hash: hash,
                choice_id,
                tapped_at: now_utc,
            });
            let encoded = encode_row(&row)?;
            put_meta(vault, wtxn, &key, &encoded)?;
        }
        Ok(TapAggregate::fold(&row.proposal, &row.taps))
    })
}

/// The choices every participant who tapped has in common, highest-ranked
/// first.
///
/// Only participants the proposal issued a token to are counted, and only
/// participants who actually tapped: an invitee who never answered contributes
/// no constraint. Requiring silence to count as the empty set would make a
/// group answer impossible the moment one friend does not reply, which is the
/// ordinary case this preset exists for. The companion decides WHEN there is
/// enough to act on; this function decides WHAT they agreed to.
#[must_use]
pub fn ranked_authorized_common_intersection(
    proposal: &CompanionProposal,
    aggregate: &TapAggregate,
) -> Vec<ProposalChoice> {
    let mut authorized = aggregate
        .choices_by_participant
        .iter()
        .filter(|(participant, _)| proposal.participant_token_hashes.contains(*participant))
        .map(|(_, choices)| choices);

    let Some(first) = authorized.next() else {
        return Vec::new();
    };
    let common = authorized.fold(first.clone(), |common, choices| {
        common.intersection(choices).copied().collect()
    });

    let mut chosen: Vec<ProposalChoice> = proposal
        .choices
        .iter()
        .filter(|choice| common.contains(&choice.id))
        .cloned()
        .collect();
    chosen.sort_by(|left, right| {
        right
            .slot
            .rank
            .total_cmp(&left.slot.rank)
            .then(left.id.cmp(&right.id))
    });
    chosen
}

// -------------------------------------------------------------------------
// Soft confirm
// -------------------------------------------------------------------------

/// Picks the group's answer and records it, inside the home-node booking
/// writer.
///
/// The caller supplies no choice — it supplies identity and a clock. The
/// function reloads the proposal and its taps, refuses an expired proposal,
/// recomputes the authorized intersection from stored state, and walks it from
/// the highest rank down, taking the first slot the oracle still offers under
/// the same writer lease that records the answer. That last part is the whole
/// point: a slot that went busy while the message sat unread is re-proposed,
/// never double-booked.
///
/// `Ok(None)` means "nothing to confirm yet" — no agreement, or no agreed slot
/// survived revalidation. The proposal stays open for companion follow-up and
/// nothing is committed anywhere.
///
/// Nothing outbound happens here at any point: no event, no passport, no
/// calendar dispatch. A soft confirmation is a companion's answer, not a
/// business booking.
pub fn soft_confirm_highest_common_on_home_node(
    vault: &Vault,
    oracle: &dyn SlotOracle,
    proposal_id: ProposalId,
    companion_ref: EntityId,
    now_utc: u64,
) -> Result<Option<CompanionSoftConfirmation>, BookingError> {
    let key = proposal_meta_key(proposal_id);
    booking_writer(vault, |wtxn| {
        let mut row = load_live_row(vault, &*wtxn, &key, now_utc)?;
        // A retry is answered with the answer it was answered with the first
        // time; a second confirmation would be a second authority.
        if let Some(recorded) = &row.confirmation {
            return Ok(Some(recorded.clone()));
        }

        let aggregate = TapAggregate::fold(&row.proposal, &row.taps);
        let agreed = ranked_authorized_common_intersection(&row.proposal, &aggregate);
        let Some(selected) = first_still_offered(oracle, &row.proposal, &agreed)? else {
            return Ok(None);
        };

        let confirmation = CompanionSoftConfirmation {
            proposal_id,
            selected,
            confirmed_by_companion: companion_ref,
            confirmed_at: now_utc,
        };
        row.confirmation = Some(confirmation.clone());
        let encoded = encode_row(&row)?;
        put_meta(vault, wtxn, &key, &encoded)?;
        Ok(Some(confirmation))
    })
}

/// The first agreed choice the oracle still offers, asked in rank order.
fn first_still_offered(
    oracle: &dyn SlotOracle,
    proposal: &CompanionProposal,
    agreed: &[ProposalChoice],
) -> Result<Option<ProposalChoice>, BookingError> {
    for choice in agreed {
        let solved = oracle.solve(&SolveRequest {
            event_type: proposal.event_type.clone(),
            window: revalidate_window(&choice.slot),
            constraint: None,
            visitor_tz: proposal.visitor_tz.clone(),
        })?;
        // Equality, not containment: the oracle's UTC bounds are authoritative.
        if solved.slots.iter().any(|slot| {
            slot.start_utc == choice.slot.start_utc && slot.end_utc == choice.slot.end_utc
        }) {
            return Ok(Some(choice.clone()));
        }
    }
    Ok(None)
}

/// The inclusive engine window confirm re-solves over: the chosen slot, padded
/// far enough that its buffers cannot push it outside its own ask.
fn revalidate_window(slot: &RankedSlot) -> TimeRange {
    TimeRange {
        start: slot.start_utc.saturating_sub(CONFIRM_REVALIDATE_PAD_SECS),
        end: slot
            .end_utc
            .saturating_sub(1)
            .saturating_add(CONFIRM_REVALIDATE_PAD_SECS),
    }
}

// -------------------------------------------------------------------------
// Storage
// -------------------------------------------------------------------------

/// Reads the row and applies the lazy expiry check.
///
/// The row is not deleted on expiry. A proposal occupies no inventory, and the
/// companion may still want to read a lapsed one to re-propose from it;
/// correctness is this liveness test, never a cleanup that ran.
fn load_live_row(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    key: &[u8],
    now_utc: u64,
) -> Result<CompanionProposalRow, BookingError> {
    let Some(raw) = read_meta_bytes(vault, rtxn, key)? else {
        return Err(refused("no such proposal"));
    };
    let row = decode_row(&raw)?;
    if now_utc >= row.proposal.expires_at {
        return Err(refused("this proposal has expired"));
    }
    Ok(row)
}

fn proposal_meta_key(proposal_id: ProposalId) -> Vec<u8> {
    let mut key = Vec::with_capacity(COMPANION_PROPOSAL_META_PREFIX.len() + proposal_id.0.len());
    key.extend_from_slice(COMPANION_PROPOSAL_META_PREFIX);
    key.extend_from_slice(&proposal_id.0);
    key
}

/// The persisted hash of one participant's token, bound to its proposal.
///
/// The proposal id is part of the material, so the same raw token presented
/// against a different proposal hashes to something that proposal never issued.
fn participant_token_hash(proposal_id: ProposalId, raw_token: &str) -> [u8; 32] {
    let mut material = Vec::with_capacity(proposal_id.0.len() + raw_token.len());
    material.extend_from_slice(&proposal_id.0);
    material.extend_from_slice(raw_token.as_bytes());
    digest_with(PARTICIPANT_TOKEN_DOMAIN, &material)
}

fn encode_row(row: &CompanionProposalRow) -> Result<Vec<u8>, BookingError> {
    let mut out = vec![COMPANION_ROW_VERSION];
    out.extend(
        rmp_serde::to_vec_named(row)
            .map_err(|error| refused(format!("proposal row does not encode: {error}")))?,
    );
    Ok(out)
}

fn decode_row(raw: &[u8]) -> Result<CompanionProposalRow, BookingError> {
    let Some((&version, body)) = raw.split_first() else {
        return Err(refused("proposal row is empty"));
    };
    if version != COMPANION_ROW_VERSION {
        return Err(refused("proposal row version is unsupported"));
    }
    rmp_serde::from_slice(body)
        .map_err(|error| refused(format!("proposal row does not decode: {error}")))
}

fn refused(detail: impl Into<String>) -> BookingError {
    BookingError::InvalidConstraint(detail.into())
}

fn surface<T>(result: std::result::Result<T, Error>) -> Result<T, BookingError> {
    result.map_err(|error| BookingError::Surface(error.to_string()))
}

/// Hex spelling for the one `EntityId` field each stored shape carries. The
/// booking module keeps this adapter per file rather than sharing one, matching
/// `config.rs`, `disclosure_rung.rs`, and `lifecycle.rs`.
mod entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

// -------------------------------------------------------------------------
// Oracles
//
// Co-located, mirroring `lifecycle.rs`: several of these assertions read
// `vault_meta` bytes or the module's own source, neither of which crosses a
// public boundary.
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
    use crate::eiri::{
        EIRI_FRIEND_HANGOUT_PRESET_ID, assemble_hangout_proposal_message,
        eiri_friend_hangout_preset,
    };
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
        let vault =
            Vault::open(dir.path(), crate::VaultConfig::default()).expect("open booking vault");
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
        eiri_friend_hangout_preset(synthetic_config()).expect("friend hangout preset loads")
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
        record_proposal_tap(vault, token, proposal_id, ChoiceId(choice), NOW)
            .expect("tap is recorded")
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
        assert_eq!(preset.id, EIRI_FRIEND_HANGOUT_PRESET_ID);

        // The pack row declares behaviour and nothing else: no id, no type
        // byte, no claim subject, no page.
        let row: serde_json::Value =
            serde_json::from_str(include_str!("presets/eiri_friend_hangout_v1.json"))
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
        let preset = preset();
        assert_eq!(preset.carrier, ProposalCarrier::MessageLink);
        assert_eq!(
            preset.confirmation,
            CompanionConfirmationMode::SoftViaCompanion
        );
        assert!(preset.personal_hours, "personal hours profile");
        assert!(preset.generous_flex, "generous flex");
        assert!(preset.group_intersection, "group intersection");
        assert!(!preset.email_otp_enabled, "OTP is off");
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
            record_proposal_tap(&vault, &token, created.proposal.id, ChoiceId(0), expires_at)
                .is_err(),
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

    #[test]
    fn single_participant_and_group_use_same_state_machine() {
        let (_dir, vault) = open_vault();
        let oracle = ScriptedOracle::new(scripted_slots());

        // One participant: create, tap, confirm.
        let solo = propose(&vault, &oracle, 1);
        tap(
            &vault,
            &solo.participant_tokens[0].raw_token,
            solo.proposal.id,
            1,
        );
        let solo_answer = confirm(&vault, &oracle, solo.proposal.id).expect("a solo answer");

        // Three participants: the same four functions, in the same order.
        let group = propose(&vault, &oracle, 3);
        for participant in &group.participant_tokens {
            tap(&vault, &participant.raw_token, group.proposal.id, 1);
        }
        let group_answer = confirm(&vault, &oracle, group.proposal.id).expect("a group answer");

        assert_eq!(solo_answer.selected.slot, group_answer.selected.slot);
        assert_eq!(solo_answer.selected.id, group_answer.selected.id);
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
}
