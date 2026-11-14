//! Resolution law for channel-identity selection: scope ladder, builtins, compile overlay, resolve query.

use crate::channel_identity::ChannelIdentityShape;
use crate::entity_id::EntityId;

use super::selection_rules::{ChannelIdentitySelectionRule, ChannelIdentitySelectionRuleSet};
use super::selection_vocabulary::{
    CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION, ChannelIdentityFace, RelationshipContext,
    SelectionRuleWriterKind, is_valid_ref_token,
};

/// One host-classified identity the resolver may choose.
///
/// The host owns classification: it decides which of its `ChannelIdentity`
/// records wears which face, and this module never reads or writes those
/// records. `shape` is carried through untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityCandidate {
    pub identity_ref: EntityId,
    pub shape: ChannelIdentityShape,
    pub face: ChannelIdentityFace,
    pub active: bool,
}

/// A thread's already-established identity, supplied by ONE-1827.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityThreadPin {
    pub thread_ref: String,
    pub identity_ref: EntityId,
    pub facet_ref: Option<EntityId>,
}

impl ChannelIdentityThreadPin {
    /// The pin a thread's first passport set, in the shape the selection
    /// query takes (OF-272). `None` while no passport has landed.
    ///
    /// # Errors
    /// As [`crate::Vault::sticky_thread_mask`].
    pub fn for_thread(vault: &crate::Vault, thread_ref: &str) -> crate::Result<Option<Self>> {
        use crate::write_envelope::thread_claim::StickyMaskDecision;
        let mask = match vault.sticky_thread_mask(thread_ref, None)? {
            StickyMaskDecision::Keep(mask) | StickyMaskDecision::Conflict { pinned: mask, .. } => {
                mask
            }
            StickyMaskDecision::Unset => return Ok(None),
        };
        Ok(Some(Self {
            thread_ref: vault.canonical_thread_ref(thread_ref)?,
            identity_ref: mask.identity_ref,
            facet_ref: mask.facet_ref,
        }))
    }
}

/// One selection question.
pub struct ChannelIdentitySelectionQuery<'a> {
    /// Selection only selects; the host that keeps this value hands it to
    /// the send it builds (`OutboundDispatchRequest::send_autonomy`), where
    /// the Gate's envelope release reads it.
    pub relationship: RelationshipContext,
    /// Every scope key that applies right now. Order does not matter.
    pub applicable_scopes: &'a [SelectionRuleScope],
    pub candidates: &'a [ChannelIdentityCandidate],
    pub thread_pin: Option<&'a ChannelIdentityThreadPin>,
}

#[doc(hidden)]
pub use oneiron_verb_wire::channel_identity_selection::selection_resolution::{
    ChannelIdentitySelectionDecision, ChannelIdentitySelectionError,
    ChannelIdentitySelectionResult, SelectionRuleScope,
};

/// One amendment to the stored overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelIdentitySelectionPatch {
    Upsert(ChannelIdentitySelectionRule),
    Remove { rule_id: String },
}

/// The six compiled vault defaults, in canonical order.
///
/// Every row ships agent-amendable, including the two that route to assets the
/// owner cannot cheaply replace — the owner's own delegated account and the
/// companion face reserved for personal ties — so an agent may amend them like
/// the other built-in rows. An owner may edit or unlock every row, and an
/// exact-identity override is always canonical.
#[must_use]
pub fn builtin_channel_identity_selection_rules() -> [ChannelIdentitySelectionRule; 6] {
    [
        builtin_rule(
            "builtin.work_deal",
            RelationshipContext::WorkDeal,
            ChannelIdentityFace::DelegatedOwnerAccount,
            true,
        ),
        builtin_rule(
            "builtin.scheduling_logistics",
            RelationshipContext::SchedulingLogistics,
            ChannelIdentityFace::AgentNamedAddress,
            true,
        ),
        builtin_rule(
            "builtin.campaign_outreach",
            RelationshipContext::CampaignOutreach,
            ChannelIdentityFace::SideDomainAddress,
            true,
        ),
        builtin_rule(
            "builtin.transactional_system",
            RelationshipContext::TransactionalSystem,
            ChannelIdentityFace::HouseIdentity,
            true,
        ),
        builtin_rule(
            "builtin.personal_friends",
            RelationshipContext::PersonalFriends,
            ChannelIdentityFace::CompanionIdentity,
            true,
        ),
        builtin_rule(
            "builtin.group_space",
            RelationshipContext::GroupSpace,
            ChannelIdentityFace::NamedGroupParticipant,
            true,
        ),
    ]
}

fn builtin_rule(
    rule_id: &str,
    relationship: RelationshipContext,
    face: ChannelIdentityFace,
    agent_amendable: bool,
) -> ChannelIdentitySelectionRule {
    ChannelIdentitySelectionRule {
        rule_id: rule_id.to_owned(),
        relationship,
        scope: SelectionRuleScope::VaultDefault,
        face,
        pinned_identity_ref: None,
        priority: 0,
        enabled: true,
        agent_amendable,
        updated_at: 0,
        updated_by: None,
        writer_kind: SelectionRuleWriterKind::SystemDefault,
    }
}

/// Lays a validated stored overlay over the compiled builtins.
///
/// `None` yields the six builtins at revision `0`.
pub fn compile_channel_identity_selection(
    stored: Option<&ChannelIdentitySelectionRuleSet>,
) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionRuleSet> {
    let mut rows = builtin_channel_identity_selection_rules().to_vec();
    let Some(stored) = stored else {
        return Ok(ChannelIdentitySelectionRuleSet {
            schema_version: CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION,
            revision: 0,
            rows,
        });
    };
    stored.validate_stored()?;
    for row in &stored.rows {
        match rows.iter().position(|seat| seat.rule_id == row.rule_id) {
            Some(index) => rows[index] = row.clone(),
            None => rows.push(row.clone()),
        }
    }
    let compiled = ChannelIdentitySelectionRuleSet {
        schema_version: CHANNEL_IDENTITY_SELECTION_SCHEMA_VERSION,
        revision: stored.revision,
        rows,
    };
    compiled.validate()?;
    Ok(compiled)
}

/// Resolves one query against compiled law.
///
/// A valid thread pin wins before every mutable row. Otherwise the winning row
/// picks the face, and an active candidate wearing it is chosen by stable id
/// order — never by falling through to another face.
pub fn resolve_channel_identity_selection(
    compiled: &ChannelIdentitySelectionRuleSet,
    query: ChannelIdentitySelectionQuery<'_>,
) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionDecision> {
    validate_candidates(query.candidates)?;
    for scope in query.applicable_scopes {
        scope.validate()?;
    }
    if let Some(pin) = query.thread_pin {
        return resolve_thread_pin(pin, query.candidates);
    }
    let winner = compiled
        .rows
        .iter()
        .filter(|row| row.applies_to(query.relationship, query.applicable_scopes))
        .max_by_key(|row| row.precedence())
        .ok_or(ChannelIdentitySelectionError::NoRuleForRelationship)?;
    let chosen = match winner.pinned_identity_ref {
        Some(pinned) => pinned_row_candidate(pinned, winner.face, query.candidates)?,
        None => face_candidate(winner.face, query.candidates)?,
    };
    Ok(ChannelIdentitySelectionDecision {
        identity_ref: chosen.identity_ref,
        facet_ref: None,
        face: chosen.face,
        shape: chosen.shape,
        rule_id: Some(winner.rule_id.clone()),
        used_thread_pin: false,
    })
}

fn validate_candidates(
    candidates: &[ChannelIdentityCandidate],
) -> ChannelIdentitySelectionResult<()> {
    for (index, candidate) in candidates.iter().enumerate() {
        if candidates[..index]
            .iter()
            .any(|earlier| earlier.identity_ref == candidate.identity_ref)
        {
            return Err(ChannelIdentitySelectionError::DuplicateCandidate);
        }
    }
    Ok(())
}

/// Honors an established thread identity verbatim.
fn resolve_thread_pin(
    pin: &ChannelIdentityThreadPin,
    candidates: &[ChannelIdentityCandidate],
) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionDecision> {
    if !is_valid_ref_token(&pin.thread_ref) {
        return Err(ChannelIdentitySelectionError::MalformedThreadPin);
    }
    let candidate = active_candidate(pin.identity_ref, candidates)?;
    Ok(ChannelIdentitySelectionDecision {
        identity_ref: candidate.identity_ref,
        facet_ref: pin.facet_ref,
        face: candidate.face,
        shape: candidate.shape,
        rule_id: None,
        used_thread_pin: true,
    })
}

/// Resolves a row's exact-identity override.
///
/// The override names an identity, but the row still names a face; a candidate
/// that disagrees is a contradiction, not an invitation to switch faces.
fn pinned_row_candidate(
    pinned: EntityId,
    face: ChannelIdentityFace,
    candidates: &[ChannelIdentityCandidate],
) -> ChannelIdentitySelectionResult<&ChannelIdentityCandidate> {
    let candidate = active_candidate(pinned, candidates)?;
    if candidate.face == face {
        Ok(candidate)
    } else {
        Err(ChannelIdentitySelectionError::PinnedCandidateFaceMismatch)
    }
}

fn active_candidate(
    identity_ref: EntityId,
    candidates: &[ChannelIdentityCandidate],
) -> ChannelIdentitySelectionResult<&ChannelIdentityCandidate> {
    let candidate = candidates
        .iter()
        .find(|candidate| candidate.identity_ref == identity_ref)
        .ok_or(ChannelIdentitySelectionError::PinnedCandidateMissing)?;
    if candidate.active {
        Ok(candidate)
    } else {
        Err(ChannelIdentitySelectionError::PinnedCandidateInactive)
    }
}

fn face_candidate(
    face: ChannelIdentityFace,
    candidates: &[ChannelIdentityCandidate],
) -> ChannelIdentitySelectionResult<&ChannelIdentityCandidate> {
    candidates
        .iter()
        .filter(|candidate| candidate.active && candidate.face == face)
        .min_by_key(|candidate| candidate.identity_ref)
        .ok_or(ChannelIdentitySelectionError::NoCandidateForFace)
}
