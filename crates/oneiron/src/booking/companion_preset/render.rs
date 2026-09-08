//! Lens rendering for companion proposals and opaque message links.

use crate::booking::BookingError;
use crate::booking::lifecycle::hex_lower;
use crate::lens::{
    ButtonControl, CollectionAtom, GeneratedLens, LensAtom, LensAtomId, LensNode, LensText,
    SelfUiAction, SelfUiActionId, SelfUiControl, SelfUiControlId, SelfUiOptionValue, SelfUiValue,
};

use super::proposal::PARTICIPANT_TOKEN_HEX_LEN;
use super::storage::{refused, surface};
use super::{CompanionProposal, ProposalChoice, ProposalId};
// -------------------------------------------------------------------------
// Surface
// -------------------------------------------------------------------------
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
pub(super) fn validate_participant_token(value: &str) -> Result<(), BookingError> {
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
