//! The words of a rung-2 first send and of its answers on the page
//! (INBOX-RESIDUE PR-3b-3b). Every sentence here is DRAFT copy until the
//! owner approves it (RUNG2-HELD-WINDOW = B); the owner's own front copy
//! (`ConstraintFrontCopy`) carries the rest.
//!
//! The email is a template, never a model's words: the owner's slots line,
//! the solver's offers with their zoned times and, when the host names its
//! public page URL, each offer's slot link (ARCH-0062:148-151: offers are
//! program-generated, and the solver picks every time). The visitor's own
//! words are never in it.

use oneiron::booking::agent_front::ConstraintFrontCopy;

/// What the page shows once the first send is kept and waits for the
/// owner's press.
pub(super) const RUNG2_HELD_LINE_DRAFT: &str = "DRAFT: The host reviews first emails. Your options arrive in one email once the host sends it.";

/// What the page shows once the first send went out at once.
pub(super) const RUNG2_SENT_LINE_DRAFT: &str = "DRAFT: Your options are on their way by email.";

/// The refusal a second address in one page session gets
/// (RUNG2-ONE-ADDRESS = A).
pub(super) const RUNG2_ONE_ADDRESS_DRAFT: &str =
    "DRAFT: This conversation already continues by email at another address.";

/// The subject of every first send, before the owner's display name.
const RUNG2_SUBJECT_DRAFT: &str = "DRAFT: Times that fit, from";

/// The closing line when the email carries slot links.
const RUNG2_LINKED_CLOSE_DRAFT: &str =
    "DRAFT: Open a time to book it, or reply to this email to ask for other times.";

/// The closing line when the host names no public page URL.
const RUNG2_REPLY_CLOSE_DRAFT: &str =
    "DRAFT: Reply to this email with the time you pick, or to ask for other times.";

/// One offered time as the email lists it: its zoned label, and its slot
/// link when the host names its public page URL.
pub(super) struct Rung2OfferLine {
    pub(super) label: String,
    pub(super) href: Option<String>,
}

/// The subject of a first send from the page of `owner_display`.
pub(super) fn rung2_first_send_subject(owner_display: &str) -> String {
    // A subject is one header line: no line break survives into it.
    let owner: String = owner_display
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    format!("{RUNG2_SUBJECT_DRAFT} {}", owner.trim())
}

/// The plain-text body of a first send: the owner's slots line and the
/// offers, or the owner's no-fit line when the solver found none, then the
/// closing line and the owner's speaker name. A reply the page's agent
/// answers on its thread appends the same block to the agent's words.
pub(super) fn render_rung2_first_send_text(
    copy: &ConstraintFrontCopy,
    offers: &[Rung2OfferLine],
) -> String {
    let lead = if offers.is_empty() {
        &copy.no_fit_line
    } else {
        &copy.slots_line
    };
    render_offers_text(lead, copy, offers)
}

/// The plain-text body of a reply past the page's session caps
/// (RUNG2-REPLY-CAP = B): the owner's no-fit line, then the solver's offers
/// for the kept constraint, the closing line and the speaker name. No
/// model's words.
pub(super) fn render_rung2_past_cap_text(
    copy: &ConstraintFrontCopy,
    offers: &[Rung2OfferLine],
) -> String {
    render_offers_text(&copy.no_fit_line, copy, offers)
}

/// The plain-text body of a reply about something other than scheduling
/// (RUNG2-REPLY-OFF-TOPIC = B): the owner's off-topic line and the speaker
/// name, as the page's deflect card says it.
pub(super) fn render_rung2_off_topic_text(copy: &ConstraintFrontCopy) -> String {
    format!("{}\n\n{}\n", copy.off_topic_line, copy.speaker)
}

/// `lead`, the offers with their slot links, the closing line and the
/// speaker name.
fn render_offers_text(lead: &str, copy: &ConstraintFrontCopy, offers: &[Rung2OfferLine]) -> String {
    let mut text = String::new();
    text.push_str(lead);
    text.push_str("\n\n");
    if !offers.is_empty() {
        for offer in offers {
            text.push_str("- ");
            text.push_str(&offer.label);
            text.push('\n');
            if let Some(href) = &offer.href {
                text.push_str("  ");
                text.push_str(href);
                text.push('\n');
            }
        }
        text.push('\n');
    }
    let linked = offers.iter().any(|offer| offer.href.is_some());
    text.push_str(if linked {
        RUNG2_LINKED_CLOSE_DRAFT
    } else {
        RUNG2_REPLY_CLOSE_DRAFT
    });
    text.push_str("\n\n");
    text.push_str(&copy.speaker);
    text.push('\n');
    text
}
