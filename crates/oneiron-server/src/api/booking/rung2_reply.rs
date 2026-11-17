//! Rung 2's reply (INBOX-RESIDUE PR-3b-3c-2; ARCH-0062:145-151): the
//! visitor answers the first send by email, and the page's own agent
//! continues on that thread.
//!
//! The connector reply worker asks [`rung2_thread_send`] whether a reply's
//! thread is one a rung-2 first send of its agent began, and
//! [`answer_rung2_reply`] what the reply says:
//! - past the page's session caps (RUNG2-REPLY-CAP = B), the owner's no-fit
//!   line and the solver's offers for the kept constraint, with no model call;
//! - else the reply's one parse, on the page's parse seat, decides
//!   (RUNG2-REPLY-CONSTRAINT = B, RUNG2-REPLY-OFF-TOPIC = B): a reply about
//!   something other than scheduling gets the owner's off-topic line and no
//!   further call; a reply that parses solves its own constraint; one that
//!   does not parse re-solves the kept one. The kept continuation is never
//!   rewritten, and only a canonical object reaches the solver;
//! - the agent then answers in its own words, with the offers in its context
//!   as the engine's data, and the code-rendered offers are appended to its
//!   words verbatim: no time or link passes through the model.
//!
//! The page's publication authorizes each step as it does the page's own
//! listing: the kept event type and constraint must still be on it, and it is
//! read again after each solve and, by the worker, after the agent's answer
//! ([`Rung2Answer::still_published`]). A page that no longer publishes them,
//! or whose publication changed meanwhile, makes the thread an ordinary one,
//! and a solve made under the old one is never sent.
//!
//! The page's sponsor pays the parse and the answer, as it pays the page's
//! own parses (RUNG2-SEND-PAYER = A); the vault owner pays when no sponsor is
//! stored or live.

use oneiron::booking::constraint::ConstraintParseDisposition;
use oneiron::booking::publication::{BookingPagePublication, load_public_booking_page};
use oneiron::booking::rung2::{BOOKING_RUNG2_CHANNEL, Rung2FirstSend, Rung2ReplyAdmission};
use oneiron::write_envelope::thread_claim::validate_thread_ref;
use oneiron::{EntityId, Vault, WriteActor};

use super::free_text::{anonymous_payer, parse_disposition_on_seat, parse_seat_settings};
use super::helpers::{engine_read_error, now_secs};
use super::public_availability;
use super::rung2::{continuation_listing, rung2_offers, rung2_solve_window};
use super::rung2_copy::{
    render_rung2_first_send_text, render_rung2_off_topic_text, render_rung2_past_cap_text,
};
use crate::error::ApiError;
use crate::server::SyncServer;

/// The engine's words before the offers in the agent's context.
const RUNG2_REPLY_CONTEXT_LEAD: &str = "Engine data, not the visitor's words: this email thread continues a visit to the owner's booking page, where no time fitted. The engine solved the visitor's scheduling request again, and the block below is appended verbatim after your reply. Answer the visitor in your own words, and name no time, date or link yourself.";

/// What a reply on a rung-2 thread says.
#[derive(Debug)]
pub(crate) enum Rung2Reply {
    /// The owner's words alone, with no model call: the no-fit line and the
    /// offers past the caps, or the off-topic line.
    Fixed(String),
    /// The page's agent answers, and the offers follow its words.
    Answer(Rung2Answer),
}

/// The agent's answer to a reply on a rung-2 thread.
#[derive(Debug)]
pub(crate) struct Rung2Answer {
    /// The engine's block the agent reads before the visitor's words: the
    /// offers, as data.
    pub(crate) context: String,
    /// The offers as the email lists them, appended verbatim to the agent's
    /// words.
    pub(crate) offers: String,
    /// Who pays the answer: the page's sponsor, else the vault owner.
    pub(crate) payer: WriteActor,
    /// The page the offers were solved for.
    page_ref: EntityId,
    /// The publication that authorized the solve.
    publication: BookingPagePublication,
}

impl Rung2Answer {
    /// Whether the page still publishes what authorized the offers, read
    /// now: the worker asks after the agent's answer and before saving it,
    /// so offers solved under a publication the owner has since changed or
    /// revoked never go out.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn still_published(&self, vault: &Vault) -> oneiron::Result<bool> {
        let now = now_secs().map_err(|error| {
            oneiron::Error::InvalidConfig(format!("booking rung-2 reply: {}", error.message()))
        })?;
        publication_holds(vault, self.page_ref, &self.publication, now)
    }
}

/// Whether `page_ref`'s publication read at `now` is still `publication`:
/// an owner edit of the event configuration, a republish or a revoke since
/// it was read makes it another, or none.
fn publication_holds(
    vault: &Vault,
    page_ref: EntityId,
    publication: &BookingPagePublication,
    now: u64,
) -> oneiron::Result<bool> {
    Ok(load_public_booking_page(vault, page_ref, now)?.as_ref() == Some(publication))
}

/// The rung-2 first send whose thread `thread_ref` is, when a reply came on
/// it by email and `agent`, the send's own agent, answers it. `None` for
/// every other reply: another channel, no thread, a thread no rung-2 first
/// send began, or another agent on the thread.
///
/// # Errors
///
/// Storage errors, and a kept send that does not decode.
pub(crate) fn rung2_thread_send(
    vault: &Vault,
    channel: &str,
    thread_ref: Option<&str>,
    agent: EntityId,
) -> oneiron::Result<Option<Rung2FirstSend>> {
    if channel != BOOKING_RUNG2_CHANNEL {
        return Ok(None);
    }
    // A thread ref no passport can carry began no rung-2 thread.
    let Some(thread_ref) = thread_ref.filter(|thread| validate_thread_ref(thread).is_ok()) else {
        return Ok(None);
    };
    Ok(vault
        .booking_rung2_thread_first_send(thread_ref)?
        .filter(|kept| kept.agent_ref == agent))
}

/// What the reply event `event_id`, the visitor's `reply_text` on the
/// thread `kept` began, says. `None` when the page no longer publishes its
/// front: the thread is then an ordinary one, and the agent answers it as
/// any email. Blocks on the parse seat: run it on a blocking thread.
///
/// # Errors
///
/// Storage errors, and a solve the page's oracle refuses.
pub(crate) fn answer_rung2_reply(
    server: &SyncServer,
    kept: &Rung2FirstSend,
    event_id: &str,
    reply_text: &str,
) -> oneiron::Result<Option<Rung2Reply>> {
    now_secs()
        .and_then(|now| {
            rung2_reply_with(server, kept, event_id, now, |publication| {
                let settings = parse_seat_settings(server)?;
                parse_disposition_on_seat(
                    server,
                    &settings,
                    None,
                    publication.sponsor,
                    reply_text.to_owned(),
                    kept.continuation.visitor_tz.clone(),
                    now,
                )
            })
        })
        .map_err(|error| {
            oneiron::Error::InvalidConfig(format!("booking rung-2 reply: {}", error.message()))
        })
}

/// [`answer_rung2_reply`] with the reply's parse in `parse`, which runs
/// only on an admitted reply.
pub(super) fn rung2_reply_with(
    server: &SyncServer,
    kept: &Rung2FirstSend,
    event_id: &str,
    now: u64,
    parse: impl FnOnce(&BookingPagePublication) -> Result<ConstraintParseDisposition, ApiError>,
) -> Result<Option<Rung2Reply>, ApiError> {
    let vault = &server.vault;
    let Some(publication) =
        load_public_booking_page(vault, kept.page_ref, now).map_err(engine_read_error)?
    else {
        return Ok(None);
    };
    let Some(front) = publication.constraint_front.as_ref() else {
        return Ok(None);
    };
    let copy = front.copy();
    let continuation = &kept.continuation;
    // The thread continues only what the page still offers: an event type
    // the owner withdrew, or a constraint field turned off, makes it an
    // ordinary thread, as a listing of them is refused.
    let listing = continuation_listing(continuation, rung2_solve_window(now));
    if public_availability::validate_public_request(&publication, &listing).is_err() {
        return Ok(None);
    }
    let still_published =
        || publication_holds(vault, kept.page_ref, &publication, now).map_err(engine_read_error);
    let admission = vault
        .admit_booking_rung2_reply(&kept.send_ref, event_id, &front.caps())
        .map_err(engine_read_error)?;
    if admission == Rung2ReplyAdmission::PastCap {
        let offers = rung2_offers(
            server,
            kept.page_ref,
            &continuation.event_type,
            &continuation.constraint,
            &continuation.visitor_tz,
            front.max_offered_slots,
            now,
        )?;
        if !still_published()? {
            return Ok(None);
        }
        return Ok(Some(Rung2Reply::Fixed(render_rung2_past_cap_text(
            &copy, &offers,
        ))));
    }
    let (constraint, visitor_tz) = match parse(&publication) {
        Ok(ConstraintParseDisposition::Constraint {
            object,
            visitor_tz_override,
        }) => (
            object,
            visitor_tz_override.unwrap_or_else(|| continuation.visitor_tz.clone()),
        ),
        Ok(ConstraintParseDisposition::OffTopic) => {
            return Ok(Some(Rung2Reply::Fixed(render_rung2_off_topic_text(&copy))));
        }
        // No new constraint: the reply re-solves the kept one.
        Err(error) => {
            tracing::info!(
                reason = error.message(),
                "a rung-2 reply did not parse; it re-solves the kept constraint"
            );
            (
                continuation.constraint.clone(),
                continuation.visitor_tz.clone(),
            )
        }
    };
    let offers = rung2_offers(
        server,
        kept.page_ref,
        &continuation.event_type,
        &constraint,
        &visitor_tz,
        front.max_offered_slots,
        now,
    )?;
    // The parse blocked on the seat: the solve read the event configuration
    // as it stands now, which only the publication read now authorizes.
    if !still_published()? {
        return Ok(None);
    }
    let offers = render_rung2_first_send_text(&copy, &offers);
    let payer = anonymous_payer(vault, publication.sponsor).map_err(|error| {
        tracing::warn!(code = %error.code, "a rung-2 reply's payer did not resolve");
        ApiError::internal_server_error("booking rung-2 reply payer unavailable")
    })?;
    Ok(Some(Rung2Reply::Answer(Rung2Answer {
        context: format!("{RUNG2_REPLY_CONTEXT_LEAD}\n\n{offers}"),
        offers,
        payer,
        page_ref: kept.page_ref,
        publication,
    })))
}
