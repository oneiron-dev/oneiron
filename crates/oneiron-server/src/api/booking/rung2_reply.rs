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
use super::rung2::rung2_offers;
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
    // RED BASE: no channel, thread-ref or agent check.
    let _ = (channel, agent, BOOKING_RUNG2_CHANNEL, validate_thread_ref);
    let Some(thread_ref) = thread_ref else {
        return Ok(None);
    };
    vault.booking_rung2_thread_first_send(thread_ref)
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
    // RED BASE: no tally, no parse, the agent pays.
    let copy = front.copy();
    let continuation = &kept.continuation;
    let _ = (parse, event_id, Rung2ReplyAdmission::PastCap);
    let _ = (
        render_rung2_off_topic_text,
        render_rung2_past_cap_text,
        anonymous_payer,
    );
    let offers = rung2_offers(
        server,
        kept.page_ref,
        &continuation.event_type,
        &continuation.constraint,
        &continuation.visitor_tz,
        now,
    )?;
    let offers = render_rung2_first_send_text(&copy, &offers);
    let payer = WriteActor::new(kept.agent_ref, oneiron::EdgeActorClass::Agent);
    Ok(Some(Rung2Reply::Answer(Rung2Answer {
        context: format!("{RUNG2_REPLY_CONTEXT_LEAD}\n\n{offers}"),
        offers,
        payer,
    })))
}
