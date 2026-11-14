//! The sink a drafted reply from an IMAP or a Microsoft 365 mailbox leaves
//! through (fix list rows 17872, 17643): the common recorded dispatcher's
//! last step, after its gate, ledger and the owner's one press for exactly
//! this revision. It sends only the frozen reply the dispatched intent
//! names, from the source's own mailbox to the recipients the dispatch
//! bound, every one of a reply to several among them (fix list row 17645),
//! with the hygiene headers the dispatch froze.
//!
//! - **IMAP.** Submitted over SMTP (RFC 6409) to the server the mailbox's
//!   credential names, read at the source's door with effector
//!   `connector:smtp`: a credential bound for reading only sends nothing.
//!   One `RCPT` per recipient; a refused one is `smtp_envelope_refused`, as
//!   for a send to one, and a reply to several resets before the data goes.
//! - **Microsoft 365.** One MIME `POST /me/sendMail` on Graph with the
//!   mailbox's own token (effector `connector:microsoft365`), once `/me`
//!   shows the token is the mailbox's. A `202` is the send taken; a token
//!   without `Mail.Send` is refused there.
//!
//! A send that may have been taken (the data's final dot written, or the
//! POST sent, and no answer) is uncertain, never refused: email has no
//! idempotency, and nothing sends it again by itself.

use std::collections::BTreeMap;

use base64::Engine as _;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};

use super::credential::WireReads;
use super::imap::submission_account;
use super::microsoft365::{GRAPH_ME_URL, MICROSOFT365_CONNECTOR_EFFECTOR, reads_mailbox};
use super::reply_mime::ReplyMessage;
use super::rest::{self, bearer_header, refused};
use super::smtp_client::{SmtpAuth, SmtpSession, Submitted};
use super::wire::MailSyncSource;
use crate::Vault;
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink};

/// The custody effector a mailbox's credential is bound to for sending
/// over SMTP submission.
pub const SMTP_SUBMISSION_CONNECTOR_EFFECTOR: &str = "connector:smtp";
/// Graph's send door for the signed-in mailbox.
const GRAPH_SEND_MAIL_URL: &str = "https://graph.microsoft.com/v1.0/me/sendMail";

/// The receipt fields a reply's send writes: the message's own ids, as a
/// Gmail send writes them, and the frozen reply's ref.
const RECEIPT_RFC_MESSAGE_ID: &str = "rfc_message_id";
const RECEIPT_RFC_MESSAGE_ID_SOURCE: &str = "rfc_message_id_source";
const RECEIPT_RFC_IN_REPLY_TO: &str = "rfc_in_reply_to";
const RECEIPT_RFC_REFERENCES: &str = "rfc_references";
const RECEIPT_REPLY_MESSAGE_REF: &str = "mail_reply_message_ref";
const RECEIPT_SEND_ERROR: &str = "mail_reply_send_error";

/// How a reply leaves its mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReplyTransport {
    /// SMTP submission, for an IMAP mailbox.
    Smtp,
    /// Graph `sendMail`, for a Microsoft 365 mailbox.
    Graph,
}

/// The sink of one drafted reply's send.
pub(super) struct ReplySink<'v> {
    vault: &'v Vault,
    source: MailSyncSource,
    message: ReplyMessage,
    transport: ReplyTransport,
}

impl<'v> ReplySink<'v> {
    pub(super) const fn new(
        vault: &'v Vault,
        source: MailSyncSource,
        message: ReplyMessage,
        transport: ReplyTransport,
    ) -> Self {
        Self {
            vault,
            source,
            message,
            transport,
        }
    }

    /// Submits `raw` over SMTP with the mailbox's credential.
    fn submit_smtp(&self, raw: &[u8]) -> Submitted {
        let mut outcome = None;
        let door = self.vault.with_source_token_at_door(
            &self.source,
            WireReads::Mailbox,
            SMTP_SUBMISSION_CONNECTOR_EFFECTOR,
            &mut |secret: &[u8]| {
                let account = submission_account(&self.source, secret)?;
                let auth = match (&account.access_token, &account.password) {
                    (Some(token), _) => SmtpAuth::Token(token),
                    (None, Some(password)) => SmtpAuth::Password(password),
                    (None, None) => return Err(refused("imap_credential_holds_no_secret")),
                };
                let client_name = self
                    .message
                    .from
                    .rsplit_once('@')
                    .map_or("localhost", |(_, domain)| domain);
                let mut session = SmtpSession::connect(
                    &account.host,
                    account.port,
                    account.security,
                    client_name,
                )?;
                session.authenticate(&account.username, &auth)?;
                let recipients = self.message.delivery_addresses();
                let submitted = session.submit(&self.message.from, &recipients, raw);
                session.quit();
                outcome = Some(submitted);
                Ok(())
            },
        );
        match (outcome, door) {
            (Some(submitted), _) => submitted,
            (None, Err(error)) => {
                tracing::info!(%error, "a drafted reply's submission session did not open");
                Submitted::NotSent("smtp_session_refused")
            }
            (None, Ok(_)) => Submitted::NotSent("smtp_credential_door_refused"),
        }
    }

    /// Sends `raw` through Graph with the mailbox's own token.
    fn send_graph(&self, raw: &[u8]) -> Submitted {
        let client = match rest::https_client() {
            Ok(client) => client,
            Err(_) => return Submitted::NotSent("graph_client_unavailable"),
        };
        let body = base64::engine::general_purpose::STANDARD.encode(raw);
        let mut outcome = None;
        let door = self.vault.with_source_token_at_door(
            &self.source,
            WireReads::Mailbox,
            MICROSOFT365_CONNECTOR_EFFECTOR,
            &mut |token: &[u8]| {
                // A stored Microsoft grant sends with a fresh access token.
                let fresh = rest::GrantIssuer::Microsoft.refresh(&client, token)?;
                let presented = match &fresh {
                    Some(fresh) => fresh.as_bytes(),
                    None => token,
                };
                let auth = bearer_header(presented)?;
                // The token sends as the mailbox it reads, and no other.
                let request = client
                    .get(GRAPH_ME_URL)
                    .query(&[("$select", "mail,userPrincipalName")])
                    .header(AUTHORIZATION, auth.clone());
                let me = rest::send(request)?
                    .found_or_gone("graph_mail")?
                    .ok_or_else(|| refused("graph_mail_user_not_found"))?;
                reads_mailbox(&me, &self.source)?;
                let posted = client
                    .post(GRAPH_SEND_MAIL_URL)
                    .header(AUTHORIZATION, auth)
                    .header(CONTENT_TYPE, "text/plain")
                    .body(body.clone())
                    .send();
                outcome = Some(match posted {
                    Ok(response) if response.status().is_success() => {
                        Submitted::Accepted(format!("graph:{}", response.status().as_u16()))
                    }
                    // A server failure may come after the send was taken.
                    Ok(response) if response.status().is_server_error() => {
                        Submitted::Uncertain("graph_send_server_error")
                    }
                    Ok(response) if matches!(response.status().as_u16(), 401 | 403) => {
                        Submitted::NotSent("graph_send_not_permitted")
                    }
                    Ok(response) if response.status().as_u16() == 429 => {
                        Submitted::NotSent("graph_send_throttled")
                    }
                    Ok(_) => Submitted::NotSent("graph_send_refused"),
                    Err(error) if error.is_connect() || error.is_builder() => {
                        Submitted::NotSent("graph_send_unsent")
                    }
                    Err(_) => Submitted::Uncertain("graph_send_no_answer"),
                });
                Ok(())
            },
        );
        match (outcome, door) {
            (Some(sent), _) => sent,
            (None, Err(error)) => {
                tracing::info!(%error, "a drafted reply's Graph send did not start");
                Submitted::NotSent("graph_send_not_started")
            }
            (None, Ok(_)) => Submitted::NotSent("graph_credential_door_refused"),
        }
    }
}

impl OutboundExecutionSink for ReplySink<'_> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if request.intent.channel != "email" || request.verb_contract.kind != "send" {
            return OutboundExecutionOutcome::failed("mail_reply_requires_email_send");
        }
        // The route sends as the mailbox's own account: no sender identity
        // stands in for it.
        if request.channel_identity_ref.is_some() {
            return OutboundExecutionOutcome::failed("mail_reply_sender_identity_unexpected");
        }
        if request.calendar_invite.is_some() {
            return OutboundExecutionOutcome::failed("mail_reply_calendar_invite_unsupported");
        }
        let message_ref = self.message.content_ref();
        if request.intent.content_ref.as_deref() != Some(message_ref.as_str()) {
            return OutboundExecutionOutcome::failed("mail_reply_message_mismatch");
        }
        let recipient = request.counterparty_ref.unwrap_or(&request.intent.target);
        if self.message.to != recipient || self.message.to != request.intent.target {
            return OutboundExecutionOutcome::failed("mail_reply_target_mismatch");
        }
        // Fix list row 17645: the message's recipients are the admitted
        // ones, every one in its role and place, or it does not send.
        if self.message.recipients != request.intent.recipients {
            return OutboundExecutionOutcome::failed("mail_reply_recipients_mismatch");
        }
        let Ok(raw) = self.message.render(&request.hygiene_headers) else {
            return OutboundExecutionOutcome::failed("mail_reply_headers_invalid");
        };
        let mut fields = BTreeMap::new();
        fields.insert(RECEIPT_REPLY_MESSAGE_REF.to_owned(), message_ref);
        fields.insert(
            RECEIPT_RFC_MESSAGE_ID.to_owned(),
            self.message.message_id.clone(),
        );
        fields.insert(RECEIPT_RFC_MESSAGE_ID_SOURCE.to_owned(), "plan".to_owned());
        fields.insert(
            RECEIPT_RFC_IN_REPLY_TO.to_owned(),
            self.message.in_reply_to.clone(),
        );
        fields.insert(
            RECEIPT_RFC_REFERENCES.to_owned(),
            self.message.references.join(" "),
        );
        let submitted = match self.transport {
            ReplyTransport::Smtp => self.submit_smtp(&raw),
            ReplyTransport::Graph => self.send_graph(&raw),
        };
        match submitted {
            Submitted::Accepted(answer) => {
                let provider = match self.transport {
                    ReplyTransport::Smtp => "smtp",
                    ReplyTransport::Graph => "graph",
                };
                tracing::debug!(provider, %answer, "a drafted reply was taken");
                OutboundExecutionOutcome::delivered_to_channel(format!(
                    "{provider}:{}",
                    self.message.message_id
                ))
                .with_receipt_fields(fields)
            }
            Submitted::NotSent(reason) => {
                fields.insert(RECEIPT_SEND_ERROR.to_owned(), reason.to_owned());
                OutboundExecutionOutcome::failed(reason).with_receipt_fields(fields)
            }
            Submitted::Uncertain(reason) => {
                fields.insert(RECEIPT_SEND_ERROR.to_owned(), reason.to_owned());
                OutboundExecutionOutcome::failed(reason)
                    .with_receipt_fields(fields)
                    .with_possible_delivery()
            }
        }
    }

    /// One SMTP transaction or one Graph `sendMail` delivers the frozen
    /// reply to every recipient it names (fix list row 17645).
    fn delivers_recipient_lists(&self) -> bool {
        true
    }
}
