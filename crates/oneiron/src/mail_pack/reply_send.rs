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
//!   For a reply with files, the session's own `SIZE` limit, else the
//!   host's setting `mail.smtp.max_message_octets_unadvertised`, refuses a
//!   larger message before `MAIL` (`reply_smtp`); a reply without files is
//!   submitted as before. One `RCPT` per recipient; a refused one is
//!   `smtp_envelope_refused`, as for a send to one, and a reply to several
//!   resets before the data goes.
//! - **Microsoft 365.** One MIME `POST /me/sendMail` on Graph with the
//!   mailbox's own token (effector `connector:microsoft365`), once `/me`
//!   shows the token is the mailbox's. A `202` is the send taken; a token
//!   without `Mail.Send` is refused there.
//!
//! A reply with files (fix list row 17645) sends the exact message it was
//! frozen with: its holder (`reply_attachments`) judges the send again in
//! the writer that admits it, opens the message at egress once its send
//! still stands, checked against its frozen length and BLAKE3, and judges it
//! once more in the credential door's writer. Over SMTP its data is that
//! message, dot-stuffed; through Graph the POST body is that message's
//! base64, refused above Graph's one-shot limit. Nothing is read, masked or
//! rendered again. A server that refuses it late is a refused send, as any
//! other is: no smaller or second message is ever sent.
//!
//! A send that may have been taken (the data's final dot written, or the
//! POST sent, and no answer) is uncertain, never refused: email has no
//! idempotency, and nothing sends it again by itself.

use std::collections::BTreeMap;

use base64::Engine as _;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use zeroize::Zeroizing;

use super::credential::WireReads;
use super::imap::submission_account;
use super::microsoft365::{GRAPH_ME_URL, MICROSOFT365_CONNECTOR_EFFECTOR, reads_mailbox};
use super::reply_attachments::MAX_GRAPH_SEND_BODY_BYTES;
use super::reply_mime::{ReplyMessage, ReplyMessageFiles};
use super::reply_smtp::SmtpEndpoint;
use super::rest::{self, bearer_header, refused};
use super::smtp_client::{SmtpAuth, SmtpSession, Submitted};
use super::wire::MailSyncSource;
use crate::Vault;
use crate::channel_identity_provider::mail_attachments::RetainedMailMessage;
use crate::error::{Error, Result};
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

/// The authenticated submission session of the IMAP mailbox `source`, opened
/// with `secret`, its credential at its door, and the server it is open to:
/// the submission server the credential names, over TLS, `EHLO` naming the
/// domain of `from`, the mailbox's address, then `AUTH` with its token, else
/// its password. The send and the size check of a reply with files
/// (`reply_smtp`, which records the server) open it alike.
///
/// # Errors
///
/// A credential that names no submission server or holds no secret, and any
/// refusal of the session.
pub(super) fn open_submission(
    source: &MailSyncSource,
    secret: &[u8],
    from: &str,
) -> Result<(SmtpSession, SmtpEndpoint)> {
    let account = submission_account(source, secret)?;
    let auth = match (&account.access_token, &account.password) {
        (Some(token), _) => SmtpAuth::Token(token),
        (None, Some(password)) => SmtpAuth::Password(password),
        (None, None) => return Err(refused("imap_credential_holds_no_secret")),
    };
    let client_name = from
        .rsplit_once('@')
        .map_or("localhost", |(_, domain)| domain);
    let mut session =
        SmtpSession::connect(&account.host, account.port, account.security, client_name)?;
    session.authenticate(&account.username, &auth)?;
    let endpoint = SmtpEndpoint {
        host: account.host.clone(),
        port: account.port,
    };
    Ok((session, endpoint))
}

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
    /// The holder of the message a reply with files was frozen with (fix
    /// list row 17645): it judges the send again in the writer that admits
    /// it, at egress and in the credential door's writer, and opens the
    /// message; `None` for a reply without files.
    retained: Option<&'v dyn RetainedMailMessage>,
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
            retained: None,
        }
    }

    /// Binds the sink to the one send with files it may make (fix list row
    /// 17645): `retained` judges that send again in the writer that admits
    /// it and opens its exact message at egress. A reply with files sends
    /// nothing without it.
    #[must_use]
    pub(super) fn with_retained_message(mut self, retained: &'v dyn RetainedMailMessage) -> Self {
        self.retained = Some(retained);
        self
    }

    /// The exact message `files`, what the reply with files was frozen with,
    /// names: opened by the holder bound to this sink, after its send is
    /// judged once more, once that holder still keeps the carrier and the
    /// manifest the reply's content ref `message_ref` names by its digest,
    /// and checked against the length and BLAKE3 that manifest froze. The
    /// dispatch carries no hygiene header for it, on SMTP as on Graph: the
    /// message was frozen with none.
    fn retained_message(
        &self,
        files: &ReplyMessageFiles,
        message_ref: &str,
        hygiene_headers: &BTreeMap<String, String>,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, &'static str> {
        if !hygiene_headers.is_empty() {
            return Err("mail_reply_headers_invalid");
        }
        let Some(retained) = self.retained else {
            return Err("mail_reply_message_missing");
        };
        if retained.content_ref() != message_ref || retained.carrier_ref() != files.carrier {
            return Err("mail_reply_message_missing");
        }
        let frozen = match retained.manifest() {
            Ok(Some(manifest)) if manifest.digest() == files.manifest => manifest.message,
            Ok(_) => return Err("mail_reply_message_missing"),
            Err(_) => return Err("mail_reply_message_refused"),
        };
        let raw = retained
            .open_for_egress()
            .map_err(|_| "mail_reply_message_refused")?;
        if !frozen.matches(&raw) {
            return Err("mail_reply_message_mismatch");
        }
        Ok(raw)
    }

    /// Submits `raw` over SMTP with the mailbox's credential. A reply with
    /// files (fix list row 17645) is refused before `MAIL` above the
    /// session's own `SIZE` limit, else above the host's setting for a
    /// server that names none, declares its octets where the server offers
    /// `SIZE`, and is judged once more in the credential door's writer by
    /// the holder of its message. A reply without files is submitted as it
    /// always was.
    fn submit_smtp(&self, raw: &[u8]) -> Submitted {
        let unadvertised = self.message.files.is_some().then(|| {
            self.vault
                .mail_host_settings()
                .smtp_max_message_octets_unadvertised
        });
        let mut outcome = None;
        let door = self.vault.with_source_token_at_door_admitting(
            &self.source,
            WireReads::Mailbox,
            SMTP_SUBMISSION_CONNECTOR_EFFECTOR,
            self.retained,
            &mut |secret: &[u8]| {
                let (mut session, _) = open_submission(&self.source, secret, &self.message.from)?;
                let recipients = self.message.delivery_addresses();
                let submitted = session.submit(&self.message.from, &recipients, raw, unadvertised);
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

    /// Sends `raw` through Graph with the mailbox's own token. A reply with
    /// files is refused above Graph's one-shot limit, its exact body counted,
    /// and judged once more in the credential door's writer by the holder of
    /// its message (fix list row 17645).
    fn send_graph(&self, raw: &[u8]) -> Submitted {
        let client = match rest::https_client() {
            Ok(client) => client,
            Err(_) => return Submitted::NotSent("graph_client_unavailable"),
        };
        let body = base64::engine::general_purpose::STANDARD.encode(raw);
        if self.message.files.is_some() && body.len() as u64 > MAX_GRAPH_SEND_BODY_BYTES {
            return Submitted::NotSent("graph_send_too_large");
        }
        let mut outcome = None;
        let door = self.vault.with_source_token_at_door_admitting(
            &self.source,
            WireReads::Mailbox,
            MICROSOFT365_CONNECTOR_EFFECTOR,
            self.retained,
            &mut |token: &[u8]| {
                let auth = bearer_header(token)?;
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
        // A reply with files sends the message it was frozen with, as its
        // holder opens it; nothing is rendered again (fix list row 17645).
        let raw = match &self.message.files {
            None => {
                let Ok(raw) = self.message.render(&request.hygiene_headers) else {
                    return OutboundExecutionOutcome::failed("mail_reply_headers_invalid");
                };
                Zeroizing::new(raw)
            }
            Some(files) => {
                match self.retained_message(files, &message_ref, &request.hygiene_headers) {
                    Ok(raw) => raw,
                    Err(reason) => return OutboundExecutionOutcome::failed(reason),
                }
            }
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

    /// A reply with files is judged again by the holder of its message, in
    /// the writer that admits it, before any decision is recorded; without
    /// that holder it is refused there (fix list row 17645).
    fn admit_in(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        match (self.retained, &self.message.files) {
            (Some(retained), _) => retained.admit_in(txn),
            (None, Some(_)) => Err(Error::InvalidConfig(
                "a reply with files sends only beside the holder of its message".to_owned(),
            )),
            (None, None) => Ok(()),
        }
    }

    /// One SMTP transaction or one Graph `sendMail` delivers the frozen
    /// reply to every recipient it names (fix list row 17645).
    fn delivers_recipient_lists(&self) -> bool {
        true
    }
}
