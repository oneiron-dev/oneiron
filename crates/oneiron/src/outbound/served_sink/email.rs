//! Email (OF-187, OF-519): a send from a native mail identity leaves through
//! the host's own mail server, the Stalwart instance its installed
//! [`super::ServedTransports`] place, with the built-in native mail pack's
//! checked credential. It takes the same draft-then-submission path the
//! native mail pack's own send door takes, keyed on the send's logical
//! reference, so a retried send finds its draft and its submission.
//!
//! The text is the typed content's; the subject is its first line. A send
//! from any other email identity, or on a host that names no mail server,
//! fails as not started.

use super::ServedChannelSink;
use crate::channel_identity_provider::native_mail::is_native_mail_identity_in_txn;
use crate::channel_identity_provider::stalwart::{NativeMailMessage, StalwartClient};
use crate::error::Error;
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest};

/// The built-in native mail pack connection whose checked credential sends.
const NATIVE_MAIL_PACK: &str = "oneiron.native_mail";
const NATIVE_MAIL_CONNECTION: &str = "mail-server";
/// The longest subject a send's first line gives, in characters: RFC 5322's
/// recommended line length.
const EMAIL_SUBJECT_MAX_CHARS: usize = 78;

impl ServedChannelSink<'_> {
    pub(super) fn email_send(
        &self,
        request: &OutboundExecutionRequest<'_>,
    ) -> OutboundExecutionOutcome {
        let Some(placement) = self.transports.native_mail().cloned() else {
            return OutboundExecutionOutcome::failed("email_mail_server_unconfigured");
        };
        // An invitation's calendar part rides only the calendar sink; a plain
        // message without it would be an email about a meeting.
        if request.calendar_invite.is_some() {
            return OutboundExecutionOutcome::failed("email_calendar_part_unsupported");
        }
        let Some(identity) = request.channel_identity_ref else {
            return OutboundExecutionOutcome::failed("email_sender_absent");
        };
        // Read before the door opens: the door holds the vault's writer.
        let native = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(Error::from)
            .and_then(|txn| is_native_mail_identity_in_txn(&self.vault.store, &txn, identity));
        match native {
            Ok(true) => {}
            Ok(false) => return OutboundExecutionOutcome::failed("email_sender_not_native_mail"),
            Err(_) => return OutboundExecutionOutcome::failed("email_sender_unreadable"),
        }
        let Some(text) = self.text(request) else {
            return OutboundExecutionOutcome::failed("content_unresolvable");
        };
        let message = match NativeMailMessage::new(
            &request.intent.target,
            email_subject(&text),
            Some(text),
            None,
        ) {
            Ok(message) => message,
            Err(_) => return OutboundExecutionOutcome::failed("email_message_invalid"),
        };
        let send_key = request
            .idempotency_key
            .or(request.intent.idempotency_key.as_deref())
            .unwrap_or(request.intent_ref);
        let secret = match self
            .vault
            .verified_pack_connection_secret(NATIVE_MAIL_PACK, NATIVE_MAIL_CONNECTION)
        {
            Ok(secret) => secret,
            Err(_) => return OutboundExecutionOutcome::failed("native_mail_connection_unchecked"),
        };
        let mut outcome = None;
        let _door = self.vault.inject_secret_at_door(
            &secret.name,
            &secret.effector,
            &mut |value: &[u8]| {
                let header = authorization_header(value)?;
                outcome = Some(match StalwartClient::connect(placement.clone(), header) {
                    Ok(client) => client.submit_served_text(
                        identity,
                        &message,
                        send_key,
                        &request.hygiene_headers,
                    ),
                    // Discovery runs before any draft: nothing was sent.
                    Err(_) => OutboundExecutionOutcome::failed("native_mail_unreachable"),
                });
                Ok(())
            },
        );
        // Once the server was reached, what it said is the delivery fact,
        // whatever the door reports after it.
        outcome.unwrap_or_else(|| {
            OutboundExecutionOutcome::failed("native_mail_credential_unavailable")
        })
    }
}

/// The subject a send's text gives: its first non-blank line, cut to
/// [`EMAIL_SUBJECT_MAX_CHARS`] whole characters.
fn email_subject(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(EMAIL_SUBJECT_MAX_CHARS)
        .collect()
}

/// The stored mail server credential as an `Authorization` header: the
/// whole header (`Basic ...` or `Bearer ...`), or a bare bearer token, as the
/// native mail pack's check reads it.
fn authorization_header(value: &[u8]) -> crate::error::Result<reqwest::header::HeaderValue> {
    let value = std::str::from_utf8(value)
        .map_err(|_| Error::InvalidConfig("the stored credential is not text".to_owned()))?
        .trim();
    let header = if value.starts_with("Basic ") || value.starts_with("Bearer ") {
        value.to_owned()
    } else {
        format!("Bearer {value}")
    };
    reqwest::header::HeaderValue::from_str(&header)
        .map_err(|_| Error::InvalidConfig("the stored credential is not a header value".to_owned()))
}
