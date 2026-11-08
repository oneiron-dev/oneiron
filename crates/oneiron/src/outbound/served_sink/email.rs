//! Email (OF-187, OF-519): a send from a native mail identity leaves through
//! the host's own mail server, the Stalwart instance its installed
//! [`super::ServedTransports`] place, with the built-in native mail pack's
//! checked credential. It takes the same draft-then-submission path the
//! native mail pack's own send door takes, keyed on the send's logical
//! reference, so a retried send finds its draft and its submission.
//!
//! The text is the typed content's; the subject is its first line. A reply
//! to an inbound message carries that message's Message-ID as its
//! `In-Reply-To` and in its `References`, read from the message's archive.
//! A send from any other email identity, or on a host that names no mail
//! server, fails as not started.

use super::ServedChannelSink;
use crate::EntityId;
use crate::channel_identity_provider::native_mail::is_native_mail_identity_in_txn;
use crate::channel_identity_provider::stalwart::{
    NativeMailMessage, StalwartClient, StalwartConfig,
};
use crate::channel_identity_provider::{EMAIL_CHANNEL, EmailThreadHeaders};
use crate::error::Error;
use crate::outbound::{
    EngineSendId, OutboundExecutionOutcome, OutboundExecutionRequest, SentLookup, SentLookupTarget,
};
use crate::outbound_intent_ledger::DeliveryReadBack;

/// The built-in native mail pack connection whose checked credential sends.
const NATIVE_MAIL_PACK: &str = "oneiron.native_mail";
const NATIVE_MAIL_CONNECTION: &str = "mail-server";
/// The longest subject a send's first line gives, in characters: RFC 5322's
/// recommended line length.
const EMAIL_SUBJECT_MAX_CHARS: usize = 78;

/// The route a served email send leaves by, read before any door opens:
/// the host's mail server, the native mail identity that sends, and its
/// mailbox address as its facts name it now.
struct ServedEmailRoute {
    placement: StalwartConfig,
    identity: EntityId,
    address: String,
}

impl ServedChannelSink<'_> {
    /// The route of the served email `request`, or the reason it fails as
    /// not started.
    fn email_route(
        &self,
        request: &OutboundExecutionRequest<'_>,
    ) -> Result<ServedEmailRoute, &'static str> {
        let Some(placement) = self.transports.native_mail().cloned() else {
            return Err("email_mail_server_unconfigured");
        };
        // An invitation's calendar part rides only the calendar sink; a plain
        // message without it would be an email about a meeting.
        if request.calendar_invite.is_some() {
            return Err("email_calendar_part_unsupported");
        }
        let Some(identity) = request.channel_identity_ref else {
            return Err("email_sender_absent");
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
            Ok(false) => return Err("email_sender_not_native_mail"),
            Err(_) => return Err("email_sender_unreadable"),
        }
        // The mailbox is the identity's address as its facts name it now.
        let address = match self.vault.channel_identity_facts(&identity) {
            Ok(Some(facts)) => facts.address_or_handle,
            _ => return Err("email_sender_unreadable"),
        };
        Ok(ServedEmailRoute {
            placement,
            identity,
            address,
        })
    }

    pub(super) fn email_send(
        &self,
        request: &OutboundExecutionRequest<'_>,
    ) -> OutboundExecutionOutcome {
        let ServedEmailRoute {
            placement,
            identity,
            address,
        } = match self.email_route(request) {
            Ok(route) => route,
            Err(reason) => return OutboundExecutionOutcome::failed(reason),
        };
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
        let send_key = email_send_key(request);
        // A reply threads on the message it answers, as its archive names it.
        let answered = self
            .answered_provider_event(request, EMAIL_CHANNEL)
            .and_then(|body| body.get("thread_headers").cloned())
            .and_then(|headers| serde_json::from_value::<EmailThreadHeaders>(headers).ok());
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
                        &address,
                        &message,
                        send_key,
                        &request.hygiene_headers,
                        answered.as_ref(),
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

    /// What the host's mail server's own record says became of the served
    /// email `request` (FIX 8814 follow-up): the draft its send key names,
    /// read back by the same route and the same checked credential as its
    /// send. `Unknown` when either does not open.
    pub(super) fn email_read_back(
        &self,
        request: &OutboundExecutionRequest<'_>,
    ) -> DeliveryReadBack {
        let Ok(route) = self.email_route(request) else {
            return DeliveryReadBack::Unknown;
        };
        let send_key = email_send_key(request);
        let Ok(secret) = self
            .vault
            .verified_pack_connection_secret(NATIVE_MAIL_PACK, NATIVE_MAIL_CONNECTION)
        else {
            return DeliveryReadBack::Unknown;
        };
        let mut read_back = None;
        let _door = self.vault.inject_secret_at_door(
            &secret.name,
            &secret.effector,
            &mut |value: &[u8]| {
                let header = authorization_header(value)?;
                read_back = Some(
                    match StalwartClient::connect(route.placement.clone(), header) {
                        Ok(client) => client.read_back_served(
                            route.identity,
                            &route.address,
                            send_key,
                            &request.intent.target,
                        ),
                        Err(_) => DeliveryReadBack::Unknown,
                    },
                );
                Ok(())
            },
        );
        read_back.unwrap_or(DeliveryReadBack::Unknown)
    }
}

impl ServedChannelSink<'_> {
    /// FIX 4747: whether the native mail send `engine_send_id` keys went,
    /// from the identity the dispatch resolved: the host's mail server's
    /// submission of the draft carrying its Message-ID, read with the native
    /// mail pack's checked credential. Any other email identity, or a host
    /// that names no mail server, cannot tell.
    pub(super) fn email_lookup_sent(
        &self,
        engine_send_id: &EngineSendId,
        target: &SentLookupTarget<'_>,
    ) -> SentLookup {
        let Some(placement) = self.transports.native_mail().cloned() else {
            return SentLookup::CannotTell;
        };
        let Some(identity) = target.channel_identity_ref else {
            return SentLookup::CannotTell;
        };
        // Read before the door opens: the door holds the vault's writer.
        let native = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(Error::from)
            .and_then(|txn| is_native_mail_identity_in_txn(&self.vault.store, &txn, identity));
        if !matches!(native, Ok(true)) {
            return SentLookup::CannotTell;
        }
        let address = match self.vault.channel_identity_facts(&identity) {
            Ok(Some(facts)) => facts.address_or_handle,
            _ => return SentLookup::CannotTell,
        };
        let Ok(secret) = self
            .vault
            .verified_pack_connection_secret(NATIVE_MAIL_PACK, NATIVE_MAIL_CONNECTION)
        else {
            return SentLookup::CannotTell;
        };
        let mut found = None;
        let _door = self.vault.inject_secret_at_door(
            &secret.name,
            &secret.effector,
            &mut |value: &[u8]| {
                let header = authorization_header(value)?;
                found = Some(match StalwartClient::connect(placement.clone(), header) {
                    Ok(client) => {
                        client.look_up_served_send(identity, &address, engine_send_id.as_str())
                    }
                    Err(_) => SentLookup::CannotTell,
                });
                Ok(())
            },
        );
        found.unwrap_or(SentLookup::CannotTell)
    }
}

/// The key the served email `request` drafts under, its Message-ID's
/// source. FIX 4747: a connector-send TASK's send keys on its engine send
/// id, so its Message-ID is the same from every machine. Its send and its
/// read-back (FIX 8814 follow-up) both key here, so the read-back finds the
/// draft the send made.
fn email_send_key<'r>(request: &'r OutboundExecutionRequest<'_>) -> &'r str {
    request
        .engine_send_id
        .map(EngineSendId::as_str)
        .or(request.idempotency_key)
        .or(request.intent.idempotency_key.as_deref())
        .unwrap_or(request.intent_ref)
}

/// The subject a send's text gives: its first non-blank line, cut to
/// [`EMAIL_SUBJECT_MAX_CHARS`] whole characters.
pub(super) fn email_subject(text: &str) -> String {
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
