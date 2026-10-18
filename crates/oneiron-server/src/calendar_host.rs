//! The calendar host's real CalDAV wire and iMIP submission transport.
//! Endpoints are installed only through the owner-proof typed setup doors.
use std::time::Duration;

use oneiron::outbound::{
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink, ServedChannelSink,
};
use oneiron::Vault;
use reqwest::header::HeaderValue;

mod caldav;
mod xml;
pub(crate) use caldav::HttpCalDav;

pub(super) fn client() -> Result<reqwest::blocking::Client, reqwest::Error> {
    reqwest::blocking::Client::builder().no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(30)).build()
}

pub(super) fn authorization(value: &[u8]) -> oneiron::Result<HeaderValue> {
    let text = std::str::from_utf8(value)
        .map_err(|_| oneiron::Error::InvalidConfig("calendar credential is not text".into()))?.trim();
    let text = if text.starts_with("Basic ") || text.starts_with("Bearer ") {
        text.to_owned()
    } else { format!("Bearer {text}") };
    let mut header = HeaderValue::from_str(&text)
        .map_err(|_| oneiron::Error::InvalidConfig("calendar credential is not an authorization header".into()))?;
    header.set_sensitive(true);
    Ok(header)
}

/// Extends the existing served sink, rather than running a second executor.
pub(crate) struct CalendarChannelSink<'a> {
    vault: &'a Vault,
    ordinary: ServedChannelSink<'a>,
    client: reqwest::blocking::Client,
}

impl<'a> CalendarChannelSink<'a> {
    pub(crate) fn new(vault: &'a Vault, line_push_allowance: u32) -> oneiron::Result<Self> {
        Ok(Self {
            vault,
            ordinary: ServedChannelSink::new(vault)?.with_line_push_allowance(line_push_allowance),
            client: client().map_err(|_| oneiron::Error::InvalidConfig("calendar send client unavailable".into()))?,
        })
    }

    fn invite(&self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let Some(part) = request.calendar_invite.as_ref() else {
            return OutboundExecutionOutcome::failed("calendar_invite_payload_absent");
        };
        let config = match oneiron::calendar::connectors::door::imip_transport(self.vault) {
            Ok(Some(config)) => config,
            _ => return OutboundExecutionOutcome::failed("calendar_imip_not_configured"),
        };
        let sender = request.channel_identity_ref.and_then(|id| {
            self.vault.get_channel_identity(&id).ok().flatten()
        }).map(|identity| identity.address_or_handle().to_owned());
        let Some(sender) = sender else {
            return OutboundExecutionOutcome::failed("calendar_sending_identity_absent");
        };
        let recipient = &request.intent.target;
        let mailbox = |value: &str| !value.is_empty() && value.contains('@')
            && !value.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, '<' | '>'));
        if !mailbox(&sender) || !mailbox(recipient) {
            return OutboundExecutionOutcome::failed("calendar_mailbox_invalid");
        }
        let identity = blake3::hash(request.idempotency_key.unwrap_or(request.intent_ref).as_bytes()).to_hex().to_string();
        let message_id = format!("<{identity}@calendar.invalid>");
        let now = self.vault.now_recorded_at();
        let wall = match oneiron::calendar::utc_to_wall(now, "UTC") {
            Ok(wall) => wall,
            Err(_) => return OutboundExecutionOutcome::failed("calendar_mail_date_invalid"),
        };
        let weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
        let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        let weekday = weekdays[((now / 86400 + 4) % 7) as usize];
        let month = months[usize::from(wall.mo) - 1];
        let date = format!("{weekday}, {:02} {month} {:04} {:02}:{:02}:{:02} +0000", wall.d, wall.y, wall.h, wall.mi, wall.s);
        let mut message = format!("Date: {date}\r\nFrom: {sender}\r\nTo: {recipient}\r\nMessage-ID: {message_id}\r\nSubject: Calendar invitation\r\nMIME-Version: 1.0\r\nContent-Type: {}\r\nContent-Disposition: attachment; filename=\"{}\"\r\nContent-Transfer-Encoding: base64\r\n", part.content_type, part.filename);
        for (key, value) in &request.hygiene_headers {
            if key.is_empty() || !key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') || value.chars().any(char::is_control) {
                return OutboundExecutionOutcome::failed("calendar_hygiene_header_invalid");
            }
            message.push_str(&format!("{key}: {value}\r\n"));
        }
        message.push_str("\r\n");
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&part.ics);
        for line in encoded.as_bytes().chunks(76) {
            // Base64 is always ASCII.
            message.push_str(std::str::from_utf8(line).unwrap_or_default());
            message.push_str("\r\n");
        }
        let mut sent = None;
        let _door = self.vault.inject_secret_at_door(&config.secret_ref, "calendar.imip", &mut |credential: &[u8]| {
            let auth = authorization(credential)?;
            let result = self.client.post(&config.endpoint)
                .header(reqwest::header::AUTHORIZATION, auth)
                .header(reqwest::header::CONTENT_TYPE, "message/rfc822")
                .header("Idempotency-Key", &identity).body(message.clone()).send();
            sent = Some(match result {
                Ok(response) if response.status().is_success() => OutboundExecutionOutcome::delivered_to_channel(message_id.clone()),
                Ok(response) => {
                    let status = response.status().as_u16();
                    let failed = OutboundExecutionOutcome::failed(format!("calendar_imip_http_{status}"));
                    if status >= 500 { failed.with_possible_delivery() }
                    else if status == 429 {
                        match response.headers().get(reqwest::header::RETRY_AFTER).and_then(|v| v.to_str().ok()) {
                            Some(delay) => failed.with_receipt_field("retry_after", delay),
                            None => failed,
                        }
                    } else { failed }
                }
                Err(error) if error.is_connect() => OutboundExecutionOutcome::failed("calendar_imip_unreachable"),
                Err(_) => OutboundExecutionOutcome::failed("calendar_imip_no_reply").with_possible_delivery(),
            });
            Ok(())
        });
        sent.unwrap_or_else(|| OutboundExecutionOutcome::failed("calendar_imip_credential_unavailable"))
    }
}

impl OutboundExecutionSink for CalendarChannelSink<'_> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if request.intent.channel == "calendar" && request.intent.verb == "calendar.invite" {
            self.invite(request)
        } else { self.ordinary.execute(request) }
    }
}
