//! What one send presents, and everything its connector says cleared of
//! that value inside the door (FIX 7646, FIX 7647).
//!
//! A send's credential is known before its exchange is declared: the
//! custody record a `self.use` call names, the secret grant it redeems, or
//! the route's own secret, which no call names. Its door releases the value
//! to one callback, which builds the `Authorization` header, runs the
//! exchange, and clears each raw or trimmed copy of that value from what
//! the connector said, with those very bytes, before any of it leaves: the
//! reply's content, structured content and JSON-RPC error, each question's
//! key, message and schema before the registry keeps it, the raw body the
//! ledger and a turn program's bridge read, and the failure label. A live
//! question's worker keeps a scrubbed copy, as its session keeps the
//! header, and clears each later question and the terminal reply the same
//! way. Nothing is withheld, and elicitation is declared as it always was.

use super::*;

/// The door one send presents its credential through.
enum Door {
    /// A secret grant, redeemed at the send, beside the record the call
    /// names.
    Grant {
        grant: SecretGrantRef,
        target: SecretGrantTarget,
        custody: Option<EntityId>,
    },
    /// The custody record a `self.use` call names.
    Record(EntityId),
    /// The route's own secret, by name, resolved at the door.
    Route(String),
}

/// One send's credential, known before its exchange is declared.
pub(super) struct Presenting {
    effector: String,
    /// `None` when the send presents nothing.
    door: Option<Door>,
    /// The text each copy of the presented value becomes.
    text: String,
}

impl ServedConnectorCallHost {
    /// The credential a send on `route` presents: the grant this host
    /// redeems, else the record it presents, else the route's own secret.
    pub(super) fn presenting(&self, route: ConnectorCallRoute) -> Presenting {
        let effector = format!("connector:{}", route.connector);
        let door = match (self.grant, self.credential, route.secret_ref) {
            (Some(grant), custody, _) => Some(Door::Grant {
                grant,
                target: SecretGrantTarget::Connector { name: route.name },
                custody,
            }),
            (None, Some(custody), _) => Some(Door::Record(custody)),
            (None, None, Some(secret_ref)) => Some(Door::Route(secret_ref)),
            (None, None, None) => None,
        };
        let text = match &door {
            Some(Door::Grant { custody, .. }) => self.vault.secret_clear_text(custody.as_ref()),
            Some(Door::Record(custody)) => self.vault.secret_clear_text(Some(custody)),
            Some(Door::Route(secret_ref)) => self.vault.secret_clear_text_for_ref(secret_ref),
            None => String::new(),
        };
        Presenting {
            effector,
            door,
            text,
        }
    }
}

impl Presenting {
    /// Runs `exchange` with this credential, inside its door, and clears
    /// what came back there. `presented` is what the door released.
    pub(super) fn send(
        self,
        vault: &Vault,
        exchange: &Exchange<'_>,
        presented: &mut Option<SentPresentation>,
    ) -> Sent {
        let Some(door) = self.door else {
            return exchange.run(None, None);
        };
        let mut sent = None;
        let mut present = |value: &[u8]| -> oneiron::Result<()> {
            let header = authorization_header(value)?;
            let value = SentValue::new(value, &self.text);
            sent = Some(exchange.run(Some(header), Some(&value)).cleared(&value));
            Ok(())
        };
        let effector = self.effector.as_str();
        let door = match door {
            Door::Grant {
                grant,
                target,
                custody,
            } => vault
                .redeem_secret_grant_at_door(&grant, &target, &mut present)
                .map(|redeemed| {
                    custody.map(|custody| SentPresentation::cleared(custody, redeemed.generation))
                }),
            Door::Record(custody) => vault
                .inject_secret_record_at_door(&custody, effector, &mut present)
                .map(|receipt| Some(SentPresentation::cleared(custody, receipt.value_generation))),
            Door::Route(secret_ref) => vault
                .inject_secret_at_door_resolved(&secret_ref, effector, &mut present)
                .map(|(custody, receipt)| {
                    Some(SentPresentation::cleared(custody, receipt.value_generation))
                }),
        };
        // The record a door that presented its value resolved (FIX 5455),
        // and the generation it released.
        *presented = door.ok().flatten();
        // Once the exchange ran, what the connector said is the delivery
        // fact, whatever the door reports after it.
        sent.unwrap_or_else(|| Sent::not_sent(OutboundFailureKind::TransportNotStarted, None))
    }
}

/// The stored value is a whole `Authorization` header (`Basic ...` or
/// `Bearer ...`) or a bare bearer token, as the native mail check reads it.
fn authorization_header(value: &[u8]) -> oneiron::Result<HeaderValue> {
    let value = std::str::from_utf8(value)
        .map_err(|_| oneiron::Error::InvalidConfig("the stored credential is not text".to_owned()))?
        .trim();
    let header = if value.starts_with("Basic ") || value.starts_with("Bearer ") {
        value.to_owned()
    } else {
        format!("Bearer {value}")
    };
    let mut header = HeaderValue::from_str(&header).map_err(|_| {
        oneiron::Error::InvalidConfig("the stored credential is not a header value".to_owned())
    })?;
    header.set_sensitive(true);
    Ok(header)
}

impl Sent {
    /// This send's answer cleared of the value `value` it presented: its
    /// reply, raw body and failure label. Its questions were cleared before
    /// the registry took them.
    pub(super) fn cleared(mut self, value: &SentValue<'_>) -> Self {
        if let Some(reply) = self.reply.as_mut() {
            clear_reply(reply, value);
        }
        if let Some(body) = self.body.as_mut() {
            value.clear_bytes(body);
        }
        if let Some(error) = self.error.as_mut() {
            value.clear_string(error);
        }
        self
    }
}

impl Declared<'_> {
    /// Keeps `questions` in the registry under this send's binding, each
    /// cleared first of the value the send presented, if it presented one.
    pub(super) fn keep_questions(
        &self,
        questions: &mut [ConnectorQuestion],
        value: Option<&SentValue<'_>>,
    ) -> Option<Registered> {
        if let Some(value) = value {
            clear_questions(questions, value);
        }
        self.registry.register(self.binding.clone(), questions)
    }
}

/// A tool's reply cleared of `value`: its content (an `isError` reply's
/// too), structured content and JSON-RPC error.
fn clear_reply(reply: &mut UntrustedToolResult, value: &SentValue<'_>) {
    value.clear_json(&mut reply.content);
    if let Some(structured) = reply.structured_content.as_mut() {
        value.clear_json(structured);
    }
    if let Some(error) = reply.rpc_error.as_mut() {
        value.clear_json(error);
    }
}

/// Each question's key, message and schema cleared of `value`.
pub(super) fn clear_questions(questions: &mut [ConnectorQuestion], value: &SentValue<'_>) {
    for question in questions {
        value.clear_string(&mut question.key);
        value.clear_string(&mut question.message);
        value.clear_json(&mut question.requested_schema);
    }
}

/// A live exchange worker's event cleared of `value`: a next round's
/// questions, or the terminal reply.
pub(super) fn clear_event(event: &mut WorkerEvent, value: &SentValue<'_>) {
    match event {
        WorkerEvent::Question { questions, .. } => clear_questions(questions, value),
        WorkerEvent::Result(reply) => clear_reply(reply, value),
        WorkerEvent::Failed { .. } => {}
    }
}
