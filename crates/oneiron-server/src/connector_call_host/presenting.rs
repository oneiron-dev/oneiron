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
//!
//! A question key the clearing changed held the value: the caller answers it
//! under a unique alias, and the original key, kept zeroized for its round
//! only, goes back only on the wire (FIX 8051). A route's own secret is
//! presented by the record its name resolved to before the exchange was
//! declared, never by the name again at the door
//! (CONNECTOR_PRESENT_BY_RECORD_ID).

use oneiron::limit_ask::EngineLimit;
use oneiron::outbound_consent::{
    ConnectorSentClearer, SentGeneration, SentGenerations, replace_spans,
};
use oneiron::secret_lease::ConnectorGrantRedemption;
use zeroize::Zeroizing;

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
    /// A record the use's own run found, presented through that run's seat
    /// binding under the route effector's door policy (FIX 8334).
    Run(EntityId, RunSecretHolder),
    /// The record the route's own secret name resolved to before the
    /// exchange was declared, presented by its id.
    Route(EntityId),
    /// The route's own secret names no live record: nothing is sent, as
    /// the door refused it before.
    Unresolved,
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
            (None, Some(custody), _) => Some(match self.run {
                Some(holder) => Door::Run(custody, holder),
                None => Door::Record(custody),
            }),
            (None, None, Some(secret_ref)) => {
                Some(match self.vault.resolve_secret_ref(&secret_ref) {
                    Ok(Some(custody)) => Door::Route(custody),
                    _ => Door::Unresolved,
                })
            }
            (None, None, None) => None,
        };
        let text = match &door {
            Some(Door::Grant { custody, .. }) => self.vault.secret_clear_text(custody.as_ref()),
            Some(Door::Record(custody) | Door::Route(custody) | Door::Run(custody, _)) => {
                self.vault.secret_clear_text(Some(custody))
            }
            Some(Door::Unresolved) | None => String::new(),
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
    /// what came back there. `presented` is what the door released. `row`
    /// is the call's governing key and tool: their durable issuer binding is
    /// read before the door opens, so a held send opens no door and counts
    /// no grant redemption (FIX 12097), and again inside the door, the last
    /// point before the credential leaves. While an issuer change the owner
    /// has not accepted holds the row, nothing is presented or sent (FIX
    /// 9303).
    pub(super) fn send(
        self,
        vault: &Vault,
        exchange: &Exchange<'_>,
        row: Option<(&EntityId, &str)>,
        presented: &mut Option<SentPresentation>,
    ) -> Sent {
        if let Some((key_ref, tool)) = row {
            match vault.connector_issuer_hold(key_ref, tool) {
                Ok(Some(reason)) => return Sent::held(reason),
                Ok(None) => {}
                // A binding that cannot be read sends nothing, as the read
                // inside the door answers it.
                Err(error) => {
                    tracing::warn!(%error, "connector issuer binding not read");
                    return Sent::not_sent(OutboundFailureKind::TransportNotStarted, None);
                }
            }
        }
        let Some(door) = self.door else {
            // A live exchange it opens presented nothing (fix list row
            // 10550).
            return exchange
                .run(None, None)
                .presenting(SentGenerations::CredentialFree);
        };
        let mut sent = None;
        let mut held = None;
        let mut trimmed = false;
        let mut present = |value: &[u8]| -> oneiron::Result<()> {
            if let Some((key_ref, tool)) = row {
                held = vault.connector_issuer_hold(key_ref, tool)?;
                if held.is_some() {
                    return Ok(());
                }
            }
            trimmed = reads_trimmed(value);
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
            } => match row {
                Some((key_ref, tool)) => match vault.redeem_connector_grant_at_door(
                    &grant,
                    &target,
                    key_ref,
                    tool,
                    &mut present,
                ) {
                    Ok(ConnectorGrantRedemption::Redeemed(redeemed)) => Ok(custody
                        .map(|custody| SentPresentation::cleared(custody, redeemed.generation))),
                    Ok(ConnectorGrantRedemption::Held { reason }) => {
                        return Sent::held(reason);
                    }
                    Err(error) => Err(error),
                },
                None => vault
                    .redeem_secret_grant_at_door(&grant, &target, &mut present)
                    .map(|redeemed| {
                        custody
                            .map(|custody| SentPresentation::cleared(custody, redeemed.generation))
                    }),
            },
            Door::Record(custody) => vault
                .inject_secret_record_at_door(&custody, effector, &mut present)
                .map(|receipt| Some(SentPresentation::cleared(custody, receipt.value_generation))),
            // The record's handle text names it at the run's door.
            Door::Run(custody, holder) => vault
                .with_run_secret_for(&holder, &self.text, effector, &mut present)
                .map(|receipt| Some(SentPresentation::cleared(custody, receipt.value_generation))),
            Door::Route(custody) => vault
                .present_resolved_secret_at_door(&custody, effector, &mut present)
                .map(|receipt| Some(SentPresentation::cleared(custody, receipt.value_generation))),
            Door::Unresolved => Ok(None),
        };
        // A held row presented nothing to the connector: the send answers
        // with its hold (FIX 9303).
        if let Some(reason) = held {
            return Sent::held(reason);
        }
        // A typed secret refusal at any door answers as its typed refusal
        // (FIX 6673, FIX 11565); any other door error keeps today's
        // transport answer.
        let refused = match &door {
            Err(oneiron::Error::Secret(secret)) => {
                Some(oneiron::outbound_intent_ledger::SecretSendRefusal::from_secret_error(secret))
            }
            _ => None,
        };
        // The record a door that presented its value resolved (FIX 5455),
        // and the generation it released.
        *presented = door.ok().flatten();
        // A live exchange keeps what its send presented, as the door's
        // receipt names it (fix list row 10550): a value no record names is
        // unknown, and that exchange is never resumed.
        let presentation = match *presented {
            Some(presentation) => SentGenerations::of(Some(SentGeneration {
                custody: presentation.custody,
                generation: presentation.generation,
                trimmed,
            })),
            None => SentGenerations::Unknown,
        };
        // Once the exchange ran, what the connector said is the delivery
        // fact, whatever the door reports after it.
        sent.map_or_else(
            || match refused {
                // A stale grant and its siblings refuse, they do not fail delivery (FIX 6673).
                Some(secret) => Sent::refused(secret),
                None => Sent::not_sent(OutboundFailureKind::TransportNotStarted, None),
            },
            |sent| sent.presenting(presentation),
        )
    }
}

/// Whether the presented bytes read the same trimmed (fix list row 10550).
fn reads_trimmed(value: &[u8]) -> bool {
    std::str::from_utf8(value).is_ok_and(|text| text.trim() == text)
}

/// What a credential presents again for a live exchange taken up after a
/// restart (FIX 9157): the `Authorization` header its session sends, and
/// the value everything the connector says next is cleared of.
pub(super) struct Presented {
    pub(super) auth: Option<HeaderValue>,
    pub(super) kept: Option<KeptSentValue>,
    /// The presentation the door's receipt names, when it presented a
    /// value under a record (fix list row 10550).
    pub(super) sent: Option<SentGeneration>,
}

impl Presenting {
    /// Presents this credential again, inside its door, for a live exchange
    /// taken up after a restart (FIX 9157): the callback only rebuilds the
    /// header and the clearing value, and nothing is sent here. A grant door
    /// counts the redemption as a send, unless the call's row meets an
    /// issuer hold, which counts nothing. `None` when the door refuses it,
    /// the row is held, or the route's secret names no live record.
    pub(super) fn present_again(
        self,
        vault: &Vault,
        row: Option<(&EntityId, &str)>,
    ) -> Option<Presented> {
        if let Some((key_ref, tool)) = row {
            match vault.connector_issuer_hold(key_ref, tool) {
                Ok(None) => {}
                Ok(Some(_)) => return None,
                Err(error) => {
                    tracing::warn!(%error, "connector issuer binding not read");
                    return None;
                }
            }
        }
        let Some(door) = self.door else {
            return Some(Presented {
                auth: None,
                kept: None,
                sent: None,
            });
        };
        let mut presented = None;
        let mut trimmed = false;
        let mut present = |value: &[u8]| -> oneiron::Result<()> {
            trimmed = reads_trimmed(value);
            presented = Some(Presented {
                auth: Some(authorization_header(value)?),
                kept: Some(SentValue::new(value, &self.text).keep()),
                sent: None,
            });
            Ok(())
        };
        let effector = self.effector.as_str();
        // The record and the generation the door released, as its receipt
        // names them; `None` when it opened no door.
        let opened: Option<Option<(EntityId, u32)>> = match door {
            Door::Grant {
                grant,
                target,
                custody,
            } => match row {
                Some((key_ref, tool)) => {
                    match vault.redeem_connector_grant_at_door(
                        &grant,
                        &target,
                        key_ref,
                        tool,
                        &mut present,
                    ) {
                        Ok(ConnectorGrantRedemption::Redeemed(redeemed)) => {
                            Some(custody.map(|custody| (custody, redeemed.generation)))
                        }
                        Ok(ConnectorGrantRedemption::Held { .. }) => return None,
                        Err(_) => None,
                    }
                }
                None => vault
                    .redeem_secret_grant_at_door(&grant, &target, &mut present)
                    .ok()
                    .map(|redeemed| custody.map(|custody| (custody, redeemed.generation))),
            },
            Door::Record(custody) => vault
                .inject_secret_record_at_door(&custody, effector, &mut present)
                .ok()
                .map(|receipt| Some((custody, receipt.value_generation))),
            Door::Run(custody, holder) => vault
                .with_run_secret_for(&holder, &self.text, effector, &mut present)
                .ok()
                .map(|receipt| Some((custody, receipt.value_generation))),
            Door::Route(custody) => vault
                .present_resolved_secret_at_door(&custody, effector, &mut present)
                .ok()
                .map(|receipt| Some((custody, receipt.value_generation))),
            Door::Unresolved => None,
        };
        let released = opened?;
        let mut presented = presented?;
        presented.sent = released.map(|(custody, generation)| SentGeneration {
            custody,
            generation,
            trimmed,
        });
        Some(presented)
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
    /// This send with what it presented kept beside its first round's
    /// resume state, when it keeps one (fix list row 10550).
    fn presenting(mut self, presented: SentGenerations) -> Self {
        if let Some(resume) = self.resume.as_mut() {
            resume.sent = presented;
        }
        self
    }

    /// This send's answer cleared of the value `value` it presented: its
    /// reply and failure label. Its raw body was cleared before the send
    /// was acknowledged; its questions before the registry took them.
    pub(super) fn cleared(mut self, value: &SentValue<'_>) -> Self {
        if let Some(reply) = self.reply.as_mut() {
            clear_reply(reply, value);
        }
        if let Some(error) = self.error.as_mut() {
            value.clear_string(error);
        }
        self
    }
}

/// One round of a connector's questions the registry took in: its
/// registration, the questions as the caller sees them, and the original key
/// behind each alias.
pub(super) struct KeptRound {
    pub(super) registered: Registered,
    pub(super) questions: Vec<ConnectorQuestion>,
    pub(super) aliases: KeyAliases,
}

impl Declared<'_> {
    /// Keeps `questions` in the registry under this send's binding, each
    /// cleared first of the value the send presented, if it presented one.
    /// It never refuses them: past the `[limits]` row of live question sets
    /// the row asks whether everything is okay (FIX 3895).
    pub(super) fn keep_questions(
        &self,
        mut questions: Vec<ConnectorQuestion>,
        value: Option<&SentValue<'_>>,
    ) -> KeptRound {
        let aliases = match value {
            Some(value) => clear_questions(&mut questions, value),
            None => KeyAliases::default(),
        };
        let registered = self.registry.register(self.binding.clone(), &questions);
        let live = u64::try_from(registered.live).unwrap_or(u64::MAX);
        let _ = self
            .vault
            .measure_limit(EngineLimit::ConnectorLiveQuestions, live);
        KeptRound {
            registered,
            questions,
            aliases,
        }
    }
}

/// One round's question keys the clearing changed (FIX 8051): each alias
/// the caller answers under, beside the original key the connector asked
/// under, which held the presented value. The original is kept zeroized for
/// the round only, never shown, and goes back only on the wire.
#[derive(Default)]
pub(super) struct KeyAliases(Vec<(String, Zeroizing<String>)>);

impl KeyAliases {
    /// The key the connector asked under for the caller's key `key`.
    fn original<'a>(&'a self, key: &'a str) -> &'a str {
        self.0
            .iter()
            .find(|(alias, _)| alias == key)
            .map_or(key, |(_, original)| original.as_str())
    }

    /// `responses`, keyed as the caller answered, keyed as the connector's
    /// wire takes them.
    pub(super) fn restore(&self, responses: &BTreeMap<String, Value>) -> Map<String, Value> {
        responses
            .iter()
            .map(|(key, response)| (self.original(key).to_owned(), response.clone()))
            .collect()
    }

    /// Each alias beside the original key it stands for: what a round's
    /// resume state keeps (FIX 9157).
    pub(super) fn pairs(&self) -> Vec<(&str, &str)> {
        self.0
            .iter()
            .map(|(alias, original)| (alias.as_str(), original.as_str()))
            .collect()
    }

    /// The aliases a round's resume state kept, each original zeroized
    /// again (FIX 9157).
    pub(super) fn of_pairs(pairs: Vec<(String, String)>) -> Self {
        Self(
            pairs
                .into_iter()
                .map(|(alias, original)| (alias, Zeroizing::new(original)))
                .collect(),
        )
    }

    /// The response to the connector's own key `key`.
    pub(super) fn response<'r>(
        &self,
        responses: &'r BTreeMap<String, Value>,
        key: &str,
    ) -> Option<&'r Value> {
        responses
            .iter()
            .find(|(answered, _)| self.original(answered) == key)
            .map(|(_, response)| response)
    }
}

/// What clears what a connector says of what its exchange presented: the
/// value a door released for this send, the earlier presentations of a
/// resumed exchange (fix list row 10550), or both.
pub(super) trait Clears {
    fn clear_json(&self, json: &mut Value);
    fn clear_string(&self, string: &mut String);
}

impl Clears for SentValue<'_> {
    fn clear_json(&self, json: &mut Value) {
        SentValue::clear_json(self, json);
    }

    fn clear_string(&self, string: &mut String) {
        SentValue::clear_string(self, string);
    }
}

impl Clears for ConnectorSentClearer {
    fn clear_json(&self, json: &mut Value) {
        ConnectorSentClearer::clear_json(self, json);
    }

    fn clear_string(&self, string: &mut String) {
        ConnectorSentClearer::clear_string(self, string);
    }
}

/// The value presented now, then the presentations made before, each
/// when there is one.
pub(super) struct Both<'n, 'b> {
    pub(super) now: Option<SentValue<'n>>,
    pub(super) before: Option<&'b ConnectorSentClearer>,
}

impl Clears for Both<'_, '_> {
    fn clear_json(&self, json: &mut Value) {
        if self.before.is_none() {
            if let Some(now) = &self.now {
                now.clear_json(json);
            }
            return;
        }
        match json {
            Value::String(string) => self.clear_string(string),
            Value::Array(items) => items.iter_mut().for_each(|item| self.clear_json(item)),
            Value::Object(fields) => {
                let taken = std::mem::take(fields);
                for (mut key, mut field) in taken {
                    self.clear_string(&mut key);
                    self.clear_json(&mut field);
                    fields.insert(key, field);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// The value now and the earlier ones are matched against the untouched
    /// text and replaced together, so a value that contains another, or
    /// that another contains, goes whole.
    fn clear_string(&self, string: &mut String) {
        let Some(before) = self.before else {
            if let Some(now) = &self.now {
                now.clear_string(string);
            }
            return;
        };
        let data = string.as_bytes();
        let mut spans = before.spans(data);
        if let Some(now) = &self.now {
            spans.extend(now.spans(data));
        }
        if let Some(bytes) = replace_spans(data, spans) {
            *string = String::from_utf8(bytes)
                .unwrap_or_else(|error| String::from_utf8_lossy(&error.into_bytes()).into_owned());
        }
    }
}

/// A tool's reply cleared of `value`: its content (an `isError` reply's
/// too), structured content and JSON-RPC error.
fn clear_reply(reply: &mut UntrustedToolResult, value: &dyn Clears) {
    value.clear_json(&mut reply.content);
    if let Some(structured) = reply.structured_content.as_mut() {
        value.clear_json(structured);
    }
    if let Some(error) = reply.rpc_error.as_mut() {
        value.clear_json(error);
    }
}

/// Each question's key, message and schema cleared of `value`. A key the
/// clearing changed held the value: it becomes a unique alias, its cleared
/// text (with `#2`, `#3`, ... while another key of the round reads the
/// same), and its original goes in the returned map (FIX 8051). A key the
/// clearing did not change stays byte for byte.
pub(super) fn clear_questions(
    questions: &mut [ConnectorQuestion],
    value: &dyn Clears,
) -> KeyAliases {
    let mut changed = Vec::new();
    for (at, question) in questions.iter_mut().enumerate() {
        let original = Zeroizing::new(question.key.clone());
        value.clear_string(&mut question.key);
        if question.key != *original {
            changed.push((at, original));
        }
        value.clear_string(&mut question.message);
        value.clear_json(&mut question.requested_schema);
    }
    let mut aliases = Vec::with_capacity(changed.len());
    for (at, original) in changed {
        let alias = unique_key(questions, at);
        questions[at].key.clone_from(&alias);
        aliases.push((alias, original));
    }
    KeyAliases(aliases)
}

/// The key of question `at`, made unique among the round's keys: as it
/// reads, else with the first free `#n` (from 2) after it.
fn unique_key(questions: &[ConnectorQuestion], at: usize) -> String {
    let base = &questions[at].key;
    let taken = |key: &str| {
        questions
            .iter()
            .enumerate()
            .any(|(other, question)| other != at && question.key == key)
    };
    let mut alias = base.clone();
    let mut n = 1_u64;
    while taken(&alias) {
        n += 1;
        alias = format!("{base}#{n}");
    }
    alias
}

/// A live exchange worker's event cleared of `value`: a next round's
/// questions, or the terminal reply.
pub(super) fn clear_event(event: &mut WorkerEvent, value: &dyn Clears) {
    match event {
        // A terminal event carries no round to answer; a round's questions
        // take their aliases in the worker.
        WorkerEvent::Question { questions, .. } => drop(clear_questions(questions, value)),
        WorkerEvent::Result(reply) => clear_reply(reply, value),
        WorkerEvent::Failed { .. } => {}
    }
}
