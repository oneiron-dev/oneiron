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
    /// is the call's governing key and tool: inside the door, the last point
    /// before the credential leaves, their durable issuer binding is read
    /// again, and while an issuer change the owner has not accepted holds
    /// the row, nothing is presented or sent (FIX 9303).
    pub(super) fn send(
        self,
        vault: &Vault,
        exchange: &Exchange<'_>,
        row: Option<(&EntityId, &str)>,
        presented: &mut Option<SentPresentation>,
    ) -> Sent {
        let Some(door) = self.door else {
            return exchange.run(None, None);
        };
        let mut sent = None;
        let mut held = None;
        let mut present = |value: &[u8]| -> oneiron::Result<()> {
            if let Some((key_ref, tool)) = row {
                held = vault.connector_issuer_hold(key_ref, tool)?;
                if held.is_some() {
                    return Ok(());
                }
            }
            let header = authorization_header(value)?;
            let value = SentValue::new(value, &self.text);
            sent = Some(exchange.run(Some(header), Some(&value)).cleared(&value));
            Ok(())
        };
        let effector = self.effector.as_str();
        // A grant refusal at the send answers as its typed refusal (FIX 6673).
        let mut grant_refused = false;
        let door = match door {
            Door::Grant {
                grant,
                target,
                custody,
            } => {
                match vault.redeem_secret_grant_at_door(&grant, &target, &mut present) {
                    Ok(redeemed) => Ok(custody
                        .map(|custody| SentPresentation::cleared(custody, redeemed.generation))),
                    Err(error) => {
                        grant_refused = matches!(error, oneiron::Error::Secret(_));
                        Ok(None)
                    }
                }
            }
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
        // The record a door that presented its value resolved (FIX 5455),
        // and the generation it released.
        *presented = door.ok().flatten();
        // Once the exchange ran, what the connector said is the delivery
        // fact, whatever the door reports after it.
        sent.unwrap_or_else(|| {
            if grant_refused {
                // A stale grant and its siblings refuse, they do not fail delivery (FIX 6673).
                Sent::not_sent(OutboundFailureKind::Rejected, None)
            } else {
                Sent::not_sent(OutboundFailureKind::TransportNotStarted, None)
            }
        })
    }
}

/// What a credential presents again for a live exchange taken up after a
/// restart (FIX 9157): the `Authorization` header its session sends, and
/// the value everything the connector says next is cleared of.
pub(super) struct Presented {
    pub(super) auth: Option<HeaderValue>,
    pub(super) kept: Option<KeptSentValue>,
}

impl Presenting {
    /// Presents this credential again, inside its door, for a live exchange
    /// taken up after a restart (FIX 9157): the callback only rebuilds the
    /// header and the clearing value, and nothing is sent here. A grant door
    /// counts the redemption as a send. `None` when the door refuses it or
    /// the route's secret names no live record.
    pub(super) fn present_again(self, vault: &Vault) -> Option<Presented> {
        let Some(door) = self.door else {
            return Some(Presented {
                auth: None,
                kept: None,
            });
        };
        let mut presented = None;
        let mut present = |value: &[u8]| -> oneiron::Result<()> {
            presented = Some(Presented {
                auth: Some(authorization_header(value)?),
                kept: Some(SentValue::new(value, &self.text).keep()),
            });
            Ok(())
        };
        let effector = self.effector.as_str();
        let opened = match door {
            Door::Grant { grant, target, .. } => vault
                .redeem_secret_grant_at_door(&grant, &target, &mut present)
                .is_ok(),
            Door::Record(custody) => vault
                .inject_secret_record_at_door(&custody, effector, &mut present)
                .is_ok(),
            Door::Run(_, holder) => vault
                .with_run_secret_for(&holder, &self.text, effector, &mut present)
                .is_ok(),
            Door::Route(custody) => vault
                .present_resolved_secret_at_door(&custody, effector, &mut present)
                .is_ok(),
            Door::Unresolved => false,
        };
        if !opened {
            return None;
        }
        presented
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

/// Each question's key, message and schema cleared of `value`. A key the
/// clearing changed held the value: it becomes a unique alias, its cleared
/// text (with `#2`, `#3`, ... while another key of the round reads the
/// same), and its original goes in the returned map (FIX 8051). A key the
/// clearing did not change stays byte for byte.
pub(super) fn clear_questions(
    questions: &mut [ConnectorQuestion],
    value: &SentValue<'_>,
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
pub(super) fn clear_event(event: &mut WorkerEvent, value: &SentValue<'_>) {
    match event {
        // A terminal event carries no round to answer; a round's questions
        // take their aliases in the worker.
        WorkerEvent::Question { questions, .. } => drop(clear_questions(questions, value)),
        WorkerEvent::Result(reply) => clear_reply(reply, value),
        WorkerEvent::Failed { .. } => {}
    }
}
