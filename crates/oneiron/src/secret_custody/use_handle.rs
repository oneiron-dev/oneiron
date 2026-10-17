//! `self.use(handle)` (OF-560; ARCH-0069 "One use(handle) call"): an agent
//! hands a secret to one trusted operation by its handle, and gets back the
//! operation's result, never the value.
//!
//! The agent names a handle, an operation and the operation's arguments. It
//! names no tier and no effector: the operation fixes its effector, and the
//! rung is the one the record's binding for that effector names. Every v1
//! operation is a T0 door, where the value goes straight into the operation
//! and comes back to nobody.
//!
//! The only authorization is the custody binding (ARCH-0069
//! `#broker-grant-check`): the record is active, it holds a binding for the
//! operation's effector that grants `read`, and the live floor admits the
//! rung. There is no per-use ask, and a reveal's grant does not reach here.
//! A secret the mask on write found carries no binding, so its handle is
//! refused until the owner binds it ([`SECRET_BIND_DOOR`],
//! [`Vault::bind_secret_as_owner`]).
//!
//! The operation's result and its failure text are cleared of the value
//! (each copy becomes the record's `[secret scN]` text) before they go
//! anywhere, so no hook, receipt, record or reply holds it. Every use the
//! handle resolves for writes one Gate record: the handle, the record's
//! generation, the effector, the operation, the decision and the send status.

mod bind;

use std::fmt;

use serde_json::{Value, json};

use super::doors::{read_secret_custody_admission_in_txn, resolve_secret_ref_in_txn};
use super::reveal::parse_secret_handle;
use super::types::{SecretBinding, SecretCustodyStatus};
use crate::connector_key::{
    GMAIL_PROFILE_CHECK, LINE_BOT_INFO_CHECK, LINKEDIN_SESSION_CHECK, PackConnectionCheck,
    PackConnectionVerifier, ProviderConnectionChecks, SLACK_AUTH_TEST_CHECK,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::skill_hub::pack_catalog::{PackSetupAuth, PackSetupSecret};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, Store};
use crate::vault::Vault;

pub use self::bind::{SECRET_BIND_REASON, SecretBindRequest, SecretBound};

/// The owner door that adds a binding to a secret, named by every refusal of
/// a handle that has none for the operation's effector.
pub const SECRET_BIND_DOOR: &str = "POST /v1/owner/secrets/bind";

/// The Gate reason code of every use's record.
pub const SECRET_USE_REASON: &str = "gate.secret.use";

/// The Gate content kind of every use's record.
const SECRET_USE_CONTENT_KIND: &str = "secret_use";

/// Domain of a use record's diff handle: a digest of what was used, by
/// what, never of the value.
const USE_DIFF_DOMAIN: &[u8] = b"oneiron.secret_use.v1";

/// What the agent's own surface sees in place of the record's name: the
/// operation table's `pack` for a provider check.
const USE_PACK: &str = "self.use";

/// The operations `self.use` hands a secret to, each a trusted door that
/// already takes a credential at T0 through the credential door: the
/// read-only provider checks the engine ships, each to one fixed provider
/// endpoint. A call on the canon rows waits for its own entry (the FIX-LIST
/// names them). One table, so a ruling changes one entry.
pub const SECRET_USE_OPERATIONS: [SecretUseOperation; 4] = [
    SecretUseOperation {
        name: SLACK_AUTH_TEST_CHECK,
        effector: "connector:slack",
        what: "Slack's auth.test with the token: the workspace and app it belongs to",
        consume: slack_auth_test,
    },
    SecretUseOperation {
        name: LINE_BOT_INFO_CHECK,
        effector: "connector:line",
        what: "LINE's bot info with the channel token: the Official Account it belongs to",
        consume: line_bot_info,
    },
    SecretUseOperation {
        name: GMAIL_PROFILE_CHECK,
        effector: "connector:gmail",
        what: "Gmail's profile with the grant: the mailbox it reads",
        consume: gmail_profile,
    },
    SecretUseOperation {
        name: LINKEDIN_SESSION_CHECK,
        effector: "connector:linkedin",
        what: "LinkedIn's own profile with the session cookie: the member it signs in as",
        consume: linkedin_session,
    },
];

/// One operation of [`SECRET_USE_OPERATIONS`].
pub struct SecretUseOperation {
    /// What the agent names in `operation`.
    pub name: &'static str,
    /// The effector the record's binding must name.
    pub effector: &'static str,
    /// What it does with the secret, and what comes back, in plain words.
    pub what: &'static str,
    consume: SecretUseConsumer,
}

impl fmt::Debug for SecretUseOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretUseOperation")
            .field("name", &self.name)
            .field("effector", &self.effector)
            .finish_non_exhaustive()
    }
}

/// An operation's consumer: it presents the secret named by `target` through
/// the credential door, for `target.effector` only, and answers with what
/// came back or why it failed. Its answer is cleared of the value after it
/// returns.
type SecretUseConsumer =
    fn(&Vault, &SecretUseTarget<'_>, &Value) -> std::result::Result<Value, String>;

/// The secret an operation presents: the record's live name, and the
/// operation's effector.
struct SecretUseTarget<'a> {
    name: &'a str,
    effector: &'a str,
    operation: &'a str,
}

/// Who uses a secret: a verified actor of a recorded session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SecretUser {
    actor: EntityId,
    actor_class: EdgeActorClass,
}

impl SecretUser {
    pub(crate) const fn new(actor: EntityId, actor_class: EdgeActorClass) -> Self {
        Self { actor, actor_class }
    }
}

/// Whether a use ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretUseDecision {
    /// The binding admitted it and the operation ran.
    Used,
    /// The binding, the record's status or the floor refused it.
    Refused,
}

impl SecretUseDecision {
    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Used => "used",
            Self::Refused => "refused",
        }
    }
}

/// What the operation's send came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretUseSend {
    /// The provider answered, and the result is the answer.
    Answered,
    /// The operation failed; the failure says why.
    Failed,
    /// Nothing was sent.
    NotSent,
    /// It ran, but the result could not be cleared of the value, so none
    /// comes back.
    Withheld,
}

impl SecretUseSend {
    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::Failed => "failed",
            Self::NotSent => "not_sent",
            Self::Withheld => "withheld",
        }
    }
}

/// One use's receipt: what was used, by what, and how it went. No value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretUseReceipt {
    /// The record's handle, such as `sc12`.
    pub handle: String,
    /// The record's rotation generation when it was used.
    pub generation: u32,
    pub effector: String,
    pub operation: String,
    pub decision: SecretUseDecision,
    pub send: SecretUseSend,
    /// The Gate record that keeps it.
    pub receipt: GateDecisionId,
    pub used_at: u64,
}

/// What a use came to. `result` and `failure` hold no copy of the value.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretUseOutcome {
    pub receipt: SecretUseReceipt,
    /// The operation's answer, when it answered.
    pub result: Option<Value>,
    /// Why it failed, when it did.
    pub failure: Option<String>,
}

impl Vault {
    /// Hands the secret `handle` names to `operation`, one of
    /// [`SECRET_USE_OPERATIONS`], with its `arguments`, for `user`.
    ///
    /// # Errors
    /// [`GateError::InvalidConsentBound`] for text that is not a handle, an
    /// operation the table does not hold, or arguments that are not an
    /// object. [`SecretError::SecretRefNotFound`] for a handle that names no
    /// secret. Then, each with its refused Gate record:
    /// [`SecretError::SecretCustodyNotActive`] for a revoked or suspended
    /// record; [`SecretError::SecretBindingDenied`] for a record with no
    /// binding for the operation's effector, or one that does not grant
    /// `read`; the floor's and the door policy's own refusals.
    pub(crate) fn use_secret_handle(
        &self,
        user: &SecretUser,
        handle: &str,
        operation: &str,
        arguments: &Value,
    ) -> Result<SecretUseOutcome> {
        let op = SECRET_USE_OPERATIONS
            .iter()
            .find(|op| op.name == operation)
            .ok_or_else(|| {
                Error::Gate(GateError::InvalidConsentBound(
                    "self.use takes one of its operations, such as slack.auth_test",
                ))
            })?;
        if !arguments.is_object() {
            return Err(Error::Gate(GateError::InvalidConsentBound(
                "an operation's arguments are a JSON object",
            )));
        }
        let txn = self.store.env.read_txn()?;
        let (short, id) = handle_record_in_txn(&self.store, &txn, handle)?;
        let rec = read_secret_custody_admission_in_txn(&self.store, &txn, &id)?
            .ok_or_else(|| unknown(&short))?;
        let live = resolve_secret_ref_in_txn(&self.store, &txn, &rec.name)? == Some(id);
        drop(txn);
        let used = Used {
            user: *user,
            handle: short,
            secret: id,
            generation: rec.rotation_generation,
            op,
        };
        let admitted = if !live || rec.status != SecretCustodyStatus::Active {
            Err(not_active(&used.handle))
        } else if !rec
            .binding_for(op.effector)
            .is_some_and(SecretBinding::grants_read)
        {
            Err(unbound(&used.handle, op.effector))
        } else {
            self.check_secret_at_door(&rec.name, op.effector)
        };
        if let Err(refusal) = admitted {
            used.record(self, SecretUseDecision::Refused, SecretUseSend::NotSent)?;
            return Err(refusal);
        }
        let target = SecretUseTarget {
            name: &rec.name,
            effector: op.effector,
            operation: op.name,
        };
        // A consumer blocks on its provider. It runs on a thread of its own,
        // outside whatever async runtime the caller's door is on.
        let answer = std::thread::scope(|scope| {
            scope
                .spawn(|| (op.consume)(self, &target, arguments))
                .join()
        })
        .unwrap_or_else(|_| Err("the operation stopped before it answered".to_owned()));
        let (mut result, mut failure) = match answer {
            Ok(result) => (Some(result), None),
            Err(failure) => (None, Some(failure)),
        };
        let mut send = if result.is_some() {
            SecretUseSend::Answered
        } else {
            SecretUseSend::Failed
        };
        // The value is read once more, through the same door, only to find
        // it in what came back. If it cannot be, nothing comes back.
        let text = format!("[secret {}]", used.handle);
        let cleared = self.inject_secret_record_at_door(&id, op.effector, &mut |value: &[u8]| {
            if let Some(result) = result.as_mut() {
                clear_value(result, value, &text);
            }
            if let Some(failure) = failure.as_mut() {
                clear_text(failure, value, &text);
            }
            Ok(())
        });
        if cleared.is_err() {
            result = None;
            failure = Some("the result was withheld: it could not be cleared of the value".into());
            send = SecretUseSend::Withheld;
        }
        let receipt = used.record(self, SecretUseDecision::Used, send)?;
        Ok(SecretUseOutcome {
            receipt,
            result,
            failure,
        })
    }
}

/// One use as its Gate record keeps it.
struct Used {
    user: SecretUser,
    handle: String,
    secret: EntityId,
    generation: u32,
    op: &'static SecretUseOperation,
}

impl Used {
    fn record(
        &self,
        vault: &Vault,
        decision: SecretUseDecision,
        send: SecretUseSend,
    ) -> Result<SecretUseReceipt> {
        let decision_id = GateDecisionId::from_bytes(vault.store.clock.ulid()?);
        let generation = self.generation.to_be_bytes();
        let parts: [&[u8]; 5] = [
            USE_DIFF_DOMAIN,
            self.secret.as_bytes(),
            &generation,
            self.op.name.as_bytes(),
            self.op.effector.as_bytes(),
        ];
        let mut digest = blake3::Hasher::new();
        for part in parts {
            digest.update(&(part.len() as u64).to_be_bytes());
            digest.update(part);
        }
        let used_at = vault.with_write_txn_grouped(|txn| {
            let created_at = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            let record = GateDecisionRecord {
                version: GATE_DECISION_LEDGER_VERSION,
                decision_id,
                created_at,
                outcome: match decision {
                    SecretUseDecision::Used => "approved",
                    SecretUseDecision::Refused => "denied",
                }
                .into(),
                reason_codes: vec![SECRET_USE_REASON.into()],
                receipt_reasons: vec![
                    format!("use:{}", self.op.name),
                    format!("handle:{}", self.handle),
                    format!("generation:{}", self.generation),
                    format!("effector:{}", self.op.effector),
                    format!("decision:{}", decision.as_str()),
                    format!("send:{}", send.as_str()),
                ],
                system_notices: Vec::new(),
                actor_class: self.user.actor_class.gate_actor_class().into(),
                actor_ref: Some(self.user.actor.to_hex()),
                content_kind: SECRET_USE_CONTENT_KIND.into(),
                policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
                claim_id: None,
                grant_ref: None,
                diff_handle: digest.finalize().as_bytes().to_vec(),
                read_frontier_hash: [0; 32],
                redacted_at: None,
            };
            vault.store.append_gate_decision_in_txn(txn, &record)?;
            Ok(created_at)
        })?;
        Ok(SecretUseReceipt {
            handle: self.handle.clone(),
            generation: self.generation,
            effector: self.op.effector.to_owned(),
            operation: self.op.name.to_owned(),
            decision,
            send,
            receipt: decision_id,
            used_at,
        })
    }
}

/// Resolves a handle to its short id and the custody record it names.
fn handle_record_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    handle: &str,
) -> Result<(String, EntityId)> {
    let (short, hash) = parse_secret_handle(handle)?;
    // A forward key is the short id and one content-hash byte; a bare handle
    // names whichever hash the record holds now.
    let mut found = None;
    for row in store.short_ids.prefix_iter(txn, short.as_bytes())? {
        let (key, value) = row?;
        if key.len() != short.len() + 1 || hash.is_some_and(|hash| key[short.len()] != hash) {
            continue;
        }
        let bytes = <[u8; 16]>::try_from(&*value)
            .map_err(|_| Error::CorruptedIndex("short id entity id"))?;
        found = Some(EntityId::from_bytes(bytes)?);
        break;
    }
    let id = found.ok_or_else(|| unknown(short))?;
    match crate::ports::ShortIdStoreRead::port_short_id_reference(store, txn, &id)? {
        Some((name, _)) if name == short => Ok((short.to_owned(), id)),
        _ => Err(unknown(short)),
    }
}

/// Each copy of `value` in `json`, in a string or a key at any depth,
/// replaced by `text`.
fn clear_value(json: &mut Value, value: &[u8], text: &str) {
    match json {
        Value::String(string) => clear_text(string, value, text),
        Value::Array(items) => items
            .iter_mut()
            .for_each(|item| clear_value(item, value, text)),
        Value::Object(fields) => {
            let taken = std::mem::take(fields);
            for (mut key, mut field) in taken {
                clear_text(&mut key, value, text);
                clear_value(&mut field, value, text);
                fields.insert(key, field);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Each copy of `value` in `string`, as held and with its surrounding
/// whitespace trimmed (consumers trim before they present it), replaced by
/// `text`.
fn clear_text(string: &mut String, value: &[u8], text: &str) {
    let Ok(value) = std::str::from_utf8(value) else {
        return;
    };
    let trimmed = value.trim();
    for form in [value, trimmed] {
        if !form.is_empty() && string.contains(form) {
            *string = string.replace(form, text);
        }
        if trimmed == value {
            break;
        }
    }
}

/// A provider check: `check` on the secret, with the auth kind its pack
/// declares. It takes no arguments. The reply's digest is not passed on: it
/// is a digest of a reply that went out with the secret.
fn provider_check(
    check: &str,
    auth: PackSetupAuth,
    vault: &Vault,
    target: &SecretUseTarget<'_>,
    arguments: &Value,
) -> std::result::Result<Value, String> {
    if arguments
        .as_object()
        .is_some_and(|fields| !fields.is_empty())
    {
        return Err(format!("{} takes no arguments", target.operation));
    }
    let checks = ProviderConnectionChecks::new().map_err(|error| error.to_string())?;
    let secrets = [PackSetupSecret {
        name: target.name.to_owned(),
        label: target.operation.to_owned(),
        effector: target.effector.to_owned(),
        hint: None,
    }];
    let evidence = checks.verify(
        vault,
        &PackConnectionCheck {
            pack: USE_PACK,
            connection: target.operation,
            check,
            auth,
            secrets: &secrets,
            allowed_scopes: &[],
        },
    )?;
    Ok(json!({
        "account": evidence.account,
        "provider_account": evidence.provider_account,
        "scopes": evidence.scopes,
    }))
}

fn slack_auth_test(
    vault: &Vault,
    target: &SecretUseTarget<'_>,
    arguments: &Value,
) -> std::result::Result<Value, String> {
    provider_check(
        SLACK_AUTH_TEST_CHECK,
        PackSetupAuth::BotToken,
        vault,
        target,
        arguments,
    )
}

fn line_bot_info(
    vault: &Vault,
    target: &SecretUseTarget<'_>,
    arguments: &Value,
) -> std::result::Result<Value, String> {
    provider_check(
        LINE_BOT_INFO_CHECK,
        PackSetupAuth::BotToken,
        vault,
        target,
        arguments,
    )
}

fn gmail_profile(
    vault: &Vault,
    target: &SecretUseTarget<'_>,
    arguments: &Value,
) -> std::result::Result<Value, String> {
    provider_check(
        GMAIL_PROFILE_CHECK,
        PackSetupAuth::Oauth,
        vault,
        target,
        arguments,
    )
}

fn linkedin_session(
    vault: &Vault,
    target: &SecretUseTarget<'_>,
    arguments: &Value,
) -> std::result::Result<Value, String> {
    provider_check(
        LINKEDIN_SESSION_CHECK,
        PackSetupAuth::Session,
        vault,
        target,
        arguments,
    )
}

fn unknown(handle: &str) -> Error {
    Error::Secret(SecretError::SecretRefNotFound {
        name: handle.to_owned(),
    })
}

fn not_active(handle: &str) -> Error {
    Error::Secret(SecretError::SecretCustodyNotActive {
        name: handle.to_owned(),
    })
}

fn unbound(handle: &str, effector: &str) -> Error {
    Error::Secret(SecretError::SecretBindingDenied {
        effector: effector.to_owned(),
        secret_ref: handle.to_owned(),
    })
}
