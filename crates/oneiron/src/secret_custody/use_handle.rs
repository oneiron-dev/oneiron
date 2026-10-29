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
//! anywhere, so no hook, receipt, record or reply holds it: inside the send's
//! own door, with the bytes it released (`output`, FIX 7647). Every use the
//! handle resolves for writes its Gate records (`receipt`): an admitted use
//! commits its intent, send `pending`, before the send, and appends its
//! outcome after, linked to it (FIX 2622); a refused one writes one outcome.
//! The outcome names the handle, the generation its send released, the
//! effector, the operation, the decision and the send status, and beside the
//! handle's own identity the record and generation its send actually
//! presented (FIX 8052).
//!
//! Beside the table, a server sends [`SECRET_USE_CONNECTOR_CALL`]: one
//! connector call with the handle's secret as its credential, in place of
//! the route's own, for the effector `connector:<connector>` the route
//! names. Its body is the same use (`Vault::use_secret_with`); the call's
//! row keeps the record, so a held call that a resume sends presents the
//! same one, and its host clears its reply of the value inside each send's
//! door (`ConnectorCallHost::clears_at_door`).

mod bind;
mod lease;
mod output;
mod receipt;

use std::fmt;
use std::sync::{Mutex, PoisonError};

use serde_json::{Value, json};

use super::doors::{read_secret_custody_admission_in_txn, resolve_secret_ref_in_txn};
use super::reveal::parse_secret_handle;
use super::types::{SecretBinding, SecretCustodyStatus};
use crate::connector_key::{
    GMAIL_PROFILE_CHECK, LINE_BOT_INFO_CHECK, LINKEDIN_SESSION_CHECK, PackConnectionCheck,
    ProviderConnectionChecks, SLACK_AUTH_TEST_CHECK,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::secret_lease::{SecretGrantRef, SecretGrantTarget};
use crate::skill_hub::pack_catalog::{PackSetupAuth, PackSetupSecret};
use crate::store::{GateDecisionId, Store};
use crate::vault::Vault;

pub use self::bind::{SECRET_BIND_REASON, SecretBindRequest, SecretBound};
pub use self::output::{
    KeptSentValue, SECRET_USE_CLEAR_VALUE_SOURCE, SecretClearValueSource, SecretReleasePolicy,
    SentPresentation, SentValue,
};
use self::output::{clear_text, handle_text};
use self::receipt::{UsePhase, Used};

/// The owner door that adds a binding to a secret, named by every refusal of
/// a handle that has none for the operation's effector.
pub const SECRET_BIND_DOOR: &str = "POST /v1/owner/secrets/bind";

/// The Gate reason code of every use's record.
pub const SECRET_USE_REASON: &str = "gate.secret.use";

/// What the agent's own surface sees in place of the record's name: the
/// operation table's `pack` for a provider check.
const USE_PACK: &str = "self.use";

/// The operation that hands a secret to one connector call as its
/// credential. A server's operation, beside the table: only a server's
/// host sends a connector call, so an embedded vault refuses it.
pub const SECRET_USE_CONNECTOR_CALL: &str = "connector.call";

/// The operations `self.use` hands a secret to, each a trusted door that
/// already takes a credential at T0 through the credential door: the
/// read-only provider checks the engine ships, each to one fixed provider
/// endpoint. A call on the canon rows waits for its own entry (the FIX-LIST
/// names them). One table, so a ruling changes one entry.
pub static SECRET_USE_OPERATIONS: [SecretUseOperation; 4] = [
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
/// came back or why it failed, cleared of the value inside that door; it
/// notes what it sent on `target` ([`SecretUseTarget::note_sent`]).
type SecretUseConsumer =
    fn(&Vault, &SecretUseTarget<'_>, &Value) -> std::result::Result<Value, String>;

/// The secret an operation presents: the record's live name and id, and
/// the operation's effector.
pub(crate) struct SecretUseTarget<'a> {
    name: &'a str,
    effector: &'a str,
    operation: &'a str,
    /// The custody record the handle names.
    pub(crate) custody: EntityId,
    /// The record's handle, whose text stands in for the value.
    handle: &'a str,
    /// For a table operation under a secret grant, the grant as presented
    /// and its target: the operation redeems it at its real send (FIX 4491).
    grant: Option<(SecretGrantRef, &'a SecretGrantTarget)>,
    /// The redemption's refusal at that send, when it refused: nothing was
    /// sent, and the use answers with it.
    refusal: Mutex<Option<Error>>,
    /// What the operation's send presented, its answer already cleared of
    /// it inside the door (FIX 7647).
    sent: Mutex<Option<SentPresentation>>,
}

impl SecretUseTarget<'_> {
    /// Keeps the refusal a redemption at the send gave.
    fn refuse(&self, refusal: Error) {
        *self.refusal.lock().unwrap_or_else(PoisonError::into_inner) = Some(refusal);
    }

    /// Notes what the operation's send presented, as its door released it,
    /// its answer and failure already cleared of that value inside the door.
    pub(crate) fn note_sent(&self, sent: Option<SentPresentation>) {
        if sent.is_some() {
            *self.sent.lock().unwrap_or_else(PoisonError::into_inner) = sent;
        }
    }
}

/// What an operation's consumer came to: its answer, why it failed, and
/// how its send went. Both are cleared of the value inside the send's door.
pub(crate) struct SecretUseConsumed {
    pub(crate) result: Option<Value>,
    pub(crate) failure: Option<String>,
    pub(crate) send: SecretUseSend,
}

impl SecretUseConsumed {
    /// A failure, with no answer.
    pub(crate) const fn failed(failure: String) -> Self {
        Self {
            result: None,
            failure: Some(failure),
            send: SecretUseSend::Failed,
        }
    }

    /// A table consumer's answer: the provider answered, or it failed.
    fn of_answer(answer: std::result::Result<Value, String>) -> Self {
        match answer {
            Ok(result) => Self {
                result: Some(result),
                failure: None,
                send: SecretUseSend::Answered,
            },
            Err(failure) => Self::failed(failure),
        }
    }
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
    /// The use's intent, committed before its send: sent or not is not
    /// known until its outcome says (FIX 2622). An intent no outcome
    /// answers reads so.
    Pending,
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
            Self::Pending => "pending",
        }
    }
}

/// One use's receipt: what was used, by what, and how it went. No value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretUseReceipt {
    /// The record's handle, such as `sc12`.
    pub handle: String,
    /// The record's rotation generation when it was used: the one its send
    /// released when it presented this record, else the one admitted.
    pub generation: u32,
    /// What the send actually presented, as its door released it: the
    /// record and the generation sent, kept apart from the handle's own
    /// (FIX 8052). `None` when nothing was sent, or nothing said what was.
    pub presented: Option<SentPresentation>,
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
        self.use_secret_with(user, handle, op.name, op.effector, &mut |target| {
            // A consumer blocks on its provider. It runs on a thread of its
            // own, outside whatever async runtime the caller's door is on.
            let answer = std::thread::scope(|scope| {
                scope.spawn(|| (op.consume)(self, target, arguments)).join()
            })
            .unwrap_or_else(|_| Err("the operation stopped before it answered".to_owned()));
            SecretUseConsumed::of_answer(answer)
        })
    }

    /// The use every operation shares: the handle resolved, the record's
    /// binding for `effector` checked, `consume` run on the secret, what
    /// came back cleared of the value, and one Gate record of `operation`.
    /// `consume` presents the secret only through the credential door, for
    /// `effector` only, and runs on the caller's thread.
    ///
    /// # Errors
    /// As [`Self::use_secret_handle`], past its operation and arguments.
    pub(crate) fn use_secret_with(
        &self,
        user: &SecretUser,
        handle: &str,
        operation: &str,
        effector: &str,
        consume: &mut dyn FnMut(&SecretUseTarget<'_>) -> SecretUseConsumed,
    ) -> Result<SecretUseOutcome> {
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
            operation,
            effector,
            grant: None,
        };
        let admitted = if !live || rec.status != SecretCustodyStatus::Active {
            Err(not_active(&used.handle))
        } else if !rec
            .binding_for(effector)
            .is_some_and(SecretBinding::grants_read)
        {
            Err(unbound(&used.handle, effector))
        } else {
            self.check_secret_at_door(&rec.name, effector)
        };
        self.use_admitted(&used, &rec.name, admitted, None, consume)
    }

    /// The half of a use every entry shares once its admission is settled:
    /// a refused admission writes its one refused record and returns the
    /// refusal; an admitted one commits its intent record, send `pending`,
    /// then runs `consume` on the record `used` names (its live name is
    /// `name`; `grant`, for a table operation under a grant, is redeemed at
    /// its send), which clears what came back of the value inside the
    /// send's door, and appends the used outcome, linked to that intent, at
    /// the generation that send released (FIX 2622). A grant the send's
    /// redemption refused appends the refused outcome and answers with that
    /// refusal (FIX 4491).
    fn use_admitted(
        &self,
        used: &Used<'_>,
        name: &str,
        admitted: Result<()>,
        grant: Option<(SecretGrantRef, &SecretGrantTarget)>,
        consume: &mut dyn FnMut(&SecretUseTarget<'_>) -> SecretUseConsumed,
    ) -> Result<SecretUseOutcome> {
        if let Err(refusal) = admitted {
            used.record(
                self,
                UsePhase::Outcome,
                None,
                SecretUseDecision::Refused,
                SecretUseSend::NotSent,
                None,
            )?;
            return Err(refusal);
        }
        // The intent is durable before the send (FIX 2622): a crash past it
        // leaves it pending, sent or not unknown, never an invented outcome.
        let intent = used
            .record(
                self,
                UsePhase::Intent,
                None,
                SecretUseDecision::Used,
                SecretUseSend::Pending,
                None,
            )?
            .receipt;
        let (id, effector) = (used.secret, used.effector);
        let target = SecretUseTarget {
            name,
            effector,
            operation: used.operation,
            custody: id,
            handle: &used.handle,
            grant,
            refusal: Mutex::new(None),
            sent: Mutex::new(None),
        };
        let SecretUseConsumed {
            mut result,
            mut failure,
            mut send,
        } = consume(&target);
        let refused = target
            .refusal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(refusal) = refused {
            used.record(
                self,
                UsePhase::Outcome,
                Some(intent),
                SecretUseDecision::Refused,
                SecretUseSend::NotSent,
                None,
            )?;
            return Err(refusal);
        }
        let sent = target
            .sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        // A send that said what it presented cleared what came back inside
        // its door, with the bytes it sent (FIX 7647). Otherwise nothing was
        // sent, or nothing said what was: the value is read once more,
        // through the same door, only to find it there; if it cannot be,
        // nothing comes back.
        if sent.is_none()
            && !self.clear_use_by_reread(&id, effector, &used.handle, &mut result, &mut failure)
        {
            send = SecretUseSend::Withheld;
        }
        // The receipt names the generation the send released for the
        // handle's own record, and beside it what the send actually
        // presented, never the admitted generation in its place (FIX 8052).
        let receipt = used.at_sent(sent).record(
            self,
            UsePhase::Outcome,
            Some(intent),
            SecretUseDecision::Used,
            send,
            sent,
        )?;
        Ok(SecretUseOutcome {
            receipt,
            result,
            failure,
        })
    }
}

/// Resolves a handle to its short id and the custody record it names.
pub(crate) fn handle_record_in_txn(
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
    let check = PackConnectionCheck {
        pack: USE_PACK,
        connection: target.operation,
        check,
        auth,
        secrets: &secrets,
        allowed_scopes: &[],
    };
    // What comes back is cleared inside the send's own door, with the value
    // that went (FIX 4491, FIX 7647).
    let text = handle_text(target.handle);
    let scrub = |string: &mut String, value: &[u8]| clear_text(string, value, &text);
    let evidence = match target.grant {
        None => {
            let (answer, sent) = checks.verify_cleared(vault, &check, &target.custody, &scrub);
            target.note_sent(sent);
            answer?
        }
        // Under a grant, the grant is redeemed at the send itself, at the
        // generation it pins.
        Some((grant, granted)) => {
            match checks.verify_granted(vault, &check, &grant, granted, &scrub) {
                Ok((answer, generation)) => {
                    let sent = |generation| SentPresentation::cleared(target.custody, generation);
                    target.note_sent(generation.map(sent));
                    answer?
                }
                Err(refusal) => {
                    let failure = refusal.to_string();
                    target.refuse(refusal);
                    return Err(failure);
                }
            }
        }
    };
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
