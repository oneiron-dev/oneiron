//! A secret's value by its handle (OF-560; ARCH-0069 #reveal-check and
//! #handle-verbs, DEC-0006 #model-connection).
//!
//! A model reads a secret as its handle, `sc12`, never as its value.
//! `reveal(handle, why)` asks for the value. That is a DEC-0006 disclosure:
//! one custody record's value, to one model connection. It runs through the
//! consent machinery every disclosure does, and adds none. One check decides
//! it: does a standing grant cover this connection × this class × this
//! project? Inside one, the reveal is covered and its delivery leaves a quiet
//! use receipt. Outside, it is one ask the owner answers: approve once,
//! approve and stop asking (a standing grant on exactly that bound), or deny.
//! Either way the agent gets a pending reveal back, and `wait` collects the
//! value once it is granted.
//!
//! A granted reveal is a T1 lease whose effector is the model connection
//! ([`crate::secret_lease::stamp_reveal_lease_in_txn`]): the materialization
//! receipt lands before the lease, and the value goes back to the caller and
//! nowhere else. A reveal delivers its value once, and again only to the
//! step that collected it, under its lease (FIX 2360, FIX 11683).
//!
//! The owner reads a value on their own surface: an owner-tier proof and a
//! reason, and the reveal row is the receipt. No lease is stamped, as no
//! model receives it.
//!
//! Every row here, every receipt and every error holds the handle, never the
//! value.

mod actor_erase;
mod agent;
mod close;
mod file;
mod notice;
mod owner;
mod person;
mod replay;
mod scope;
mod types;

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::doors::read_secret_custody_in_txn;
use super::types::{CustodyClass, SecretCustodyStatus};
use crate::consent::{
    ComposedEffect, ConsentDecision, EffectDigest, EffectFacts, EffectPlace, GrantBound,
    StandingConsentGrant, UndoFidelity, evaluate_consent,
};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::side_table::{self, Named, SideTable};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, Store};
use crate::vault::Vault;

pub(crate) use self::actor_erase::erase_reveal_actor_in_txn;
pub(super) use self::actor_erase::names_no_actor;
pub use self::actor_erase::{ACTOR_ERASE_REVEAL_ASK, RevealAskErase};
pub(crate) use self::close::close_secret_reveals_in_txn;
pub use self::file::RepoFileRevealScope;
pub(crate) use self::file::{
    RepoFileKeys, RepoFileOriginal, RepoFileReadDisclosure, RepoFileRevealDelivery,
    RepoFileRevealTarget, RepoFileSight,
};
pub use self::types::{
    HandleReveal, OwnerSecretReveal, RevealGrantScope, RevealTarget, SecretHandleCard,
    SecretProvenance, SecretRevealAnswer, SecretRevealAnswered, SecretRevealAsk, SecretRevealCause,
    SecretRevealDecision, SecretRevealReceipt, SecretRevealState,
};

/// How long a pending reveal waits for its answer and its collection, in
/// seconds. Canon names no window; a widen proposal's one-hour cap is the
/// house ceiling for an ask that waits on the owner.
pub const REVEAL_ASK_TTL_SECS: u64 = 3600;

/// The life of the T1 lease a delivered reveal stamps, and of the lease a
/// PERSON reveal keeps on its row (FIX 11683), in seconds. Canon names none.
pub const REVEAL_LEASE_TTL_SECS: u64 = 900;

/// The longest `why`, or owner reason, a reveal keeps, in bytes after
/// trimming. It lands in a receipt a later mask cannot reach, so it is
/// scanned too.
pub const REVEAL_TEXT_MAX_BYTES: usize = 512;

/// The envelope selector of a reveal asked outside any project: a grant for
/// it covers reveals that name no project, and no other.
pub const NO_PROJECT_SELECTOR: &str = "project:none";

/// Gate reason code: an agent's reveal waits on the owner's answer.
pub const SECRET_REVEAL_REASON_ASKED: &str = "gate.consent.secret_reveal.asked";

/// Gate reason code: the owner read a secret's value, with a reason.
pub const SECRET_REVEAL_REASON_OWNER: &str = "gate.secret.owner_reveal";

/// The composed effect's operation kind, and the ask card's verb class.
const SECRET_REVEAL_OPERATION: &str = "secret.reveal";

/// The Gate content kind of every reveal record.
const SECRET_REVEAL_CONTENT_KIND: &str = "secret_reveal";

/// The version of the engine's disclosure line, bound into the once digest:
/// a change of wording is a different ask.
const DISCLOSURE_VERSION: &str = "secret_reveal.disclosure.v2";

/// What the disclosure line names when no host named the agent's model
/// provider (an external HTTP or MCP agent, or a model no ladder served).
/// One constant, so a ruling changes one line.
pub const UNKNOWN_PROVIDER_DISCLOSURE: &str =
    "this agent's model provider, which this host does not know";

/// Domain of the digest an owner's answer authorizes.
const ONCE_DIGEST_DOMAIN: &[u8] = b"oneiron.secret_reveal.once.v1";

/// The reader of an agent's reveal; the owner's own read is `owner`.
const READER_AGENT: &str = "agent";
const READER_OWNER: &str = "owner";

/// Every reveal, keyed by its id.
const REVEALS: SideTable<EntityId, RevealRow, Named> = SideTable::new(&side_table::SECRET_REVEAL);

/// Who asks for an agent's reveal, as the host bound it: the agent, the
/// project and the run, read from the actor binding and the run's host
/// binding, never from guest text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RevealAsker {
    agent: EntityId,
    /// The model provider the host's ladder served the agent's turn from;
    /// `None` when no host named one, and the disclosure line then says the
    /// provider is unknown ([`UNKNOWN_PROVIDER_DISCLOSURE`]).
    provider: Option<String>,
    project: Option<EntityId>,
    run: Option<String>,
    reader: Option<crate::claim::ScopedReadActorKey>,
    /// The leased try the asker's run holds, as its host bound it: the run
    /// a run-bound secret's record names (FIX 8028); `None` for an asker no
    /// run binds.
    attempt: Option<crate::AttemptId>,
    /// The task the asker's run works, its leased try's task ref: what a
    /// grant of this task names (FIX 2354); `None` for an asker no task binds.
    task: Option<String>,
    /// The durable code-mode step the asker's call is, as its run's
    /// dispatcher named it (FIX 11683); `None` for any other call.
    step: Option<crate::runtime_hooks::InvocationId>,
}

impl RevealAsker {
    pub(crate) fn new(agent: EntityId, project: Option<EntityId>, run: Option<String>) -> Self {
        Self {
            agent,
            provider: None,
            project,
            run,
            reader: None,
            attempt: None,
            task: None,
            step: None,
        }
    }

    /// This asker with the code-mode step its call is, as the host bound it.
    pub(crate) fn with_step(mut self, step: Option<crate::runtime_hooks::InvocationId>) -> Self {
        self.step = step;
        self
    }

    /// This asker with the task its leased try works, as the host bound it.
    pub(crate) fn with_task(mut self, task: Option<String>) -> Self {
        self.task = task;
        self
    }

    /// This asker with the leased try its run's host binding holds.
    pub(crate) fn with_attempt(mut self, attempt: Option<crate::AttemptId>) -> Self {
        self.attempt = attempt;
        self
    }

    pub(crate) fn with_reader(mut self, reader: crate::claim::ScopedReadActorKey) -> Self {
        self.reader = Some(reader);
        self
    }

    /// This asker with the model provider its host named, if any.
    pub(crate) fn with_provider(mut self, provider: Option<&str>) -> Self {
        self.provider = provider.map(str::to_owned);
        self
    }

    fn connection(&self) -> String {
        reveal_connection(&self.agent)
    }
}

/// What `wait` hands back: the decision, and the value once, when granted.
pub(crate) struct SecretRevealWait {
    pub(crate) decision: SecretRevealDecision,
    pub(crate) value: Option<Zeroizing<Vec<u8>>>,
    pub(crate) receipt: Option<SecretRevealReceipt>,
}

impl fmt::Debug for SecretRevealWait {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretRevealWait")
            .field("decision", &self.decision)
            .field("value", &self.value.as_ref().map(|_| "<redacted>"))
            .field("receipt", &self.receipt)
            .finish()
    }
}

/// The proof the T1 reveal lease takes: the consent the reveal door settled,
/// in the transaction that stamps the lease. Only this module builds one.
#[derive(Debug)]
pub(crate) struct RevealAuthority {
    secret: EntityId,
    handle: String,
    class: CustodyClass,
    effector: String,
}

impl RevealAuthority {
    pub(crate) const fn secret(&self) -> &EntityId {
        &self.secret
    }

    pub(crate) fn handle(&self) -> &str {
        &self.handle
    }

    pub(crate) const fn class(&self) -> CustodyClass {
        self.class
    }

    /// The lease's effector: the model connection, `model:agent:<hex>`.
    pub(crate) fn effector(&self) -> &str {
        &self.effector
    }
}

/// The value a granted reveal delivers, read under `authority` in the
/// transaction that stamps its lease; the record must still be active. A
/// binding's read grant admits every other value read
/// ([`Vault::get_secret_value_in_txn`]); a reveal holds no binding, and its
/// consent is what admits this one.
pub(crate) fn reveal_value_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    authority: &RevealAuthority,
) -> Result<Zeroizing<Vec<u8>>> {
    let (value, status, _) = value_in_txn(store, txn, &authority.secret, &authority.handle)?;
    if status != SecretCustodyStatus::Active {
        return Err(not_active(&authority.handle));
    }
    Ok(value)
}

/// The record's value, status and class, the value wiped on every path.
fn value_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    secret: &EntityId,
    handle: &str,
) -> Result<(Zeroizing<Vec<u8>>, SecretCustodyStatus, CustodyClass)> {
    let mut rec = read_secret_custody_in_txn(store, txn, secret)?.ok_or_else(|| unknown(handle))?;
    let value = Zeroizing::new(std::mem::take(&mut rec.value_bytes));
    Ok((value, rec.status, rec.class))
}

/// One reveal as the vault keeps it. It holds no value.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RevealRow {
    /// `agent` or `owner`.
    reader: String,
    /// The agent that asked, or the owner who read; `None` once that actor
    /// was erased (FIX 3520).
    actor: Option<EntityId>,
    /// The model connection; `None` for the owner's read. It names no one
    /// once its agent was erased.
    connection: Option<String>,
    provider: Option<String>,
    secret: EntityId,
    person: Option<person::PersonRevealTarget>,
    handle: String,
    /// The custody class, as [`CustodyClass::as_str`] spells it.
    class: String,
    /// The agent's why, or the owner's reason.
    why: String,
    project: Option<EntityId>,
    run: Option<String>,
    created_at: u64,
    expires_at: u64,
    state: SecretRevealState,
    /// What the owner's answer authorizes, while an agent's reveal is open.
    once_digest: Option<[u8; 32]>,
    /// The pending Gate record its ask appended.
    asked_decision: Option<GateDecisionId>,
    answered_by: Option<String>,
    decision: Option<GateDecisionId>,
    lease: Option<EntityId>,
    delivered_at: Option<u64>,
    /// An agent's read of a file stored with keys in it, or of one projection
    /// of a typed body whose lifted texts hold keys (one row per custody
    /// class of its keys), where this reveal is one; `None` for a handle's
    /// reveal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<FileSight>,
    /// The inbox Asks this ask raised (FIX 2355), settled (seen and acked)
    /// when the ask is answered, expires or is asked again; empty for a
    /// reveal a standing grant covers. Notice ids only, never a value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    notices: Vec<EntityId>,
    /// Why it closed with no value (FIX 8350).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    closed: Option<SecretRevealCause>,
    /// The task and the leased try the asking run held: the reach a task's or
    /// a run's grant names (FIX 2354).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    task: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt: Option<crate::AttemptId>,
    /// The reach of the standing grant that answered it (FIX 2354).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<RevealGrantScope>,
    /// The step whose wait collected the value, and a PERSON reveal's lease
    /// window (FIX 11683): what a replay of that step reads again under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    collected: Option<replay::RevealCollection>,
}

/// The file an agent's read names: the artifact, its stored bytes' hash, and
/// each key with its handle, in the file's order. Delivery adds each key's
/// lease.
///
/// A typed body's read (FIX 2941) names its artifact, and in `hash` the
/// read's fingerprint in place of stored bytes' hash: the projection it
/// shows (a deck's export key, a body's view) and each custody class group's
/// keys, hashed under their own domain (`reveal::file`), so it never equals
/// a stored file's hash. Its keys are one class group's, in custody-id
/// order.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileSight {
    artifact: EntityId,
    /// The stored bytes' blake3, or a typed body read's fingerprint.
    hash: [u8; 32],
    keys: Vec<(EntityId, String)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    leases: Vec<EntityId>,
    /// The read's other class groups, each as its class word and its keys'
    /// handles, value-free; none for a read of one group (FIX 6738).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    siblings: Vec<(String, String)>,
    /// A repo file read's ORIGINAL file and actual recipient (FIX 7608
    /// 2b-ii); none for every other read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    repo: Option<file::RepoFileRevealTarget>,
}

impl RevealRow {
    fn class(&self) -> Result<CustodyClass> {
        CustodyClass::parse(&self.class).ok_or(Error::CorruptedIndex("secret reveal class"))
    }

    fn is_agents(&self, agent: &EntityId) -> bool {
        self.reader == READER_AGENT && self.actor == Some(*agent)
    }

    /// The bound this reveal asks for: this connection × this class × this
    /// project. An owner's read asks for none.
    fn bound(&self) -> Result<GrantBound> {
        let connection = self
            .connection
            .as_deref()
            .ok_or(Error::CorruptedIndex("secret reveal connection"))?;
        match (
            &self.person,
            self.file.as_ref().and_then(|file| file.repo.as_ref()),
        ) {
            (Some(_), _) => disclosure_bound(connection, "names", self.project.as_ref()),
            (None, Some(repo)) => {
                repo.standing_bound(connection, self.class()?, self.project.as_ref())
            }
            (None, None) => reveal_bound(connection, self.class()?, self.project.as_ref()),
        }
    }

    /// What the owner's answer to this reveal authorizes: every fact the ask
    /// card shows, so an answer covers exactly that ask. The agent, the
    /// connection and its provider, the scope and the lease's lifetime are
    /// bound into the digest itself, not only into the words.
    fn ask_digest(&self, reveal: &EntityId) -> EffectDigest {
        let project = self
            .project
            .map(|project| project.to_hex())
            .unwrap_or_default();
        let lease_ttl = REVEAL_LEASE_TTL_SECS.to_be_bytes();
        let expires_at = self.expires_at.to_be_bytes();
        let fields: [&[u8]; 13] = [
            reveal.as_bytes(),
            self.actor
                .as_ref()
                .map_or(&[][..], |actor| &actor.as_bytes()[..]),
            self.connection.as_deref().unwrap_or_default().as_bytes(),
            self.provider.as_deref().unwrap_or_default().as_bytes(),
            self.secret.as_bytes(),
            self.handle.as_bytes(),
            self.class.as_bytes(),
            project.as_bytes(),
            self.run.as_deref().unwrap_or_default().as_bytes(),
            self.why.as_bytes(),
            &lease_ttl,
            &expires_at,
            DISCLOSURE_VERSION.as_bytes(),
        ];
        let mut hasher = blake3::Hasher::new();
        hasher.update(ONCE_DIGEST_DOMAIN);
        let mut part = |field: &[u8]| {
            hasher.update(&(field.len() as u64).to_be_bytes());
            hasher.update(field);
        };
        for field in fields {
            part(field);
        }
        if let Some(person) = &self.person {
            part(person.claim.as_bytes());
            part(&person.digest);
        }
        // A file's read binds the file, its bytes (or a typed body read's
        // fingerprint) and each key it opens.
        if let Some(file) = &self.file {
            part(file.artifact.as_bytes());
            part(&file.hash);
            for (secret, handle) in &file.keys {
                part(secret.as_bytes());
                part(handle.as_bytes());
            }
            if let Some(repo) = &file.repo {
                repo.bind_digest(&mut part);
            }
        }
        EffectDigest::from_bytes(*hasher.finalize().as_bytes())
    }

    fn stored_once_digest(&self) -> Result<EffectDigest> {
        self.once_digest
            .map(EffectDigest::from_bytes)
            .ok_or(Error::CorruptedIndex("secret reveal once digest"))
    }

    fn disclosure(&self) -> Option<String> {
        let connection = self.connection.as_deref()?;
        let what = match &self.file {
            Some(FileSight {
                repo: Some(repo), ..
            }) => repo.disclosure_what(&self.handle),
            Some(file) => format!(
                "Reading file {} unmasked sends its keys {}",
                file.artifact.to_hex(),
                self.handle
            ),
            None => format!("Revealing {} sends its value", self.handle),
        };
        Some(disclosure_line(&what, connection, self.provider.as_deref()))
    }

    fn receipt(&self, reveal: EntityId) -> Result<SecretRevealReceipt> {
        Ok(SecretRevealReceipt {
            reveal,
            handle: self.handle.clone(),
            class: self.class.clone(),
            why: self.why.clone(),
            reader: format!(
                "{}:{}",
                self.reader,
                self.actor.map_or_else(
                    || crate::receipt::ERASED_CALL_IDENTITY.to_owned(),
                    |actor| actor.to_hex()
                )
            ),
            connection: self.connection.clone(),
            provider: self.provider.clone(),
            project: self.project,
            run: self.run.clone(),
            answered_by: self.answered_by.clone(),
            decision: self.decision,
            lease: self.lease,
            asked_at: self.created_at,
            delivered_at: self.delivered_at,
            file: self.file.as_ref().map(|file| file.artifact),
            cause: self.closed,
            scope: self.scope,
        })
    }
}

/// What "this connection" is: the asking agent's own actor. The engine holds
/// no connection entity; one agent identity is one paired client.
pub(super) fn reveal_connection(agent: &EntityId) -> String {
    format!("agent:{}", agent.to_hex())
}

/// What "this class" is: the record's custody class.
fn reveal_class(class: CustodyClass) -> String {
    format!("secret:{}", class.as_str())
}

/// What "this project" is: the project the run works in, or
/// [`NO_PROJECT_SELECTOR`].
fn project_selector(project: Option<&EntityId>) -> String {
    project.map_or_else(
        || NO_PROJECT_SELECTOR.to_owned(),
        |project| format!("project:{}", project.to_hex()),
    )
}

/// The bound a reveal asks for at its default reach. "Approve and stop
/// asking" mints this bound unless the owner picks another reach (FIX 2354):
/// this connection × this class × this project.
pub(super) fn reveal_bound(
    connection: &str,
    class: CustodyClass,
    project: Option<&EntityId>,
) -> Result<GrantBound> {
    disclosure_bound(connection, &reveal_class(class), project)
}

/// Shared class × connection × project bound for custody and PERSON claims,
/// at this project's reach ([`scope`]).
fn disclosure_bound(
    connection: &str,
    class: &str,
    project: Option<&EntityId>,
) -> Result<GrantBound> {
    scope::project_reach(project)
        .bound(connection, class, RevealGrantScope::Project)?
        .ok_or(Error::InvariantViolation(
            "a project's reach names its project",
        ))
}

/// The registry ref of the standing grant that covers `bound` now, by the one
/// evaluator; `None` when it is not covered. A reveal's value reaches a model
/// provider and no undo brings it back, so only a grant covers it.
fn covering_grant(
    bound: &GrantBound,
    project: Option<EntityId>,
    grants: &[StandingConsentGrant],
) -> Result<Option<String>> {
    let facts = EffectFacts::new(SECRET_REVEAL_OPERATION)?
        .with_external_observers(true)
        .with_undo_fidelity(UndoFidelity::None);
    let effect = ComposedEffect::new(facts)
        .with_disclosure_requirement(bound.clone())?
        .in_place(EffectPlace {
            project,
            thread: None,
        });
    if evaluate_consent(&effect, None, grants) != ConsentDecision::Auto {
        return Ok(None);
    }
    Ok(grants
        .iter()
        .find(|grant| grant.bound().contains(bound))
        .map(|grant| grant.bound().digest().to_hex()))
}

/// The engine's own line on where a revealed value goes, in words no agent
/// wrote: `what` (such as "Revealing sc12 sends its value") goes on to name
/// the connection and the provider. It names no value.
fn disclosure_line(what: &str, connection: &str, provider: Option<&str>) -> String {
    match provider {
        Some(provider) => format!(
            "{what} through {connection} to {provider}; {provider} and its logs then hold it."
        ),
        None => format!(
            "{what} through {connection} to {UNKNOWN_PROVIDER_DISCLOSURE}; that provider and \
             its logs then hold it."
        ),
    }
}

/// A reveal's why or an owner's reason: 1..=[`REVEAL_TEXT_MAX_BYTES`] bytes
/// after trimming, one line, and no credential in it.
fn checked_text(text: &str, empty: &'static str, long: &'static str) -> Result<String> {
    let text = text.trim();
    if text.is_empty() {
        return Err(Error::Gate(GateError::InvalidConsentBound(empty)));
    }
    if text.len() > REVEAL_TEXT_MAX_BYTES || text.contains(['\n', '\r']) {
        return Err(Error::Gate(GateError::InvalidConsentBound(long)));
    }
    crate::batch::secret_scan::scan_metadata_field(text)?;
    Ok(text.to_owned())
}

/// A handle's syntax alone, as a model writes it: `sc12`, `sc12:ab`, or the
/// text form `[secret sc12]`. Returns the bare short id, and the content-hash
/// byte when one is written. Text that is no handle is refused without being
/// echoed, as an agent may have pasted a value there.
pub(crate) fn parse_secret_handle(text: &str) -> Result<(&str, Option<u8>)> {
    let not_a_handle = || {
        Error::Gate(GateError::InvalidConsentBound(
            "a secret is named by its handle, such as sc12",
        ))
    };
    let text = text.trim();
    let text = text
        .strip_prefix("[secret ")
        .and_then(|rest| rest.strip_suffix(']'))
        .map_or(text, str::trim);
    let (short, hash) = if text.contains(':') {
        let (short, hash) =
            crate::entity_id::parse_short_ref_syntax(text).map_err(|_| not_a_handle())?;
        (short, Some(hash))
    } else {
        (text, None)
    };
    let parsed = crate::entity_id::parse_presentation_id(short).map_err(|_| not_a_handle())?;
    if parsed.prefix != crate::registry::short_id_prefix(ENTITY_TYPE_SECRET_CUSTODY)? {
        return Err(not_a_handle());
    }
    Ok((short, hash))
}

/// Resolves a handle to the custody record it names, inside `txn`. Returns
/// the bare handle and the record. Only a live custody short id resolves.
pub(super) fn resolve_handle_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    handle: &str,
) -> Result<(String, EntityId)> {
    let (short, hash) = parse_secret_handle(handle)?;
    resolve_parsed_handle_in_txn(store, txn, short, hash)
}

/// Typed public handle lookup shared by custody and PERSON reveals.
fn resolve_typed_handle_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    handle: &str,
    entity_type: u8,
) -> Result<(String, EntityId)> {
    let handle = handle.trim();
    let (short, hash) = if handle.contains(':') {
        let (short, hash) = crate::entity_id::parse_short_ref_syntax(handle)?;
        (short, Some(hash))
    } else {
        (handle, None)
    };
    let parsed = crate::entity_id::parse_presentation_id(short)?;
    if parsed.prefix != crate::registry::short_id_prefix(entity_type)? {
        return Err(Error::EntityNotFound);
    }
    resolve_parsed_handle_in_txn(store, txn, short, hash)
}

fn resolve_parsed_handle_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    short: &str,
    hash: Option<u8>,
) -> Result<(String, EntityId)> {
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

/// The two reveal acts the Gate receipt family records outside the consent
/// doors: an agent's ask filed, and the owner's own read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevealAct {
    Asked,
    OwnerRead,
}

impl RevealAct {
    const fn outcome(self) -> &'static str {
        match self {
            Self::Asked => "pending",
            Self::OwnerRead => "approved",
        }
    }

    const fn reason_code(self) -> &'static str {
        match self {
            Self::Asked => SECRET_REVEAL_REASON_ASKED,
            Self::OwnerRead => SECRET_REVEAL_REASON_OWNER,
        }
    }

    const fn actor_class(self) -> &'static str {
        match self {
            Self::Asked => "agent",
            Self::OwnerRead => "human",
        }
    }
}

/// Appends one reveal act to the Gate receipt family, in `txn`. Its diff
/// handle is the once digest for an ask, the reveal's id for a read.
fn append_reveal_decision_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reveal: &EntityId,
    row: &RevealRow,
    act: RevealAct,
    diff_handle: Vec<u8>,
) -> Result<GateDecisionId> {
    let decision_id = GateDecisionId::from_bytes(vault.store.clock.ulid()?);
    let record = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id,
        created_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        outcome: act.outcome().into(),
        reason_codes: vec![act.reason_code().into()],
        receipt_reasons: Vec::new(),
        system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
            SECRET_REVEAL_CONTENT_KIND,
            vec![
                format!("reveal:{}", reveal.to_hex()),
                format!("handle:{}", row.handle),
                format!("class:{}", row.class),
            ],
        ),
        actor_class: act.actor_class().into(),
        actor_ref: row.actor.map(|actor| actor.to_hex()),
        content_kind: SECRET_REVEAL_CONTENT_KIND.into(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
        claim_id: None,
        grant_ref: None,
        diff_handle,
        read_frontier_hash: [0; 32],
        context: Default::default(),
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(txn, &record)?;
    Ok(decision_id)
}

pub(super) fn unknown(handle: &str) -> Error {
    Error::Secret(SecretError::SecretRefNotFound {
        name: handle.to_owned(),
    })
}

pub(super) fn not_active(handle: &str) -> Error {
    Error::Secret(SecretError::SecretCustodyNotActive {
        name: handle.to_owned(),
    })
}
