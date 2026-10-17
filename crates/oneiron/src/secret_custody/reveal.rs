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
//! nowhere else. A reveal delivers its value once.
//!
//! The owner reads a value on their own surface: an owner-tier proof and a
//! reason, and the reveal row is the receipt. No lease is stamped, as no
//! model receives it.
//!
//! Every row here, every receipt and every error holds the handle, never the
//! value.

mod agent;
mod file;
mod owner;

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::doors::read_secret_custody_in_txn;
use super::types::{CustodyClass, SecretCustodyStatus};
use crate::consent::{
    AudienceBound, ComposedEffect, ConsentDecision, DisclosureClass, DisclosureEnvelope,
    EffectDigest, EffectFacts, EffectPlace, GrantBound, StandingConsentGrant, UndoFidelity,
    evaluate_consent,
};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::genui::ConsentAskCard;
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::side_table::{self, Named, SideTable};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, Store};
use crate::vault::Vault;

/// How long a pending reveal waits for its answer and its collection, in
/// seconds. Canon names no window; a widen proposal's one-hour cap is the
/// house ceiling for an ask that waits on the owner.
pub const REVEAL_ASK_TTL_SECS: u64 = 3600;

/// The life of the T1 lease a delivered reveal stamps, in seconds. Canon
/// names none.
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

/// Where a reveal stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRevealState {
    /// A standing grant covered the reveal when it was asked.
    Covered,
    /// It waits on the owner's answer.
    Asked,
    /// The owner approved this one reveal.
    ApprovedOnce,
    /// The owner approved and stopped asking: a standing grant covers it.
    ApprovedStanding,
    /// The owner denied it.
    Denied,
    /// Its window closed before it was answered or collected.
    Expired,
    /// Its value went to its reader.
    Delivered,
}

impl SecretRevealState {
    /// The pinned state word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::Asked => "asked",
            Self::ApprovedOnce => "approved_once",
            Self::ApprovedStanding => "approved_standing",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Delivered => "delivered",
        }
    }
}

/// What `wait` answers about one reveal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRevealDecision {
    /// The owner has not answered, or a grant was revoked and the reveal is
    /// asked again.
    Pending,
    /// Granted: the value comes with this answer, the first time only.
    Granted,
    /// The owner denied it.
    Denied,
    /// Its window closed.
    Expired,
}

impl SecretRevealDecision {
    /// The pinned decision word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Granted => "granted",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }
}

/// One reveal's receipt: what was revealed, to whom, why and on whose answer.
/// It names the handle, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRevealReceipt {
    /// The reveal's id.
    pub reveal: EntityId,
    /// The handle the reveal named, such as `sc12`.
    pub handle: String,
    /// The secret's custody class.
    pub class: CustodyClass,
    /// The agent's why, or the owner's reason.
    pub why: String,
    /// `agent:<hex>` or `owner:<hex>`.
    pub reader: String,
    /// The model connection the value goes to; `None` for the owner's read.
    pub connection: Option<String>,
    /// The model provider behind the connection, when a host named one.
    pub provider: Option<String>,
    /// The project the reveal was asked in.
    pub project: Option<EntityId>,
    /// The run it was asked from, when a host bound one.
    pub run: Option<String>,
    /// Who answered: `standing:<grant ref>` or `owner:<hex>`; `None` while
    /// it waits.
    pub answered_by: Option<String>,
    /// The Gate decision of its last consent act: the use of a grant, the
    /// owner's approval or denial, or the owner's read.
    pub decision: Option<GateDecisionId>,
    /// The T1 lease that delivered an agent's reveal.
    pub lease: Option<EntityId>,
    /// When it was asked.
    pub asked_at: u64,
    /// When its value went out.
    pub delivered_at: Option<u64>,
    /// The file an agent's read of a marked file named: its keys are the
    /// handles above, and each went out under its own T1 lease.
    pub file: Option<EntityId>,
}

/// One reveal as the owner reads it, with the in-moment card while it waits
/// on them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRevealAsk {
    /// The reveal's receipt so far.
    pub receipt: SecretRevealReceipt,
    /// Where it stands; an ask past its window reads `expired`.
    pub state: SecretRevealState,
    /// When its window closes.
    pub expires_at: u64,
    /// The engine's line on where the value goes; `None` for an owner read.
    pub disclosure: Option<String>,
    /// The digest an answer sends back as `expected_digest`.
    pub once_digest: Option<EffectDigest>,
    /// The registry row a `standing` answer writes: this connection × this
    /// class × this project.
    pub grant_ref: Option<String>,
    /// The DEC-0006 ask card, while the reveal waits on the owner.
    pub card: Option<ConsentAskCard>,
}

/// The owner's answer to one asked reveal: the DEC-0006 trio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretRevealAnswer {
    /// Approve this one reveal.
    Once,
    /// Approve and stop asking: a standing grant on this connection × this
    /// class × this project.
    Standing,
    /// Deny it.
    Deny,
}

impl SecretRevealAnswer {
    /// The pinned answer word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Standing => "standing",
            Self::Deny => "deny",
        }
    }
}

/// What an owner's answer wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRevealAnswered {
    /// The reveal answered.
    pub reveal: EntityId,
    /// The answer given.
    pub answer: SecretRevealAnswer,
    /// The answer's Gate decision.
    pub decision: GateDecisionId,
    /// The standing grant a `standing` answer wrote.
    pub grant_ref: Option<String>,
}

/// The secret an owner's read names: its handle, or its custody name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealTarget {
    /// A handle, `sc12` or `sc12:ab`.
    Handle(String),
    /// A custody name.
    Name(String),
}

/// What the owner reads: the value, and the receipt that names their reason.
pub struct OwnerSecretReveal {
    /// The value. It is wiped when dropped.
    pub value: Zeroizing<Vec<u8>>,
    /// The read's receipt.
    pub receipt: SecretRevealReceipt,
}

impl fmt::Debug for OwnerSecretReveal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerSecretReveal")
            .field("value", &"<redacted>")
            .field("receipt", &self.receipt)
            .finish()
    }
}

/// A secret as a model reads it through `describe(h)`: what it is, and what a
/// reveal of it would do for this asker now. It holds no value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretHandleCard {
    /// The handle.
    pub handle: String,
    /// The custody name.
    pub label: String,
    /// The custody class.
    pub class: CustodyClass,
    /// The record's status.
    pub status: SecretCustodyStatus,
    /// Where a mask on write found it, when one did.
    pub provenance: Option<SecretProvenance>,
    /// What a reveal would do now.
    pub reveal: HandleReveal,
}

/// Where a mask on write found a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretProvenance {
    /// The record whose text or field held it.
    pub record: EntityId,
    /// Where in that record: `body`, `claim`, `text:<field>` or `file`.
    pub place: String,
    /// The scan's word for the key's kind, such as `openai_key`.
    pub kind: String,
    /// When it was lifted.
    pub masked_at: u64,
}

/// What a reveal of a handle would do for its asker now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleReveal {
    /// A standing grant covers it: the value would come at once.
    Hydrates {
        /// The covering grant's registry ref.
        grant_ref: String,
    },
    /// It would ask the owner.
    Asks,
    /// It would be refused.
    Refused {
        /// Why, with no value in it.
        reason: String,
    },
}

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
}

impl RevealAsker {
    pub(crate) fn new(agent: EntityId, project: Option<EntityId>, run: Option<String>) -> Self {
        Self {
            agent,
            provider: None,
            project,
            run,
        }
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
    /// The agent that asked, or the owner who read.
    actor: EntityId,
    /// The model connection; `None` for the owner's read.
    connection: Option<String>,
    provider: Option<String>,
    secret: EntityId,
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
    /// An agent's read of a file stored with keys in it, where this reveal is
    /// one; `None` for a handle's reveal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<FileSight>,
}

/// The file an agent's read names: the artifact, its stored bytes' hash, and
/// each key with its handle, in the file's order. Delivery adds each key's
/// lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileSight {
    artifact: EntityId,
    hash: [u8; 32],
    keys: Vec<(EntityId, String)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    leases: Vec<EntityId>,
}

impl RevealRow {
    fn class(&self) -> Result<CustodyClass> {
        CustodyClass::parse(&self.class).ok_or(Error::CorruptedIndex("secret reveal class"))
    }

    fn is_agents(&self, agent: &EntityId) -> bool {
        self.reader == READER_AGENT && self.actor == *agent
    }

    /// The bound this reveal asks for: this connection × this class × this
    /// project. An owner's read asks for none.
    fn bound(&self) -> Result<GrantBound> {
        let connection = self
            .connection
            .as_deref()
            .ok_or(Error::CorruptedIndex("secret reveal connection"))?;
        reveal_bound(connection, self.class()?, self.project.as_ref())
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
            self.actor.as_bytes(),
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
        // A file's read binds the file, its bytes and each key it opens.
        if let Some(file) = &self.file {
            part(file.artifact.as_bytes());
            part(&file.hash);
            for (secret, handle) in &file.keys {
                part(secret.as_bytes());
                part(handle.as_bytes());
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
            class: self.class()?,
            why: self.why.clone(),
            reader: format!("{}:{}", self.reader, self.actor.to_hex()),
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

/// The bound a reveal asks for. "Approve and stop asking" mints exactly this
/// bound, so its reach is this connection × this class × this project.
pub(super) fn reveal_bound(
    connection: &str,
    class: CustodyClass,
    project: Option<&EntityId>,
) -> Result<GrantBound> {
    GrantBound::disclosure(
        AudienceBound::singleton(connection)?,
        DisclosureClass::new(reveal_class(class))?,
        DisclosureEnvelope::new([project_selector(project)])?,
    )
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
        actor_ref: Some(row.actor.to_hex()),
        content_kind: SECRET_REVEAL_CONTENT_KIND.into(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
        claim_id: None,
        grant_ref: None,
        diff_handle,
        read_frontier_hash: [0; 32],
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
