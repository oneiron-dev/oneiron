//! The owner's work requests and their results, and their wire codec: the
//! key, custody or root work an owner act needs done by an install that can
//! do it.
//!
//! An install that carries the owner's act ([`OwnerAct`]) but cannot do the
//! work the act needs (it may not read the world, or holds none of its key)
//! records an [`OwnerWorkRequest`] signed with its install key, the carrier,
//! naming the one install that is to do the work, the executor. The
//! executor, and only it, signs the [`OwnerWorkResult`] with its own install
//! key, naming the request's entry, which its parents' fold carries: the work
//! was enacted, or refused for a closed, value-free reason. Both are main-log
//! metadata, so every linked machine folds them; neither names a person or a
//! world's text, nor carries a secret byte.
//!
//! Key, custody and root acts are the owner's own: every work kind refuses
//! an agent's act until a Grant line names it (Engine 10-19 02:2x). The one
//! exception is the key work a world settings edit leaves a holder
//! ([`WorldPrivacyWorkBasis`], FIX 4704): it carries that edit's own act,
//! whoever's it is (a holder who owns no vault, or an agent within its
//! Grant), never a new key act, and binds the key to a live vault owner.
//!
//! The first kind is a world's key work ([`OwnerWorkBody::WorldKey`]): ensure
//! the world's key after a settings edit, or re-assert the executor's own
//! keys of it after a pin change ([`WorldKeyMode`]). A root request
//! ([`OwnerWorkBody::Root`]) asks one install, its target, to change its own
//! recovery root ([`RootChange`]); it names ids only, never a seed, piece,
//! passphrase, code or carry list, which only the target receives. A bundle
//! publication ([`OwnerWorkBody::PublishBundle`]) asks one install that holds
//! every world's key to publish the vault's sealed bundle to the home its
//! act targets. A custody change ([`OwnerWorkBody::Custody`]) asks for one
//! change to one portable secret's custody, by its id: ids, digests and a
//! generation only, its recipients inline (`custody`). Each kind is one
//! [`OwnerWorkBody`] variant with its [`OwnerWorkKind`], the [`OwnerActKind`]
//! its act carries and the wire map it states under `work`; the request and
//! result envelopes stay as they are.

mod custody;

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

pub use self::custody::{
    CUSTODY_RECIPIENTS_MAX, CUSTODY_WORK_REVISION_CONTEXT, CustodyChange, CustodyRecipientPermit,
};
use super::*;

pub const OP_KIND_OWNER_WORK_REQUEST: &str = "owner_work_request";
pub const OP_KIND_OWNER_WORK_RESULT: &str = "owner_work_result";
const REQUEST_KEYS: [&str; 6] = [
    OP_KEY_KIND,
    "carrier",
    OP_KEY_ACT,
    "executor",
    "work",
    "privacy_basis",
];
const PRIVACY_BASIS_KEYS: [&str; 3] = ["edit", "after", "key_owner"];
const RESULT_KEYS: [&str; 4] = [OP_KEY_KIND, "request", "executor", "outcome"];
const WORLD_KEY_WORK_KEYS: [&str; 2] = [OP_KEY_KIND, "mode"];
const ROOT_WORK_KEYS: [&str; 4] = [OP_KEY_KIND, "change", "root", "machine"];
const PUBLISH_BUNDLE_WORK_KEYS: [&str; 2] = [OP_KEY_KIND, "home"];
const OUTCOME_KEYS: [&str; 2] = [OP_KEY_KIND, "reason"];

/// What kind of work a request asks for: the `kind` of its `work` map.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OwnerWorkKind {
    /// A world's key work: mint its first key, or wrap its current key to
    /// every reader its settings allow.
    WorldKey,
    /// A change to one install's own recovery root, done on that install.
    Root,
    /// A publication of the vault's sealed bundle to one home.
    PublishBundle,
    /// A change to one portable secret's custody.
    Custody,
}

impl OwnerWorkKind {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WorldKey => "world_key",
            Self::Root => "root",
            Self::PublishBundle => "publish_bundle",
            Self::Custody => "custody",
        }
    }

    /// The kind a wire tag names; `None` for any other text.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "world_key" => Some(Self::WorldKey),
            "root" => Some(Self::Root),
            "publish_bundle" => Some(Self::PublishBundle),
            "custody" => Some(Self::Custody),
            _ => None,
        }
    }

    /// The act kind a request of this kind carries.
    #[must_use]
    pub fn act(self) -> OwnerActKind {
        match self {
            Self::WorldKey | Self::PublishBundle => OwnerActKind::WorldKeyRequest,
            Self::Root => OwnerActKind::RootRequest,
            Self::Custody => OwnerActKind::CustodyTransition,
        }
    }
}

/// How a world's key work runs: the `mode` of its `work` map.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WorldKeyMode {
    /// Mint the world's first key, or wrap its current key to every reader
    /// its settings allow: what a settings edit leaves a holder.
    Ensure,
    /// Re-wrap the keys the executor wrapped itself, from its own records
    /// and under the current settings and pin, keeping each key id, and only
    /// then ensure: what the owner's re-assertion of a world after a pin
    /// change leaves a holder.
    Reassert,
}

impl WorldKeyMode {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ensure => "ensure",
            Self::Reassert => "reassert",
        }
    }

    /// The mode a wire tag names; `None` for any other text.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ensure" => Some(Self::Ensure),
            "reassert" => Some(Self::Reassert),
            _ => None,
        }
    }
}

/// The context a root request's `seen` is hashed under: one kind's revision
/// never stands for another's ([`act_revision`]).
pub const ROOT_WORK_REVISION_CONTEXT: &[u8] = b"oneiron/root-work-revision/v1";

/// The context a bundle publication's `seen` is hashed under: the vault-wide
/// world policy revision the deciding surface showed ([`act_revision`]).
pub const BUNDLE_PUBLISH_REVISION_CONTEXT: &[u8] = b"oneiron/bundle-publish-revision/v1";

/// The change a root request asks of its target install: the `change` of its
/// `work` map. Ids only: the seed, kit pieces, passphrase, enrolment code and
/// carried machines a change needs reach the target alone, in the call that
/// does it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RootChange {
    /// Pin `root` on the target.
    Pin { root: RecoveryRootId },
    /// Activate a new root on the target, through its kit's issue and
    /// confirm.
    Activate,
    /// Restore the world keys wrapped to `root` on the target, from that
    /// root's seed or kit.
    Restore { root: RecoveryRootId },
    /// Anchor `machine`'s enrolment with the seed of `root`, held on the
    /// target.
    Anchor {
        root: RecoveryRootId,
        machine: EntityId,
    },
}

impl RootChange {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pin { .. } => "pin",
            Self::Activate => "activate",
            Self::Restore { .. } => "restore",
            Self::Anchor { .. } => "anchor",
        }
    }

    /// The root the change binds; `None` for an activation, whose root the
    /// target draws.
    #[must_use]
    pub fn root(self) -> Option<RecoveryRootId> {
        match self {
            Self::Pin { root } | Self::Restore { root } | Self::Anchor { root, .. } => Some(root),
            Self::Activate => None,
        }
    }

    /// The machine an anchoring marks.
    fn machine(self) -> Option<EntityId> {
        match self {
            Self::Anchor { machine, .. } => Some(machine),
            Self::Pin { .. } | Self::Activate | Self::Restore { .. } => None,
        }
    }

    /// The change a wire tag and its fields name, each field present exactly
    /// when the change states it; `None` otherwise.
    fn from_parts(
        name: &str,
        root: Option<RecoveryRootId>,
        machine: Option<EntityId>,
    ) -> Option<Self> {
        Some(match (name, root, machine) {
            ("pin", Some(root), None) => Self::Pin { root },
            ("activate", None, None) => Self::Activate,
            ("restore", Some(root), None) => Self::Restore { root },
            ("anchor", Some(root), Some(machine)) => Self::Anchor { root, machine },
            _ => return None,
        })
    }
}

/// The work one request asks for. Closed: each kind is one variant, with the
/// fields its own wire map states. `Clone`, not `Copy`: a custody change
/// carries its recipients inline (CALLS CUSTODY_SHARED_BODY).
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OwnerWorkBody {
    /// The key work a world settings edit left to a holder. The act's target
    /// is the world, and its `seen` is the world's `PolicyRevision` right
    /// after the edit: the revision the key work is for.
    WorldKey { mode: WorldKeyMode },
    /// A change to the target install's own recovery root. The act's target
    /// is that install, which is also the request's executor, and its `seen`
    /// is the revision of the roots and of the target's standing the change
    /// is for ([`ROOT_WORK_REVISION_CONTEXT`]).
    Root { change: RootChange },
    /// A publication of the vault's sealed bundle to `home`, the install that
    /// keeps it. The act's target is `home`, and its `seen` is the vault-wide
    /// world policy revision when the owner asked
    /// ([`BUNDLE_PUBLISH_REVISION_CONTEXT`]), for audit only: the executor
    /// seals to the policy current when it publishes. Ids only.
    PublishBundle { home: EntityId },
    /// A change to one portable secret's custody. The act's target is the
    /// secret's custody record id, and its `seen` is the revision of that
    /// secret's live custody requests the change follows
    /// ([`CUSTODY_WORK_REVISION_CONTEXT`]). An active change names the
    /// `holder` that executes it, the `generation` it approves, the digest of
    /// its encrypted `input` (none for a rewrap) and the `recipients` the
    /// owner permits; a revoke names none of them and its carrier executes it.
    Custody {
        change: CustodyChange,
        generation: u32,
        input: Option<[u8; 32]>,
        holder: Option<EntityId>,
        recipients: Vec<CustodyRecipientPermit>,
    },
}

impl OwnerWorkBody {
    #[must_use]
    pub fn kind(&self) -> OwnerWorkKind {
        match self {
            Self::WorldKey { .. } => OwnerWorkKind::WorldKey,
            Self::Root { .. } => OwnerWorkKind::Root,
            Self::PublishBundle { .. } => OwnerWorkKind::PublishBundle,
            Self::Custody { .. } => OwnerWorkKind::Custody,
        }
    }
}

/// The world settings edit a request's key work follows (FIX 4704): what
/// lets a holder who owns no vault, or an agent within its Grant, leave the
/// key work its change needs to a holder. The request then carries that
/// edit's own act, exactly as its entry signed it, and only Ensure work.
/// `Clone`, never `Copy`, as the request is.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct WorldPrivacyWorkBasis {
    /// The settings edit's signed entry, in the request's causal past (the
    /// fold of its parents).
    pub edit: AuthorityEntryHash,
    /// The world's `PolicyRevision` right after the edit: the revision the
    /// key work is for.
    pub after: [u8; 32],
    /// The live vault owner PERSON the world's key binds: the edit's author
    /// when he owns the vault, else the vault owner the key stays with.
    pub key_owner: EntityId,
}

/// One owner work request, signed by the install key of `carrier`: a live
/// machine of the vault, in any role, that carried the owner's act. It need
/// not hold anything the work needs; `executor` does.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct OwnerWorkRequest {
    pub carrier: EntityId,
    /// The owner's act: who decided, from which surface, on which revision
    /// of the target. Its kind is the work kind's act and its target is the
    /// work's target. With a `privacy_basis`, the settings edit's own act.
    pub act: OwnerAct,
    /// The one install that does the work: pinned, never elected, and only
    /// a new owner act names another.
    pub executor: EntityId,
    pub work: OwnerWorkBody,
    /// The settings edit this key work follows, when a settings edit left
    /// it; `None` for work the owner's own act asks for.
    pub privacy_basis: Option<WorldPrivacyWorkBasis>,
}

impl OwnerWorkRequest {
    #[must_use]
    pub fn kind(&self) -> OwnerWorkKind {
        self.work.kind()
    }

    /// The vault owner PERSON the work's key binds: the basis's key owner
    /// for key work a settings edit left, else the act's owner.
    #[must_use]
    pub fn key_owner(&self) -> EntityId {
        self.privacy_basis
            .as_ref()
            .map_or(self.act.owner, |basis| basis.key_owner)
    }

    /// The target revision the work is for: the world's revision right
    /// after the settings edit for key work it left, else the act's `seen`.
    #[must_use]
    pub fn revision(&self) -> [u8; 32] {
        self.privacy_basis
            .as_ref()
            .map_or(self.act.seen, |basis| basis.after)
    }

    pub fn validate(&self) -> Result<()> {
        // Key work a settings edit left carries that edit's act, a holder's
        // or an agent's, and asks for Ensure alone (FIX 4704).
        if let Some(basis) = &self.privacy_basis {
            self.act
                .validate_carried(OwnerActKind::WorldPrivacy, self.act.target)?;
            let ensure = OwnerWorkBody::WorldKey {
                mode: WorldKeyMode::Ensure,
            };
            if self.work != ensure || basis.edit == [0; 32] {
                return Err(invalid_authority());
            }
            return Ok(());
        }
        self.act
            .validate_carried(self.work.kind().act(), self.act.target)?;
        // Key, custody and root acts are owner-only until a Grant line names
        // them (Engine 10-19 02:2x).
        if self.act.by != ActBy::Owner {
            return Err(invalid_authority());
        }
        // A root change is done on the install it changes, and only there.
        if matches!(self.work, OwnerWorkBody::Root { .. }) && self.act.target != self.executor {
            return Err(invalid_authority());
        }
        // A publication's act targets the home it names.
        if let OwnerWorkBody::PublishBundle { home } = self.work
            && home != self.act.target
        {
            return Err(invalid_authority());
        }
        // A custody change has its change's shape, and names its holder, or
        // for a revoke its carrier, as executor.
        if let OwnerWorkBody::Custody {
            change,
            input,
            holder,
            recipients,
            ..
        } = &self.work
        {
            custody::validate_custody(self, *change, *input, *holder, recipients)?;
        }
        Ok(())
    }

    /// Signed alone by an Ed25519 install key, the carrier's.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        signed_alone_by_install_key(entry)
    }
}

/// An owner work entry is signed by one Ed25519 install key and cosigned by
/// none.
fn signed_alone_by_install_key(entry: &AuthorityLogEntry) -> Result<()> {
    if entry.signer.suite != AuthoritySignatureSuite::Ed25519 || !entry.cosigns.is_empty() {
        return Err(invalid_authority());
    }
    Ok(())
}

/// Why an executor refused a request. Closed and value-free: each reason
/// names a fact the executor read in its own transaction.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OwnerWorkRefusal {
    /// The target's revision moved past the act's `seen`: a newer act
    /// carries its own work, or did it in its own commit.
    StaleRevision,
    /// The applicable work/key owner is no longer a live owner of the vault.
    OwnerNotLive,
    /// The world is not a live WORLD row on the executor.
    WorldNotLive,
    /// The executor is no longer an eligible reader of the world, or, for a
    /// bundle publication, no longer holds every key the bundle seals.
    ExecutorNotReader,
    /// The home a bundle publication names is no longer a linked install of
    /// the vault.
    HomeNotLinked,
    /// The custody record its holder holds may not leave its device:
    /// device bound, cross-vault or "this device only".
    SecretNotPortable,
    /// The custody record its holder holds is not in a state the change
    /// takes: a rotate needs it active, a rewrap not revoked.
    SecretNotActive,
    /// A recipient the owner permitted is no longer a live linked install
    /// with the encryption key he permitted: a changed key needs a fresh
    /// permit.
    RecipientChanged,
    /// The encrypted input does not open on the holder under the request's
    /// binding, or opens to something the change cannot take.
    InvalidInput,
    /// The holder already holds another record under the secret's id, or a
    /// live record under its name.
    CustodyConflict,
    /// The live custody floor on the holder no longer admits the secret's
    /// bindings.
    WiderThanFloor,
}

impl OwnerWorkRefusal {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleRevision => "stale_revision",
            Self::OwnerNotLive => "owner_not_live",
            Self::WorldNotLive => "world_not_live",
            Self::ExecutorNotReader => "executor_not_reader",
            Self::HomeNotLinked => "home_not_linked",
            Self::SecretNotPortable => "secret_not_portable",
            Self::SecretNotActive => "secret_not_active",
            Self::RecipientChanged => "recipient_changed",
            Self::InvalidInput => "invalid_input",
            Self::CustodyConflict => "custody_conflict",
            Self::WiderThanFloor => "wider_than_floor",
        }
    }

    /// The reason a wire tag names; `None` for any other text.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "stale_revision" => Self::StaleRevision,
            "owner_not_live" => Self::OwnerNotLive,
            "world_not_live" => Self::WorldNotLive,
            "executor_not_reader" => Self::ExecutorNotReader,
            "home_not_linked" => Self::HomeNotLinked,
            "secret_not_portable" => Self::SecretNotPortable,
            "secret_not_active" => Self::SecretNotActive,
            "recipient_changed" => Self::RecipientChanged,
            "invalid_input" => Self::InvalidInput,
            "custody_conflict" => Self::CustodyConflict,
            "wider_than_floor" => Self::WiderThanFloor,
            _ => return None,
        })
    }
}

/// What the executor did with a request: its one terminal state.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum OwnerWorkOutcome {
    /// The executor did the work and committed it. It says nothing of every
    /// replica holding what it wrote; replication is the sync's.
    Enacted,
    Refused {
        reason: OwnerWorkRefusal,
    },
}

impl OwnerWorkOutcome {
    /// The wire tag of the outcome, a refusal's reason for a refusal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enacted => "enacted",
            Self::Refused { reason } => reason.as_str(),
        }
    }
}

/// One executor's result for one request, signed by its install key.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct OwnerWorkResult {
    /// The request's signed entry, in this entry's causal past (the fold of
    /// its parents).
    pub request: AuthorityEntryHash,
    /// The install that signed it: the one the request names.
    pub executor: EntityId,
    pub outcome: OwnerWorkOutcome,
}

impl OwnerWorkResult {
    pub fn validate(&self) -> Result<()> {
        if self.request == [0; 32] {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// Signed alone by an Ed25519 install key. Its shape names no parent:
    /// the request must be in the result's causal past, which only the fold
    /// of its parents knows, so the fold judges it there and refuses a result
    /// whose request is not (CALLS "FIX 4987 causal request presence"). A
    /// result never precedes what it answers.
    pub(super) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        signed_alone_by_install_key(entry)
    }
}

/// Canonical field order: kind, carrier, act, executor, work, privacy_basis;
/// a world key work map is kind, then mode; a root work map is kind, change,
/// root, then machine, each field the change does not state nil; a
/// publication work map is kind, then home; a custody work map is
/// `custody`'s. The basis is nil for work the owner's act asks for, else a
/// map of edit, after, then key_owner.
pub(super) fn owner_work_request_value(request: &OwnerWorkRequest) -> Value {
    let work = match &request.work {
        OwnerWorkBody::WorldKey { mode } => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OwnerWorkKind::WorldKey.as_str()),
            ),
            (Value::from("mode"), Value::from(mode.as_str())),
        ]),
        OwnerWorkBody::Root { change } => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OwnerWorkKind::Root.as_str()),
            ),
            (Value::from("change"), Value::from(change.as_str())),
            (
                Value::from("root"),
                change
                    .root()
                    .map_or(Value::Nil, |root| binary_value(root.0)),
            ),
            (
                Value::from("machine"),
                change
                    .machine()
                    .map_or(Value::Nil, |machine| Value::from(machine.to_hex())),
            ),
        ]),
        OwnerWorkBody::PublishBundle { home } => Value::Map(vec![
            (
                Value::from(OP_KEY_KIND),
                Value::from(OwnerWorkKind::PublishBundle.as_str()),
            ),
            (Value::from("home"), Value::from(home.to_hex())),
        ]),
        OwnerWorkBody::Custody {
            change,
            generation,
            input,
            holder,
            recipients,
        } => custody::custody_work_value(*change, *generation, *input, *holder, recipients),
    };
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_OWNER_WORK_REQUEST),
        ),
        (
            Value::from("carrier"),
            Value::from(request.carrier.to_hex()),
        ),
        (
            Value::from(OP_KEY_ACT),
            super::owner_act::owner_act_value(&request.act),
        ),
        (
            Value::from("executor"),
            Value::from(request.executor.to_hex()),
        ),
        (Value::from("work"), work),
        (
            Value::from("privacy_basis"),
            request
                .privacy_basis
                .as_ref()
                .map_or(Value::Nil, privacy_basis_value),
        ),
    ])
}

/// A basis's map: edit, after, then key_owner.
fn privacy_basis_value(basis: &WorldPrivacyWorkBasis) -> Value {
    Value::Map(vec![
        (Value::from("edit"), binary_value(basis.edit)),
        (Value::from("after"), binary_value(basis.after)),
        (
            Value::from("key_owner"),
            Value::from(basis.key_owner.to_hex()),
        ),
    ])
}

/// The work map's own keys follow its kind; the envelope's canonical
/// re-encode pins their order.
pub(super) fn decode_owner_work_request(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &REQUEST_KEYS)?;
    let work = map_entries(required(entries, "work")?)?;
    let kind = required(work, OP_KEY_KIND)?
        .as_str()
        .and_then(OwnerWorkKind::from_name)
        .ok_or_else(invalid_authority)?;
    let work = match kind {
        OwnerWorkKind::WorldKey => {
            validate_keys(work, &WORLD_KEY_WORK_KEYS)?;
            OwnerWorkBody::WorldKey {
                mode: required(work, "mode")?
                    .as_str()
                    .and_then(WorldKeyMode::from_name)
                    .ok_or_else(invalid_authority)?,
            }
        }
        OwnerWorkKind::Root => {
            validate_keys(work, &ROOT_WORK_KEYS)?;
            let root = match required(work, "root")? {
                Value::Nil => None,
                value => Some(RecoveryRootId(decode_hash(value)?)),
            };
            let machine = match required(work, "machine")? {
                Value::Nil => None,
                value => Some(decode_canonical_id(value)?),
            };
            OwnerWorkBody::Root {
                change: required(work, "change")?
                    .as_str()
                    .and_then(|name| RootChange::from_parts(name, root, machine))
                    .ok_or_else(invalid_authority)?,
            }
        }
        OwnerWorkKind::PublishBundle => {
            validate_keys(work, &PUBLISH_BUNDLE_WORK_KEYS)?;
            OwnerWorkBody::PublishBundle {
                home: decode_canonical_id(required(work, "home")?)?,
            }
        }
        OwnerWorkKind::Custody => custody::decode_custody_work(work)?,
    };
    let privacy_basis = match required(entries, "privacy_basis")? {
        Value::Nil => None,
        value => {
            let basis = map_entries(value)?;
            validate_keys(basis, &PRIVACY_BASIS_KEYS)?;
            Some(WorldPrivacyWorkBasis {
                edit: decode_hash(required(basis, "edit")?)?,
                after: decode_hash(required(basis, "after")?)?,
                key_owner: decode_canonical_id(required(basis, "key_owner")?)?,
            })
        }
    };
    let request = OwnerWorkRequest {
        carrier: decode_canonical_id(required(entries, "carrier")?)?,
        act: super::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        executor: decode_canonical_id(required(entries, "executor")?)?,
        work,
        privacy_basis,
    };
    request.validate()?;
    Ok(AuthorityOp::OwnerWorkRequest(request))
}

/// Canonical field order: kind, request, executor, outcome; the outcome's
/// own map is kind, then reason (nil once enacted).
pub(super) fn owner_work_result_value(result: &OwnerWorkResult) -> Value {
    let (outcome, reason) = match result.outcome {
        OwnerWorkOutcome::Enacted => ("enacted", Value::Nil),
        OwnerWorkOutcome::Refused { reason } => ("refused", Value::from(reason.as_str())),
    };
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_OWNER_WORK_RESULT),
        ),
        (Value::from("request"), binary_value(result.request)),
        (
            Value::from("executor"),
            Value::from(result.executor.to_hex()),
        ),
        (
            Value::from("outcome"),
            Value::Map(vec![
                (Value::from(OP_KEY_KIND), Value::from(outcome)),
                (Value::from("reason"), reason),
            ]),
        ),
    ])
}

pub(super) fn decode_owner_work_result(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    validate_keys(entries, &RESULT_KEYS)?;
    let outcome = map_entries(required(entries, "outcome")?)?;
    validate_keys(outcome, &OUTCOME_KEYS)?;
    let outcome = match (
        required(outcome, OP_KEY_KIND)?.as_str(),
        required(outcome, "reason")?,
    ) {
        (Some("enacted"), Value::Nil) => OwnerWorkOutcome::Enacted,
        (Some("refused"), reason) => OwnerWorkOutcome::Refused {
            reason: reason
                .as_str()
                .and_then(OwnerWorkRefusal::from_name)
                .ok_or_else(invalid_authority)?,
        },
        _ => return Err(invalid_authority()),
    };
    let result = OwnerWorkResult {
        request: decode_hash(required(entries, "request")?)?,
        executor: decode_canonical_id(required(entries, "executor")?)?,
        outcome,
    };
    result.validate()?;
    Ok(AuthorityOp::OwnerWorkResult(result))
}
