//! Custody write context, stored-value forms, and value-free change and found-key records.

use serde::{Deserialize, Serialize};

use super::{CustodyClass, SecretCustodyRecord};
use crate::entity_id::EntityId;
use crate::git_wire::GitOid;
use crate::store::Store;
use crate::vault::Vault;

/// What the owner did about one found key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FoundKeyAction {
    /// The custody record took a new value.
    Rotate,
    /// The record or file that held the key was deleted.
    Delete,
    /// An agent was granted reveals of the key's class.
    Grant,
    /// The owner ruled it no secret: the value went back, and its custody
    /// record was revoked.
    NotASecret,
    /// The owner accepted the risk and kept the marked span as text by choice.
    KeptAsText,
}

impl FoundKeyAction {
    /// The pinned action word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rotate => "rotate",
            Self::Delete => "delete",
            Self::Grant => "grant",
            Self::NotASecret => "not_a_secret",
            Self::KeptAsText => "kept_as_text",
        }
    }
}

/// The owner's last act on one found key, and its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundKeySettled {
    pub action: FoundKeyAction,
    /// The owner who acted; `None` for a rotation, whose receipt names it,
    /// or once that owner was erased (FIX 3520).
    pub by: Option<EntityId>,
    pub at: u64,
    /// The act's receipt: `rotation:<hex>`, `redaction:<hex>` or
    /// `gate:<hex>`.
    pub receipt: String,
    /// The standing grant a `grant` wrote; revoke it in the consent
    /// registry.
    pub grant_ref: Option<String>,
}

/// One key a mask lifted, as the mask hands it over.
#[derive(Debug, Clone)]
pub(crate) struct FoundNote {
    pub(crate) record: EntityId,
    pub(crate) custody: EntityId,
    pub(crate) handle: String,
    pub(crate) reason: &'static str,
    pub(crate) place: String,
}

/// Who the owner names for an active custody change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CustodyPlan {
    /// The install that holds the value and does the change; `None` is this
    /// install.
    pub holder: Option<EntityId>,
    /// The installs he permits to hold its bytes, each a live linked install
    /// with an importable key, in any role. Empty: a register permits its
    /// holder alone, a rotate keeps the permits of the secret's live change,
    /// and a rewrap is refused. A machine he makes his is added by its
    /// holders' own rewrap (CALLS CUSTODY_ROSTER_REWRAP); any other linked
    /// machine only by his.
    pub recipients: Vec<EntityId>,
}

/// Why a change to a portable secret stays on this install, recorded for no
/// other machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyKeptHere {
    /// The record may not leave its device: device bound, cross-vault or
    /// "this device only".
    DeviceLocal,
    /// This install has no live machine profile to carry the owner's act,
    /// so no other machine learns of the change from here.
    NoCarrier,
    /// A revoke this install cannot carry yet, with no live machine profile
    /// or no install key loaded: it stands here, and its carry is pending
    /// until this install can sign (CALLS CUSTODY_REVOKE_PENDING_CARRY).
    CarryPending,
    /// This install, the holder, has no encryption key that imports, so no
    /// request can name it (CALLS CUSTODY_EXECUTOR).
    NoHolderKey,
}

impl CustodyKeptHere {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeviceLocal => "device_local",
            Self::NoCarrier => "no_carrier",
            Self::CarryPending => "carry_pending",
            Self::NoHolderKey => "no_holder_key",
        }
    }

    /// The words a surface shows.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::DeviceLocal => "kept on this device: this secret never leaves it",
            Self::NoCarrier => {
                "kept on this install only: it has no live machine profile to carry your act \
                 to your other machines"
            }
            Self::NoHolderKey => {
                "kept on this install only: it has no encryption key to hold the secret for \
                 your other machines"
            }
            Self::CarryPending => {
                "revoked here; your other machines learn of it once this install can sign your \
                 act (it has no live machine profile yet, or its install key is not loaded)"
            }
        }
    }
}

/// A stored value: sealed under its custody key, the only form a value
/// rests in (KS-6 part 2: the restored carrier form is gone, FIX 7456).
pub(crate) enum StoredValue {
    /// `nonce | ciphertext`, sealed at `generation`; empty for no value.
    Sealed { generation: u32, bytes: Vec<u8> },
}

impl StoredValue {
    /// Whether a value is held at all: a revoked record's is not.
    pub(crate) fn holds_value(&self) -> bool {
        let Self::Sealed { bytes, .. } = self;
        !bytes.is_empty()
    }
}

/// What an owner archive's import finds of a record whose id is already
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveSameId {
    /// The same record: unchanged.
    Same,
    /// Another record: a collision, refused as before.
    Different,
    /// The comparison faulted: the record here stays as it is, pending.
    Pending,
}

/// What a custody write applies through: the vault's store, config and
/// analyzer, and whether its text index is trusted. The batch door's mask on
/// write (OF-560) holds these without a [`Vault`].
pub(crate) struct CustodyWrite<'a> {
    pub(crate) store: &'a Store,
    pub(crate) config: &'a crate::config::VaultConfig,
    pub(crate) analyzer: &'a crate::analyzer::MultilingualAnalyzer,
    pub(crate) text_index_trusted: bool,
}

impl<'a> CustodyWrite<'a> {
    pub(crate) fn of(vault: &'a Vault) -> Self {
        Self {
            store: &vault.store,
            config: &vault.config,
            analyzer: &vault.analyzer,
            text_index_trusted: vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
        }
    }
}

/// Whether `record` may leave this device: custody-portable with its "this
/// device only" dial off.
pub(crate) fn custody_portable(record: &SecretCustodyRecord) -> bool {
    record.class == CustodyClass::CustodyPortable && !record.device_only
}

/// Every slot's name starts with this: the engine's reserved namespace.
pub(crate) const SLOT_PREFIX: &str = "oneiron.cloud-registration/";

/// Whether `name` is a cloud registration slot's: the engine's own, under
/// its reserved namespace.
pub(crate) fn is_cloud_registration_slot(name: &str) -> bool {
    name.starts_with(SLOT_PREFIX)
}

/// One marked repo file as its door pinned it: the ORIGINAL, never a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoFileOriginal {
    /// The repo the file is read from.
    pub(crate) repo: EntityId,
    /// The canonical store identity the blob is kept in.
    pub(crate) store: String,
    /// The snapshot the read is pinned to, when its door names one.
    pub(crate) snapshot: Option<EntityId>,
    /// The file's path in the repo.
    pub(crate) path: String,
    /// The stored blob.
    pub(crate) blob: GitOid,
    /// The import source the repo came from, when it has one.
    pub(crate) source: Option<EntityId>,
    /// Every readable mark on the blob, sorted.
    pub(crate) marks: Vec<EntityId>,
}

/// The keys a repo file's marks hold, value-free: each placed key's custody
/// record, and whether residue no span isolates is marked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RepoFileKeys {
    pub(crate) custody: Vec<EntityId>,
    pub(crate) opaque: bool,
}
