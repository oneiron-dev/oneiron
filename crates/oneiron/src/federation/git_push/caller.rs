//! The receive-pack decision's values (FIX 6867, G1-PUSH): the pusher a
//! host transport authenticated, the served repository it names, and the
//! sealed admission and the stamp it leaves on the push's evidence, intent
//! and recovery.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::codebase::RepoRef;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{CodeError, Error};
use crate::federation::GitPushRepo;

/// The credential a host transport proved for one push, as the final intent
/// writer rechecks it: the capability slip's id, or the store key whose
/// presence marks the token revoked, and a digest naming the credential. It
/// holds no token or secret bytes, comes from the host's own verification,
/// never from a request field, and confers nothing by itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitPushCredential {
    slip: Option<[u8; 32]>,
    revoked_marker: Option<String>,
    binding: Option<[u8; 32]>,
}

impl GitPushCredential {
    /// The credential `slip` (a capability slip's id), or a token whose
    /// revocation `revoked_marker` (its sync-state key) records, named by
    /// the digest `binding`. Each part is optional: a credential with no
    /// revocable identity is checked once, at the request.
    #[must_use]
    pub const fn new(
        slip: Option<[u8; 32]>,
        revoked_marker: Option<String>,
        binding: Option<[u8; 32]>,
    ) -> Self {
        Self {
            slip,
            revoked_marker,
            binding,
        }
    }
}

/// The pusher, as the host transport authenticated it: a sidecar beside the
/// request, never a wire field. It has no `Deserialize`; only a host builds
/// one, from the credential it verified.
#[derive(Debug, Clone)]
pub struct GitPushCaller {
    pub(super) principal: EntityId,
    pub(super) class: Option<EdgeActorClass>,
    pub(super) credential: GitPushCredential,
    pub(super) host: bool,
}

impl GitPushCaller {
    /// The pusher a host transport authenticated: its credential's
    /// registered `principal`, the actor `class` the credential binds when
    /// it binds one, and the `credential` the final writer rechecks.
    #[must_use]
    pub const fn authenticated(
        principal: EntityId,
        class: Option<EdgeActorClass>,
        credential: GitPushCredential,
    ) -> Self {
        Self {
            principal,
            class,
            credential,
            host: true,
        }
    }

    /// An in-process caller, named by a request's remote user alone: it may
    /// push as the vault's owner and as no one else.
    pub(crate) fn in_process(remote_user: &str) -> Option<Self> {
        let principal = EntityId::from_hex(remote_user).ok()?;
        Some(Self {
            principal,
            class: None,
            credential: GitPushCredential::default(),
            host: false,
        })
    }

    /// The registered principal this caller pushes as.
    #[must_use]
    pub const fn principal(&self) -> EntityId {
        self.principal
    }
}

/// The served repository a push names, as the serving host resolved it: its
/// name, its directory and its Git object-store identity.
#[derive(Debug, Clone)]
pub(crate) struct ServedPushRepo {
    pub(super) name: String,
    dir: PathBuf,
    identity: Option<String>,
}

impl ServedPushRepo {
    /// The served repository `name` at `dir`. A store whose identity does
    /// not read is logged and matches no Grant's anchor: only the owner can
    /// push to it, as he could before.
    pub(crate) fn resolve(vault: &Vault, name: &str, dir: &Path) -> Self {
        let identity = crate::git_wire::GitWire::new(vault)
            .and_then(|wire| wire.repository_identity(dir))
            .map(|identity| identity.as_hex())
            .inspect_err(|error| {
                tracing::warn!(kind = ?error.kind(), "git push: the served store's identity did not read");
            })
            .ok();
        Self {
            name: name.to_owned(),
            dir: dir.to_path_buf(),
            identity,
        }
    }

    /// Whether `anchor_identity`, a Grant anchor's store identity, is this
    /// served store's.
    pub(super) fn is_store(&self, anchor_identity: Option<&str>) -> bool {
        self.identity
            .as_deref()
            .is_some_and(|identity| anchor_identity == Some(identity))
    }

    /// The repo the checkout door compares a ticket's lease against.
    pub(super) fn repo_ref(&self) -> RepoRef {
        RepoRef::LocalFolder {
            path: self.dir.to_string_lossy().into_owned(),
            commit: "0".repeat(40),
        }
    }
}

/// The typed refusal naming the repo and the missing capability.
pub(super) fn refused(repo: &str, reason: &str) -> Error {
    Error::Code(CodeError::GitPushCapabilityRequired {
        repo: repo.to_owned(),
        reason: reason.to_owned(),
    })
}

/// Which arm admitted a push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GitPushArm {
    Owner,
    Grant,
    Checkout,
}

impl GitPushArm {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Grant => "grant",
            Self::Checkout => "checkout",
        }
    }
}

/// What one admitted push stands on: the arm, the pusher, the Grant and the
/// repo it names, the checkout of a lease push, and the credential's
/// revocable identity. The admission evidence records it, the intent keeps
/// it, and recovery rebuilds the stamp from it rather than from a bare
/// principal. It holds no secret bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GitPushStamp {
    pub(super) arm: GitPushArm,
    pub(super) served: String,
    pub(super) principal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) grant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) repo: Option<GitPushRepo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) checkout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) class: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) slip: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) revoked_marker: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) binding: Option<[u8; 32]>,
}

impl GitPushStamp {
    pub(super) fn new(arm: GitPushArm, caller: &GitPushCaller, served: &ServedPushRepo) -> Self {
        Self {
            arm,
            served: served.name.clone(),
            principal: caller.principal.to_hex(),
            grant: None,
            repo: None,
            anchor: None,
            checkout: None,
            class: None,
            slip: caller.credential.slip,
            revoked_marker: caller.credential.revoked_marker.clone(),
            binding: caller.credential.binding,
        }
    }

    pub(super) fn naming(mut self, grant: EntityId, repo: GitPushRepo, anchor: String) -> Self {
        self.grant = Some(grant.to_hex());
        self.repo = Some(repo);
        self.anchor = Some(anchor);
        self
    }

    /// Whether this push was admitted on a checkout's run Grant: its ref
    /// moves and changed paths are judged again in the final writer.
    pub(crate) const fn is_checkout(&self) -> bool {
        matches!(self.arm, GitPushArm::Checkout)
    }

    /// The admission evidence's record of this authority: the arm, the
    /// Grant, the repo, the checkout and the credential digest.
    pub(crate) fn evidence_value(stamp: Option<&Self>) -> Value {
        let Some(stamp) = stamp else {
            return Value::Nil;
        };
        let text =
            |value: Option<&String>| value.map_or(Value::Nil, |text| Value::from(text.as_str()));
        Value::Map(vec![
            (Value::from("arm"), Value::from(stamp.arm.as_str())),
            (Value::from("grant"), text(stamp.grant.as_ref())),
            (
                Value::from("repo"),
                stamp
                    .repo
                    .map_or(Value::Nil, |repo| Value::from(repo.repo.to_hex())),
            ),
            (
                Value::from("project"),
                stamp
                    .repo
                    .map_or(Value::Nil, |repo| Value::from(repo.project.to_hex())),
            ),
            (Value::from("checkout"), text(stamp.checkout.as_ref())),
            (
                Value::from("credential_binding"),
                stamp.binding.map_or(Value::Nil, |digest| {
                    Value::from(bytes_to_hex_lower(&digest))
                }),
            ),
        ])
    }
}

/// An admitted push. Sealed: only [`Vault::admit_git_receive_pack_in_txn`]
/// builds one, and its authority is read through the stamp it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitPushAdmission {
    /// The vault's live owner.
    Owner(GitPushSeal),
    /// A live GitPush grant naming the pusher and this repo.
    Grant(GitPushSeal),
    /// An SDK checkout whose run's Grant covers this repo.
    Checkout(GitPushSeal),
}

/// The authority inside a [`GitPushAdmission`]; nothing outside this module
/// can build or open one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPushSeal(GitPushStamp);

impl GitPushAdmission {
    pub(super) fn sealed(stamp: GitPushStamp) -> Self {
        match stamp.arm {
            GitPushArm::Owner => Self::Owner(GitPushSeal(stamp)),
            GitPushArm::Grant => Self::Grant(GitPushSeal(stamp)),
            GitPushArm::Checkout => Self::Checkout(GitPushSeal(stamp)),
        }
    }

    /// The stamp this admission's evidence and intent carry.
    pub(crate) fn into_stamp(self) -> GitPushStamp {
        match self {
            Self::Owner(seal) | Self::Grant(seal) | Self::Checkout(seal) => seal.0,
        }
    }
}

/// One ref a checkout push moves and every path that move changes, the old
/// and new name of a rename and the path of a delete among them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitPushRefChange {
    pub(crate) git_ref: String,
    pub(crate) paths: BTreeSet<String>,
}

/// The stored byte of an actor class, as [`EdgeActorClass::try_from_u8`]
/// reads it back.
pub(super) const fn class_byte(class: EdgeActorClass) -> u8 {
    match class {
        EdgeActorClass::Human => 0,
        EdgeActorClass::Agent => 1,
        EdgeActorClass::System => 2,
    }
}
