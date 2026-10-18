//! The owner registers a secret (ARCH-0069 S1–S3) and rotates it (S6).
//! Registration puts the value into custody, with the repo manifest's entry
//! when a repository declares the name. Rotation is a vault update the owner
//! starts; the next lease materializes the new value, and exhaust built with
//! the old one reads as stale at its next publish or export check.
//!
//! A portable secret's register, rotate, rewrap and revoke are custody
//! requests on the shared owner-work log (WILL L04 row 04): each names the
//! holder that does it, this install unless the body names another, and the
//! installs the owner permits to hold its bytes. Every reply carries the
//! request's receipt as it stands, why a change stayed on this install, and
//! that delivery to his other machines is unknown: no machine acknowledges.

use axum::body::{Body, Bytes, HttpBody as _};
use base64::Engine as _;
use futures_util::StreamExt as _;
use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{
    CustodyClass, CustodyKeptHere, CustodyPlan, CustodyTier, ManifestSource,
    OwnerSecretRegistration, RequestedBinding, SECRET_NAME_MAX_BYTES, SecretCustodyWork,
    SecretRegistered,
};
use oneiron::world_keys::{OwnerWorkReceipt, OwnerWorkUnassigned};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use zeroize::{Zeroize, Zeroizing};

use super::{OwnerError, OwnerResult};

/// The largest body read: a name, its bindings and one base64 value, far
/// above any key or certificate.
const BODY_LIMIT: usize = 1 << 20;

/// The ref a manifest is read at when the request names none.
const DEFAULT_MANIFEST_REF: &str = "refs/heads/main";

/// One rotation request. The value travels as standard base64 so binary
/// secrets survive JSON; it reaches the vault's custody plane and no receipt,
/// log or reply.
///
/// Read by [`RotateSecret::read`] rather than an extractor, because every
/// buffer that holds the value or its encoding has to be wiped on every path,
/// a refused request included. Above the transport there are three: the
/// frames the body hands over, the one buffer they are copied into, and the
/// decoded value. Parsing borrows from the second and copies nothing.
pub(crate) struct RotateSecret {
    /// The secret's custody name.
    name: String,
    value: Zeroizing<Vec<u8>>,
    plan: CustodyPlan,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateFields<'a> {
    name: String,
    /// Raw, so the parser skips the string in place and never unescapes it
    /// into its own scratch buffer, not even when the string fails part way.
    /// Base64 needs no escapes, so a value carrying one is refused.
    #[serde(borrow)]
    value_base64: &'a RawValue,
    /// The install that holds the secret and rotates it, as 32 hex; this
    /// install when absent.
    #[serde(default)]
    holder: Option<String>,
    /// The installs permitted to hold the new value, as 32 hex each; the
    /// secret's live permits when empty.
    #[serde(default)]
    recipients: Vec<String>,
}

/// The holder and recipients a body names, as machine ids.
pub(crate) fn custody_plan(
    holder: Option<String>,
    recipients: Vec<String>,
) -> OwnerResult<CustodyPlan> {
    Ok(CustodyPlan {
        holder: holder
            .map(|holder| super::entity_id("holder", &holder))
            .transpose()?,
        recipients: recipients
            .iter()
            .map(|machine| super::entity_id("recipients", machine))
            .collect::<OwnerResult<_>>()?,
    })
}

impl RotateSecret {
    pub(crate) async fn read(body: Body) -> OwnerResult<Self> {
        let body = OwnedBody::read(body).await?;
        let fields: RotateFields<'_> =
            serde_json::from_slice(&body.0).map_err(|_| invalid_body())?;
        let value = decode_value(fields.value_base64)?;
        if value.is_empty() {
            return Err(OwnerError::Invalid("a rotated secret needs a value".into()));
        }
        Ok(Self {
            name: secret_name(fields.name)?,
            value,
            plan: custody_plan(fields.holder, fields.recipients)?,
        })
    }
}

/// A name the custody index can key: 1 to 255 bytes.
fn secret_name(name: String) -> OwnerResult<String> {
    if name.is_empty() || name.len() > SECRET_NAME_MAX_BYTES {
        return Err(OwnerError::Invalid("name must be 1 to 255 bytes".into()));
    }
    Ok(name)
}

/// Decodes a borrowed `value_base64` into a buffer sized up front, so decoding
/// never reallocates and leaves a copy behind; a decode that fails part way is
/// wiped with the rest. Base64 needs no escapes, so a value carrying one is
/// refused.
fn decode_value(raw: &RawValue) -> OwnerResult<Zeroizing<Vec<u8>>> {
    let not_base64 = || OwnerError::Invalid("value_base64 must be standard base64".into());
    let encoded = raw
        .get()
        .as_bytes()
        .strip_prefix(b"\"")
        .and_then(|raw| raw.strip_suffix(b"\""))
        .ok_or_else(not_base64)?;
    let mut value = Zeroizing::new(Vec::with_capacity(base64::decoded_len_estimate(
        encoded.len(),
    )));
    base64::engine::general_purpose::STANDARD
        .decode_vec(encoded, &mut value)
        .map_err(|_| not_base64())?;
    Ok(value)
}

/// One registration request: the name, the custody class, the rung, the
/// bindings and the value, and the repository whose manifest declares the
/// name, if one does. Read like [`RotateSecret`], and for the same reason.
pub(crate) struct RegisterSecret {
    name: String,
    class: CustodyClass,
    device_only: bool,
    rung: CustodyTier,
    bindings: Vec<RequestedBinding>,
    manifest: Option<ManifestSource>,
    value: Zeroizing<Vec<u8>>,
    plan: CustodyPlan,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterFields<'a> {
    name: String,
    /// `custody-portable`, `custody-device-bound` or `cross-vault`.
    class: String,
    /// The custody ladder's rung: 0 doored, 1 leased, 2 local-registered.
    rung: u8,
    #[serde(default)]
    device_only: bool,
    #[serde(default)]
    bindings: Vec<BindingFields>,
    #[serde(default)]
    manifest: Option<ManifestFields>,
    /// Raw, as in [`RotateFields`].
    #[serde(borrow)]
    value_base64: &'a RawValue,
    /// A portable secret's holder, as 32 hex; this install when absent.
    #[serde(default)]
    holder: Option<String>,
    /// The installs permitted to hold a portable secret, as 32 hex each;
    /// its holder alone when empty.
    #[serde(default)]
    recipients: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingFields {
    effector: String,
    #[serde(default)]
    scopes: Vec<String>,
    /// The binding's rung, at or below the secret's; the secret's when absent.
    #[serde(default)]
    tier_ceiling: Option<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFields {
    repo: String,
    #[serde(default, rename = "ref")]
    git_ref: Option<String>,
}

impl ManifestFields {
    /// Where the manifest is read, checked here so a malformed name is the
    /// caller's error, not the git layer's.
    fn source(self) -> OwnerResult<ManifestSource> {
        oneiron::origin::smart_http::validate_repo_name(&self.repo).map_err(|_| {
            OwnerError::Invalid("manifest.repo must be a served repository's name".into())
        })?;
        let git_ref = self
            .git_ref
            .unwrap_or_else(|| DEFAULT_MANIFEST_REF.to_owned());
        if oneiron::git_wire::GitRefName::parse_full(git_ref.as_str()).is_err()
            || !git_ref.starts_with("refs/heads/")
        {
            return Err(OwnerError::Invalid(
                "manifest.ref must be a branch, such as refs/heads/main".into(),
            ));
        }
        Ok(ManifestSource {
            repo: self.repo,
            git_ref,
        })
    }
}

impl RegisterSecret {
    pub(crate) async fn read(body: Body) -> OwnerResult<Self> {
        let body = OwnedBody::read(body).await?;
        let fields: RegisterFields<'_> =
            serde_json::from_slice(&body.0).map_err(|_| invalid_body())?;
        let value = decode_value(fields.value_base64)?;
        let class = CustodyClass::parse(&fields.class).ok_or_else(|| {
            OwnerError::Invalid(
                "class must be custody-portable, custody-device-bound or cross-vault".into(),
            )
        })?;
        let bindings = fields
            .bindings
            .into_iter()
            .map(|binding| {
                Ok(RequestedBinding {
                    effector: binding.effector,
                    tier_ceiling: binding.tier_ceiling.map(rung).transpose()?,
                    scopes: binding.scopes,
                })
            })
            .collect::<OwnerResult<_>>()?;
        Ok(Self {
            name: secret_name(fields.name)?,
            class,
            device_only: fields.device_only,
            rung: rung(fields.rung)?,
            bindings,
            manifest: fields.manifest.map(ManifestFields::source).transpose()?,
            value,
            plan: custody_plan(fields.holder, fields.recipients)?,
        })
    }
}

fn rung(grade: u8) -> OwnerResult<CustodyTier> {
    CustodyTier::from_u8(grade).ok_or_else(|| {
        OwnerError::Invalid("a rung is 0 (doored), 1 (leased) or 2 (local-registered)".into())
    })
}

impl std::fmt::Debug for RegisterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterSecret")
            .field("name", &self.name)
            .field("class", &self.class)
            .field("rung", &self.rung)
            .field("bindings", &self.bindings)
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for RotateSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateSecret")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// The body in the one buffer this request owns, wiped when it drops. It is
/// sized before the first byte arrives and never grows: growing would move
/// the bytes and free the old allocation unwiped.
struct OwnedBody(Vec<u8>);

impl OwnedBody {
    async fn read(body: Body) -> OwnerResult<Self> {
        let room = match body.size_hint().upper() {
            None => BODY_LIMIT,
            Some(declared) => usize::try_from(declared)
                .ok()
                .filter(|declared| *declared <= BODY_LIMIT)
                .ok_or_else(invalid_body)?,
        };
        let mut owned = Self(Vec::with_capacity(room));
        let mut frames = body.into_data_stream();
        while let Some(frame) = frames.next().await {
            let frame = frame.map_err(|_| invalid_body())?;
            let fits = frame.len() <= owned.0.capacity() - owned.0.len();
            if fits {
                owned.0.extend_from_slice(&frame);
            }
            wipe_frame(frame);
            if !fits {
                return Err(invalid_body());
            }
        }
        Ok(owned)
    }
}

impl Drop for OwnedBody {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Wipes a frame in place once it is copied, when this request holds its
/// only reference. A frame the server still shares with the connection's read
/// buffer, which hyper splits frames from, is transport memory: no handler
/// reaches it, as none reaches the bearer token read with the headers.
fn wipe_frame(frame: Bytes) {
    if let Ok(mut frame) = frame.try_into_mut() {
        wipe(&mut frame[..]);
    }
}

/// Every buffer the request owns that held the value or its encoding ends
/// here.
fn wipe<B: Zeroize + AsRef<[u8]> + ?Sized>(buffer: &mut B) {
    #[cfg(test)]
    wiped::saw(buffer.as_ref());
    buffer.zeroize();
}

fn invalid_body() -> OwnerError {
    OwnerError::Invalid("invalid JSON request body".into())
}

/// The wipe hook's record, so a test can name a buffer by its contents and
/// see that it went through [`wipe`].
#[cfg(test)]
pub(crate) mod wiped {
    use std::cell::RefCell;

    thread_local! {
        // Per thread: a request read on a current-thread test runtime wipes
        // on the test's own thread.
        static SEEN: RefCell<Vec<blake3::Hash>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn saw(buffer: &[u8]) {
        SEEN.with_borrow_mut(|seen| seen.push(blake3::hash(buffer)));
    }

    /// How many buffers this thread wiped that held exactly `bytes` just
    /// before the wipe.
    pub(crate) fn count(bytes: &[u8]) -> usize {
        let held = blake3::hash(bytes);
        SEEN.with_borrow(|seen| seen.iter().filter(|seen| **seen == held).count())
    }
}

/// What a custody change recorded for the owner's other machines,
/// value-free (WILL L04 row 04).
#[derive(Debug, Serialize)]
pub(crate) struct CustodyReply {
    /// The custody request's shared receipt; absent when nothing was
    /// recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) work: Option<OwnerWorkReceipt>,
    /// Why the change stayed on this install.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kept_here: Option<&'static str>,
    /// `unknown` once a request is recorded, since no machine acknowledges
    /// a transition; `not_sent` when the change stayed here.
    pub(crate) delivery: &'static str,
    /// The words a surface shows.
    pub(crate) said: &'static str,
}

impl From<SecretCustodyWork> for CustodyReply {
    fn from(custody: SecretCustodyWork) -> Self {
        Self {
            said: custody.text(),
            kept_here: custody.kept_here.map(CustodyKeptHere::as_str),
            delivery: custody.delivery.as_str(),
            work: custody.work,
        }
    }
}

/// A rotation or revoke's reply: the receipt this install wrote, when it
/// wrote one, and what the custody request says.
#[derive(Debug, Serialize)]
pub(crate) struct CustodyRotated {
    #[serde(flatten)]
    pub(crate) receipt: Option<Rotated>,
    pub(crate) custody: CustodyReply,
}

/// What the rotation or revoke changed: the generation moved, never the
/// value. `kind` is the receipt's own (`rotated` or `revoked`, FIX 1753), so
/// a revoke reads as one without its route.
#[derive(Debug, Serialize)]
pub(crate) struct Rotated {
    pub(crate) receipt_id: String,
    pub(crate) name: String,
    pub(crate) from_generation: u32,
    pub(crate) to_generation: u32,
    pub(crate) rotated_at: u64,
    pub(crate) kind: &'static str,
}

/// What the registration stored: the record's metadata and its manifest
/// copy, never the value.
#[derive(Debug, Serialize)]
pub(crate) struct Registered {
    pub(crate) secret_id: String,
    pub(crate) name: String,
    pub(crate) class: CustodyClass,
    pub(crate) device_only: bool,
    pub(crate) rotation_generation: u32,
    pub(crate) registered_at: u64,
    pub(crate) bindings: Vec<RegisteredBinding>,
    pub(crate) manifest_ref: String,
    pub(crate) declared_paths: Vec<String>,
    pub(crate) custody: CustodyReply,
}

/// A stored binding, its rung on the wire's 0–2 grade.
#[derive(Debug, Serialize)]
pub(crate) struct RegisteredBinding {
    pub(crate) effector: String,
    pub(crate) tier_ceiling: u8,
    pub(crate) scopes: Vec<String>,
}

pub(crate) fn register(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    request: &RegisterSecret,
) -> OwnerResult<Registered> {
    let registered = vault.register_secret_with_custody(
        owner,
        surface,
        &OwnerSecretRegistration {
            name: &request.name,
            class: request.class,
            device_only: request.device_only,
            rung: request.rung,
            bindings: request.bindings.clone(),
            manifest: request.manifest.clone(),
            value: &request.value,
        },
        &request.plan,
        vault.now_recorded_at(),
    )?;
    Ok(registered.into())
}

impl From<SecretRegistered> for Registered {
    fn from(registered: SecretRegistered) -> Self {
        Self {
            secret_id: registered.secret_id.to_hex(),
            name: registered.name,
            class: registered.class,
            device_only: registered.device_only,
            rotation_generation: registered.rotation_generation,
            registered_at: registered.registered_at,
            bindings: registered
                .bindings
                .into_iter()
                .map(|binding| RegisteredBinding {
                    effector: binding.effector,
                    tier_ceiling: binding.tier_ceiling.as_u8(),
                    scopes: binding.scopes,
                })
                .collect(),
            manifest_ref: registered.manifest_ref,
            declared_paths: registered.declared_paths,
            custody: registered.custody.into(),
        }
    }
}

pub(crate) fn rotate(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    request: &RotateSecret,
) -> OwnerResult<CustodyRotated> {
    let rotated = vault.rotate_secret_with_custody(
        owner,
        surface,
        &request.name,
        &request.value,
        &request.plan,
        vault.now_recorded_at(),
    )?;
    Ok(CustodyRotated {
        receipt: rotated.rotation.map(Rotated::from),
        custody: rotated.custody.into(),
    })
}

impl From<oneiron::secret_rotation::RotationReceipt> for Rotated {
    fn from(receipt: oneiron::secret_rotation::RotationReceipt) -> Self {
        Self {
            receipt_id: receipt.receipt_id.to_hex(),
            name: receipt.secret_ref,
            from_generation: receipt.from_generation,
            to_generation: receipt.to_generation,
            rotated_at: receipt.rotated_at,
            kind: receipt.kind.as_str(),
        }
    }
}

/// Reads a revoke request, `{"name"}`, into the secret's custody name. It
/// carries no value, but the body goes through [`OwnedBody`] all the same,
/// under the same limit as the others.
pub(crate) async fn read_revoke(body: Body) -> OwnerResult<String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RevokeFields {
        name: String,
    }
    let body = OwnedBody::read(body).await?;
    let fields: RevokeFields = serde_json::from_slice(&body.0).map_err(|_| invalid_body())?;
    secret_name(fields.name)
}

/// Revokes a secret on the owner's behalf (OF-422): the record goes terminal
/// and every lease over it is revoked, stamped on the vault clock as a
/// rotation is. The receipt reads as a rotation's does, with
/// `from_generation` equal to `to_generation` (nothing replaced the value)
/// and `kind: "revoked"`, beside the custody revoke request carried for the
/// owner's other machines from `surface` (audit only). With none recorded
/// the reply says the revoke was not carried to them from here.
pub(crate) fn revoke(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    name: &str,
) -> OwnerResult<CustodyRotated> {
    let revoked = vault.revoke_secret_as_owner(owner, surface, name, vault.now_recorded_at())?;
    let custody = match revoked.work {
        Some(work) => CustodyReply {
            said: work
                .unassigned
                .map_or_else(|| work.status.text(), OwnerWorkUnassigned::text),
            kept_here: None,
            delivery: if work.request.is_some() {
                "unknown"
            } else {
                "not_sent"
            },
            work: Some(work),
        },
        None => CustodyReply {
            work: None,
            kept_here: Some("not_carried"),
            delivery: "not_sent",
            said: "revoked here only: it stays on its device, or this install carries no act \
                   to your other machines; revoke it again from a linked install",
        },
    };
    Ok(CustodyRotated {
        receipt: Some(revoked.rotation.into()),
        custody,
    })
}

/// Seals a portable secret again to the installs `plan` permits, by its
/// holder (WILL L04 row 04): how a machine linked later gets it, since
/// linking alone permits nobody.
pub(crate) fn rewrap(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    name: &str,
    plan: &CustodyPlan,
) -> OwnerResult<CustodyReply> {
    Ok(vault
        .rewrap_secret_as_owner(owner, surface, name, plan, vault.now_recorded_at())?
        .into())
}

/// What the owner's kit push of a secret's custody did (OF-422).
#[derive(Debug, Serialize)]
pub(crate) struct AnchorSigned {
    pub(crate) name: String,
    /// Whether a transition was written. None is for a record that stays on
    /// its device (device bound, cross-vault or "this device only").
    pub(crate) signed: bool,
}

/// Pushes the current custody transition of the portable secret `name`,
/// signed with the owner anchor of `seed`, the recovery root this vault
/// pins, to the installs `recipients` names (CALLS CUSTODY_KIT_PUSH): the
/// owner's kit is his authority; the install carries no act. The engine
/// takes it only from an install with no live machine profile; any other
/// rewraps the secret as its holder. The record keeps its generation,
/// status and value. No route takes a kit; the seed is the caller's to wipe.
pub(crate) fn sign_with_anchor(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    seed: &oneiron::world_keys::RecoveryRootSeed,
    name: &str,
    recipients: &[oneiron::EntityId],
) -> OwnerResult<AnchorSigned> {
    let signed =
        vault.sign_custody_with_anchor(owner, seed, name, recipients, vault.now_recorded_at())?;
    Ok(AnchorSigned {
        name: name.to_owned(),
        signed,
    })
}
