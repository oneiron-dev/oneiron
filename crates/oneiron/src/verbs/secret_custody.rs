//! The owner's custody doors as typed rows (WILL L04 row 04, FIX 4993):
//! `vault.secrets.register`, `vault.secrets.rotate`, `vault.secrets.rewrap`,
//! `vault.secrets.custody.get` and `vault.secrets.custody.submit`. Each runs
//! the same engine door as its `/v1/owner/secrets/*` route, with the same
//! request and reply fields, under the owner's proof. A host passes its own
//! reading of where the request came from as the act's surface, for audit
//! only. An embedded handle acts as this install.
//!
//! A register or rotate that carries the value (`value_base64`) is the
//! owner's explicit plaintext choice: the value reaches the custody plane
//! and no reply. [`seal_custody_submit`] is the other way: the client seals
//! the input to the holder on its own side, under the binding
//! `vault.secrets.custody.get` answered. `vault.secrets.custody.submit`
//! then hands this install only ciphertext. The three rows that carry a
//! value or its ciphertext keep no call receipt (`no_record`). Their record
//! is the custody request's own receipt in the reply, as on the owner's
//! routes. A request that holds a value wipes it when it drops, and none
//! prints it.

mod surface_seal;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::authority::{ActSurface, CustodyChange, CustodyRecipientPermit};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::secret_custody::{
    CustodyClass, CustodyManifestCheck, CustodyPlan, CustodyTier, ManifestSource,
    OwnerSecretRegistration, RequestedBinding, SECRET_NAME_MAX_BYTES, SealedCustodyChange,
    SecretCustodyView, SecretCustodyWork, SecretRegistered,
};
use crate::secret_rotation::RotationReceipt;
use crate::world_keys::OwnerWorkReceipt;
use crate::{EntityId, Vault};

pub use self::surface_seal::seal_custody_submit;

/// The custody rows whose input carries a secret's value or its sealed
/// input. The action registry offers none of them: an action keeps its
/// whole input in its replay record.
pub const CUSTODY_VALUE_ROWS: [&str; 3] = [
    "vault.secrets.register",
    "vault.secrets.rotate",
    "vault.secrets.custody.submit",
];

/// The ref a manifest is read at when the request names none, as on the
/// owner's register route.
const DEFAULT_MANIFEST_REF: &str = "refs/heads/main";

/// `vault.secrets.register`'s input: the body `POST
/// /v1/owner/secrets/register` takes. `Debug` never prints the value.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretRegisterRequest {
    /// The secret's custody name: 1 to 255 bytes, unique among live
    /// records.
    pub name: String,
    /// `custody-portable`, `custody-device-bound` or `cross-vault`.
    pub class: String,
    /// The custody ladder's rung: 0 doored, 1 leased, 2 local-registered.
    pub rung: u8,
    /// The portable record's "this device only" dial.
    #[serde(default)]
    pub device_only: bool,
    #[serde(default)]
    pub bindings: Vec<SecretRegisterBinding>,
    /// The served repository whose manifest declares the name, if one does.
    #[serde(default)]
    pub manifest: Option<SecretManifestSource>,
    /// The value, as standard base64.
    pub value_base64: String,
    /// A portable secret's holder, as 32 hex; this install when absent.
    #[serde(default)]
    pub holder: Option<String>,
    /// The installs permitted to hold a portable secret, as 32 hex each;
    /// its holder alone when empty.
    #[serde(default)]
    pub recipients: Vec<String>,
}

/// One binding a register asks for.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretRegisterBinding {
    /// The effector that may use the secret, such as `connector:gmail`.
    pub effector: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The binding's rung, at or below the secret's; the secret's when
    /// absent.
    #[serde(default)]
    pub tier_ceiling: Option<u8>,
}

/// Where a register reads the manifest that declares its name.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretManifestSource {
    /// The served repository's name.
    pub repo: String,
    /// The branch, such as `refs/heads/main`, which it is when absent.
    #[serde(default, rename = "ref")]
    pub git_ref: Option<String>,
}

/// `vault.secrets.rotate`'s input: the body `POST /v1/owner/secrets/rotate`
/// takes. `Debug` never prints the value.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretRotateRequest {
    /// The secret's custody name.
    pub name: String,
    /// The new value, as standard base64.
    pub value_base64: String,
    /// The install that holds the secret and rotates it, as 32 hex; this
    /// install when absent.
    #[serde(default)]
    pub holder: Option<String>,
    /// The installs permitted to hold the new value, as 32 hex each; the
    /// secret's live permits when empty.
    #[serde(default)]
    pub recipients: Vec<String>,
}

impl Drop for SecretRegisterRequest {
    fn drop(&mut self) {
        self.value_base64.zeroize();
    }
}

impl Drop for SecretRotateRequest {
    fn drop(&mut self) {
        self.value_base64.zeroize();
    }
}

impl std::fmt::Debug for SecretRegisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRegisterRequest")
            .field("name", &self.name)
            .field("class", &self.class)
            .field("rung", &self.rung)
            .field("device_only", &self.device_only)
            .field("bindings", &self.bindings)
            .field("manifest", &self.manifest)
            .field("holder", &self.holder)
            .field("recipients", &self.recipients)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for SecretRotateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRotateRequest")
            .field("name", &self.name)
            .field("holder", &self.holder)
            .field("recipients", &self.recipients)
            .finish_non_exhaustive()
    }
}

/// `vault.secrets.rewrap`'s input: the body `POST /v1/owner/secrets/rewrap`
/// takes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretRewrapRequest {
    pub name: String,
    /// The install that holds the secret, as 32 hex; this install when
    /// absent.
    #[serde(default)]
    pub holder: Option<String>,
    /// The installs permitted to hold it, as 32 hex each.
    pub recipients: Vec<String>,
}

/// `vault.secrets.custody.get`'s input: the secret's custody name.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretCustodyGetRequest {
    pub name: String,
}

/// `vault.secrets.custody.submit`'s input: the body `POST
/// /v1/owner/secrets/custody` takes, a register or rotate whose protected
/// input the surface sealed to the holder itself ([`seal_custody_submit`]).
/// `Debug` never prints the ciphertext.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretCustodySubmitRequest {
    /// `register` or `rotate`.
    pub change: String,
    /// The custody record id the view gave, as 32 hex.
    pub secret_id: String,
    /// The generation the change approves.
    pub generation: u32,
    /// The custody revision the surface read, as 64 hex.
    pub seen: String,
    /// The install the input is sealed to, as 32 hex.
    pub holder: String,
    /// The exact permits the input binds, ascending by machine.
    pub recipients: Vec<SecretCustodyPermit>,
    /// For a register, the `manifest_ref` its sealed record names: this
    /// install attaches the manifest it resolves for it. Absent, it
    /// attaches every manifest the vault publishes, or says it has none.
    #[serde(default)]
    pub manifest_ref: Option<String>,
    /// The input sealed to the holder's key, as standard base64: one
    /// envelope, or the frame of numbered envelopes.
    pub input_base64: String,
}

impl std::fmt::Debug for SecretCustodySubmitRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretCustodySubmitRequest")
            .field("change", &self.change)
            .field("secret_id", &self.secret_id)
            .field("generation", &self.generation)
            .field("holder", &self.holder)
            .field("recipients", &self.recipients.len())
            .field("manifest_ref", &self.manifest_ref)
            .finish_non_exhaustive()
    }
}

/// One exact permit a sealed input binds, as the custody view lists its
/// candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretCustodyPermit {
    /// The install, as 32 hex.
    pub machine: String,
    /// The profile entry the permit binds, as 64 hex.
    pub profile: String,
    /// The encryption key digest the permit binds, as 64 hex.
    pub encryption_key_digest: String,
}

/// What a custody change recorded for the owner's other machines,
/// value-free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCustodyReply {
    /// The custody request's shared receipt; absent when nothing was
    /// recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work: Option<OwnerWorkReceipt>,
    /// Why the change stayed on this install.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kept_here: Option<String>,
    /// `unknown` once a request is recorded, since no machine acknowledges
    /// a transition; `not_sent` when the change stayed here.
    pub delivery: String,
    /// The words a surface shows.
    pub said: String,
    /// For a sealed register that stated no `manifest_ref`, what its holder
    /// checked the record against, or what this install attached for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
}

/// What a register stored: the record's metadata and its manifest copy,
/// never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRegisterReply {
    pub secret_id: String,
    pub name: String,
    pub class: String,
    pub device_only: bool,
    pub rotation_generation: u32,
    pub registered_at: u64,
    pub bindings: Vec<SecretRegisteredBinding>,
    pub manifest_ref: String,
    pub declared_paths: Vec<String>,
    pub custody: SecretCustodyReply,
}

/// A stored binding, its rung on the wire's 0 to 2 grade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRegisteredBinding {
    pub effector: String,
    pub tier_ceiling: u8,
    pub scopes: Vec<String>,
}

/// A rotate's reply, as the owner route writes it: the fields of the
/// receipt this install wrote when it rotated the record itself, beside
/// what the custody request says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRotateReply {
    /// Absent while another holder has the rotation to do.
    #[serde(flatten)]
    pub receipt: Option<SecretRotationReceipt>,
    pub custody: SecretCustodyReply,
}

/// What a rotation changed: the generation moved, never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRotationReceipt {
    pub receipt_id: String,
    pub name: String,
    pub from_generation: u32,
    pub to_generation: u32,
    pub rotated_at: u64,
    /// The receipt's own kind, `rotated`.
    pub kind: String,
}

/// What a surface reads to ask a custody change, value-free: the binding a
/// sealed input takes, the secret's live requests, and every live linked
/// install it may offer as holder or recipient. Offering one is not the
/// owner's consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCustodyViewReply {
    /// The vault an input binds, as 64 hex.
    pub vault_id: String,
    /// The custody record id; a fresh one for a name nothing live holds,
    /// which a register binds.
    pub secret_id: String,
    pub name: String,
    pub known: bool,
    pub held_here: bool,
    pub portable: bool,
    #[serde(default)]
    pub status: Option<String>,
    /// The record's generation: the one a register approves for an unknown
    /// name, one below a rotate's.
    pub generation: u32,
    /// The custody revision a change states as seen, as 64 hex.
    pub seen: String,
    pub live: Vec<SecretCustodyLiveRequest>,
    pub candidates: Vec<SecretCustodyCandidateReply>,
    pub delivery: String,
}

/// One live custody request as the view shows it: its receipt, ids only,
/// and the words for what its holder checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretCustodyLiveRequest {
    #[serde(flatten)]
    pub receipt: OwnerWorkReceipt,
    /// The text of the manifest check the receipt's result names; absent
    /// before the result, and for any other work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_text: Option<String>,
}

/// One install a surface may offer as holder or recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCustodyCandidateReply {
    /// The install, as 32 hex.
    pub machine: String,
    /// The profile entry a permit binds, as 64 hex.
    pub profile: String,
    /// The encryption key digest a permit binds, as 64 hex.
    pub encryption_key_digest: String,
    /// The key a surface seals an input to: its suite and public bytes.
    pub suite: u16,
    pub encryption_key_base64: String,
    pub this_install: bool,
}

/// `vault.secrets.register`: registers the secret, a portable one as a
/// custody register request its holder enacts, by the door
/// `/v1/owner/secrets/register` runs.
///
/// # Errors
/// A malformed field; every refusal of
/// [`Vault::register_secret_with_custody`].
pub fn register_secret_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: SecretRegisterRequest,
) -> MemoryResult<SecretRegisterReply> {
    let value = decode_value(&input.value_base64)?;
    let class = CustodyClass::parse(&input.class).ok_or_else(|| {
        MemoryError::bad_request(
            "class must be custody-portable, custody-device-bound or cross-vault",
        )
    })?;
    let bindings = input
        .bindings
        .iter()
        .map(|binding| {
            Ok(RequestedBinding {
                effector: binding.effector.clone(),
                tier_ceiling: binding.tier_ceiling.map(rung).transpose()?,
                scopes: binding.scopes.clone(),
            })
        })
        .collect::<MemoryResult<Vec<_>>>()?;
    let manifest = input.manifest.as_ref().map(manifest_source).transpose()?;
    let registered = vault.register_secret_with_custody(
        owner,
        surface,
        &OwnerSecretRegistration {
            name: secret_name(&input.name)?,
            class,
            device_only: input.device_only,
            rung: rung(input.rung)?,
            bindings,
            manifest,
            value: &value,
        },
        &custody_plan(input.holder.as_deref(), &input.recipients)?,
        vault.now_recorded_at(),
    )?;
    Ok(registered.into())
}

/// `vault.secrets.rotate`: rotates the secret, a portable one as a custody
/// rotate request its holder enacts, by the door
/// `/v1/owner/secrets/rotate` runs.
///
/// # Errors
/// A malformed field or an empty value; every refusal of
/// [`Vault::rotate_secret_with_custody`].
pub fn rotate_secret_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: SecretRotateRequest,
) -> MemoryResult<SecretRotateReply> {
    let value = decode_value(&input.value_base64)?;
    if value.is_empty() {
        return Err(MemoryError::bad_request("a rotated secret needs a value"));
    }
    let rotated = vault.rotate_secret_with_custody(
        owner,
        surface,
        secret_name(&input.name)?,
        &value,
        &custody_plan(input.holder.as_deref(), &input.recipients)?,
        vault.now_recorded_at(),
    )?;
    Ok(SecretRotateReply {
        receipt: rotated.rotation.map(SecretRotationReceipt::from),
        custody: rotated.custody.into(),
    })
}

/// `vault.secrets.rewrap`: seals a portable secret again, same generation
/// and status, to the installs the owner names now, by its holder.
///
/// # Errors
/// A malformed id; every refusal of [`Vault::rewrap_secret_as_owner`].
pub fn rewrap_secret_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: SecretRewrapRequest,
) -> MemoryResult<SecretCustodyReply> {
    let plan = custody_plan(input.holder.as_deref(), &input.recipients)?;
    Ok(vault
        .rewrap_secret_as_owner(owner, surface, &input.name, &plan, vault.now_recorded_at())?
        .into())
}

/// `vault.secrets.custody.get`: the secret's custody binding, live
/// requests and candidate installs, value-free.
///
/// # Errors
/// Every refusal of [`Vault::secret_custody_view`].
pub fn secret_custody_get_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SecretCustodyGetRequest,
) -> MemoryResult<SecretCustodyViewReply> {
    Ok(vault.secret_custody_view(owner, &input.name)?.into())
}

/// `vault.secrets.custody.submit`: records a register or rotate whose
/// protected input the surface sealed to the holder, by the door `POST
/// /v1/owner/secrets/custody` runs. This install sees only ciphertext.
///
/// # Errors
/// A malformed field; every refusal of
/// [`Vault::seal_custody_change_as_owner`].
pub fn submit_sealed_custody_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: SecretCustodySubmitRequest,
) -> MemoryResult<SecretCustodyReply> {
    let change = CustodyChange::from_name(&input.change)
        .filter(|change| matches!(change, CustodyChange::Register | CustodyChange::Rotate))
        .ok_or_else(|| MemoryError::bad_request("change must be register or rotate"))?;
    let recipients = input
        .recipients
        .iter()
        .map(SecretCustodyPermit::permit)
        .collect::<MemoryResult<Vec<_>>>()?;
    let sealed = base64::engine::general_purpose::STANDARD
        .decode(input.input_base64.as_bytes())
        .map_err(|_| MemoryError::bad_request("input_base64 must be standard base64"))?;
    let custody = vault.seal_custody_change_as_owner(
        owner,
        surface,
        &SealedCustodyChange {
            manifest_ref: input.manifest_ref.as_deref(),
            change,
            secret_id: entity_id("secret_id", &input.secret_id)?,
            generation: input.generation,
            seen: digest("seen", &input.seen)?,
            holder: entity_id("holder", &input.holder)?,
            recipients: &recipients,
            input: &sealed,
        },
        vault.now_recorded_at(),
    )?;
    Ok(custody.into())
}

impl SecretCustodyPermit {
    fn permit(&self) -> MemoryResult<CustodyRecipientPermit> {
        Ok(CustodyRecipientPermit {
            machine: entity_id("recipients.machine", &self.machine)?,
            profile: digest("recipients.profile", &self.profile)?,
            encryption_key: digest(
                "recipients.encryption_key_digest",
                &self.encryption_key_digest,
            )?,
        })
    }
}

/// The holder and recipients a request names, as machine ids.
fn custody_plan(holder: Option<&str>, recipients: &[String]) -> MemoryResult<CustodyPlan> {
    Ok(CustodyPlan {
        holder: holder
            .map(|holder| entity_id("holder", holder))
            .transpose()?,
        recipients: recipients
            .iter()
            .map(|machine| entity_id("recipients", machine))
            .collect::<MemoryResult<_>>()?,
    })
}

/// A name the custody index can key: 1 to 255 bytes.
fn secret_name(name: &str) -> MemoryResult<&str> {
    if name.is_empty() || name.len() > SECRET_NAME_MAX_BYTES {
        return Err(MemoryError::bad_request("name must be 1 to 255 bytes"));
    }
    Ok(name)
}

/// The value a request carries, decoded into a buffer sized up front and
/// wiped when it drops.
fn decode_value(encoded: &str) -> MemoryResult<Zeroizing<Vec<u8>>> {
    let mut value = Zeroizing::new(Vec::with_capacity(base64::decoded_len_estimate(
        encoded.len(),
    )));
    base64::engine::general_purpose::STANDARD
        .decode_vec(encoded.as_bytes(), &mut value)
        .map_err(|_| MemoryError::bad_request("value_base64 must be standard base64"))?;
    Ok(value)
}

fn rung(grade: u8) -> MemoryResult<CustodyTier> {
    CustodyTier::from_u8(grade).ok_or_else(|| {
        MemoryError::bad_request("a rung is 0 (doored), 1 (leased) or 2 (local-registered)")
    })
}

/// Where a register's manifest is read, checked here so a malformed name
/// is the caller's error, as on the owner's route.
fn manifest_source(source: &SecretManifestSource) -> MemoryResult<ManifestSource> {
    crate::origin::smart_http::validate_repo_name(&source.repo).map_err(|_| {
        MemoryError::bad_request("manifest.repo must be a served repository's name")
    })?;
    let git_ref = source
        .git_ref
        .clone()
        .unwrap_or_else(|| DEFAULT_MANIFEST_REF.to_owned());
    if crate::git_wire::GitRefName::parse_full(git_ref.as_str()).is_err()
        || !git_ref.starts_with("refs/heads/")
    {
        return Err(MemoryError::bad_request(
            "manifest.ref must be a branch, such as refs/heads/main",
        ));
    }
    Ok(ManifestSource {
        repo: source.repo.clone(),
        git_ref,
    })
}

fn entity_id(field: &str, value: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value)
        .map_err(|_| MemoryError::bad_request(format!("{field} must be a 32-hex entity id")))
}

/// A 32-byte digest or revision a request names, as 64 hex.
fn digest(field: &str, value: &str) -> MemoryResult<[u8; 32]> {
    let invalid = || MemoryError::bad_request(format!("{field} must be 64 hex"));
    let text = value.as_bytes();
    if text.len() != 64 {
        return Err(invalid());
    }
    let mut out = [0_u8; 32];
    for (byte, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        let high = char::from(pair[0]).to_digit(16).ok_or_else(invalid)?;
        let low = char::from(pair[1]).to_digit(16).ok_or_else(invalid)?;
        *byte = u8::try_from((high << 4) | low).map_err(|_| invalid())?;
    }
    Ok(out)
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl From<SecretCustodyWork> for SecretCustodyReply {
    fn from(custody: SecretCustodyWork) -> Self {
        Self {
            said: custody.text().to_owned(),
            kept_here: custody.kept_here.map(|why| why.as_str().to_owned()),
            delivery: custody.delivery.as_str().to_owned(),
            manifest: custody.manifest.as_ref().map(CustodyManifestCheck::text),
            work: custody.work,
        }
    }
}

impl From<SecretRegistered> for SecretRegisterReply {
    fn from(registered: SecretRegistered) -> Self {
        Self {
            secret_id: registered.secret_id.to_hex(),
            name: registered.name,
            class: registered.class.as_str().to_owned(),
            device_only: registered.device_only,
            rotation_generation: registered.rotation_generation,
            registered_at: registered.registered_at,
            bindings: registered
                .bindings
                .into_iter()
                .map(|binding| SecretRegisteredBinding {
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

impl From<RotationReceipt> for SecretRotationReceipt {
    fn from(receipt: RotationReceipt) -> Self {
        Self {
            receipt_id: receipt.receipt_id.to_hex(),
            name: receipt.secret_ref,
            from_generation: receipt.from_generation,
            to_generation: receipt.to_generation,
            rotated_at: receipt.rotated_at,
            kind: receipt.kind.as_str().to_owned(),
        }
    }
}

impl From<OwnerWorkReceipt> for SecretCustodyLiveRequest {
    fn from(receipt: OwnerWorkReceipt) -> Self {
        let manifest_text = receipt
            .manifest_check
            .clone()
            .map(|check| CustodyManifestCheck::Judged(check).text());
        Self {
            receipt,
            manifest_text,
        }
    }
}

impl From<SecretCustodyView> for SecretCustodyViewReply {
    fn from(view: SecretCustodyView) -> Self {
        Self {
            vault_id: hex(&view.vault_id),
            secret_id: view.secret_id.to_hex(),
            name: view.name,
            known: view.known,
            held_here: view.held_here,
            portable: view.portable,
            status: view.status.map(|status| status.as_str().to_owned()),
            generation: view.generation,
            seen: hex(&view.seen),
            live: view
                .live
                .into_iter()
                .map(SecretCustodyLiveRequest::from)
                .collect(),
            candidates: view
                .candidates
                .into_iter()
                .map(|candidate| SecretCustodyCandidateReply {
                    machine: candidate.permit.machine.to_hex(),
                    profile: hex(&candidate.permit.profile),
                    encryption_key_digest: hex(&candidate.permit.encryption_key),
                    suite: candidate.suite,
                    encryption_key_base64: base64::engine::general_purpose::STANDARD
                        .encode(&candidate.encryption_key),
                    this_install: candidate.this_install,
                })
                .collect(),
            delivery: view.delivery.as_str().to_owned(),
        }
    }
}
