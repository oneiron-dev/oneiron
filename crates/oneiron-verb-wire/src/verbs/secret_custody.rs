//! Moved from `crates/oneiron/src/verbs/secret_custody.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use oneiron_authority::authority::CustodyRecipientPermit;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// `vault.secrets.register`'s input: the body `POST
/// /v1/owner/secrets/register` takes. `Debug` never prints the value.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretRegisterRequest {
    /// The secret's custody name: 1 to 488 bytes (what its name-index key
    /// holds), unique among live records.
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

/// `vault.secrets.revoke`'s input: the secret's custody name, as `POST
/// /v1/owner/secrets/revoke` reads it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretRevokeRequest {
    pub name: String,
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

pub fn entity_id(field: &str, value: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value)
        .map_err(|_| MemoryError::bad_request(format!("{field} must be a 32-hex entity id")))
}

/// A 32-byte digest or revision a request names, as 64 hex.
pub fn digest(field: &str, value: &str) -> MemoryResult<[u8; 32]> {
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
