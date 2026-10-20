//! What the supervisor hands a restoring engine on `--restore-input-fd`: one
//! [`ManagedRestoreInput`] JSON object, then EOF. It names the plan, the
//! artifact, what the artifact must be and the custody anchor to admit it
//! against; it carries no secret. The data key rides the credential frame
//! and the anchor's owner credential its own pipe, as on every start.
//!
//! The recipient plan (`RestorePlan` and its parts) is the engine's own
//! (`oneiron::recovery::checkpoint`, which re-exports these): one definition
//! for the plan the supervisor writes and the restore spends.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The one [`ManagedRestoreInput`] schema this crate reads.
pub const RESTORE_INPUT_SCHEMA_VERSION: u32 = 1;

/// The escrow role a managed recipient serves; its label is
/// `<role>.<first 16 hex of BLAKE3(public key)>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EscrowRole {
    Managed,
    BreakGlass,
}

impl EscrowRole {
    /// The label prefix a wrap of this role carries.
    pub fn label_prefix(self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::BreakGlass => "break-glass",
        }
    }
}

/// A recipient whose secret the restore's key release used: its label,
/// role, full fingerprint and host-recipient epoch, as the plan maps them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasedRecipient {
    pub label: String,
    pub role: EscrowRole,
    /// BLAKE3 of the recipient's public key bytes.
    #[serde(with = "super::hex::array")]
    pub fingerprint: [u8; 32],
    /// The host recipient's epoch, carried to the receipt; never the custody
    /// writer epoch or the checkpoint's crypto epoch.
    pub epoch: u64,
}

/// A fresh recipient the restored key is wrapped to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshRecipient {
    pub label: String,
    pub role: EscrowRole,
    /// The hybrid public key's bytes, as the supervisor names them.
    #[serde(with = "super::hex::bytes")]
    pub public_key: Vec<u8>,
}

/// The plan's restore-specific scope: who asked, and the recipients it
/// adds and retires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePlan {
    pub restore_id: String,
    #[serde(with = "super::hex::array")]
    pub plan_digest: [u8; 32],
    pub attempt_id: String,
    /// The process generation; never an epoch.
    pub generation: u64,
    pub released: Vec<ReleasedRecipient>,
    pub fresh: Vec<FreshRecipient>,
}

/// The input pipe's one object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRestoreInput {
    /// [`RESTORE_INPUT_SCHEMA_VERSION`]; any other is refused.
    pub schema_version: u32,
    pub plan: ManagedRestorePlan,
}

/// One cold managed restore, as the supervisor authorized it. The engine
/// checks each binding against its own argv before anything is touched:
/// `vault_name` and `source.registry_id` are `--vault-name`, the owners and
/// `member_vault` the routing flags, and `maximum_tier` the tier the start
/// settled. The destination is `--data-dir`, never a path in the plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRestorePlan {
    pub request: RestorePlan,
    /// The registry's id for the vault (`--vault-name`).
    pub vault_name: String,
    /// `--derivation-owner`.
    #[serde(with = "super::hex::array")]
    pub derivation_owner: [u8; 32],
    /// `--organization-owner`, or `null` without one.
    #[serde(with = "super::hex::option_array")]
    pub organization_owner: Option<[u8; 32]>,
    /// `--member-vault`.
    pub member_vault: bool,
    /// The signed artifact the restore lands, an absolute path the engine
    /// reads. Its custody head is looked for in the same directory.
    pub artifact: PathBuf,
    /// Whether the restored vault seals its pages (the maximum tier).
    pub maximum_tier: bool,
    pub source: RestoreSourceExpectation,
    pub custody: RestoreCustodyPlan,
    pub evidence: RestoreEvidence,
}

/// What the plan says the artifact is, from a record kept apart from it:
/// nothing here is read from the artifact being checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSourceExpectation {
    /// The engine vault id the backup prelude must name.
    #[serde(with = "super::hex::array")]
    pub engine_vault_id: [u8; 32],
    /// The data-key commitment the key header names, and the delivered
    /// key's own.
    #[serde(with = "super::hex::array")]
    pub data_key_commitment: [u8; 32],
    /// BLAKE3 of every byte of the artifact (the catalog's object digest).
    #[serde(with = "super::hex::array")]
    pub artifact_digest: [u8; 32],
    /// The snapshot id the prelude and commitment name.
    #[serde(with = "super::hex::array")]
    pub snapshot: [u8; 32],
    /// The checkpoint id: BLAKE3 of the canonical image, not the snapshot.
    #[serde(with = "super::hex::array")]
    pub checkpoint_id: [u8; 32],
    pub kind: RestoreArtifactKind,
    /// The signers the catalog pins, from outside the artifact; the only
    /// signers the commitment is checked against.
    pub signer_pins: Vec<RestoreSignerPin>,
    /// The registry's id for the vault, checked against a registry binding
    /// the artifact carries; never the DNS slug, the engine vault id or the
    /// custody namespace.
    pub registry_id: String,
}

/// Which kind of sealed artifact the plan names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreArtifactKind {
    Checkpoint,
    Backup,
}

/// One pinned checkpoint signer: the install that signs, and its Ed25519
/// and SLH-DSA-SHA2-256s public keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreSignerPin {
    #[serde(with = "super::hex::array")]
    pub install: [u8; 16],
    #[serde(with = "super::hex::array")]
    pub ed25519: [u8; 32],
    /// 64 bytes; a pin of another length is refused.
    #[serde(with = "super::hex::bytes")]
    pub slhdsa: Vec<u8>,
}

/// The custody anchor the plan names, explicitly: none ("rollback not
/// proven", as with no anchor configured), a self-host anchor directory, or
/// an anchor door, called with the owner credential the supervisor hands on
/// `--custody-anchor-credentials-fd`. A promised door never quietly becomes
/// none. The restored vault keeps publishing to the same anchor once it
/// serves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "anchor", rename_all = "snake_case", deny_unknown_fields)]
pub enum RestoreCustodyPlan {
    Unset,
    Root { root: PathBuf },
    Http { url: String },
}

/// The supervisor's references for where the plan's facts came from,
/// carried to the receipt as they are and never read by the engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreEvidence {
    pub signer_pins_reference: String,
    pub host_release_reference: String,
    pub host_report_id: Option<String>,
    pub engine_report_id: Option<String>,
}
