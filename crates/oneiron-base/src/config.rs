//! Portable runtime configuration moved down from the engine crate.

pub mod failure_signals;
pub mod ppr_community;

use std::fmt;

use serde::{Deserialize, Serialize};

pub use ppr_community::PprCommunityConfig;

/// Validates the opt-in community prior without relaxing its safety bounds.
pub fn validate_ppr_community(config: &PprCommunityConfig) -> crate::error::Result<()> {
    config
        .validate()
        .map_err(|error| crate::error::Error::InvalidConfig(error.to_string()))
}

/// Production remains default-off, regardless of benchmark results.
pub const PPR_VAD_ALPHA_DEFAULT: f32 = 0.0;
/// Largest supported PPR VAD salience coefficient.
pub const PPR_VAD_ALPHA_MAX: f32 = 0.4;
/// Pinned BEAM retrieval sweep.
pub const PPR_VAD_ALPHA_SWEEP: &[f32] = &[0.0, 0.1, 0.2, 0.3, 0.4];

/// Rejects non-finite or out-of-range PPR VAD coefficients without clamping.
pub fn validate_ppr_vad_alpha(alpha: f32) -> crate::error::Result<()> {
    if !alpha.is_finite() || !(0.0..=PPR_VAD_ALPHA_MAX).contains(&alpha) {
        return Err(crate::error::Error::InvalidConfig(format!(
            "ppr_vad_alpha must be finite and within 0..={PPR_VAD_ALPHA_MAX}, got {alpha}"
        )));
    }
    Ok(())
}

/// Default hard byte budget for one live off-record session overlay.
pub const DEFAULT_OFF_RECORD_OVERLAY_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// The LMDB reader slots every opener of a vault asks for: both presets, the
/// read-only door and the history import's dry run. LMDB sizes a vault's reader table (in `lock.mdb`) when
/// a process opens it with no other process holding it, and never shrinks
/// it; a process that opens beside a holder gets the holder's table. So every
/// opener asks for the same table, and whoever opens first builds it.
///
/// LMDB keeps a slot for each thread that has read, and a server reads on
/// its blocking pool (up to 512 threads): at 126 slots, 128 agents recalling
/// at once were refused with `MDB_READERS_FULL`. A slot is 64 bytes of the
/// lock file.
pub const READER_SLOTS: u32 = 1024;

/// Deployment posture: managed host root, blind relay, or owner self-host.
/// This describes key custody, not an encryption protocol.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostingPrivacyPosture {
    /// Operator-hosted and host-readable: the hosting process holds the data
    /// key, whichever custody supplies it. Opted into explicitly.
    #[serde(rename = "managed")]
    Hosted,
    /// Blind relay: the host holds no owner key and mints no authority.
    Relay,
    /// Owner-operated local process holding its own key material. The default
    /// for the open-source engine and every embedded caller.
    #[default]
    #[serde(rename = "self-host")]
    SelfHostLocal,
}

impl HostingPrivacyPosture {
    /// Returns the exact wire value used by the CLI, environment, TOML, and
    /// serde representations: `managed`, `relay`, or `self-host`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hosted => "managed",
            Self::Relay => "relay",
            Self::SelfHostLocal => "self-host",
        }
    }
}

impl fmt::Display for HostingPrivacyPosture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for HostingPrivacyPosture {
    type Err = String;

    /// Accepts ONLY the three exact wire values. Every other spelling — including
    /// case variants, aliases, and any legacy "unreadable hosted" naming — is a
    /// hard error, so an unrecognized posture can never silently degrade into a
    /// weaker or stronger one.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "managed" => Ok(Self::Hosted),
            "relay" => Ok(Self::Relay),
            "self-host" => Ok(Self::SelfHostLocal),
            _ => Err(format!(
                "expected one of managed, relay, self-host; got {value:?}"
            )),
        }
    }
}

/// Where the deployment's data key comes from.
///
/// The hosted variant carries an OPAQUE host-managed key reference (a KMS/HSM
/// ARN, URI, or key id) and never key material: raw key bytes are not part of
/// this type, its serialized form, or its [`Debug`] output.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VaultDataKeyCustody {
    /// Host-managed KMS/HSM custody, identified by an opaque reference.
    HostManagedKms {
        /// Opaque reference to a host-managed key (ARN / URI / key id).
        /// NEVER key material, and redacted in [`Debug`].
        key_ref: String,
    },
    /// Owner-held local key source. No host reference is stored at all.
    OwnerHeldLocal,
    /// The managed supervisor delivers the vault key at boot; the host
    /// process holds it to decrypt. No reference and no key material is
    /// stored.
    SupervisorDelivered,
}

impl fmt::Debug for VaultDataKeyCustody {
    /// Manual so the host-managed reference never reaches logs. A derived
    /// `Debug` would print `key_ref` verbatim everywhere a `VaultConfig` or
    /// `Vault` config is traced.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostManagedKms { .. } => f
                .debug_struct("HostManagedKms")
                .field("key_ref", &"<redacted>")
                .finish(),
            Self::OwnerHeldLocal => f.write_str("OwnerHeldLocal"),
            Self::SupervisorDelivered => f.write_str("SupervisorDelivered"),
        }
    }
}

/// Refusal text for KMS custody whose key reference is missing or blank.
const KMS_REQUIRES_KEY_REF: &str = "KMS key custody requires a non-empty key reference";
/// Refusal text for a blind relay carrying a KMS key: a relay holds no data
/// key, so a key reference would make it a keyholder. This is what a relay
/// is, not a hosting ban: the same key is accepted on a hosted or self-hosted
/// keyholder.
const RELAY_HOLDS_NO_KEY: &str =
    "a blind relay holds no data key; use the hosted or self-host posture for a KMS key";

/// The deployment posture together with the key custody it is paired with.
///
/// Where the key may sit is the owner's choice of placement; custody says who
/// supplies it. Placement never vetoes a supported custody (owner, 10-19:
/// a hosted-only refusal stays only for law, provider terms or capacity, and
/// none applies here). CALLS: HOSTED_OWNER_KEY_SUPPORT.
///
/// The pairing is enforced — not merely documented — by [`Self::validate`],
/// which every vault opener runs before the storage environment is mapped:
///
/// | posture | custody | outcome |
/// |---|---|---|
/// | `Hosted` | `HostManagedKms` with a non-empty reference | valid, host-readable |
/// | `Hosted` | `OwnerHeldLocal` | valid, host-readable with the owner's key |
/// | `Hosted` | `SupervisorDelivered` | valid, host-readable with the supervisor-delivered key |
/// | `SelfHostLocal` | `OwnerHeldLocal` | valid, owner-held key |
/// | `SelfHostLocal` | `HostManagedKms` with a non-empty reference | valid, the owner's own KMS |
/// | `SelfHostLocal` | `SupervisorDelivered` | valid, the supervisor-delivered key |
/// | `Relay` | `OwnerHeldLocal` | valid, blind relay |
/// | `Relay` | `HostManagedKms` | rejected: a relay holds no key |
/// | `Relay` | `SupervisorDelivered` | rejected: a relay holds no key |
/// | any | `HostManagedKms` with a blank reference | rejected |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultPrivacyConfig {
    /// Deployment posture. Defaults to [`HostingPrivacyPosture::SelfHostLocal`].
    pub posture: HostingPrivacyPosture,
    /// Data-key custody paired with `posture`.
    pub data_key_custody: VaultDataKeyCustody,
}

impl Default for VaultPrivacyConfig {
    /// Self-host/local with an owner-held local key — the posture of the
    /// open-source engine and of every embedded caller that does not opt in to
    /// hosting. Hosted is never reached by default.
    fn default() -> Self {
        Self {
            posture: HostingPrivacyPosture::SelfHostLocal,
            data_key_custody: VaultDataKeyCustody::OwnerHeldLocal,
        }
    }
}

impl VaultPrivacyConfig {
    /// Rejects the pairings no deployment can run, with no fallback between
    /// them: a KMS reference blank after trimming, and a KMS or
    /// supervisor-delivered key on a blind relay. Any placement takes any
    /// supported custody otherwise. An
    /// invalid pairing is [`crate::error::Error::InvalidConfig`], raised before any
    /// storage environment is opened. Configuration is not proof a KMS backend
    /// exists: the opener that needs the key still fails if none answers.
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        use crate::error::Error;

        match (self.posture, &self.data_key_custody) {
            (_, VaultDataKeyCustody::HostManagedKms { key_ref }) if key_ref.trim().is_empty() => {
                Err(Error::InvalidConfig(KMS_REQUIRES_KEY_REF.to_owned()))
            }
            (HostingPrivacyPosture::Relay, VaultDataKeyCustody::HostManagedKms { .. })
            | (HostingPrivacyPosture::Relay, VaultDataKeyCustody::SupervisorDelivered) => {
                Err(Error::InvalidConfig(RELAY_HOLDS_NO_KEY.to_owned()))
            }
            (
                HostingPrivacyPosture::Hosted | HostingPrivacyPosture::SelfHostLocal,
                VaultDataKeyCustody::HostManagedKms { .. },
            )
            | (
                HostingPrivacyPosture::Hosted | HostingPrivacyPosture::SelfHostLocal,
                VaultDataKeyCustody::SupervisorDelivered,
            )
            | (_, VaultDataKeyCustody::OwnerHeldLocal) => Ok(()),
        }
    }

    /// True when the hosting operator can read this vault.
    ///
    /// A hosted deployment is host-readable whoever supplies its key: the
    /// hosting process holds it to decrypt. Self-host/local has no operator
    /// in the loop.
    #[must_use]
    pub const fn host_readable(&self) -> bool {
        matches!(self.posture, HostingPrivacyPosture::Hosted)
    }

    /// Short, honest description of who holds the key. An owner-supplied key
    /// on a hosted deployment is still `host-readable`: supplying it does not
    /// make the host blind. No label claims a host cannot read what it
    /// stores.
    #[must_use]
    pub const fn honest_label(&self) -> &'static str {
        match (self.posture, &self.data_key_custody) {
            (HostingPrivacyPosture::Hosted, VaultDataKeyCustody::HostManagedKms { .. }) => {
                "host-readable"
            }
            (HostingPrivacyPosture::Hosted, VaultDataKeyCustody::OwnerHeldLocal) => {
                "host-readable-owner-supplied-key"
            }
            (HostingPrivacyPosture::Hosted, VaultDataKeyCustody::SupervisorDelivered) => {
                "host-readable-supervisor-delivered-key"
            }
            (HostingPrivacyPosture::Relay, _) => "blind-relay-owner-held-key",
            (HostingPrivacyPosture::SelfHostLocal, VaultDataKeyCustody::OwnerHeldLocal) => {
                "owner-held-key"
            }
            (HostingPrivacyPosture::SelfHostLocal, VaultDataKeyCustody::HostManagedKms { .. }) => {
                "owner-kms-key"
            }
            (HostingPrivacyPosture::SelfHostLocal, VaultDataKeyCustody::SupervisorDelivered) => {
                "supervisor-delivered-key"
            }
        }
    }
}

/// Where vector evidence starts in one embedding space, for the check that
/// withholds a pack with no real match (ARCH-0004, pre-assembly validation).
///
/// A raw cosine means different things in different models: a compressed
/// space scores a true paraphrase below where a wide one scores noise. The
/// host that knows its model states these; the default is the engine's
/// original calibration.
/// A space row stores it as `{floor, strong}` (embed/space.rs).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VectorEvidenceFloors {
    /// The similarity floor: with no keyword hit, a pack whose every vector
    /// score sits under it abstains.
    pub floor: f32,
    /// The score of a strong match: under it, a top hit that barely leads
    /// the next is uniformly mediocre and the pack abstains.
    pub strong: f32,
}

impl Default for VectorEvidenceFloors {
    fn default() -> Self {
        Self {
            floor: 0.3,
            strong: 0.5,
        }
    }
}

impl VectorEvidenceFloors {
    /// Both are cosine similarities, which span `-1.0..=1.0`. A floor under
    /// zero would count a vector pointing away from the query as evidence,
    /// so each must lie in `0.0..=1.0`, and a strong match is no weaker than
    /// the floor: `0 <= floor <= strong <= 1`. A value outside that, or not a
    /// number, would admit evidence the check exists to withhold, so it is
    /// refused, never clamped.
    pub fn validate(&self) -> crate::error::Result<()> {
        let in_range = |value: f32| value.is_finite() && (0.0..=1.0).contains(&value);
        if !in_range(self.floor) || !in_range(self.strong) || self.floor > self.strong {
            return Err(crate::error::Error::InvalidConfig(format!(
                "vector evidence floors must satisfy 0 <= floor <= strong <= 1, \
                 got floor {} and strong {}",
                self.floor, self.strong
            )));
        }
        Ok(())
    }
}

/// Text analyzer configuration. Kept minimal in v1 — the full analyzer
/// manifest (normalization policy, per-channel schema, lang modes) is
/// computed from dict discovery at open time and stored in the vault's
/// on-disk manifest. Fields here cover caller-controllable knobs only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TextAnalyzerConfig {}

/// Per-call overrides for `BatchBuilder::text`. Reserved; v1 ignores all
/// fields but the struct is public so downstream can adopt without a
/// minor-version bump later.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TextIndexOptions {
    /// Explicit language hint for this batch of text fields. Overrides
    /// `whichlang` detection on Latin/Cyrillic/Greek runs and the
    /// DualHanFallback decision on Han runs. Unambiguous-script runs
    /// (Hiragana, Katakana, Hangul, Hebrew, Thai, Lao, Khmer, Myanmar)
    /// route by their own script class regardless of this hint — the
    /// script is the stronger signal.
    pub language_hint: Option<crate::analyzer::LanguageHint>,
}
