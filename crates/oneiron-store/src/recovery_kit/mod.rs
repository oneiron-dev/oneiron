//! Offline recovery-kit values, passphrases, piece formats and pure codecs.

use oneiron_contracts::entity_id::EntityId;
use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};
use zeroize::Zeroizing;

pub mod piece;
pub use piece::{KitId, KitPiece, PieceExport, RecoveryCode};

/// The one 32-byte secret a kit carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KitSecretKind {
    /// A vault's data key, on any valid custody and placement (CALLS:
    /// DATA_KEY_KIT). It recovers the data key from the pieces. It does not
    /// remove or revoke the provider's, the supervisor's, a device's or an
    /// escrow's copy, and does not recover private-world keys (the recovery
    /// root kit does); a running host that holds the key reads what it
    /// decrypts.
    VaultKey,
    /// The world recovery root seed. Any posture, a hosted vault included.
    RecoveryRoot,
}

/// Where the owner keeps one piece. There is no host, cloud or server variant.
#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PieceHome {
    /// The issuing machine, in its device-only key slot; never the vault store or sync.
    ThisMachine,
    /// Another of the owner's machines, by its id.
    OtherMachine(EntityId),
    /// A recovery code the owner keeps.
    RecoveryCode(CodeKeeping),
    /// The owner's passphrase. Nothing is stored; the point is rebuilt from it.
    Passphrase,
    /// A trusted person. Never required.
    TrustedPerson,
    /// A hardware security key holding the piece's export. Never required.
    SecurityKey,
}

impl PieceHome {
    /// The machine whose loss takes this piece with it, if any.
    pub fn machine(&self) -> Option<KitMachine> {
        match self {
            Self::ThisMachine => Some(KitMachine::ThisMachine),
            Self::OtherMachine(id) => Some(KitMachine::Other(*id)),
            Self::RecoveryCode(CodeKeeping::FileOn(machine)) => Some(*machine),
            _ => None,
        }
    }
}

/// Where the owner keeps a recovery code. Only a file on a machine leaves with it.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CodeKeeping {
    /// A file on one of the owner's machines.
    FileOn(KitMachine),
    /// A file kept apart from every machine: a USB stick, a disk in a drawer.
    FileElsewhere,
    /// Printed.
    Paper,
    /// A password manager.
    PasswordManager,
    /// The owner's own mailbox, sent from the owner's device.
    OwnEmail,
}

/// A machine that holds a piece.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum KitMachine {
    /// The issuing machine.
    ThisMachine,
    /// Another of the owner's machines.
    Other(EntityId),
}

/// What losing one machine leaves, judged from the homes at issue. Clients word it.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum KitCoverage {
    /// Losing any one machine that holds a piece still leaves two pieces.
    SurvivesMachineLoss,
    /// Fewer than two pieces live away from `machine`: its theft or loss locks the kit.
    /// For a one-machine owner `machine` is the issuing machine.
    FewerThanTwoAway {
        /// The machine whose loss locks the kit.
        machine: KitMachine,
        /// Pieces that survive its loss.
        away: u8,
    },
}

/// Argon2id cost of the passphrase piece. Memory is a power of two in MiB; the lanes are
/// fixed at 4. Every stored piece carries it, since the passphrase has no storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassphraseCost {
    pub memory_mib: u32,
    pub passes: u8,
}

impl PassphraseCost {
    /// RFC 9106 section 4, second recommended option. Below it, issue and import refuse.
    pub const FLOOR: Self = Self {
        memory_mib: 64,
        passes: 3,
    };
    /// What issue uses unless the device cannot afford it.
    pub const DEFAULT: Self = Self {
        memory_mib: 256,
        passes: 3,
    };
    /// The most work a piece may ask a restore to do.
    pub const CEILING: Self = Self {
        memory_mib: 1024,
        passes: 8,
    };
    const LANES: u8 = 4;

    /// Refuses memory that is not a power of two, and any cost outside FLOOR..=CEILING.
    pub fn new(memory_mib: u32, passes: u8) -> Result<Self, KitError> {
        if !memory_mib.is_power_of_two()
            || !(Self::FLOOR.memory_mib..=Self::CEILING.memory_mib).contains(&memory_mib)
            || !(Self::FLOOR.passes..=Self::CEILING.passes).contains(&passes)
        {
            return Err(KitError::PassphraseCost);
        }
        Ok(Self { memory_mib, passes })
    }
    /// Argon2id memory in MiB.
    pub fn memory_mib(&self) -> u32 {
        self.memory_mib
    }
    /// Argon2id passes.
    pub fn passes(&self) -> u8 {
        self.passes
    }
    pub fn below(&self, other: &Self) -> bool {
        self.memory_mib < other.memory_mib || self.passes < other.passes
    }
    pub fn argon2(self) -> oneiron_crypto::Argon2Cost {
        oneiron_crypto::Argon2Cost {
            m_kib: self.memory_mib * 1024,
            t: self.passes.into(),
            p: Self::LANES,
        }
    }
}

/// The kit passphrase, NFC-normalised so the same words typed on two systems rebuild the
/// same piece. Debug never prints it; drop scrubs it.
pub struct KitPassphrase(pub oneiron_crypto::Passphrase);

impl std::fmt::Debug for KitPassphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KitPassphrase(<redacted>)")
    }
}

impl KitPassphrase {
    /// Refuses an empty passphrase and one over 1024 bytes after normalisation. Strength is
    /// the client's call: the kit never opens on the passphrase alone, whatever its strength.
    pub fn new(text: &str) -> Result<Self, KitError> {
        // Text the NFC quick check passes (all ASCII, most typed text) skips the normaliser,
        // whose scratch for long combining runs this crate cannot wipe.
        if matches!(is_nfc_quick(text.chars()), IsNormalized::Yes) {
            return Self::from_normal(text);
        }
        let mut normal = Zeroizing::new(String::with_capacity(text.len().saturating_mul(3)));
        normal.extend(text.nfc());
        Self::from_normal(&normal)
    }
    fn from_normal(text: &str) -> Result<Self, KitError> {
        oneiron_crypto::Passphrase::new(text.as_bytes())
            .map(Self)
            .map_err(|_| KitError::PassphraseLength)
    }
}

/// What the owner picked at issue.
pub struct KitIssue<'a> {
    /// The vault the kit belongs to.
    pub vault_id: [u8; 32],
    /// One home per Shamir point: `homes[i]` holds x = i + 1.
    pub homes: [PieceHome; 3],
    /// Required exactly when a home is the passphrase.
    pub passphrase: Option<&'a KitPassphrase>,
    /// Used only with a passphrase home.
    pub cost: PassphraseCost,
    /// The issuing machine is the owner's only machine. Only then may two pieces share it
    /// (with the `FewerThanTwoAway` warning). `Vault::issue_world_kit` sets it from the
    /// machine roster; elsewhere the caller says.
    pub only_machine: bool,
}

/// Public facts about a kit: no piece material and no tag. With the passphrase it still
/// yields only one point, so it may be stored anywhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KitManifest {
    /// Public kit identifier, also inside every stored piece.
    pub kit_id: KitId,
    /// The secret the kit carries.
    pub kind: KitSecretKind,
    /// The owner's pick per point.
    pub homes: [PieceHome; 3],
    /// The passphrase piece's Argon2id cost, when the kit has one.
    pub cost: Option<PassphraseCost>,
    /// What losing one machine leaves.
    pub coverage: KitCoverage,
}

/// A freshly issued kit. Debug prints the manifest and the piece count only.
pub struct IssuedKit {
    pub manifest: KitManifest,
    pub pieces: Vec<KitPiece>,
}

impl std::fmt::Debug for IssuedKit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedKit")
            .field("manifest", &self.manifest)
            .field("pieces", &self.pieces.len())
            .finish()
    }
}

impl IssuedKit {
    /// Public facts about the kit.
    pub fn manifest(&self) -> &KitManifest {
        &self.manifest
    }
    /// The stored pieces in x order. A passphrase home has none.
    pub fn into_pieces(self) -> Vec<KitPiece> {
        self.pieces
    }
}

/// A rebuilt secret. Debug never prints it; drop scrubs it.
pub struct RestoredKitSecret {
    pub kind: KitSecretKind,
    pub kit_id: KitId,
    pub bytes: Zeroizing<[u8; 32]>,
    pub reissue_advised: bool,
    pub stored_pieces: u8,
}

impl std::fmt::Debug for RestoredKitSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoredKitSecret")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl RestoredKitSecret {
    /// The secret the kit carried.
    pub fn kind(&self) -> KitSecretKind {
        self.kind
    }
    /// The kit the pieces belong to.
    pub fn kit_id(&self) -> KitId {
        self.kit_id
    }
    /// Explicit access for the vault-key unlock or the recovery-root rebuild.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
    /// Hands the bytes on, still scrubbed on drop.
    pub fn into_bytes(self) -> Zeroizing<[u8; 32]> {
        self.bytes
    }
    /// The kit's passphrase cost is below today's default: clients offer a reissue.
    pub fn reissue_advised(&self) -> bool {
        self.reissue_advised
    }
    /// The distinct stored pieces the secret was rebuilt from. With two or more, a forged
    /// piece beside a genuine one would have to match the genuine tag: 2^72 work. With one,
    /// the passphrase supplied the other point and the tag checked is that piece's own, so
    /// anyone who knows the passphrase could have written the piece for a secret they chose.
    /// Nothing in the kit authenticates such a secret; it needs confirmation from outside,
    /// such as a root this install already pins, a machine that pins it, or the owner.
    pub fn stored_pieces(&self) -> u8 {
        self.stored_pieces
    }
}

/// No piece, passphrase, key or entropy material appears in these errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KitError {
    /// The vault's posture/custody pairing does not validate.
    #[error("the vault's key custody configuration is invalid")]
    InvalidCustodyConfig,
    /// Entropy acquisition failed.
    #[error("backup entropy unavailable")]
    EntropyUnavailable,
    /// Two pieces on this machine, or on one other machine.
    #[error("two kit pieces would live on one machine")]
    SameMachineTwice,
    /// Two passphrase pieces would let memory alone open the kit.
    #[error("a kit holds at most one passphrase piece")]
    PassphraseTwice,
    /// A passphrase home with no passphrase.
    #[error("the passphrase piece needs a passphrase")]
    PassphraseMissing,
    /// A passphrase for a kit without a passphrase home.
    #[error("this kit has no passphrase piece")]
    PassphraseUnused,
    /// Empty, or over 1024 bytes after normalisation.
    #[error("passphrase length out of range")]
    PassphraseLength,
    /// An Argon2id cost outside the kit's floor and ceiling.
    #[error("passphrase cost outside the kit's bounds")]
    PassphraseCost,
    /// The passphrase stretch could not run (its work memory was refused).
    #[error("passphrase stretch failed")]
    PassphraseStretch,
    /// An all-zero vault id or secret.
    #[error("invalid vault id or secret")]
    InvalidSecret,
    /// Not a v2 kit piece: wrong magic (a v1 share included), length or field.
    #[error("not a v2 kit piece")]
    InvalidPiece,
    /// A recovery code failed its check: a typo.
    #[error("recovery code check failed")]
    CodeChecksum,
    /// A piece of the other kit kind.
    #[error("piece belongs to another kind of kit")]
    WrongKind,
    /// Pieces of different kits.
    #[error("pieces come from different kits")]
    MixedKits,
    /// Fewer than two distinct points.
    #[error("two distinct kit pieces are required")]
    NeedTwoPieces,
    /// The points do not rebuild this kit's secret. Never says which piece was wrong.
    #[error("the pieces do not open this kit")]
    NoMatch,
    /// Too few pieces were given, and this machine's own piece, which its key slots
    /// hold, could not be read to make up the two (FIX 2063).
    #[error("this machine's kit piece could not be read; give two pieces")]
    KeptPieceUnreadable,
}

/// Which slot pair of this install's kit pieces (FIX 11977, 12046).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KitPiecePair {
    /// The piece of the kit of this kind in force.
    Current(KitSecretKind),
    /// The piece of the world kit with this id, drawn and not yet confirmed.
    Pending(KitId),
}

impl KitPiecePair {
    /// Whether `piece` belongs in this pair: a piece of its kind for a current
    /// pair, a world kit's piece of its kit for a pending one.
    pub fn holds(self, piece: &KitPiece) -> bool {
        match self {
            Self::Current(kind) => piece.kind() == kind,
            Self::Pending(kit) => {
                piece.kind() == KitSecretKind::RecoveryRoot && piece.kit_id() == kit
            }
        }
    }
}
