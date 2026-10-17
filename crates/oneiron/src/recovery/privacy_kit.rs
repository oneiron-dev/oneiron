//! Vault-scoped 2-of-3 offline recovery kits; no person-level master secret.
//!
//! A kit carries one 32-byte secret: an owner-held vault key, or the world recovery root
//! seed. Shamir over GF(2^8), degree 1, bytewise; the point x (1, 2 or 3) is only the
//! point. Beside it sits the home the owner picked. The host and the cloud have no home.
//! The passphrase piece stores nothing: its point is Argon2id(passphrase), and the line is
//! fitted through it and the secret, so the passphrase alone (or with any public byte) is
//! one point and opens nothing, and testing a guess needs a stored piece.
use rand_core::{OsRng, RngCore};
use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};
use zeroize::{Zeroize, Zeroizing};

use crate::EntityId;

mod piece;
#[cfg(test)]
mod tests;

pub use piece::{KitId, KitPiece, PieceExport, RecoveryCode};

const SALT_CONTEXT: &str = "oneiron/kit/v2/passphrase-salt";
const TAG_CONTEXT: &str = "oneiron/kit/v2/tag";

/// The one 32-byte secret a kit carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KitSecretKind {
    /// An owner-held vault's data key. Refused on a host-readable vault.
    VaultKey,
    /// The world recovery root seed. Any posture, a hosted vault included.
    RecoveryRoot,
}

/// Where the owner keeps one piece. There is no host, cloud or server variant.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    fn machine(&self) -> Option<KitMachine> {
        match self {
            Self::ThisMachine => Some(KitMachine::ThisMachine),
            Self::OtherMachine(id) => Some(KitMachine::Other(*id)),
            Self::RecoveryCode(CodeKeeping::FileOn(machine)) => Some(*machine),
            _ => None,
        }
    }
}

/// Where the owner keeps a recovery code. Only a file on a machine leaves with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KitMachine {
    /// The issuing machine.
    ThisMachine,
    /// Another of the owner's machines.
    Other(EntityId),
}

/// What losing one machine leaves, judged from the homes at issue. Clients word it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    memory_mib: u32,
    passes: u8,
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
    fn below(&self, other: &Self) -> bool {
        self.memory_mib < other.memory_mib || self.passes < other.passes
    }
    fn argon2(self) -> oneiron_crypto::Argon2Cost {
        oneiron_crypto::Argon2Cost {
            m_kib: self.memory_mib * 1024,
            t: self.passes.into(),
            p: Self::LANES,
        }
    }
}

/// The kit passphrase, NFC-normalised so the same words typed on two systems rebuild the
/// same piece. Debug never prints it; drop scrubs it.
pub struct KitPassphrase(oneiron_crypto::Passphrase);

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
    manifest: KitManifest,
    pieces: Vec<KitPiece>,
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
    kind: KitSecretKind,
    bytes: Zeroizing<[u8; 32]>,
    reissue_advised: bool,
    stored_pieces: u8,
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
    /// A hosted-readable vault cannot present a vault-key kit as host-blind recovery.
    #[error("privacy backup requires owner-held keys")]
    PrivacyModeRequired,
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
}

/// Issues a kit for an owner-held vault's data key. The hosted-readable refusal stands:
/// this does not implement an unratified sealed-envelope VEK-rotation protocol either.
pub fn issue_vault_key_kit(
    posture: &crate::config::VaultPrivacyConfig,
    issue: &KitIssue<'_>,
    vault_key: &[u8; 32],
) -> Result<IssuedKit, KitError> {
    if posture.validate().is_err() || posture.host_readable() {
        return Err(KitError::PrivacyModeRequired);
    }
    issue_kit(KitSecretKind::VaultKey, issue, vault_key)
}

/// Issues a kit for the world recovery root seed, on any posture: the host never holds a
/// piece, so a hosted vault's kit is host-blind too.
pub fn issue_recovery_root_kit(
    issue: &KitIssue<'_>,
    seed: &[u8; 32],
) -> Result<IssuedKit, KitError> {
    issue_kit(KitSecretKind::RecoveryRoot, issue, seed)
}

fn issue_kit(
    kind: KitSecretKind,
    issue: &KitIssue<'_>,
    secret: &[u8; 32],
) -> Result<IssuedKit, KitError> {
    check_homes(&issue.homes, issue.only_machine)?;
    let passphrase_x = issue
        .homes
        .iter()
        .position(|home| *home == PieceHome::Passphrase)
        .map_or(0, |i| i as u8 + 1);
    let cost = match (passphrase_x, issue.passphrase) {
        (0, None) => None,
        (0, Some(_)) => return Err(KitError::PassphraseUnused),
        (_, None) => return Err(KitError::PassphraseMissing),
        (_, Some(_)) => Some(issue.cost),
    };
    if issue.vault_id == [0; 32] || *secret == [0; 32] {
        return Err(KitError::InvalidSecret);
    }
    let mut kit_id = [0; 4];
    OsRng
        .try_fill_bytes(&mut kit_id)
        .map_err(|_| KitError::EntropyUnavailable)?;
    if kit_id == [0; 4] {
        return Err(KitError::EntropyUnavailable);
    }
    issue_with_id(kind, issue, secret, passphrase_x, cost, KitId(kit_id))
}

/// The rest of issue, once the kit id is drawn.
fn issue_with_id(
    kind: KitSecretKind,
    issue: &KitIssue<'_>,
    secret: &[u8; 32],
    passphrase_x: u8,
    mut cost: Option<PassphraseCost>,
    kit_id: KitId,
) -> Result<IssuedKit, KitError> {
    let mut slope = Zeroizing::new([0u8; 32]);
    match (&mut cost, issue.passphrase) {
        (Some(cost), Some(passphrase)) => {
            // A device that cannot afford the asked memory steps down toward FLOOR, never
            // below it; the pieces and the manifest carry the cost actually used.
            let point = loop {
                match passphrase_point(&issue.vault_id, kind, kit_id, *cost, passphrase) {
                    Err(KitError::PassphraseStretch)
                        if cost.memory_mib > PassphraseCost::FLOOR.memory_mib =>
                    {
                        cost.memory_mib /= 2;
                    }
                    point => break point?,
                }
            };
            let inv = inverse(passphrase_x);
            for ((slope, point), secret) in slope.iter_mut().zip(point.iter()).zip(secret) {
                *slope = multiply(point ^ secret, inv);
            }
        }
        _ => OsRng
            .try_fill_bytes(&mut slope[..])
            .map_err(|_| KitError::EntropyUnavailable)?,
    }
    let tag = tag(&issue.vault_id, kind, passphrase_x, cost, kit_id, secret);
    let mut pieces = Vec::with_capacity(3);
    for (x, home) in (1u8..).zip(&issue.homes) {
        if *home == PieceHome::Passphrase {
            continue;
        }
        pieces.push(KitPiece::issued(
            home.clone(),
            piece::Point {
                x,
                kind,
                passphrase_x,
                cost,
                kit_id,
                y: Zeroizing::new(std::array::from_fn(|i| secret[i] ^ multiply(slope[i], x))),
                tag: Zeroizing::new(*tag),
            },
        ));
    }
    Ok(IssuedKit {
        manifest: KitManifest {
            kit_id,
            kind,
            homes: issue.homes.clone(),
            cost,
            coverage: coverage(&issue.homes),
        },
        pieces,
    })
}

/// Rebuilds a kit's secret from at least two distinct points: stored pieces, plus the
/// passphrase when given. Every point given must lie on one line, and the tag must match.
/// The vault id comes from the vault being restored. The result opens that vault's key
/// custody or recovery root; it confers no authority-log widening.
pub fn restore_kit(
    vault_id: [u8; 32],
    kind: KitSecretKind,
    pieces: &[&KitPiece],
    passphrase: Option<&KitPassphrase>,
) -> Result<RestoredKitSecret, KitError> {
    let Some(first) = pieces.first() else {
        return Err(KitError::NeedTwoPieces);
    };
    let first = first.point();
    if vault_id == [0; 32] {
        return Err(KitError::InvalidSecret);
    }
    let rebuilt;
    let mut points: Vec<(u8, &[u8; 32])> = Vec::with_capacity(3);
    // A piece that disagrees with the first is noted, not returned at once: the passphrase
    // work below runs either way, so an altered piece fails after the same work as a wrong
    // passphrase. Kind and kit id are public facts about the pieces and fail first.
    let mut mismatch = false;
    for piece in pieces {
        let point = piece.point();
        if point.kind != kind {
            return Err(KitError::WrongKind);
        }
        if point.kit_id != first.kit_id {
            return Err(KitError::MixedKits);
        }
        if point.passphrase_x != first.passphrase_x
            || point.cost != first.cost
            || point.tag != first.tag
        {
            mismatch = true;
            continue;
        }
        match points.iter().find(|(x, _)| *x == point.x) {
            Some((_, y)) if **y == *point.y => {}
            Some(_) => mismatch = true,
            None => points.push((point.x, &point.y)),
        }
    }
    let stored_pieces = points.len() as u8;
    if let Some(passphrase) = passphrase {
        // Only pieces that all agree the kit has no passphrase piece say so.
        let Some(cost) = first.cost else {
            return Err(if mismatch {
                KitError::NoMatch
            } else {
                KitError::PassphraseUnused
            });
        };
        rebuilt = passphrase_point(&vault_id, kind, first.kit_id, cost, passphrase)?;
        points.push((first.passphrase_x, &rebuilt));
    }
    if mismatch {
        return Err(KitError::NoMatch);
    }
    let [(x1, y1), (x2, y2), ..] = points[..] else {
        return Err(KitError::NeedTwoPieces);
    };
    let inv = inverse(x1 ^ x2);
    let slope = Zeroizing::new(std::array::from_fn::<_, 32, _>(|i| {
        multiply(y1[i] ^ y2[i], inv)
    }));
    let secret = Zeroizing::new(std::array::from_fn::<_, 32, _>(|i| {
        y1[i] ^ multiply(slope[i], x1)
    }));
    let mut diff = 0u8;
    for (x, y) in &points {
        for ((y, secret), slope) in y.iter().zip(secret.iter()).zip(slope.iter()) {
            diff |= y ^ secret ^ multiply(*slope, *x);
        }
    }
    let expected = tag(
        &vault_id,
        kind,
        first.passphrase_x,
        first.cost,
        first.kit_id,
        &secret,
    );
    for (a, b) in expected.iter().zip(first.tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 || *secret == [0; 32] {
        return Err(KitError::NoMatch);
    }
    Ok(RestoredKitSecret {
        kind,
        bytes: secret,
        reissue_advised: first
            .cost
            .is_some_and(|cost| cost.below(&PassphraseCost::DEFAULT)),
        stored_pieces,
    })
}

/// A second passphrase is refused, and so are two pieces on one machine. One exception,
/// as the owner ruled: on the owner's only machine, this machine's piece beside a code
/// file on it is issued, and coverage reports the warning; that machine already holds what
/// the kit opens. Codes, people and security keys may repeat: each is a separate item or
/// person.
fn check_homes(homes: &[PieceHome; 3], only_machine: bool) -> Result<(), KitError> {
    let count = |home: &PieceHome| homes.iter().filter(|other| *other == home).count();
    if count(&PieceHome::Passphrase) > 1 {
        return Err(KitError::PassphraseTwice);
    }
    if count(&PieceHome::ThisMachine) > 1 {
        return Err(KitError::SameMachineTwice);
    }
    let machines: Vec<KitMachine> = homes.iter().filter_map(PieceHome::machine).collect();
    let only_this_machine = only_machine
        && machines
            .iter()
            .all(|machine| *machine == KitMachine::ThisMachine);
    for (i, machine) in machines.iter().enumerate() {
        if !only_this_machine && machines[i + 1..].contains(machine) {
            return Err(KitError::SameMachineTwice);
        }
    }
    Ok(())
}

/// For each machine holding a piece, this machine first, the pieces that survive its loss.
fn coverage(homes: &[PieceHome; 3]) -> KitCoverage {
    let mut machines: Vec<KitMachine> = homes.iter().filter_map(PieceHome::machine).collect();
    machines.sort_by_key(|machine| *machine != KitMachine::ThisMachine);
    for machine in machines {
        let away = homes
            .iter()
            .filter(|home| home.machine() != Some(machine))
            .count();
        if away < 2 {
            return KitCoverage::FewerThanTwoAway {
                machine,
                away: away as u8,
            };
        }
    }
    KitCoverage::SurvivesMachineLoss
}

/// The passphrase's Shamir point. The salt binds the vault, the kind and the kit id, so
/// every kit gets its own point and its own line.
fn passphrase_point(
    vault_id: &[u8; 32],
    kind: KitSecretKind,
    kit_id: KitId,
    cost: PassphraseCost,
    passphrase: &KitPassphrase,
) -> Result<Zeroizing<[u8; 32]>, KitError> {
    let mut salt = blake3::Hasher::new_derive_key(SALT_CONTEXT);
    salt.update(vault_id);
    salt.update(&[piece::kind_bit(kind)]);
    salt.update(&kit_id.0);
    oneiron_crypto::stretch_passphrase(&passphrase.0, &cost.argon2(), salt.finalize().as_bytes())
        .map_err(|_| KitError::PassphraseStretch)
}

/// The kit's self-check, shared by every piece: it binds the vault, the kind, the
/// passphrase point's place, the cost and the kit id to the secret.
fn tag(
    vault_id: &[u8; 32],
    kind: KitSecretKind,
    passphrase_x: u8,
    cost: Option<PassphraseCost>,
    kit_id: KitId,
    secret: &[u8; 32],
) -> Zeroizing<[u8; piece::TAG_LEN]> {
    let mut h = blake3::Hasher::new_derive_key(TAG_CONTEXT);
    h.update(vault_id);
    h.update(&[piece::header(kind, passphrase_x, 0), piece::cost_byte(cost)]);
    h.update(&kit_id.0);
    h.update(secret);
    let mut digest = h.finalize();
    let mut tag = Zeroizing::new([0; piece::TAG_LEN]);
    tag.copy_from_slice(&digest.as_bytes()[..piece::TAG_LEN]);
    // The hasher's block buffer still holds the secret's bytes. Scratch inside the
    // provider's own frames (its finalize block) is not reached: best effort.
    h.zeroize();
    digest.zeroize();
    tag
}

// GF(2^8), irreducible polynomial x^8+x^4+x^3+x+1. Fixed work per secret byte.
fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0;
    for _ in 0..8 {
        result ^= a & 0u8.wrapping_sub(b & 1);
        a = (a << 1) ^ (0x1b & 0u8.wrapping_sub(a >> 7));
        b >>= 1;
    }
    result
}
fn inverse(a: u8) -> u8 {
    let mut result = 1;
    let mut power = a;
    for bit in 0..8 {
        if 254 & (1 << bit) != 0 {
            result = multiply(result, power);
        }
        power = multiply(power, power);
    }
    result
}
