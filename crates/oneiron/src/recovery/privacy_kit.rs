//! Vault-scoped 2-of-3 offline recovery shares; no person-level master secret.
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8] = b"oneiron/backup-share/v1\0";
const COMMITMENT_DOMAIN: &[u8] = b"oneiron/privacy-backup-kit/v1";

/// The three independent places in a privacy-mode recovery kit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupShareLocation {
    Device,
    PhysicalMedia,
    Guardian,
}
impl BackupShareLocation {
    fn x(self) -> u8 {
        match self {
            Self::Device => 1,
            Self::PhysicalMedia => 2,
            Self::Guardian => 3,
        }
    }
    fn from_x(x: u8) -> Option<Self> {
        match x {
            1 => Some(Self::Device),
            2 => Some(Self::PhysicalMedia),
            3 => Some(Self::Guardian),
            _ => None,
        }
    }
}

/// One sensitive share. Debug never prints its material; drop scrubs it.
pub struct PrivacyBackupShare {
    vault_id: [u8; 32],
    kit_id: [u8; 16],
    location: BackupShareLocation,
    commitment: [u8; 32],
    payload: [u8; 32],
}
impl std::fmt::Debug for PrivacyBackupShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivacyBackupShare")
            .field("location", &self.location)
            .finish_non_exhaustive()
    }
}
impl Drop for PrivacyBackupShare {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}
impl PrivacyBackupShare {
    /// Destination, not an authority privilege.
    pub fn location(&self) -> BackupShareLocation {
        self.location
    }
    /// Public kit identifier; callers retain this independently of shares.
    pub fn kit_id(&self) -> [u8; 16] {
        self.kit_id
    }
    /// Explicit sensitive export for offline custody. Never stored as a claim.
    pub fn export(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAGIC.len() + 113));
        bytes.extend_from_slice(MAGIC);
        bytes.push(self.location.x());
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&self.kit_id);
        bytes.extend_from_slice(&self.commitment);
        bytes.extend_from_slice(&self.payload);
        bytes
    }
    /// Strict share import. Authenticity is established by reconstruction against the kit commitment.
    pub fn import(bytes: &[u8]) -> Result<Self, PrivacyBackupError> {
        if bytes.len() != MAGIC.len() + 113 || !bytes.starts_with(MAGIC) {
            return Err(PrivacyBackupError::InvalidShare);
        }
        let bytes = &bytes[MAGIC.len()..];
        let location =
            BackupShareLocation::from_x(bytes[0]).ok_or(PrivacyBackupError::InvalidShare)?;
        let vault_id = bytes[1..33]
            .try_into()
            .map_err(|_| PrivacyBackupError::InvalidShare)?;
        let kit_id = bytes[33..49]
            .try_into()
            .map_err(|_| PrivacyBackupError::InvalidShare)?;
        let commitment = bytes[49..81]
            .try_into()
            .map_err(|_| PrivacyBackupError::InvalidShare)?;
        let payload = bytes[81..113]
            .try_into()
            .map_err(|_| PrivacyBackupError::InvalidShare)?;
        if vault_id == [0; 32] || kit_id == [0; 16] {
            return Err(PrivacyBackupError::InvalidShare);
        }
        Ok(Self {
            vault_id,
            kit_id,
            location,
            commitment,
            payload,
        })
    }
}

/// No share, key, or entropy material appears in these errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PrivacyBackupError {
    /// A hosted-readable vault cannot present this as host-blind recovery.
    #[error("privacy backup requires owner-held keys")]
    PrivacyModeRequired,
    /// Entropy acquisition failed.
    #[error("backup entropy unavailable")]
    EntropyUnavailable,
    /// A single share, duplicates, mixed kits, corruption, or an invalid vault/key.
    #[error("two distinct authentic shares from this vault's kit are required")]
    InvalidShare,
}

/// Issues exactly three shares of one vault key. The owner chooses their offsite custody.
/// Co-locating the physical and guardian shares defeats the independent-custody protection.
/// This does not implement an unratified sealed-envelope VEK-rotation protocol.
pub fn issue_privacy_backup_kit(
    posture: &crate::config::VaultPrivacyConfig,
    vault_id: [u8; 32],
    vault_key: &[u8; 32],
) -> Result<[PrivacyBackupShare; 3], PrivacyBackupError> {
    if posture.validate().is_err() || posture.host_readable() {
        return Err(PrivacyBackupError::PrivacyModeRequired);
    }
    if vault_id == [0; 32] || vault_key == &[0; 32] {
        return Err(PrivacyBackupError::InvalidShare);
    }
    let mut slope = Zeroizing::new([0u8; 32]);
    let mut kit_id = [0; 16];
    OsRng
        .try_fill_bytes(&mut slope[..])
        .map_err(|_| PrivacyBackupError::EntropyUnavailable)?;
    OsRng
        .try_fill_bytes(&mut kit_id)
        .map_err(|_| PrivacyBackupError::EntropyUnavailable)?;
    if kit_id == [0; 16] {
        return Err(PrivacyBackupError::EntropyUnavailable);
    }
    let commitment = commitment(vault_id, kit_id, vault_key);
    Ok([
        BackupShareLocation::Device,
        BackupShareLocation::PhysicalMedia,
        BackupShareLocation::Guardian,
    ]
    .map(|location| {
        let payload = std::array::from_fn(|i| vault_key[i] ^ multiply(slope[i], location.x()));
        PrivacyBackupShare {
            vault_id,
            kit_id,
            location,
            commitment,
            payload,
        }
    }))
}

/// Reconstructed sensitive key. Debug and serialization never disclose it.
pub struct RestoredVaultKey(Zeroizing<[u8; 32]>);
impl std::fmt::Debug for RestoredVaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RestoredVaultKey(<redacted>)")
    }
}
impl RestoredVaultKey {
    /// Explicit access for the host's vault-key unlock operation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Reconstructs a vault key only from two or three distinct matching shares.
/// The expected vault and kit ids come from the owner's retained recovery metadata.
/// The result opens that vault's key custody; it confers no authority-log widening.
pub fn restore_privacy_backup_kit(
    vault_id: [u8; 32],
    kit_id: [u8; 16],
    shares: &[&PrivacyBackupShare],
) -> Result<RestoredVaultKey, PrivacyBackupError> {
    if !(2..=3).contains(&shares.len()) {
        return Err(PrivacyBackupError::InvalidShare);
    }
    let first = shares[0];
    let second = shares[1];
    let mut seen = 0u8;
    for share in shares {
        let bit = 1 << share.location.x();
        if seen & bit != 0
            || share.vault_id != vault_id
            || share.kit_id != kit_id
            || share.commitment != first.commitment
        {
            return Err(PrivacyBackupError::InvalidShare);
        }
        seen |= bit;
    }
    let inv = inverse(first.location.x() ^ second.location.x());
    let slope = Zeroizing::new(std::array::from_fn::<_, 32, _>(|i| {
        multiply(first.payload[i] ^ second.payload[i], inv)
    }));
    let key = Zeroizing::new(std::array::from_fn::<_, 32, _>(|i| {
        first.payload[i] ^ multiply(slope[i], first.location.x())
    }));
    if commitment(vault_id, kit_id, &key) != first.commitment {
        return Err(PrivacyBackupError::InvalidShare);
    }
    for share in shares {
        if (0..32).any(|i| share.payload[i] != key[i] ^ multiply(slope[i], share.location.x())) {
            return Err(PrivacyBackupError::InvalidShare);
        }
    }
    Ok(RestoredVaultKey(key))
}

fn commitment(vault_id: [u8; 32], kit_id: [u8; 16], secret: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(COMMITMENT_DOMAIN);
    h.update(&vault_id);
    h.update(&kit_id);
    h.update(secret);
    *h.finalize().as_bytes()
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_field_vector_restores_a_key() {
        // GF(256)/0x11b: secret 0x53, slope 0xca gives y(1)=0x99,
        // y(2)=0xdc, y(3)=0x16. This pins interoperability, not just self-roundtrip.
        let vault_id = [1; 32];
        let kit_id = [2; 16];
        let commitment = commitment(vault_id, kit_id, &[0x53; 32]);
        let first = PrivacyBackupShare {
            vault_id,
            kit_id,
            commitment,
            location: BackupShareLocation::Device,
            payload: [0x99; 32],
        };
        let second = PrivacyBackupShare {
            vault_id,
            kit_id,
            commitment,
            location: BackupShareLocation::PhysicalMedia,
            payload: [0xdc; 32],
        };
        let third = PrivacyBackupShare {
            vault_id,
            kit_id,
            commitment,
            location: BackupShareLocation::Guardian,
            payload: [0x16; 32],
        };
        assert_eq!(
            *restore_privacy_backup_kit(vault_id, kit_id, &[&first, &second, &third])
                .unwrap()
                .as_bytes(),
            [0x53; 32]
        );
    }
    #[test]
    fn any_two_shares_restore_only_their_vault_key() {
        let posture = crate::config::VaultPrivacyConfig::default();
        let secret = [0x73; 32];
        let hosted = crate::config::VaultPrivacyConfig {
            posture: crate::config::HostingPrivacyPosture::Hosted,
            data_key_custody: crate::config::VaultDataKeyCustody::HostManagedKms {
                key_ref: "host-key-ref".into(),
            },
        };
        assert!(matches!(
            issue_privacy_backup_kit(&hosted, [1; 32], &secret),
            Err(PrivacyBackupError::PrivacyModeRequired)
        ));
        let shares = issue_privacy_backup_kit(&posture, [1; 32], &secret).unwrap();
        let kit = shares[0].kit_id();
        for i in 0..3 {
            assert!(matches!(
                restore_privacy_backup_kit([1; 32], kit, &[&shares[i]]),
                Err(PrivacyBackupError::InvalidShare)
            ));
            for j in 0..3 {
                if i != j {
                    let restored =
                        restore_privacy_backup_kit([1; 32], kit, &[&shares[i], &shares[j]])
                            .unwrap();
                    assert_eq!(*restored.as_bytes(), secret);
                }
            }
        }
        let exported = shares[0].export();
        let imported = PrivacyBackupShare::import(&exported).unwrap();
        assert_eq!(
            *restore_privacy_backup_kit([1; 32], kit, &[&imported, &shares[2]])
                .unwrap()
                .as_bytes(),
            secret
        );
        assert!(restore_privacy_backup_kit([2; 32], kit, &[&shares[0], &shares[1]]).is_err());
        assert!(restore_privacy_backup_kit([1; 32], kit, &[&shares[0], &shares[0]]).is_err());
        let other = issue_privacy_backup_kit(&posture, [1; 32], &secret).unwrap();
        assert!(restore_privacy_backup_kit([1; 32], kit, &[&shares[0], &other[1]]).is_err());
        let mut corrupt = shares[1].export();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        let corrupt = PrivacyBackupShare::import(&corrupt).unwrap();
        assert!(restore_privacy_backup_kit([1; 32], kit, &[&shares[0], &corrupt]).is_err());
    }
}
