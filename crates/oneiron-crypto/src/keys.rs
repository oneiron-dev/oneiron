//! Key material types. Every secret zeroizes on drop and has a redacted `Debug`.

use core::fmt;

use ml_kem::array::Array;
use ml_kem::{DecapsulationKey1024, EncapsulationKey1024, KeyExport};
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

use crate::codec::check_len;
use crate::error::{Error, Result};

/// ML-KEM-1024 encapsulation key length (FIPS 203).
pub const MLKEM1024_ENCAPSULATION_KEY_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext length (FIPS 203).
pub const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;
/// Wire length of a [`HybridPublicKey`]: the ML-KEM-1024 encapsulation key, then the
/// X25519 public key.
pub const HYBRID_PUBLIC_KEY_LEN: usize = MLKEM1024_ENCAPSULATION_KEY_LEN + 32;

macro_rules! redacted_debug {
    ($ty:ty) => {
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(redacted)"))
            }
        }
    };
}

/// A 256-bit key-encryption key: a device key, a keystore secret, a passkey-derived
/// secret or a managed node key. How E1 obtains it is outside this crate.
pub struct Kek(Zeroizing<[u8; 32]>);
redacted_debug!(Kek);

impl Kek {
    /// Wraps existing key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Draws a fresh key from `rng`.
    pub fn generate<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        fill(rng, &mut *bytes)?;
        Ok(Self(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The 256-bit secret recovered from a Shamir share set. Combining the shares and
/// checking the threshold is E1's job; this crate only wraps under the result.
pub struct RecoverySecret(Zeroizing<[u8; 32]>);
redacted_debug!(RecoverySecret);

impl RecoverySecret {
    /// Wraps the recovered secret bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A user passphrase, 1..=1024 bytes. Strength policy belongs to the caller.
pub struct Passphrase(Zeroizing<Vec<u8>>);
redacted_debug!(Passphrase);

impl Passphrase {
    /// Upper bound on a passphrase in bytes.
    pub const MAX_LEN: usize = 1024;

    /// Copies the passphrase bytes; refuses empty or oversized input.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        check_len("passphrase", bytes.len(), 1, Self::MAX_LEN)?;
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

/// Argon2id cost parameters (RFC 9106), bounded on both sides so a hostile header
/// can neither weaken the KDF nor exhaust the opener's memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Cost {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u8,
}

impl Argon2Cost {
    /// RFC 9106 section 4, second recommended option: 64 MiB, 3 passes, 4 lanes.
    pub const RFC9106_SECOND: Argon2Cost = Argon2Cost {
        m_kib: 64 * 1024,
        t: 3,
        p: 4,
    };
    /// Lowest accepted memory: 19 MiB (the OWASP floor).
    pub const MIN_M_KIB: u32 = 19 * 1024;
    /// Highest accepted memory: 2 GiB (RFC 9106 first recommended option).
    pub const MAX_M_KIB: u32 = 2 * 1024 * 1024;
    pub const MIN_T: u32 = 1;
    pub const MAX_T: u32 = 64;
    pub const MIN_P: u8 = 1;
    pub const MAX_P: u8 = 16;

    pub(crate) fn check(&self) -> Result<()> {
        bound(
            "argon2id m_kib",
            self.m_kib.into(),
            Self::MIN_M_KIB.into(),
            Self::MAX_M_KIB.into(),
        )?;
        bound(
            "argon2id t",
            self.t.into(),
            Self::MIN_T.into(),
            Self::MAX_T.into(),
        )?;
        bound(
            "argon2id p",
            self.p.into(),
            Self::MIN_P.into(),
            Self::MAX_P.into(),
        )
    }
}

/// Fills `buf` from a fallible CSPRNG; a generator failure is [`Error::Rng`].
pub(crate) fn fill<R: TryCryptoRng + ?Sized>(rng: &mut R, buf: &mut [u8]) -> Result<()> {
    rng.try_fill_bytes(buf).map_err(|_| Error::Rng)
}

fn bound(param: &'static str, value: u64, min: u64, max: u64) -> Result<()> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(Error::KdfParamOutOfRange {
            param,
            value,
            min,
            max,
        })
    }
}

/// A recipient's public key for hybrid capsules: ML-KEM-1024 and X25519. It must come
/// from authenticated recipient metadata; this type only checks its encoding.
#[derive(Clone)]
pub struct HybridPublicKey {
    mlkem: EncapsulationKey1024,
    mlkem_bytes: Box<[u8; MLKEM1024_ENCAPSULATION_KEY_LEN]>,
    x25519: x25519_dalek::PublicKey,
}

impl fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridPublicKey(..)")
    }
}

impl PartialEq for HybridPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.mlkem_bytes == other.mlkem_bytes && self.x25519.as_bytes() == other.x25519.as_bytes()
    }
}

impl HybridPublicKey {
    /// Parses `ek_mlkem1024 || x25519_public` and runs the FIPS 203 encapsulation-key
    /// check.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_len(
            "hybrid public key",
            bytes.len(),
            HYBRID_PUBLIC_KEY_LEN,
            HYBRID_PUBLIC_KEY_LEN,
        )?;
        let (ek, x) = bytes.split_at(MLKEM1024_ENCAPSULATION_KEY_LEN);
        let ek_array = Array::try_from(ek).map_err(|_| Error::KemKeyRejected)?;
        let mlkem = EncapsulationKey1024::new(&ek_array).map_err(|_| Error::KemKeyRejected)?;
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(x);
        let mut mlkem_bytes = Box::new([0u8; MLKEM1024_ENCAPSULATION_KEY_LEN]);
        mlkem_bytes.copy_from_slice(ek);
        Ok(Self {
            mlkem,
            mlkem_bytes,
            x25519: x25519_dalek::PublicKey::from(x_bytes),
        })
    }

    /// The wire form, `ek_mlkem1024 || x25519_public`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_PUBLIC_KEY_LEN);
        out.extend_from_slice(&self.mlkem_bytes[..]);
        out.extend_from_slice(self.x25519.as_bytes());
        out
    }

    pub(crate) fn mlkem(&self) -> &EncapsulationKey1024 {
        &self.mlkem
    }

    pub(crate) fn mlkem_bytes(&self) -> &[u8; MLKEM1024_ENCAPSULATION_KEY_LEN] {
        &self.mlkem_bytes
    }

    pub(crate) fn x25519(&self) -> &x25519_dalek::PublicKey {
        &self.x25519
    }
}

/// A recipient's hybrid secret key. Both halves are kept as seeds (FIPS 203 seed
/// form for ML-KEM) and zeroize on drop.
pub struct HybridSecretKey {
    mlkem: DecapsulationKey1024,
    x25519: x25519_dalek::StaticSecret,
    public: HybridPublicKey,
}
redacted_debug!(HybridSecretKey);

impl HybridSecretKey {
    /// Draws fresh seeds from `rng`.
    pub fn generate<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut mlkem_seed = Zeroizing::new([0u8; 64]);
        let mut x25519 = Zeroizing::new([0u8; 32]);
        fill(rng, &mut *mlkem_seed)?;
        fill(rng, &mut *x25519)?;
        Ok(Self::from_seeds(&mlkem_seed, &x25519))
    }

    /// Rebuilds the key from its 64-byte ML-KEM seed (`d || z`) and X25519 secret.
    pub fn from_seeds(mlkem_seed: &[u8; 64], x25519_secret: &[u8; 32]) -> Self {
        let mlkem = DecapsulationKey1024::from_seed(Array::from(*mlkem_seed));
        let x25519 = x25519_dalek::StaticSecret::from(*x25519_secret);
        let ek = mlkem.encapsulation_key().to_bytes();
        let mut mlkem_bytes = Box::new([0u8; MLKEM1024_ENCAPSULATION_KEY_LEN]);
        mlkem_bytes.copy_from_slice(ek.as_slice());
        let public = HybridPublicKey {
            mlkem: mlkem.encapsulation_key().clone(),
            mlkem_bytes,
            x25519: x25519_dalek::PublicKey::from(&x25519),
        };
        Self {
            mlkem,
            x25519,
            public,
        }
    }

    /// The matching public key.
    pub fn public_key(&self) -> &HybridPublicKey {
        &self.public
    }

    pub(crate) fn mlkem(&self) -> &DecapsulationKey1024 {
        &self.mlkem
    }

    pub(crate) fn x25519(&self) -> &x25519_dalek::StaticSecret {
        &self.x25519
    }
}
