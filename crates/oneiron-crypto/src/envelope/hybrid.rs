//! The `kem-x25519-mlkem1024-v1` capsule: ML-KEM-1024 (FIPS 203) and X25519
//! (RFC 7748) combined with the UniversalCombiner of draft-irtf-cfrg-hybrid-kems-12
//! (section 5.1.3), instantiated with SHA3-256 over the nominal-group framework:
//!
//! `W = SHA3-256(ss_M || ss_X || ct_M || ct_X || ek_M || pk_X || LABEL)`
//!
//! Every input has a fixed length. `W` is then the wrap secret of the envelope key
//! schedule, whose HKDF info carries the full header (recipient, vault id, purpose,
//! both suites, epoch, both encapsulations). The sender is anonymous (as in HPKE base
//! mode); origin authentication comes only from a signature record.

use ml_kem::array::Array;
use ml_kem::{Decapsulate, ml_kem_1024};
use rand_core::TryCryptoRng;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::keys::{HybridPublicKey, HybridSecretKey, MLKEM1024_CIPHERTEXT_LEN, fill};

const LABEL: &[u8] = b"oneiron-crypto/kem-x25519-mlkem1024-v1";

pub(super) struct Encapsulation {
    pub(super) x25519_ephemeral: [u8; 32],
    pub(super) mlkem_ciphertext: Box<[u8; MLKEM1024_CIPHERTEXT_LEN]>,
    pub(super) secret: Zeroizing<[u8; 32]>,
}

/// Sender side. Refuses a recipient X25519 key that yields a non-contributory result.
pub(super) fn encapsulate<R: TryCryptoRng + ?Sized>(
    recipient: &HybridPublicKey,
    rng: &mut R,
) -> Result<Encapsulation> {
    let mut m = Zeroizing::new([0u8; 32]);
    let mut ephemeral = Zeroizing::new([0u8; 32]);
    fill(rng, &mut *m)?;
    fill(rng, &mut *ephemeral)?;

    // FIPS 203 ML-KEM.Encaps: `m` drawn above from the caller's CSPRNG, exactly as the
    // crate's own `encapsulate_with_rng` does, so an RNG failure stays an error.
    let (ct_m, mut ss_m) = recipient
        .mlkem()
        .encapsulate_deterministic(&Array::from(*m));
    let ephemeral = x25519_dalek::StaticSecret::from(*ephemeral);
    let ct_x = x25519_dalek::PublicKey::from(&ephemeral).to_bytes();
    let ss_x = ephemeral.diffie_hellman(recipient.x25519());
    if !ss_x.was_contributory() {
        ss_m.as_mut_slice().zeroize();
        return Err(Error::KemKeyRejected);
    }
    let mut mlkem_ciphertext = Box::new([0u8; MLKEM1024_CIPHERTEXT_LEN]);
    mlkem_ciphertext.copy_from_slice(ct_m.as_slice());
    let secret = combine(&ss_m, ss_x.as_bytes(), &mlkem_ciphertext, &ct_x, recipient);
    ss_m.as_mut_slice().zeroize();
    Ok(Encapsulation {
        x25519_ephemeral: ct_x,
        mlkem_ciphertext,
        secret,
    })
}

/// Recipient side. The public keys bound into the combiner come from the recipient's
/// own key, never from the wire. ML-KEM decapsulation rejects implicitly, so a
/// tampered ciphertext only shows up as a failed AEAD open.
pub(super) fn decapsulate(
    key: &HybridSecretKey,
    x25519_ephemeral: &[u8; 32],
    mlkem_ciphertext: &[u8; MLKEM1024_CIPHERTEXT_LEN],
) -> Result<Zeroizing<[u8; 32]>> {
    let ct_m =
        ml_kem_1024::Ciphertext::try_from(&mlkem_ciphertext[..]).map_err(|_| Error::OpenFailed)?;
    let mut ss_m = key.mlkem().decapsulate(&ct_m);
    let ss_x = key
        .x25519()
        .diffie_hellman(&x25519_dalek::PublicKey::from(*x25519_ephemeral));
    if !ss_x.was_contributory() {
        ss_m.as_mut_slice().zeroize();
        return Err(Error::OpenFailed);
    }
    let secret = combine(
        &ss_m,
        ss_x.as_bytes(),
        mlkem_ciphertext,
        x25519_ephemeral,
        key.public_key(),
    );
    ss_m.as_mut_slice().zeroize();
    Ok(secret)
}

fn combine(
    ss_m: &[u8],
    ss_x: &[u8; 32],
    ct_m: &[u8; MLKEM1024_CIPHERTEXT_LEN],
    ct_x: &[u8; 32],
    recipient: &HybridPublicKey,
) -> Zeroizing<[u8; 32]> {
    let mut hash = Sha3_256::new();
    hash.update(ss_m);
    hash.update(ss_x);
    hash.update(ct_m);
    hash.update(ct_x);
    hash.update(recipient.mlkem_bytes());
    hash.update(recipient.x25519().as_bytes());
    hash.update(LABEL);
    let mut digest = hash.finalize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(digest.as_slice());
    digest.as_mut_slice().zeroize();
    out
}

#[cfg(test)]
mod tests;
