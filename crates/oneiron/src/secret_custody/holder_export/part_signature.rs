//! The holder's signature of each numbered part an export secret copy rides
//! in (FIX 12373; Engine 13:54 call A).
//!
//! The signed result names the whole copy's digest and length, never a
//! run's bytes, so a part that copies a genuine witness, count and sealing
//! second could carry any run beside them. The key that signs the result
//! signs each part as well, in the same commit, once the sealed bytes and
//! the second are fixed: over the vault, the request, the result's
//! canonical entry hash, the copy's digest and length, the sealing second,
//! the part count, the part's index, and its run's length and BLAKE3. Each
//! part then proves itself, without part zero or any sibling, by that
//! result's own signer under strict Ed25519, as a custody input's witness
//! parts do (FIX 8088). The runs signed are those of the frame with no
//! witness and no signatures (`KeptExportOutput::copy_frame`), cut as any
//! window carrier is, so no signature covers itself. A relay carries the
//! signatures as they came and never signs one.

#[cfg(feature = "sync")]
use ed25519_dalek::{Signature, VerifyingKey};
use ed25519_dalek::{Signer, SigningKey};

use crate::authority::{AuthorityEntryHash, AuthorityVaultId, SealedWorkOutput};
use crate::error::Result;
use crate::room_codec::carrier_parts::split_parts;

/// The domain every part signature's transcript starts with.
const PART_SIGN_DOMAIN: &[u8] = b"oneiron/export-secret-output-part-sig/v1\0";

/// What the signature of every part of one copy binds beside the part's
/// count, place and run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutputPartBinding {
    pub(crate) vault_id: AuthorityVaultId,
    pub(crate) request: AuthorityEntryHash,
    /// The canonical entry hash of the signed result that names the copy.
    pub(crate) result: AuthorityEntryHash,
    /// The copy as that result names it: its digest and length.
    pub(crate) output: SealedWorkOutput,
    /// The second the copy was sealed at.
    pub(crate) sealed_at: u64,
}

impl OutputPartBinding {
    /// What the signature of part `index` of `count` covers: the domain, the
    /// vault, the request, the result, the copy's digest and length, the
    /// sealing second, the count, the index, the run's length and the run's
    /// BLAKE3, `run_digest`.
    fn transcript(&self, count: u32, index: u32, run_len: u64, run_digest: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(PART_SIGN_DOMAIN.len() + 32 * 5 + 8 * 3 + 4 * 2);
        out.extend_from_slice(PART_SIGN_DOMAIN);
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&self.result);
        out.extend_from_slice(&self.output.digest);
        out.extend_from_slice(&self.output.bytes.to_be_bytes());
        out.extend_from_slice(&self.sealed_at.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(&index.to_be_bytes());
        out.extend_from_slice(&run_len.to_be_bytes());
        out.extend_from_slice(run_digest);
        out
    }

    /// Whether `signature` is `signer`'s, under strict Ed25519, over part
    /// `index` of `count` with bytes `run`: the part proves itself alone.
    #[cfg(feature = "sync")]
    pub(crate) fn verifies(
        &self,
        signer: &[u8; 32],
        count: u32,
        index: u32,
        run: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        VerifyingKey::from_bytes(signer).is_ok_and(|key| {
            key.verify_strict(
                &self.transcript(count, index, run.len() as u64, blake3::hash(run).as_bytes()),
                &Signature::from_bytes(signature),
            )
            .is_ok()
        })
    }
}

/// The signature, by `signing`, of each run `frame` is cut into, in order,
/// each bound to `binding`, the part count and its own place (FIX 12373).
/// `frame` is a copy's frame with no witness (`KeptExportOutput::copy_frame`),
/// cut as its relay cuts it (`carrier_parts::split_parts`). None for a
/// frame cut into more parts than a `u32` counts: such a copy stays with its
/// keepers.
///
/// # Errors
/// A frame longer than its cut's codec counts.
pub(super) fn sign_parts(
    binding: &OutputPartBinding,
    frame: &[u8],
    signing: &SigningKey,
) -> Result<Vec<[u8; 64]>> {
    let (parts, pieces) = split_parts(frame)?;
    let Ok(count) = u32::try_from(parts.parts.len()) else {
        return Ok(Vec::new());
    };
    Ok((0_u32..)
        .zip(parts.parts.iter().zip(&pieces))
        .map(|(index, (digest, (_, run)))| {
            signing
                .sign(&binding.transcript(count, index, run.len() as u64, digest))
                .to_bytes()
        })
        .collect())
}
