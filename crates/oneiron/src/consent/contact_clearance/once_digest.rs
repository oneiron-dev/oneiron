use std::io::{self, Write};

use super::{ContactDisclosureProposal, ONCE_DIGEST_DOMAIN, invalid_offer};
use crate::Result;
use crate::consent::effect::EffectDigest;

pub(super) fn digest(
    proposal: &ContactDisclosureProposal,
    proposal_ref: &str,
) -> Result<EffectDigest> {
    let value = proposal.to_value()?;
    let mut payload_len = EncodedLength(0);
    rmpv::encode::write_value(&mut payload_len, &value).map_err(|_| invalid_offer())?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(ONCE_DIGEST_DOMAIN);
    hasher.update(&(proposal_ref.len() as u64).to_be_bytes());
    hasher.update(proposal_ref.as_bytes());
    hasher.update(&payload_len.0.to_be_bytes());
    rmpv::encode::write_value(&mut hasher, &value).map_err(|_| invalid_offer())?;
    Ok(EffectDigest::from_bytes(*hasher.finalize().as_bytes()))
}

struct EncodedLength(u64);

impl Write for EncodedLength {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
