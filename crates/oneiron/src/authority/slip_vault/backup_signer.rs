//! The managed host root's signature on a backup signer's delegation (FIX
//! 968): one root's vote toward the vault's external mode-root policy, made
//! under the delegation's own domain, so it is never a checkpoint statement
//! or a slip (`sign_checkpoint` is unchanged).

use ed25519_dalek::Signer;

use super::HostSlipIssuer;
use crate::authority::{AuthoritySignature, AuthoritySignatureSuite, BackupSignerStatement};
use crate::error::Result;

impl HostSlipIssuer {
    /// This host root's signature over `statement`'s transcript.
    ///
    /// # Errors
    ///
    /// The statement does not encode.
    pub fn sign_backup_signer_delegation(
        &self,
        statement: &BackupSignerStatement,
    ) -> Result<AuthoritySignature> {
        let transcript = statement.transcript()?;
        Ok(AuthoritySignature {
            suite: AuthoritySignatureSuite::Ed25519,
            public_key: self.public_key(),
            signature: self.signing.sign(&transcript).to_bytes().to_vec(),
        })
    }
}
