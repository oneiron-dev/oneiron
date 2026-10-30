//! The credential revocation notice (FIX 10381): content-free, per open
//! vault, bumped after each commit that revoked a capability slip. A stream
//! that judges its credential before each emission awaits it beside its own
//! changes, so an idle stream judges again at the revoke rather than at its
//! next change. Never persisted, and no deadline: a notice only says
//! "judge again".

use crate::Vault;

impl Vault {
    /// Changes after each commit that revoked a capability slip on this open
    /// vault. Subscribe before the first judgement; every change means "judge
    /// the credential again", never "this credential was revoked".
    #[must_use]
    pub fn subscribe_credential_revocations(&self) -> tokio::sync::watch::Receiver<u64> {
        self.store.credential_revocations.subscribe()
    }
}

impl crate::store::Store {
    /// Only post-commit callers signal; the value carries no credential.
    pub(crate) fn notify_credential_revocations(&self) {
        self.credential_revocations.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }
}
