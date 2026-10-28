//! Every reference upload re-reads the bank (FIX 9517).
//! Entry: VoiceReferenceUploadGuard::admits_upload.
//!
//! A worker that renders from a banked identity's reference clip (an
//! own-server VoxCPM2 worker) is sent the clip with every render request. A
//! long text goes as several renders, so one call uploads the clip several
//! times. Before each actual upload the guard re-reads the reference from
//! the bank of the vault whose runtime built the worker, and compares its
//! owner, register and revision (the identity's incarnation, its refs and
//! the render consent) with the reference the call was admitted under; then
//! it asks the bank, without waiting, whether a withdrawal or a new decision
//! is committing. No store transaction is held across the upload. A
//! withdrawal or a replacement stops the uploads still to come, and the
//! renders already answered keep their usage and receipts.
//!
//! The guard is bound to one vault, the runtime's, once that vault is known
//! (`with_media_vault`); never a process-wide one. Unbound, it admits no
//! reference upload: a banked voice is a vault's.

use std::sync::{Arc, OnceLock};

use oneiron::Vault;
use oneiron::llm::ModelLocality;
use oneiron::voice_cascade::media::BankVoiceBinding;

/// The per-runtime guard every reference-rendering backend asks before an
/// upload. Clones share the one binding.
#[derive(Clone, Default)]
pub(in crate::models) struct VoiceReferenceUploadGuard {
    vault: Arc<OnceLock<Arc<Vault>>>,
}

/// The reference a call was admitted under, as its request carries it.
pub(in crate::models) struct AdmittedReference<'a> {
    pub(in crate::models) voice_id: &'a str,
    /// The identity's owner, entity hex.
    pub(in crate::models) owner: &'a str,
    pub(in crate::models) register: &'a str,
    /// [`BankVoiceBinding::reference_revision`] at admission.
    pub(in crate::models) revision: &'a str,
}

impl VoiceReferenceUploadGuard {
    /// Binds the guard to `vault`, the runtime's own. A runtime is bound to
    /// one vault: a second binding to another vault is refused, never a
    /// swap.
    pub(in crate::models) fn bind(&self, vault: Arc<Vault>) {
        if let Err(other) = self.vault.set(vault)
            && self
                .vault
                .get()
                .is_some_and(|bound| !Arc::ptr_eq(bound, &other))
        {
            tracing::error!("a media runtime's voice references stay bound to its first vault");
        }
    }

    /// The vault the guard is bound to, once it is: the runtime's own, into
    /// whose body directory a render's audio spools (FIX 6122).
    pub(in crate::models) fn vault(&self) -> Option<Arc<Vault>> {
        self.vault.get().cloned()
    }

    /// Whether `admitted` is still the bank's current reference for render
    /// target `target` at `locality`, now: the same owner, register and
    /// revision, with no withdrawal or new decision committing. Ask right
    /// before each upload; `false` stops it and every later one.
    pub(in crate::models) fn admits_upload(
        &self,
        target: &str,
        locality: ModelLocality,
        admitted: &AdmittedReference<'_>,
    ) -> bool {
        let Some(vault) = self.vault.get() else {
            return false;
        };
        let Ok((clip, fence)) = vault.fenced_voice_reference(
            admitted.voice_id,
            target,
            Some(admitted.register),
            locality,
        ) else {
            return false;
        };
        clip.register == admitted.register
            && fence.owner.to_hex() == admitted.owner
            && BankVoiceBinding::reference_revision(&fence) == admitted.revision
            && vault
                .voice_ref_fence_current_now(admitted.voice_id, target, &fence)
                .unwrap_or(false)
    }
}
