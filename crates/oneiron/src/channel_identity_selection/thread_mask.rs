//! Selection-law projection of an email thread mask.
use super::ChannelIdentityThreadPin;
use crate::write_envelope::thread_claim::ThreadMask;

/// Converts a continuity mask into the selection law's borrowed thread context.
pub trait ThreadMaskSelectionExt {
    fn thread_pin(self, thread_ref: impl Into<String>) -> ChannelIdentityThreadPin;
}

impl ThreadMaskSelectionExt for ThreadMask {
    /// The selection-law pin this mask stands for ON `thread_ref`.
    ///
    /// The composer resolves a thread here first, then feeds the result to
    /// selection: build the pin from the mask and the CANONICAL thread ref
    /// this module returned ([`ThreadPassportResolution::canonical_thread_ref`]
    /// or [`Vault::canonical_thread_ref`]), set it as the `thread_pin` field of
    /// a [`ChannelIdentitySelectionQuery`] — which borrows it — and call
    /// [`resolve_channel_identity_selection`].
    ///
    /// Two deliberate omissions. The actor is continuity state that selection
    /// never sees. And a NON-canonical ref must not be pinned: selection
    /// honours the pin verbatim, so pinning a ref that has since been
    /// converged away would strand the reply on a dead thread.
    ///
    /// Not `const`: the upstream pin owns its `thread_ref` [`String`], which is
    /// not const-constructible.
    ///
    /// [`ChannelIdentitySelectionQuery`]: crate::channel_identity_selection::ChannelIdentitySelectionQuery
    /// [`resolve_channel_identity_selection`]: crate::channel_identity_selection::resolve_channel_identity_selection
    #[must_use]
    fn thread_pin(self, thread_ref: impl Into<String>) -> ChannelIdentityThreadPin {
        ChannelIdentityThreadPin {
            thread_ref: thread_ref.into(),
            identity_ref: self.identity_ref,
            facet_ref: self.facet_ref,
        }
    }
}
