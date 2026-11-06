//! Successful shared invitation acceptance on the SDK's verified HTTPS wire.

use ed25519_dalek::SigningKey;
use oneiron::memory::MemoryError;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::SharedInvitationAcceptedWithCredential;
use oneiron::verbs::SharedInvitationAcceptWithCredentialRequest;
use reqwest::Url;

use super::wire::Wire;
use super::{RemoteClient, bearer_header, slip_holder};
use crate::{Backend, OneironClient};

const ACCEPT_WITH_CREDENTIAL: &str = "vault.members.accept_with_credential";

/// An actual successful acceptance response from the intended HTTPS home.
///
/// This value cannot be decoded or assembled from a receipt or token. It keeps
/// the exact request, recipient key and returned credential with the verified
/// call that produced them. It does not verify an authority history, import a
/// window, or establish that the returned grant is still live.
pub struct HttpsSharedInvitationAcceptance {
    base_url: Url,
    acceptance_url: Url,
    request: SharedInvitationAcceptWithCredentialRequest,
    invocation: InvocationId,
    reply: SharedInvitationAcceptedWithCredential,
    holder_key: SigningKey,
    wire: Wire,
}

impl std::fmt::Debug for HttpsSharedInvitationAcceptance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsSharedInvitationAcceptance")
            .field("home_url", &self.base_url.as_str())
            .field("vault_id", &self.request.vault_id)
            .finish_non_exhaustive()
    }
}

impl HttpsSharedInvitationAcceptance {
    /// The normalized home selected before the acceptance request.
    pub fn home_url(&self) -> &str {
        self.base_url.as_str()
    }

    /// The exact facade URL the acceptance request used; redirects are disabled.
    pub fn acceptance_url(&self) -> &str {
        self.acceptance_url.as_str()
    }

    /// The selected shared vault, invitation and requested credential expiry.
    pub fn request(&self) -> &SharedInvitationAcceptWithCredentialRequest {
        &self.request
    }

    /// The logical invocation used for this acceptance.
    pub fn invocation(&self) -> &InvocationId {
        &self.invocation
    }

    /// The recipient key that signed the acceptance request.
    pub fn recipient_binding_key(&self) -> [u8; 32] {
        self.holder_key.verifying_key().to_bytes()
    }

    /// The complete successful response, including the actual native token.
    ///
    /// The native producer minted it in the same admitted selected-vault
    /// writer as the acceptance. Reading its claims is not authority to import
    /// content: native history, grant, scope and window checks still apply.
    pub fn reply(&self) -> &SharedInvitationAcceptedWithCredential {
        &self.reply
    }

    /// A facade client for the accepted member, on the same home and HTTP wire.
    ///
    /// This only changes the credential to the returned member token, with the
    /// same recipient key. The home admits each call normally. It neither
    /// opens a local vault nor grants access to the owner's full sync socket.
    /// A malformed returned credential cannot hide the successful acceptance:
    /// its complete reply remains available on this value if this call fails.
    pub fn member_client(&self) -> Result<OneironClient, MemoryError> {
        let bearer = &self.reply.credential.slip;
        Ok(OneironClient {
            backend: Backend::Remote(RemoteClient {
                base_url: self.base_url.clone(),
                authorization: bearer_header(bearer)?,
                holder: slip_holder(bearer, Some(self.holder_key.clone()))?,
                wire: self.wire.clone(),
                room_turn: None,
                off_record_session: None,
                last_receipt_ref: std::sync::Mutex::new(None),
            }),
            host_root: None,
        })
    }
}

impl OneironClient {
    /// Accepts an invitation and keeps the successful call's HTTPS provenance.
    ///
    /// Use the existing ordinary acceptance method for cleartext loopback or
    /// in-process calls: neither can construct this HTTPS-only value. All
    /// transport and holder checks here happen before the acceptance runs.
    /// The returned value retains the receipt even if a later member-client
    /// construction or native bootstrap fails.
    pub fn accept_shared_invitation_https(
        &self,
        request: SharedInvitationAcceptWithCredentialRequest,
    ) -> Result<HttpsSharedInvitationAcceptance, MemoryError> {
        self.accept_shared_invitation_https_as(request, crate::invocation::mint())
    }

    /// Retries this HTTPS acceptance under the invocation a pending ask names.
    ///
    /// As with the ordinary SDK retry, the same request and recipient
    /// credential must be used. Refusals other than PENDING_ASK do not run an
    /// acceptance. A generic decoded retry response cannot construct this value.
    pub fn retry_shared_invitation_https(
        &self,
        pending: &MemoryError,
        request: SharedInvitationAcceptWithCredentialRequest,
    ) -> Result<HttpsSharedInvitationAcceptance, MemoryError> {
        let invocation = crate::pending_invocation(pending)
            .and_then(InvocationId::parse_hex)
            .ok_or_else(|| {
                crate::error::bad_request(
                    "only a pending acceptance's invocation can be retried",
                    &["Use accept_shared_invitation_https for a new acceptance."],
                )
            })?;
        self.accept_shared_invitation_https_as(request, invocation)
    }

    fn accept_shared_invitation_https_as(
        &self,
        request: SharedInvitationAcceptWithCredentialRequest,
        invocation: InvocationId,
    ) -> Result<HttpsSharedInvitationAcceptance, MemoryError> {
        let remote = match &self.backend {
            Backend::Remote(remote)
                if matches!(&remote.wire, Wire::Http { .. })
                    && remote.base_url.scheme() == "https" =>
            {
                remote
            }
            _ => {
                return Err(crate::error::forbidden(
                    "HTTPS acceptance provenance requires a connected HTTPS home",
                    &["Use ordinary invitation acceptance for a loopback or in-process home."],
                ));
            }
        };
        let holder_key = remote
            .holder
            .as_deref()
            .map(|(_, key)| key.clone())
            .ok_or_else(|| {
                crate::error::forbidden(
                    "invitation acceptance requires the recipient's holder key",
                    &["Connect with the invitee's invitation credential."],
                )
            })?;
        let acceptance_url = remote.verb_url(ACCEPT_WITH_CREDENTIAL)?;
        let reply = remote.call_as(ACCEPT_WITH_CREDENTIAL, &request, invocation)?;
        Ok(HttpsSharedInvitationAcceptance {
            base_url: remote.base_url.clone(),
            acceptance_url,
            request,
            invocation,
            reply,
            holder_key,
            wire: remote.wire.clone(),
        })
    }
}
