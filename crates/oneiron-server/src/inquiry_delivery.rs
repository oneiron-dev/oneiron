//! The company host's inquiry transport (INQUIRE-1 PR 5; Engine ruling
//! INQUIRE-SHAPE Q2 = A). One blocking HTTPS POST of the inquiry's wire
//! bytes to the member host's `INQUIRY_PEER_PATH`, under the guest slip the
//! member's vault minted for this host on its inquiry edge, with this
//! host's signature over the slip's binding transcript on each call (the
//! `x-oneiron-binding` holder proof every slip-bound call carries). The
//! reply is the answer's wire bytes.
//!
//! Blocking: call it off the async runtime, as every host door does.

use std::io::Read;
use std::time::Duration;

use oneiron::EntityId;
use oneiron::authority::{
    AuthorityVaultId, CapabilitySlip, HostSlipIssuer, holder_proof_challenge,
};
use oneiron::inquiry::{INQUIRY_PEER_PATH, InquiryTransport, InquiryTransportError};

/// How long one exchange may take before the member host counts as
/// unreachable. The member's vault answers at once (`pending` while the
/// member is asked), so this bounds a stopped or slow host only.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest answer the company host reads. It reads one byte past it
/// and no further, so a member host that sends more is refused before its
/// answer is held whole (review round 1 of #7603).
const MAX_ANSWER_BYTES: u64 = 64 * 1024;

/// An [`InquiryTransport`] over HTTP that signs each call with `issuer`,
/// the key the route's slip is bound to.
pub struct HttpInquiryTransport<'a> {
    issuer: &'a HostSlipIssuer,
}

impl<'a> HttpInquiryTransport<'a> {
    /// The transport that signs with this host's `issuer`.
    #[must_use]
    pub fn new(issuer: &'a HostSlipIssuer) -> Self {
        Self { issuer }
    }

    /// The `x-oneiron-binding` value for one call under `slip`, at `now`.
    fn holder_proof(
        &self,
        slip: &CapabilitySlip,
        now: u64,
    ) -> Result<String, InquiryTransportError> {
        let nonce = EntityId::now().to_hex();
        let signature = self
            .issuer
            .binding_proof(slip, &holder_proof_challenge(now, &nonce))
            .map_err(|_| refused("this host could not sign the route's slip"))?;
        let signature: String = signature.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(
            serde_json::json!({"timestamp": now, "nonce": nonce, "signature": signature})
                .to_string(),
        )
    }
}

fn refused(why: &str) -> InquiryTransportError {
    InquiryTransportError::Refused(why.to_owned())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The member host's inquiry route under `member_host`, an origin: HTTPS,
/// or plain HTTP on loopback only, with no credentials, query or fragment.
fn destination(member_host: &str) -> Result<String, InquiryTransportError> {
    let url = format!(
        "{}{INQUIRY_PEER_PATH}",
        member_host.trim().trim_end_matches('/')
    );
    crate::feedback_delivery::check_endpoint(&url)
        .map_err(|_| refused("the route's member host is not an https origin"))?;
    Ok(url)
}

impl InquiryTransport for HttpInquiryTransport<'_> {
    fn exchange(
        &self,
        member_host: &str,
        _member_vault_id: &AuthorityVaultId,
        slip_token: &str,
        inquiry: &[u8],
    ) -> Result<Vec<u8>, InquiryTransportError> {
        // The slip names the member's vault itself; the member host checks
        // it was issued there.
        let url = destination(member_host)?;
        let slip = CapabilitySlip::from_token(slip_token)
            .map_err(|_| refused("the route's slip does not decode"))?;
        let binding = self.holder_proof(&slip, unix_now())?;
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(EXCHANGE_TIMEOUT)
            .build()
            .map_err(|error| InquiryTransportError::Unreachable(error.to_string()))?;
        let response = client
            .post(url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {slip_token}"),
            )
            .header("x-oneiron-binding", binding)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::USER_AGENT, "oneiron-inquiry")
            .body(inquiry.to_vec())
            .send()
            .map_err(|error| {
                InquiryTransportError::Unreachable(if error.is_timeout() {
                    "timeout".to_owned()
                } else {
                    "network".to_owned()
                })
            })?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            return Err(
                if (400..500).contains(&status) && !matches!(status, 408 | 429) {
                    InquiryTransportError::Refused(format!("http {status}"))
                } else {
                    InquiryTransportError::Unreachable(format!("http {status}"))
                },
            );
        }
        let too_large = || refused("the member host's answer is too large");
        if response
            .content_length()
            .is_some_and(|length| length > MAX_ANSWER_BYTES)
        {
            return Err(too_large());
        }
        let mut body = Vec::new();
        response
            .take(MAX_ANSWER_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| InquiryTransportError::Unreachable("network".to_owned()))?;
        if u64::try_from(body.len()).is_ok_and(|length| length <= MAX_ANSWER_BYTES) {
            Ok(body)
        } else {
            Err(too_large())
        }
    }
}
