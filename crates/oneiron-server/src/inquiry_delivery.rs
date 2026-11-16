//! The company host's inquiry transport (INQUIRE-1 PR 5; Engine ruling
//! INQUIRE-SHAPE Q2 = A). One blocking HTTPS POST of the inquiry's wire
//! bytes to the member host's `INQUIRY_PEER_PATH`, under the guest slip the
//! member's vault minted for this host on its inquiry edge, with this
//! host's signature over the slip's binding transcript on each call (the
//! `x-oneiron-binding` holder proof every slip-bound call carries). The
//! reply is the answer's wire bytes.
//!
//! The same transport carries the member host's told statements (the
//! member's [Now], L7-03): one POST of the push's wire bytes to the company
//! host's `INQUIRY_PUSH_PEER_PATH`, under the guest slip the company's
//! vault minted for this host on its reciprocal grant, signed the same way.
//!
//! Blocking: call it off the async runtime, as every host door does.

use std::io::Read;
use std::time::Duration;

use oneiron::EntityId;
use oneiron::authority::{
    AuthorityVaultId, CapabilitySlip, HostSlipIssuer, holder_proof_challenge,
};
use oneiron::inquiry::{
    INQUIRY_PEER_PATH, INQUIRY_PUSH_PEER_PATH, InquiryPushTransport, InquiryTransport,
    InquiryTransportError,
};
use oneiron_base::unix_seconds_now;

/// How long one exchange may take before the member host counts as
/// unreachable. The member's vault answers at once (`pending` while the
/// member is asked), so this bounds a stopped or slow host only.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest answer the company host reads. It reads one byte past it
/// and no further, so a member host that sends more is refused before its
/// answer is held whole (review round 1 of #7603).
const MAX_ANSWER_BYTES: u64 = 64 * 1024;

/// An [`InquiryTransport`] and [`InquiryPushTransport`] over HTTP that
/// signs each call with `issuer`, the key the route's slip is bound to.
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

    /// One POST of `body` to `url` under `slip_token`, with this host's
    /// holder proof: the 2xx answer; a 4xx (but 408 and 429) is the host's
    /// refusal, anything else a failure to reach it.
    fn post_signed(
        &self,
        url: String,
        slip_token: &str,
        body: &[u8],
    ) -> Result<reqwest::blocking::Response, InquiryTransportError> {
        let slip = CapabilitySlip::from_token(slip_token)
            .map_err(|_| refused("the route's slip does not decode"))?;
        let binding = self.holder_proof(&slip, unix_seconds_now())?;
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
            .body(body.to_vec())
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
        Ok(response)
    }
}

fn refused(why: &str) -> InquiryTransportError {
    InquiryTransportError::Refused(why.to_owned())
}

/// The route `path` under `host`, an origin: HTTPS, or plain HTTP on
/// loopback only, with no credentials, query or fragment.
fn destination(host: &str, path: &str) -> Result<String, InquiryTransportError> {
    let url = format!("{}{path}", host.trim().trim_end_matches('/'));
    crate::feedback_delivery::check_endpoint(&url)
        .map_err(|_| refused("the route's host is not an https origin"))?;
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
        let url = destination(member_host, INQUIRY_PEER_PATH)?;
        let response = self.post_signed(url, slip_token, inquiry)?;
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

impl InquiryPushTransport for HttpInquiryTransport<'_> {
    fn push(
        &self,
        company_host: &str,
        _company_vault_id: &AuthorityVaultId,
        slip_token: &str,
        wire: &[u8],
    ) -> Result<(), InquiryTransportError> {
        // The slip names the company's vault itself; the company host
        // checks it was issued there. Its answer carries nothing to read.
        let url = destination(company_host, INQUIRY_PUSH_PEER_PATH)?;
        self.post_signed(url, slip_token, wire)?;
        Ok(())
    }
}
