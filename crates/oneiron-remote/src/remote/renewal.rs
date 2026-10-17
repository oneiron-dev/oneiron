//! FIX 3377: a paired owner device renews its own credential over the server
//! route `POST /v1/core/slips/renew`.
//!
//! A transport helper, not a verb: the route sits outside the facade nest,
//! as the checkpoint fetch does. One request carries the credential's slip,
//! a fresh holder proof signed with its connection key, and this install's
//! machine proof over that same token, timestamp and nonce, which the
//! device's own vault signs (`Vault::machine_connection_proof`). The server
//! answers with a new slip bound to the same key; this hands it back as a
//! `v2.cred.…` credential with the SAME seed. The old credential still works
//! until it runs out, so a caller keeps it until the replacement is stored.
//! Like the rest of this crate, it never reads either slip's claims.

use super::*;
use crate::OneironClient;

/// The renewal route, beside `/v1/core/slips/revoke`.
const RENEW_PATH: &str = "v1/core/slips/renew";

/// The renew route's success body.
#[derive(serde::Deserialize)]
struct Renewed {
    token: String,
}

/// The renewal round trip behind
/// [`OneironClient::renew_owner_device_credential`].
fn renew(
    origin: &str,
    credential: &str,
    device_vault: &oneiron::Vault,
    requested_secs: Option<u64>,
) -> Result<String, MemoryError> {
    if requested_secs == Some(0) {
        return Err(bad_request(
            "a renewal lifetime must be a positive number of seconds",
            &["Omit the lifetime to keep the credential's own."],
        ));
    }
    let not_paired = || {
        bad_request(
            "the key is not a paired credential",
            &["Pass the v2.cred credential this device was paired with, exactly as stored."],
        )
    };
    let (token, key) = parse_credential(credential)?;
    let key = key.ok_or_else(not_paired)?;
    let slip = CapabilitySlip::from_token(&token).map_err(|_| not_paired())?;
    let base_url = normalize_origin(origin)?;
    let unsigned = || transport_error("could not sign the renewal's holder proof");
    let timestamp = crate::unix_seconds_now();
    let proof = oneiron::authority::holder_proof(&slip, &key, timestamp).map_err(|_| unsigned())?;
    let nonce = proof
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(unsigned)?;
    let (machine, signature) = device_vault
        .machine_connection_proof(&token, timestamp, nonce)
        .map_err(|_| transport_error("could not sign this machine's proof"))?
        .ok_or_else(|| {
            forbidden(
                "this install is not a machine of the vault yet",
                &["Enrol this machine with its home first (`oneiron device enrol`)."],
            )
        })?;
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, bearer_header(&token)?);
    let mut binding = HeaderValue::from_str(&proof.to_string()).map_err(|_| unsigned())?;
    binding.set_sensitive(true);
    headers.insert(BINDING_HEADER, binding);
    headers.insert(
        oneiron::authority::MACHINE_PROOF_HEADER,
        HeaderValue::from_str(&oneiron::authority::machine_proof_header_value(
            machine, &signature,
        ))
        .map_err(|_| transport_error("could not name this machine"))?,
    );
    let body = match requested_secs {
        Some(secs) => serde_json::json!({ "lifetime_secs": secs }),
        None => serde_json::json!({}),
    };
    let body = encode_request(serialize_request(&body)?, &mut headers);
    accept_json(&mut headers);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let url = base_url
        .join(RENEW_PATH)
        .map_err(|error| transport_error(format!("could not build the renewal URL: {error}")))?;
    let response = blocking_agent()?
        .post(url)
        .headers(headers)
        .body(body)
        .send()
        .map_err(|error| transport_error(describe_send_failure(&error)))?;
    let status = response.status();
    if !status.is_success() {
        return Err(read_error_envelope(response, status));
    }
    let renewed: Renewed = read_json(response, status, "a credential renewal")?;
    // Parsed only as a v2 slip, as connect parses one; its claims stay unread.
    CapabilitySlip::from_token(&renewed.token)
        .ok()
        .and_then(|_| super::pairing::credential_string(&renewed.token, &key))
        .ok_or_else(|| transport_error(format!("the server answered {status} with no slip")))
}

impl OneironClient {
    /// Renews this device's paired owner credential at `origin` (FIX 3377)
    /// and returns the replacement `v2.cred.…`, bound to the SAME seed.
    ///
    /// `credential` is the device's current credential and `device_vault` is
    /// this install's own copy of the vault, whose machine key signs the
    /// request's machine proof. The server renews only a live, unattenuated
    /// owner slip whose own-device grant stands, for a machine the owner
    /// enrolled; the replacement lives no longer than the original's own
    /// lifetime, the vault's owner ceiling, or `requested_secs`. An expired
    /// or revoked credential refuses (pair again). The call is blocking: run
    /// it off an async loop. It stores nothing; the caller replaces its
    /// credential file and keeps the old one until that write lands.
    pub fn renew_owner_device_credential(
        origin: &str,
        credential: &str,
        device_vault: &oneiron::Vault,
        requested_secs: Option<u64>,
    ) -> Result<String, MemoryError> {
        renew(origin, credential, device_vault, requested_secs)
    }
}
