use oneiron::authority::AuthorityCheckpointPin;

use super::*;

/// What a paired client stores, in one string:
/// `v2.cred.{slip hex}.{seed hex}`.
///
/// `{slip hex}` is the slip token after `v2.slip.`; `{seed hex}` is the
/// connection key's 32-byte Ed25519 seed as 64 lowercase hex. A key that
/// starts `v2.cred.` and does not parse is refused without being echoed. Any
/// other key — the host secret, or a bare slip the server will refuse —
/// crosses as a bare bearer.
const CREDENTIAL_PREFIX: &str = "v2.cred.";

/// Splits a key into the bearer it sends and the connection key it signs with.
pub(crate) fn parse_credential(key: &str) -> Result<(String, Option<SigningKey>), MemoryError> {
    let Some(credential) = key.strip_prefix(CREDENTIAL_PREFIX) else {
        return Ok((key.to_owned(), None));
    };
    let (slip, seed) = credential
        .rsplit_once('.')
        .and_then(|(slip, seed)| Some((slip, seed_from_hex(seed)?)))
        .ok_or_else(|| {
            bad_request(
                "the key is not a paired credential",
                &["Pass the credential exactly as pair returned it, or pair again."],
            )
        })?;
    Ok((
        format!("v2.slip.{slip}"),
        Some(SigningKey::from_bytes(&seed)),
    ))
}

fn seed_from_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut seed = [0; 32];
    for (slot, pair) in seed.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(seed)
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The redeem route's success body.
#[derive(serde::Deserialize)]
struct Paired {
    token: String,
    /// The checkpoint pin the link kept, when the vault has an attested
    /// checkpoint (OF-469).
    #[serde(default)]
    pin: Option<AuthorityCheckpointPin>,
}

/// Redeems a pairing link once and returns `(origin, credential, pin)`.
///
/// A fresh connection key signs the link's code and holder, and the link's
/// checkpoint challenge and pin digest when it carries them; the request
/// carries no `Authorization` header, because the link is the enrollment. A
/// pin the server returns must be exactly the one the owner-delivered link
/// names, and a link that names one must get it back; any mismatch refuses
/// the pairing. It builds no handle and stores no pin: the caller connects
/// with what it returns.
pub(crate) fn pair(
    link: &str,
) -> Result<(String, String, Option<AuthorityCheckpointPin>), MemoryError> {
    use ed25519_dalek::Signer;
    // The link and its code are never echoed: the code is the enrollment grant
    // until it is spent.
    let malformed = || {
        bad_request(
            "the pairing link does not parse",
            &["Pass the one-line link the server owner created, exactly as printed."],
        )
    };
    let (origin, code, holder_ref, pin_ref) =
        oneiron::authority::parse_pinned_pairing_link(link).map_err(|_| malformed())?;
    let base_url = normalize_origin(&origin)?;
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let binding_key = key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &code,
        &binding_key,
        &holder_ref,
        pin_ref.as_ref(),
    )
    .map_err(|_| malformed())?;
    let body = serialize_request(&serde_json::json!({
        "code": code,
        "holder_ref": holder_ref,
        "binding_key": lower_hex(&binding_key),
        "signature": lower_hex(&key.sign(&transcript).to_bytes()),
    }))?;
    let url = base_url
        .join("v1/core/pairing/redeem")
        .map_err(|error| transport_error(format!("could not build the pairing URL: {error}")))?;
    let response = blocking_agent()?
        .post(url)
        .header(ACCEPT, HeaderValue::from_static("application/json"))
        .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
        .body(body)
        .send()
        .map_err(|error| transport_error(describe_send_failure(&error)))?;
    let status = response.status();
    if !status.is_success() {
        return Err(read_error_envelope(response, status));
    }
    let bytes = read_capped(response, MAX_REMOTE_RESPONSE_BYTES)
        .map_err(|_| transport_error("the server's pairing reply was truncated or oversized"))?;
    let paired = serde_json::from_slice::<Paired>(&bytes)
        .map_err(|_| transport_error(format!("the server answered {status} with no slip")))?;
    let slip = paired
        .token
        .strip_prefix("v2.slip.")
        .map(str::to_owned)
        .ok_or_else(|| transport_error(format!("the server answered {status} with no slip")))?;
    let pinned = match (&pin_ref, &paired.pin) {
        (None, None) => true,
        (Some(named), Some(pin)) => named.names(pin),
        _ => false,
    };
    if !pinned {
        return Err(transport_error(
            "the server's checkpoint pin is not the one the pairing link names; pair again with a link from the owner",
        ));
    }
    Ok((
        origin,
        format!("{CREDENTIAL_PREFIX}{slip}.{}", lower_hex(key.as_bytes())),
        paired.pin,
    ))
}
