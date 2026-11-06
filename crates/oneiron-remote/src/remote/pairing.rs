use oneiron::authority::{AuthorityCheckpointPin, CommReach};

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

/// The credential string for `slip_token` (`v2.slip.…`) bound to `key`, in
/// the form [`pair`] returns: a renewal hands its new slip back this way
/// with the seed the device already holds. `None` for a token that is not a
/// v2 slip.
pub(super) fn credential_string(slip_token: &str, key: &SigningKey) -> Option<String> {
    slip_token
        .strip_prefix("v2.slip.")
        .map(|slip| format!("{CREDENTIAL_PREFIX}{slip}.{}", lower_hex(key.as_bytes())))
}

/// Returns the public binding key from a credential retained by this app.
///
/// A bare bearer has no connection key and returns `None`. This only reads the
/// local key; it does not verify the slip or grant. Give the owner the returned
/// public key, never the credential itself.
pub fn paired_binding_key(credential: &str) -> Result<Option<[u8; 32]>, MemoryError> {
    let (_, key) = parse_credential(credential)?;
    Ok(key.map(|key| key.verifying_key().to_bytes()))
}

/// Keeps the app's existing connection key while adopting a separately issued slip.
///
/// This formats a credential; it neither issues nor verifies a slip or grant.
/// The caller must receive the new slip through its own channel. The server
/// still checks its signature, binding key, holder and current grant on use.
pub fn replace_paired_slip(credential: &str, slip_token: &str) -> Result<String, MemoryError> {
    let (_, key) = parse_credential(credential)?;
    let key = key.ok_or_else(|| {
        bad_request(
            "the key is not a paired credential",
            &["Pass the app's paired credential so its connection key is retained."],
        )
    })?;
    credential_string(slip_token, &key).ok_or_else(|| {
        bad_request(
            "the replacement is not a slip token",
            &["Pass the slip token issued for this app's binding key."],
        )
    })
}

/// The redeem route's success body.
#[derive(serde::Deserialize)]
struct Paired {
    token: String,
    /// The checkpoint pin the link kept, when the vault has an attested
    /// checkpoint (OF-469).
    #[serde(default)]
    pin: Option<AuthorityCheckpointPin>,
    /// The comm reach the paired credential carries, as the vault took it
    /// (FIX 5058): whom an agent paired by it may address.
    comm: CommReach,
}

/// An app-owned pairing key and signed request, separate from its transport.
///
/// Keep this value inside the pairing app. Its request body contains the one-use
/// link code; neither the value nor the body should be logged or published.
/// It stores no credential on disk and performs no HTTP request.
pub struct PreparedPairing {
    origin: String,
    base_url: Url,
    key: SigningKey,
    pin_ref: Option<oneiron::authority::PairingPinRef>,
    body: serde_json::Value,
}

impl PreparedPairing {
    pub fn new(link: &str) -> Result<Self, MemoryError> {
        Self::with_key(link, || SigningKey::generate(&mut rand_core::OsRng))
    }

    /// Prepares pairing with a connection key retained by this app.
    ///
    /// The seed is the app's private Ed25519 key, not a grant or a bearer token.
    /// The app owns its generation, storage and delivery to this process. Never
    /// place it in a published snapshot, browser state, logs or request body.
    /// The owner-delivered link and all ordinary redemption checks still apply.
    pub fn from_seed(link: &str, seed: [u8; 32]) -> Result<Self, MemoryError> {
        Self::with_key(link, || SigningKey::from_bytes(&seed))
    }

    fn with_key(link: &str, key: impl FnOnce() -> SigningKey) -> Result<Self, MemoryError> {
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
        let key = key();
        let binding_key = key.verifying_key().to_bytes();
        let transcript = oneiron::authority::pairing_binding_transcript_pinned(
            &code,
            &binding_key,
            &holder_ref,
            pin_ref.as_ref(),
        )
        .map_err(|_| malformed())?;
        let body = serde_json::json!({
            "code": code,
            "holder_ref": holder_ref,
            "binding_key": lower_hex(&binding_key),
            "signature": lower_hex(&key.sign(&transcript).to_bytes()),
        });
        Ok(Self {
            origin,
            base_url,
            key,
            pin_ref,
            body,
        })
    }

    /// The origin named by the owner-delivered link.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The app's public binding key, which an owner may name in an explicit grant slip.
    pub fn binding_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The signed JSON body for `POST /v1/core/pairing/redeem`.
    ///
    /// A native app may carry it through its existing Fetch relay. No bearer
    /// credential is needed: the one-use link and key possession are the proof.
    pub fn request_body(&self) -> &serde_json::Value {
        &self.body
    }

    /// Finishes a successful native redemption reply and returns the ordinary
    /// `(origin, credential, pin, comm)` result. The transport must handle any
    /// non-success HTTP response before calling this method. The credential
    /// contains this app's private connection key; keep it as one secret.
    pub fn finish(
        self,
        body: &[u8],
    ) -> Result<(String, String, Option<AuthorityCheckpointPin>, CommReach), MemoryError> {
        self.finish_with_status(StatusCode::OK, body)
    }

    fn finish_with_status(
        self,
        status: StatusCode,
        bytes: &[u8],
    ) -> Result<(String, String, Option<AuthorityCheckpointPin>, CommReach), MemoryError> {
        let Self {
            origin,
            base_url: _,
            key,
            pin_ref,
            body: _,
        } = self;
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
            paired.comm,
        ))
    }
}

/// Redeems a pairing link once and returns `(origin, credential, pin,
/// comm)`: the comm reach is the server's answer, never read back out of
/// the credential.
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
) -> Result<(String, String, Option<AuthorityCheckpointPin>, CommReach), MemoryError> {
    let prepared = PreparedPairing::new(link)?;
    let body = serialize_request(prepared.request_body())?;
    let url = prepared
        .base_url
        .join("v1/core/pairing/redeem")
        .map_err(|error| transport_error(format!("could not build the pairing URL: {error}")))?;
    let mut encoding = HeaderMap::new();
    let body = encode_request(body, &mut encoding);
    let response = blocking_agent()?
        .post(url)
        .headers(encoding)
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
    prepared.finish_with_status(status, &bytes)
}
