//! The operator's pins: the one trust root of the cloud registration client
//! (LC cloud #97 §1, §6; L14 lead call 08:3x). Trust in the issuer `I`, the
//! audience `A` and the RSA public keys comes from this file alone, never
//! from discovery, a JWKS download or a token. The same field reads it on a
//! self-hosted and a managed node (CALLS G7_TRUST_INPUT).
//!
//! The file is public JSON, read once when the server or the command
//! starts: `{"issuer": I, "audience": A, "keys": [jwk, ...]}`, each key an
//! RSA public key (`kty` RSA, `alg` RS256, `use` sig, a nonempty unique
//! `kid`, base64url `n` of at least 3072 bits and `e`), no private member.
//! A file absent, unreadable or invalid puts this feature alone in
//! `not_configured`, with the reason; serve, other auth and the anonymous
//! training window go on unchanged.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use jsonwebtoken::DecodingKey;

use super::wire::REGISTRATION_PATH;

/// The smallest RSA modulus a pinned key may have, in bytes (3072 bits).
const MIN_MODULUS_BYTES: usize = 384;

/// The JWK members a private key carries; a pin holding any is refused.
const PRIVATE_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "oth"];

/// The client's trust, as the operator pinned it.
#[derive(Clone, Debug)]
pub(crate) enum Trust {
    /// Valid pins: the feature runs on them.
    Pinned(Arc<Pins>),
    /// No usable pins: the feature alone is off, and why.
    NotConfigured(String),
}

impl Trust {
    /// Reads the pins file at `path`; `None` is no file named.
    pub(crate) fn load(path: Option<&Path>) -> Self {
        let Some(path) = path else {
            return Self::NotConfigured("no --cloud-registration-pins file is set".to_owned());
        };
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => {
                return Self::NotConfigured(format!(
                    "the pins file {} did not read: {}",
                    path.display(),
                    error.kind()
                ));
            }
        };
        match Pins::parse(&text) {
            Ok(pins) => Self::Pinned(Arc::new(pins)),
            Err(reason) => Self::NotConfigured(format!(
                "the pins file {} is invalid: {reason}",
                path.display()
            )),
        }
    }
}

/// Valid pins: the issuer's canonical origin, the audience, and each
/// trusted signing key by `kid`.
pub(crate) struct Pins {
    pub(crate) issuer: String,
    pub(crate) audience: String,
    /// `issuer`, parsed: the origin every discovered endpoint must share.
    pub(crate) issuer_url: reqwest::Url,
    keys: BTreeMap<String, DecodingKey>,
}

impl std::fmt::Debug for Pins {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pins")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("kids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Pins {
    /// The trusted key `kid` names; `None` for any other.
    pub(crate) fn key(&self, kid: &str) -> Option<&DecodingKey> {
        self.keys.get(kid)
    }

    fn parse(text: &str) -> Result<Self, String> {
        let file: serde_json::Value =
            serde_json::from_str(text).map_err(|_| "it is not JSON".to_owned())?;
        let object = file.as_object().ok_or("it is not one JSON object")?;
        let issuer = string(object, "issuer")?;
        let parsed = reqwest::Url::parse(issuer).map_err(|_| "the issuer is not a URL")?;
        if parsed.scheme() != "https" || parsed.origin().ascii_serialization() != issuer {
            return Err("the issuer is not a canonical https origin".to_owned());
        }
        let audience = string(object, "audience")?;
        if audience != format!("{issuer}{REGISTRATION_PATH}") {
            return Err(format!(
                "the audience is not the issuer + {REGISTRATION_PATH}"
            ));
        }
        let listed = object
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .filter(|keys| !keys.is_empty())
            .ok_or("it pins no key")?;
        let mut keys = BTreeMap::new();
        for jwk in listed {
            let (kid, key) = public_key(jwk)?;
            if keys.insert(kid, key).is_some() {
                return Err("two keys share one kid".to_owned());
            }
        }
        Ok(Self {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            issuer_url: parsed,
            keys,
        })
    }
}

fn string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a str, String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{key} is missing or not a string"))
}

/// One pinned JWK as a verifying key: public, RSA, RS256, for signing, its
/// modulus at least 3072 bits.
fn public_key(jwk: &serde_json::Value) -> Result<(String, DecodingKey), String> {
    let object = jwk.as_object().ok_or("a key is not a JSON object")?;
    if PRIVATE_MEMBERS
        .iter()
        .any(|member| object.contains_key(*member))
    {
        return Err("a key carries a private member".to_owned());
    }
    let kid = string(object, "kid")?;
    if kid.is_empty() {
        return Err("a key's kid is empty".to_owned());
    }
    for (member, expected) in [("kty", "RSA"), ("alg", "RS256"), ("use", "sig")] {
        if string(object, member)? != expected {
            return Err(format!("key {kid}: {member} is not {expected}"));
        }
    }
    let n = string(object, "n")?;
    let e = string(object, "e")?;
    let base64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let modulus = base64url
        .decode(n)
        .map_err(|_| format!("key {kid}: n is not base64url"))?;
    let significant = modulus.iter().skip_while(|byte| **byte == 0).count();
    if significant < MIN_MODULUS_BYTES {
        return Err(format!("key {kid}: its modulus is under 3072 bits"));
    }
    if !base64url
        .decode(e)
        .is_ok_and(|exponent| !exponent.is_empty())
    {
        return Err(format!("key {kid}: e is not base64url"));
    }
    let key = DecodingKey::from_rsa_components(n, e)
        .map_err(|_| format!("key {kid}: not an RSA public key"))?;
    Ok((kid.to_owned(), key))
}
