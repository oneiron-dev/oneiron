//! The access token, checked against the pins alone (LC cloud #97 §6, §7):
//! header exactly RS256 `at+jwt` with a pinned `kid` and no key of its own,
//! the signature under that pinned key, and the claims exactly the wire's,
//! issuer and audience the pinned ones. A valid signature says who issued
//! the token, never that the registration is live: only the audience's own
//! answer, matched field for field, is ([`matches_status`]).

use jsonwebtoken::{Algorithm, Validation};
use serde::Deserialize;

use super::pins::Pins;
use super::wire::{
    ACCESS_LIFETIME_SECS, CLIENT_ID, CLOCK_SKEW_SECS, Failure, RegistrationStatus, SCOPE,
};

/// The subject's form: `cp-owner:<account>:<owner revision>` (§6).
const SUBJECT_PREFIX: &str = "cp-owner:";

/// The claims, exactly the wire's (§6).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
    jti: String,
    client_id: String,
    scope: String,
}

/// What a verified access token says: its subject and lifetime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Verified {
    pub(crate) subject: String,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
}

fn off_wire(reason: &str) -> Failure {
    Failure::OffWire(reason.to_owned())
}

/// Checks `token` against `pins` at unix second `now`. The token must still
/// be usable: an expired one is never a verified one (CALLS
/// G7_LOCAL_CLOCK).
pub(crate) fn verify(pins: &Pins, token: &str, now: u64) -> Result<Verified, Failure> {
    let header = jsonwebtoken::decode_header(token)
        .map_err(|_| off_wire("the access token's header does not read"))?;
    let carries_key = header.jku.is_some()
        || header.jwk.is_some()
        || header.x5u.is_some()
        || header.x5c.is_some()
        || header.x5t.is_some()
        || header.x5t_s256.is_some()
        || header.cty.is_some();
    if header.alg != Algorithm::RS256 || header.typ.as_deref() != Some("at+jwt") || carries_key {
        return Err(off_wire("the access token's header is not RS256 at+jwt"));
    }
    let key = header
        .kid
        .as_deref()
        .and_then(|kid| pins.key(kid))
        .ok_or_else(|| off_wire("the access token is signed by a key the pins do not hold"))?;
    let mut validation = Validation::new(Algorithm::RS256);
    // Each claim is checked below, exactly; the library checks the
    // signature and the algorithm alone.
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<Claims>(token, key, &validation)
        .map_err(|_| off_wire("the access token's signature or claims do not verify"))?
        .claims;
    let lifetime = claims.exp.checked_sub(claims.iat);
    if claims.iss != pins.issuer
        || claims.aud != pins.audience
        || claims.client_id != CLIENT_ID
        || claims.scope != SCOPE
        || claims.jti.is_empty()
        || lifetime != Some(ACCESS_LIFETIME_SECS)
        || !subject_on_wire(&claims.sub)
    {
        return Err(off_wire("the access token's claims are not the wire's"));
    }
    if claims.iat > now.saturating_add(CLOCK_SKEW_SECS) || claims.exp <= now {
        return Err(off_wire("the access token is not usable now"));
    }
    Ok(Verified {
        subject: claims.sub,
        issued_at: claims.iat,
        expires_at: claims.exp,
    })
}

/// Whether the subject is `cp-owner:<account>:<revision>`, the account
/// nonempty and the revision decimal.
fn subject_on_wire(subject: &str) -> bool {
    subject
        .strip_prefix(SUBJECT_PREFIX)
        .and_then(|rest| rest.rsplit_once(':'))
        .is_some_and(|(account, revision)| {
            !account.is_empty()
                && !revision.is_empty()
                && revision.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// Whether the audience's answer `status` is the verified token's, field for
/// field: the only proof the registration is live now (§7).
pub(crate) fn matches_status(
    pins: &Pins,
    verified: &Verified,
    status: &RegistrationStatus,
) -> bool {
    status.iss == pins.issuer
        && status.sub == verified.subject
        && status.aud == pins.audience
        && status.scope == SCOPE
        && status.expires_at == verified.expires_at
}
