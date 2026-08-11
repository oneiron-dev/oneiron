//! ARCH-0028 host-trusted OAuth token-client verification half (ONE-1382 leg 1).
//! This module deliberately does not redesign the OAuth surface or add authority types.
use crate::auth::CoreAuth;
use crate::config::SyncServerConfig;
use crate::error::ApiError;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[cfg(test)]
use std::collections::VecDeque;
#[cfg(test)]
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OAuthRelayClaims {
    pub sub: String,
    pub aud: String,
    pub scope: String,
    pub iss: String,
    pub exp: usize,
}

const MAX_JWKS_BYTES: usize = 1024 * 1024;
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

struct CachedJwks {
    body: String,
    last_kid_miss_refresh: Option<std::time::Instant>,
}

// Holding this short-lived lock across a bounded fetch coalesces concurrent
// refreshes. The transport timeout ensures a request worker cannot wait
// indefinitely, and importantly a failed refresh never evicts good material.
static JWKS_CACHE: OnceLock<Mutex<HashMap<String, CachedJwks>>> = OnceLock::new();
fn cache() -> &'static Mutex<HashMap<String, CachedJwks>> {
    JWKS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn unauthorized() -> Result<CoreAuth, ApiError> {
    Err(ApiError::unauthorized())
}

fn bounded_file(path: &str) -> Result<String, ApiError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|_| ApiError::unauthorized())?;
    let mut bytes = Vec::new();
    file.take((MAX_JWKS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ApiError::unauthorized())?;
    if bytes.len() > MAX_JWKS_BYTES {
        return Err(ApiError::unauthorized());
    }
    String::from_utf8(bytes).map_err(|_| ApiError::unauthorized())
}

fn transport_fetch(uri: &str) -> Result<String, ApiError> {
    use std::io::Read;

    #[cfg(test)]
    if let Some(transport) = test_transports()
        .lock()
        .map_err(|_| ApiError::unauthorized())?
        .get(uri)
        .cloned()
    {
        transport.fetches.fetch_add(1, Ordering::SeqCst);
        return transport
            .responses
            .lock()
            .map_err(|_| ApiError::unauthorized())?
            .pop_front()
            .unwrap_or(Err(()))
            .map_err(|_| ApiError::unauthorized());
    }
    if let Some(path) = uri.strip_prefix("file://") {
        return bounded_file(path);
    }
    if !uri.starts_with("https://") {
        return Err(ApiError::unauthorized());
    }
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(FETCH_TIMEOUT)
        .timeout(FETCH_TIMEOUT)
        .build()
        .map_err(|_| ApiError::unauthorized())?;
    let response = client
        .get(uri)
        .send()
        .map_err(|_| ApiError::unauthorized())?;
    if !response.status().is_success() {
        return Err(ApiError::unauthorized());
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_JWKS_BYTES as u64)
    {
        return Err(ApiError::unauthorized());
    }
    let mut bytes = Vec::new();
    response
        .take((MAX_JWKS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ApiError::unauthorized())?;
    if bytes.len() > MAX_JWKS_BYTES {
        return Err(ApiError::unauthorized());
    }
    String::from_utf8(bytes).map_err(|_| ApiError::unauthorized())
}

#[cfg(test)]
#[derive(Clone)]
struct TestTransport {
    responses: Arc<Mutex<VecDeque<Result<String, ()>>>>,
    fetches: Arc<AtomicUsize>,
}

#[cfg(test)]
static TEST_TRANSPORTS: OnceLock<Mutex<HashMap<String, TestTransport>>> = OnceLock::new();

#[cfg(test)]
fn test_transports() -> &'static Mutex<HashMap<String, TestTransport>> {
    TEST_TRANSPORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn fetch_jwks(uri: &str, refresh: bool) -> Result<String, ApiError> {
    let mut guard = cache().lock().map_err(|_| ApiError::unauthorized())?;
    let now = std::time::Instant::now();
    let mut last_kid_miss_refresh = None;
    if let Some(entry) = guard.get_mut(uri) {
        if !refresh {
            return Ok(entry.body.clone());
        }
        if entry
            .last_kid_miss_refresh
            .is_some_and(|last| now.duration_since(last) < REFRESH_INTERVAL)
        {
            return Ok(entry.body.clone());
        }
        // Record the attempt before fetching so failures are rate-limited too.
        // The cached body remains available if replacement fails.
        entry.last_kid_miss_refresh = Some(now);
        last_kid_miss_refresh = entry.last_kid_miss_refresh;
    }
    let body = match transport_fetch(uri) {
        Ok(body) => body,
        Err(error) => {
            if let Some(entry) = guard.get(uri) {
                return Ok(entry.body.clone());
            }
            return Err(error);
        }
    };
    // Validate before replacement so malformed 2xx responses cannot clobber
    // known-good material.
    if serde_json::from_str::<jsonwebtoken::jwk::JwkSet>(&body).is_err() {
        if let Some(entry) = guard.get(uri) {
            return Ok(entry.body.clone());
        }
        return Err(ApiError::unauthorized());
    }
    guard.insert(
        uri.to_owned(),
        CachedJwks {
            body: body.clone(),
            last_kid_miss_refresh,
        },
    );
    Ok(body)
}

/// Best-effort startup prefetch. Failures intentionally leave an empty or
/// previous cache so verification remains fail-closed without panicking config.
pub(crate) fn warm_if_configured(config: &SyncServerConfig) -> Result<(), ApiError> {
    if let (Some(_), Some(uri), Some(_)) = (
        config.oauth_issuer.as_deref(),
        config.oauth_jwks_uri.as_deref(),
        config.oauth_resource_indicator.as_deref(),
    ) {
        fetch_jwks(uri, false).map(|_| ())
    } else {
        Ok(())
    }
}

pub(crate) fn verify_oauth_relay_token(
    token: &str,
    config: &SyncServerConfig,
) -> Result<CoreAuth, ApiError> {
    let issuer = config
        .oauth_issuer
        .as_deref()
        .ok_or_else(ApiError::unauthorized)?;
    let jwks_uri = config
        .oauth_jwks_uri
        .as_deref()
        .ok_or_else(ApiError::unauthorized)?;
    let resource = config
        .oauth_resource_indicator
        .as_deref()
        .ok_or_else(ApiError::unauthorized)?;
    let header = decode_header(token).map_err(|_| ApiError::unauthorized())?;
    if header.alg != Algorithm::RS256 {
        return unauthorized();
    }
    let kid = header.kid.as_deref().ok_or_else(ApiError::unauthorized)?;
    let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_str(&fetch_jwks(jwks_uri, false)?)
        .map_err(|_| ApiError::unauthorized())?;
    let jwk = match jwks
        .keys
        .into_iter()
        .find(|k| k.common.key_id.as_deref() == Some(kid))
    {
        Some(jwk) => jwk,
        None => {
            // A rotated key may not be in the cache. Refresh once and fail closed.
            let refreshed: jsonwebtoken::jwk::JwkSet =
                serde_json::from_str(&fetch_jwks(jwks_uri, true)?)
                    .map_err(|_| ApiError::unauthorized())?;
            refreshed
                .keys
                .into_iter()
                .find(|k| k.common.key_id.as_deref() == Some(kid))
                .ok_or_else(ApiError::unauthorized)?
        }
    };
    let key = DecodingKey::from_jwk(&jwk).map_err(|_| ApiError::unauthorized())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[resource]);
    let data = decode::<OAuthRelayClaims>(token, &key, &validation)
        .map_err(|_| ApiError::unauthorized())?;
    if !data
        .claims
        .scope
        .split_whitespace()
        .any(|v| v == "read" || v == "core:read")
    {
        return unauthorized();
    }
    Ok(CoreAuth::from_oauth_relay(data.claims.sub))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{CoreScope, RevokedTokenJtis};
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use std::time::{SystemTime, UNIX_EPOCH};

    const PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0R8/v5DQ+6rA3MMr8xXI8fguIYaZY3WnKIrVbPLo54FjKwkf\nKSLfDERnySa1BnrvsmY2tn1ttSkwEEyJ75laoGt+296Xwy35PZ3vf+Zn5GVXAW/J\n5WKExqcAlZuLaVofxpeDE3g+hNlVxONP6jnYHCItI2c8GCnBRY6/7I5Dd/bK2dWq\nTTqL0bXPBJhGAA/pbHKYIjMbDYzG3qcCYonr8/eu/0LNwefnsxZ9FOkyYu3lNK1k\nh2xQcPXI8lvz4+2CWENWzeJcFBy/O2cWSBJdgL6Qa4BtzZkdvpItcr+FifYQirGY\nibxA7el554A1LefEHCWKzoFyLXS5w3POAOpEVQIDAQABAoIBADR7EiWCM2AlPxdo\nB5yOqApJjVIulEoImbWr+dnIsDiBGSEQvfg13yIV/LHXe/CvY34y9qIfoiuntX8x\npiAyLTM7JvAI0a9S10zmWNeRPBtub0JWCqX9bnLoMFZbXcZHrtfI6EU3lQEEBelO\nXpzafWi6DvfmjYdG21EYfQPhw/7TxRAWJR1ioBX4zetqhWebMQG4MTwR+i9phfTi\nAOOUVNPTi04w+ZZK/OOJwhkSxJPLFXxvP9C7RqhOPjcvh24dC+IFvAInGSD9ophz\ncIFu//gz7L7SzwkH3j4r3X5lr4FFJnHKyOMQ9DbNqnAtLVsogi48dPwkcjnnS/GA\n/BMdQRUCgYEA+/9PoA8pJHcmVSDoRPoNKntF8inMvtSOHuSHOV+xQ7gF6DlcEaUw\nJgYSVjblIbRTWn3OYy2aY9Eo9Bjt6DEw0Q3ICNYpMEcyx4GGimmbdffxpmuUklCR\n+JPCwQn1US9ZS90ykK1G+fRdgl5jlgP1yll3TQc5cIAq/p5DWIVJ6ZsCgYEA1HGY\nf0S/3bukWcZrDZ0bn//9RMsCMc0x8AWUqt4v3MOav+m2XJ2mieXRpgmBylGfbMpA\n++dCVGtM6LAvqqO1lE68pYX8tDJLHcAaRzaOKwWOh53GQRGtNJt0G6M/8Nk9f5m5\nk4OVZju/SA564ECISHI+3oal58Vj6fvhaPuJIM8CgYEA6FRdDw6rOel4N+gc/Osl\nFFOPC1MqZ44Eccr0ORtWjT6ug4nOrp4DpCrY4Q+/dLGSX825aIr02q5N+a66OOaR\nQUxZbnw0gURDNtjeN+Jh6ANukaaB1dvemLVySxNpTy4+P8lyAx0eYPjA9Z8cZYTF\nKYgOi7/rXyNrgFBdetF4cZ0CgYAsaOK8GB8TtxoQOk4+tk0EEXtcWiPHTWHXDxOY\n9IGE4M8Et1KL4djiksxUrUAYjx+Imm8jOaDADP4y1kHgpgBbVGpTH8NH2Auj2Hil\n0l292JeG+hBrocpXaPfIn0PKkV8twXDtyV/90xeVdJFzN4pFurwxwGwGG1lbnG/u\nhkaQOQKBgBZkm4iY9qNn7i00L/r/5mnI+toXjK/BLUNLZdu9uhQkT2jjgofbVJtZ\ng+sTQQA8zt5tNdcbOFYYxKbg5FjjY00Gi3A0hwlcVnWFVgu0gkJQtntFtIdQbOEo\njm4BArW2htTCGHj8onDlxF/aSoNNNOsLcHYD2UohROeH1L7xijLT\n-----END RSA PRIVATE KEY-----\n";
    const JWKS: &str = r#"{"keys":[{"kty":"RSA","kid":"test-kid","n":"0R8_v5DQ-6rA3MMr8xXI8fguIYaZY3WnKIrVbPLo54FjKwkfKSLfDERnySa1BnrvsmY2tn1ttSkwEEyJ75laoGt-296Xwy35PZ3vf-Zn5GVXAW_J5WKExqcAlZuLaVofxpeDE3g-hNlVxONP6jnYHCItI2c8GCnBRY6_7I5Dd_bK2dWqTTqL0bXPBJhGAA_pbHKYIjMbDYzG3qcCYonr8_eu_0LNwefnsxZ9FOkyYu3lNK1kh2xQcPXI8lvz4-2CWENWzeJcFBy_O2cWSBJdgL6Qa4BtzZkdvpItcr-FifYQirGYibxA7el554A1LefEHCWKzoFyLXS5w3POAOpEVQ","e":"AQAB","alg":"RS256","use":"sig"}]}"#;
    struct NoRevocations;
    impl RevokedTokenJtis for NoRevocations {
        fn is_revoked(&self, _: &str) -> Result<bool, ()> {
            Ok(false)
        }
    }
    fn config() -> SyncServerConfig {
        SyncServerConfig {
            oauth_issuer: Some("https://issuer.example".into()),
            oauth_jwks_uri: Some("https://issuer.example/jwks".into()),
            oauth_resource_indicator: Some("https://api.example".into()),
            auth_secret: Some("root".into()),
            ..Default::default()
        }
    }
    fn token(iss: &str, aud: &str, scope: &str) -> String {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some("test-kid".into());
        encode(
            &h,
            &OAuthRelayClaims {
                sub: "relay-subject".into(),
                aud: aud.into(),
                scope: scope.into(),
                iss: iss.into(),
                exp: (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600) as usize,
            },
            &EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap()
    }
    fn cache_jwks(config: &SyncServerConfig) {
        cache().lock().unwrap().insert(
            config.oauth_jwks_uri.clone().unwrap(),
            CachedJwks {
                body: JWKS.into(),
                last_kid_miss_refresh: None,
            },
        );
    }
    #[test]
    fn oauth_bound_read_accepted() {
        let fixture = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(fixture.path(), JWKS).unwrap();
        let mut config = config();
        config.oauth_jwks_uri = Some(format!("file://{}", fixture.path().display()));
        let auth = verify_oauth_relay_token(
            &token("https://issuer.example", "https://api.example", "read"),
            &config,
        )
        .unwrap();
        assert_eq!(auth.principal(), "oauth-relay:relay-subject");
        assert!(auth.has_scope(CoreScope::Read));
        assert!(auth.require(CoreScope::Write).is_err());
        assert!(!auth.is_owner_grade());
    }
    #[test]
    fn config_absent_inert() {
        let headers = {
            let mut h = HeaderMap::new();
            h.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!(
                    "Bearer {}",
                    token("https://issuer.example", "https://api.example", "read")
                ))
                .unwrap(),
            );
            h
        };
        assert!(
            CoreAuth::from_headers(
                &headers,
                &SyncServerConfig {
                    auth_secret: Some("root".into()),
                    ..Default::default()
                },
                &NoRevocations
            )
            .is_err()
        );
    }
    #[test]
    fn warm_failure_leaves_verification_fail_closed() {
        let mut config = config();
        config.oauth_jwks_uri = Some("file:///definitely-missing-oneiron-jwks.json".into());
        assert!(warm_if_configured(&config).is_err());
        assert!(
            verify_oauth_relay_token(
                &token("https://issuer.example", "https://api.example", "read"),
                &config,
            )
            .is_err()
        );
    }

    #[test]
    fn kid_miss_refresh_keeps_good_cached_jwks() {
        let fixture = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(fixture.path(), JWKS).unwrap();
        let uri = format!("file://{}", fixture.path().display());
        assert_eq!(fetch_jwks(&uri, false).unwrap(), JWKS);
        assert_eq!(fetch_jwks(&uri, true).unwrap(), JWKS);
        let entry = cache().lock().unwrap();
        let cached = entry.get(&uri).unwrap();
        assert_eq!(cached.body, JWKS);
        assert!(cached.last_kid_miss_refresh.is_some());
        std::fs::remove_file(fixture.path()).unwrap();
    }

    #[test]
    fn kid_miss_refresh_is_limited_across_sequential_and_concurrent_attempts() {
        let uri = format!("test://counter-{}", std::process::id());
        let fetches = Arc::new(AtomicUsize::new(0));
        test_transports().lock().unwrap().insert(
            uri.clone(),
            TestTransport {
                responses: Arc::new(Mutex::new(VecDeque::from([
                    Ok(JWKS.to_owned()),
                    Ok(JWKS.to_owned()),
                ]))),
                fetches: fetches.clone(),
            },
        );
        assert_eq!(fetch_jwks(&uri, false).unwrap(), JWKS);
        assert_eq!(fetch_jwks(&uri, true).unwrap(), JWKS);
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let uri = uri.clone();
                std::thread::spawn(move || fetch_jwks(&uri, true).unwrap())
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), JWKS);
        }
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        test_transports().lock().unwrap().remove(&uri);
    }

    #[test]
    fn malformed_refresh_preserves_good_cache_and_rate_limits_attempt() {
        let uri = format!("test://malformed-{}", std::process::id());
        let fetches = Arc::new(AtomicUsize::new(0));
        test_transports().lock().unwrap().insert(
            uri.clone(),
            TestTransport {
                responses: Arc::new(Mutex::new(VecDeque::from([
                    Ok(JWKS.to_owned()),
                    Ok("not-json".to_owned()),
                ]))),
                fetches: fetches.clone(),
            },
        );
        assert_eq!(fetch_jwks(&uri, false).unwrap(), JWKS);
        assert_eq!(fetch_jwks(&uri, true).unwrap(), JWKS);
        assert_eq!(fetch_jwks(&uri, true).unwrap(), JWKS);
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        test_transports().lock().unwrap().remove(&uri);
    }

    #[test]
    fn relay_failure_terminal() {
        let config = config();
        cache_jwks(&config);
        for bad in [
            token("wrong", "https://api.example", "read"),
            token("https://issuer.example", "wrong", "read"),
            token("https://issuer.example", "https://api.example", "write"),
        ] {
            assert!(verify_oauth_relay_token(&bad, &config).is_err());
        }
    }
}
