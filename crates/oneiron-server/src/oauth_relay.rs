//! ARCH-0028 host-trusted OAuth token-client verification half (ONE-1382 leg 1).
//! This module deliberately does not redesign the OAuth surface or add authority types.
#[cfg(test)]
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<OAuthAct>,
}

/// RFC 8693 actor claim. This verifier admits one actor, never act.act.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OAuthAct {
    pub sub: String,
    #[serde(flatten)]
    pub other: std::collections::BTreeMap<String, serde_json::Value>,
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

fn unauthorized<T>() -> Result<T, ApiError> {
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

/// One exchange binds the verified OAuth subject to the caller's throwaway
/// signing key. The raw JWT only reaches the pairing door, never data routes.
pub(crate) fn oauth_binding_transcript(
    token: &str,
    binding_key: &[u8; 32],
    nonce: &str,
) -> Result<Vec<u8>, ApiError> {
    if nonce.len() != 32 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::unauthorized());
    }
    let mut transcript = b"oneiron/oauth-slip-pair/v1".to_vec();
    transcript.extend_from_slice(blake3::hash(token.as_bytes()).as_bytes());
    transcript.extend_from_slice(binding_key);
    transcript.extend_from_slice(nonce.as_bytes());
    Ok(transcript)
}

/// Identity and ceiling from a verified OAuth JWT. This is bootstrap input,
/// never direct HTTP authority; the exchange mints a logged holder-bound slip.
pub(crate) struct OAuthRelayIdentity {
    pub(crate) subject: String,
    pub(crate) scopes: std::collections::BTreeSet<CoreScope>,
    pub(crate) expires_at: u64,
}

#[cfg(test)]
pub(crate) fn verify_oauth_relay_token(
    token: &str,
    config: &SyncServerConfig,
) -> Result<CoreAuth, ApiError> {
    let identity = verify_oauth_relay_identity(token, config)?;
    Ok(CoreAuth::from_oauth_relay(
        identity.subject,
        identity.scopes,
    ))
}

pub(crate) fn verify_oauth_relay_identity(
    token: &str,
    config: &SyncServerConfig,
) -> Result<OAuthRelayIdentity, ApiError> {
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
    // Only these host-trusted capabilities cross the relay leg. Write/auth
    // claims never become authority, even when a host token names them.
    let scopes = data
        .claims
        .scope
        .split_whitespace()
        .filter_map(|scope| match scope {
            "read" | "core:read" => Some(CoreScope::Read),
            "propose" | "core:propose" => Some(CoreScope::Propose),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    if scopes.is_empty() {
        return unauthorized();
    }
    let subject = match data.claims.act {
        Some(actor) => {
            // Presence rejects even act:null: a second actor slot is never
            // interpreted as a delegated authority chain.
            if actor.other.contains_key("act") || actor.sub.trim().is_empty() {
                return unauthorized();
            }
            actor.sub
        }
        None => data.claims.sub,
    };
    Ok(OAuthRelayIdentity {
        subject,
        scopes,
        expires_at: u64::try_from(data.claims.exp).map_err(|_| ApiError::unauthorized())?,
    })
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
        token_for_subject(iss, aud, scope, "relay-subject")
    }
    fn token_for_subject(iss: &str, aud: &str, scope: &str, subject: &str) -> String {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some("test-kid".into());
        encode(
            &h,
            &OAuthRelayClaims {
                act: None,
                sub: subject.into(),
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
    fn relay_propose_is_explicit_non_owner_and_never_widens() {
        let config = config();
        cache_jwks(&config);
        for scopes in ["propose", "read core:propose write core:auth"] {
            let auth = verify_oauth_relay_token(
                &token("https://issuer.example", "https://api.example", scopes),
                &config,
            )
            .unwrap();
            assert!(auth.require(CoreScope::Propose).is_ok());
            assert!(auth.require(CoreScope::Write).is_err());
            assert!(auth.require(CoreScope::Auth).is_err());
            assert!(!auth.is_owner_grade());
        }
        let auth = verify_oauth_relay_token(
            &token("https://issuer.example", "https://api.example", "read"),
            &config,
        )
        .unwrap();
        assert!(auth.require(CoreScope::Propose).is_err());
    }

    #[tokio::test]
    async fn signed_jwt_is_bootstrap_only_even_in_hosted_scope() {
        use axum::{
            body::{Body, to_bytes},
            http::{Request, StatusCode},
        };
        use ed25519_dalek::{Signer, SigningKey};
        use oneiron::authority::CapabilitySlip;
        use tower::ServiceExt;
        let mut cfg = config();
        cfg.lease_vault_id = 7;
        cache_jwks(&cfg);
        let dir = tempfile::tempdir().unwrap();
        let wall_start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let clock = oneiron::store::ports::ManualClock::new(wall_start);
        let mut vault_config = oneiron::VaultConfig::device();
        vault_config.store_clock = clock.bundle();
        let vault = Arc::new(oneiron::Vault::open(dir.path(), vault_config).unwrap());
        let subject = oneiron::EntityId::now();
        vault
            .put_entity(
                &subject,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"oauth actor",
            )
            .unwrap();
        let server = Arc::new(crate::server::SyncServer::new(vault, cfg).unwrap());
        let app = crate::api::api_routes(server.clone());
        // The recording clock can move ahead of the authority plane's
        // monotonic observation anchor. OAuth minting must use that anchor,
        // not the raw recording clock, or this exchange fails as "future".
        clock.set(wall_start + 120);
        assert!(server.vault().now_recorded_at() > server.vault().capability_slip_now().unwrap());
        let jwt = token_for_subject(
            "https://issuer.example",
            "https://api.example",
            "read propose write core:auth",
            &subject.to_hex(),
        );
        let header = format!("Bearer {jwt}");
        for path in ["/v1/core/conversations", "/api/core/discover"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header(AUTHORIZATION, &header)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
        // A signed login JWT only reaches this explicit exchange. The holder
        // proves its chosen throwaway key and receives a logged, capped slip.
        let holder = SigningKey::from_bytes(&[89; 32]);
        let key = holder.verifying_key().to_bytes();
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut issued = None;
        for _ in 0..2 {
            let nonce = oneiron::EntityId::now().to_hex();
            let transcript = oauth_binding_transcript(&jwt, &key, &nonce).unwrap();
            let payload = serde_json::json!({"binding_key":hex(&key), "nonce":nonce,
                "signature":hex(&holder.sign(&transcript).to_bytes())});
            let request = Request::builder()
                .method("POST")
                .uri("/v1/core/pairing/oauth")
                .header(AUTHORIZATION, &header)
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = to_bytes(response.into_body(), 100_000).await.unwrap();
            let paired: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            issued = Some(CapabilitySlip::from_token(paired["token"].as_str().unwrap()).unwrap());
        }
        let slip = issued.unwrap();
        assert_eq!(slip.claims.holder_ref, subject.to_hex());
        assert!(slip.claims.scope.verbs.contains(&"core:read".to_owned()));
        assert!(slip.claims.scope.verbs.contains(&"core:propose".to_owned()));
        assert!(!slip.claims.scope.verbs.contains(&"core:write".to_owned()));
        assert!(slip.claims.expires_at <= server.vault().now_recorded_at() + 3600);
        let token = slip.to_token().unwrap();
        let bearer = format!("Bearer {token}");
        let no_proof = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/core/conversations")
                    .header(AUTHORIZATION, &bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_proof.status(), StatusCode::UNAUTHORIZED);
        let timestamp = server.vault().capability_slip_now().unwrap();
        let request_nonce = oneiron::EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{request_nonce}");
        let signature = hex(&holder
            .sign(&slip.binding_transcript(challenge.as_bytes()).unwrap())
            .to_bytes());
        let proof =
            serde_json::json!({"timestamp":timestamp,"nonce":request_nonce,"signature":signature});
        let accepted = app
            .oneshot(
                Request::builder()
                    .uri("/v1/core/conversations")
                    .header(AUTHORIZATION, &bearer)
                    .header("x-oneiron-binding", proof.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
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
    #[test]
    fn signed_nested_actor_is_rejected_by_verifier() {
        let fixture = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(fixture.path(), JWKS).unwrap();
        let mut config = config();
        config.oauth_jwks_uri = Some(format!("file://{}", fixture.path().display()));
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".into());
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        for nested in [
            serde_json::json!({"sub":"nested-agent"}),
            serde_json::Value::Null,
        ] {
            let claims = serde_json::json!({"sub":"owner", "aud":"https://api.example", "scope":"read", "iss":"https://issuer.example", "exp":exp,
                "act":{"sub":"agent", "act":nested}});
            let token = encode(
                &header,
                &claims,
                &EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes()).unwrap(),
            )
            .unwrap();
            assert!(verify_oauth_relay_token(&token, &config).is_err());
        }
        let claims = serde_json::json!({"sub":"owner", "aud":"https://api.example", "scope":"read", "iss":"https://issuer.example", "exp":exp,"act":{"sub":"agent"}});
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        assert!(verify_oauth_relay_token(&token, &config).is_ok());
    }
}
