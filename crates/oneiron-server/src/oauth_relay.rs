//! ARCH-0028 host-trusted OAuth token-client verification half (ONE-1382 leg 1).
//! This module deliberately does not redesign the OAuth surface or add authority types.
use crate::auth::CoreAuth;
use crate::config::SyncServerConfig;
use crate::error::ApiError;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OAuthRelayClaims {
    pub sub: String,
    pub aud: String,
    pub scope: String,
    pub iss: String,
    pub exp: usize,
}

static JWKS_CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
fn cache() -> &'static Mutex<HashMap<String, String>> {
    JWKS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn unauthorized() -> Result<CoreAuth, ApiError> {
    Err(ApiError::unauthorized())
}

fn fetch_jwks(uri: &str, refresh: bool) -> Result<String, ApiError> {
    if refresh {
        cache()
            .lock()
            .map_err(|_| ApiError::unauthorized())?
            .remove(uri);
    }
    if let Some(v) = cache()
        .lock()
        .map_err(|_| ())
        .ok()
        .and_then(|c| c.get(uri).cloned())
    {
        return Ok(v);
    }
    let body = if let Some(path) = uri.strip_prefix("file://") {
        std::fs::read_to_string(path).map_err(|_| ApiError::unauthorized())?
    } else if let Some(rest) = uri.strip_prefix("http://") {
        let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
        let mut stream =
            std::net::TcpStream::connect(hostport).map_err(|_| ApiError::unauthorized())?;
        use std::io::{Read, Write};
        write!(
            stream,
            "GET /{} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, hostport
        )
        .map_err(|_| ApiError::unauthorized())?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|_| ApiError::unauthorized())?;
        let (_, body) = response
            .split_once("\r\n\r\n")
            .ok_or_else(ApiError::unauthorized)?;
        if !response.starts_with("HTTP/1.0 200") && !response.starts_with("HTTP/1.1 200") {
            return Err(ApiError::unauthorized());
        }
        body.to_owned()
    } else {
        return Err(ApiError::unauthorized());
    };
    let mut c = cache().lock().map_err(|_| ApiError::unauthorized())?;
    c.insert(uri.to_owned(), body.clone());
    Ok(body)
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
        cache()
            .lock()
            .unwrap()
            .insert(config.oauth_jwks_uri.clone().unwrap(), JWKS.into());
    }
    #[test]
    fn oauth_bound_read_accepted() {
        let config = config();
        cache_jwks(&config);
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
