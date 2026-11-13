//! `POST /v1/hooks/gmail/push` (census L2-17 PR 3; ARCH-0063 #mail-import:
//! "New mail arrives live through Gmail push (watch plus `history.list`),
//! with a periodic reconcile behind it"; ruling PUSH-TRANSPORT = A): the
//! owner's Pub/Sub push subscription delivers Gmail's notices to a keyless
//! hook, and Google's OIDC token on each delivery is its authentication.
//!
//! The served app is the one `serve` mounts, in process. Google's key set is
//! a file beside the vault (`file://`; the server reads no `http://` key
//! set), holding one of the two RSA keys below. The tests sign their own
//! tokens with it, and forge one with the other. On a base with no
//! `[gmail_push]` section the file does not compile.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --test gmail_push_hook` (public paths only: no cfg flag, no test feature).
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use engine_stack::run_on_engine_stack;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use oneiron::{Vault, VaultConfig};
use oneiron_server::config::{
    EnvConfig, GOOGLE_OIDC_JWKS_URI, GmailPushConfig, ServeArgs, SyncServerConfig,
    resolve_serve_config_with_sources,
};
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const HOOK: &str = "/v1/hooks/gmail/push";
const TOPIC: &str = "projects/owner-project/topics/gmail";
const AUDIENCE: &str = "https://vault.example.com/v1/hooks/gmail/push";
const SERVICE_ACCOUNT: &str = "gmail-push@owner-project.iam.gserviceaccount.com";
const MAILBOX: &str = "owen@example.com";
/// The key id the key set publishes [`GOOGLE_KEY`] under.
const KID: &str = "google-push-1";

/// The push subscription's signing key, published in the key set as [`KID`].
const GOOGLE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAzgX4tlAFNI1VxwBE8WZRe4YUiM53qm3p7M3LPuSsjRY838M0\nMxqAWMGGyD8b+6rQ/HHrQCeVN34/CnFwQyXwzgdjCVyq135Gdf1NWlKDDuwKhU3O\nzPvTCcBFccsq6M5Ua5ZU205RyM4NESawo4NIkddnfRVF94mxTgufp+ZWsUdbB0ll\nUGz0kqS5KkKGfY+BU6erP7P+y/O6hWtRZCQ1Qum2hfKuUPmuCmy2hYQnH8Ka6VSr\nl0am/zy2JuX6SSqv3Xn8q1ivHr/rLX73rxi34nFmHhYt9xU7VHGL/vYAG92094uw\nOaOwWttSn9PmUmR5R/103nNOUv0kyZb2UqmabwIDAQABAoIBAFoLUxo/nB7NXP2m\nePt26EsQHX5zmuqisnhcs6Wv5VierQlxdCmXvhvMrZ9sscrLbB7BnXvDMRz5cQ0b\n6mB2vyoVIWxwk3yuxJYCGSJOaNiHQsvjZ2zA7YpX/iIPlZf9wfjp0fmt3+HfaOej\nnNVCZl/ToPgS6asYg6VkQCnuatp81yVM2RTsF8S1nXjcFHU3aHyRyXlto/87lBO7\nChL5wPmrsA9995UYQE4OWN3tyIk5Iw9Uu4ZhOqUFIfJ4x8mN26nqpRKV6+y64ysG\nUl4Z7crKCMnkPhW/V/QsKw+FziCmdYJeG2ZrbTZxUo7AtZ8liKEF6JTJcbGdXRZi\nQEiApzUCgYEA/brHWZr30uUT4AkPNj7PaD5caEB47LriWcv0QL27qmaCecg8hNWE\nSrcXHPWfPpW9ekssTcmEsMbJQXYEXJ/x+jI0D7a77PAz1R+jF6jH7cft/4wVrPFe\nhg3HfzAdKpiXUuuZfl1MFfwEGj6V1dC597Q6HnyT48Vyd3rpT9cEuJ0CgYEAz93p\nWIz3AADgmZSD93igRjxDaOYY+9lrC2eeiyRmte+JcqHfA7UiKKlrKF3jRMYMAbin\nlVzID7eDJ54sVcviVzF2OUU4I/uotZIUZqebcMWRnEtFSpR0VjZv7XwnhuiEhOwS\n9iiEhqRnstuqUg4adW9mkfdx/Zv4gMrJB1qSU3sCgYEAlOFfDfX/itD+C4xlT6gl\nXX6SDF4gVpAGNziUttRd5MvHrZvP3wXGXWz3c/ewHDIS/0pS0cX4RR4vg2izgIId\no3iH0dyggpQjZd/te/l+bsjMnxFcuqDanQBC2h+qTY9B49b4twwZlCDPa3LjypVy\nOaWYIMFqqdD2rKMDeeSqEYUCgYEAsTfes7Iq+4PD+OwXvqrG6lqCljJmZoGss6J6\nFuLH9qDsLCE5g22wW75lL5ssIfw/TFBkAAGER3ILjYFbByK2K+RtiNIs1PC/m12Z\nqxOGgJTQWdIKl1UOAlqS/oP1Jx2hrbmfSOKuaiRMjL6e7So9AJYjepreQnvxV8yL\nq4taaXUCgYEAjrZyzAeQTJh1UouLg9k+xGbTpSwvI5Bp2/C4Pz8+9QD1f60HI6kh\njPpoyikVI4y5GOF4IgrBm0Warsd3MxsEInAPYpOy4IgLYzUcSNbCHtTp+6uYHmAZ\n4HnslKNX9iQOxibFq46/yhnWFisqMTNLlzrnxB5SZdK1CzASNm4s1kg=\n-----END RSA PRIVATE KEY-----";
/// The modulus of [`GOOGLE_KEY`], base64url.
const GOOGLE_KEY_N: &str = "zgX4tlAFNI1VxwBE8WZRe4YUiM53qm3p7M3LPuSsjRY838M0MxqAWMGGyD8b-6rQ_HHrQCeVN34_CnFwQyXwzgdjCVyq135Gdf1NWlKDDuwKhU3OzPvTCcBFccsq6M5Ua5ZU205RyM4NESawo4NIkddnfRVF94mxTgufp-ZWsUdbB0llUGz0kqS5KkKGfY-BU6erP7P-y_O6hWtRZCQ1Qum2hfKuUPmuCmy2hYQnH8Ka6VSrl0am_zy2JuX6SSqv3Xn8q1ivHr_rLX73rxi34nFmHhYt9xU7VHGL_vYAG92094uwOaOwWttSn9PmUmR5R_103nNOUv0kyZb2Uqmabw";
/// A key the key set does not hold.
const OTHER_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA0XdaI9Pdn2P+Z7bsa9RetVFfyGdN2mcSTnC/q807Y62Q/2Sb\nEETKqsIDTF9TIpSdjKe4tEUZij+Ri85CH6uZQIC/eEbR3QlPFn3mXN2VdkjaWjEe\ni6OsVerqu7grpgfY2Q0O34NeXBLKdQPldamFtc4hglBG7cAb9hYR46MZPklS/Ngl\nQdYd9a1kbGYTE0D/BUcS1Wfdj1YBnQfcVxEiiesb5mO+rBhCTPBxsCFpKdWHYR6N\nHOf8RE0stpE4SGXVtkOBiR+qRyZtNM0Oye4bYm/ArYsKVKOZgIXKPSR8dWwILvzI\n8pq9yfocjdu58h8qjJf6nivlSfojUv4rl/lxpQIDAQABAoIBAC+asqF0V8iO6uVK\nyRHbhrep+fz7X1HsvVgW3zSuFJp7ennUdTo+DBpBNAsyGdyAzoqGHp/XmW2WM1+E\n3XnBn7dtWzZ8T9sub6syqz09PafPeFJpmeHN7Y9sL3NAsKjP3Tw8772j5zjBK4Jr\nA4XZZFI0eeCaGniTgbdMfj3QFh9VlJ8P4BsMtilfs7eMNMM8QA40v5Bp/AUILHa4\nXNdmKciWbwRZGJUMinw+5iz5xBEzns24gAVKrKWN1WBTpp/ZpWxCRvc/Nel4pzQg\nXngDwv4SNLDoNjRhpc28YEIjCSpUErUIyoEzb8IvbHfptg3mIgDPSmEXlo6KHAYv\nTtL2fwECgYEA+t8Kw9NxkfUNuge4qkt/D/PaXJLEEhcPX2ZnPOzhjk4xZvuIH+U0\nYF17ww8YvkQFklfLo3iiSZACzz+qody/g6Nx9NryyCies+O+O2jtFebmj6mx/Z4d\n9cegue+9CyDBQZlIk3QVfGgqeSYXtf7Bbup8+73cAo7T9Pk0mZV6nwECgYEA1b+c\n6qW4IcwbzIYm6u6TeXPR3/w80ta9wzzDHh56RjWGhP9GbTnmhkw6qWFbs4fmJ7nh\neRqEVxfrjuO/Hu9WmURl0iUFnFITTI5GhFe23CypayAL0hRQdzzhpLXmrdjfMrHH\nwmv4uD8twrULHifqLS1VtdfB4sEwFIVch9Em9qUCgYAmzMhFcTZndJci5n7RF8wX\nE4f6OVjJ03c1MglViu13rPBHFTAAftqS7OJvUK5q/uo9sAZ2yfmPlw5YL2ickB+u\npGDDlflmq6GgAOEzHw9MC+Is5fn5V7MaiD17hHCgf/hjxOlMpO+Nxi6LfjC8nSId\nnXanGL4mRyDRCpnwBwZoAQKBgH0jENrO6l3fAOdcIqynv+76v4RCR9mnnrEOgazA\naxVvgLGcQb7whuVY+37uYKFajoPzbu1XeOMEPgQJkXqq5CgWwwWkZwR9iI7pPJ9+\nOq/r9cOhn0n+Wp10JyYm2EYvEXy8WBaa36H+WuwC0d91vsN0JxmulvQJ5fwdl25s\nJEOBAoGATPXvqJEMItY1OOqKFSPsbdyriyL0UdK8O8lcV4JFDv3lmgDczKYSf8Ip\nBpMPHv7/YOPeD0VY4RUajP17FQWdTPlrGVfEQTfzNpm+j+qwvOuVlljW0X//v9fo\n9+Y7ON4bau8x5m+rFZ3V9Q0xR5W7IVZczQk8MZsBNFsaxPSy37I=\n-----END RSA PRIVATE KEY-----";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

/// The claims of a push subscription's token, as Google issues them.
fn google_claims() -> Value {
    json!({
        "iss": "https://accounts.google.com",
        "aud": AUDIENCE,
        "azp": "104857600000000000000",
        "sub": "104857600000000000000",
        "email": SERVICE_ACCOUNT,
        "email_verified": true,
        "iat": now(),
        "exp": now() + 3_600,
    })
}

/// [`google_claims`] with `change` made.
fn claims_with(change: impl FnOnce(&mut Value)) -> Value {
    let mut claims = google_claims();
    change(&mut claims);
    claims
}

/// `claims` signed RS256 with the PEM `key`, under the key id [`KID`].
fn signed(key: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(key.as_bytes()).expect("test RSA key"),
    )
    .expect("sign token")
}

/// A Pub/Sub push delivery of Gmail's notice for `address` at `history_id`.
fn delivery(address: &str, history_id: Value) -> String {
    let notice = json!({ "emailAddress": address, "historyId": history_id });
    json!({
        "message": {
            "data": base64::engine::general_purpose::STANDARD.encode(notice.to_string()),
            "messageId": "2070443601311540",
            "publishTime": "2026-11-14T00:00:00.000Z",
        },
        "subscription": "projects/owner-project/subscriptions/gmail-push",
    })
    .to_string()
}

/// A served vault, its host setting `[gmail_push]` when `push`, with
/// Google's key set kept as a file.
struct Hook {
    _vault_dir: tempfile::TempDir,
    _keys_dir: tempfile::TempDir,
    server: Arc<SyncServer>,
}

impl Hook {
    fn serve(push: bool) -> Self {
        let keys_dir = tempfile::tempdir().expect("key set directory");
        let jwks = keys_dir.path().join("jwks.json");
        let keys = json!({ "keys": [{
            "kty": "RSA",
            "kid": KID,
            "alg": "RS256",
            "use": "sig",
            "n": GOOGLE_KEY_N,
            "e": "AQAB",
        }]});
        std::fs::write(&jwks, keys.to_string()).expect("write key set");
        let vault_dir = tempfile::tempdir().expect("vault directory");
        let vault =
            Arc::new(Vault::open(vault_dir.path(), VaultConfig::device()).expect("open vault"));
        let gmail_push = push.then(|| GmailPushConfig {
            topic: TOPIC.to_owned(),
            audience: AUDIENCE.to_owned(),
            service_account: SERVICE_ACCOUNT.to_owned(),
            jwks_uri: format!("file://{}", jwks.display()),
        });
        let server = SyncServer::new(
            vault,
            SyncServerConfig {
                auth_secret: Some("gmail-push-hook".into()),
                gmail_push,
                ..Default::default()
            },
        )
        .expect("create server");
        Self {
            _vault_dir: vault_dir,
            _keys_dir: keys_dir,
            server: Arc::new(server),
        }
    }

    /// One delivery of `body` to the hook, with `token` as its bearer.
    async fn deliver(&self, token: Option<&str>, body: &str) -> StatusCode {
        let mut request = Request::builder()
            .method("POST")
            .uri(HOOK)
            .header(header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        build_app(Arc::clone(&self.server))
            .oneshot(request.body(Body::from(body.to_owned())).expect("request"))
            .await
            .expect("serve request")
            .status()
    }
}

#[test]
fn a_delivery_without_the_subscriptions_google_token_is_refused() {
    run_on_engine_stack("gmail-push-refused", || async {
        let hook = Hook::serve(true);
        let notice = delivery(MAILBOX, json!("4200"));
        let refused = [
            ("no token", None),
            ("not a token", Some("not-a-token".to_owned())),
            (
                "signed by a key outside Google's set",
                Some(signed(OTHER_KEY, &google_claims())),
            ),
            (
                "for another audience",
                Some(signed(
                    GOOGLE_KEY,
                    &claims_with(|claims| claims["aud"] = json!("https://elsewhere.example")),
                )),
            ),
            (
                "for another service account",
                Some(signed(
                    GOOGLE_KEY,
                    &claims_with(|claims| {
                        claims["email"] = json!("someone@owner-project.iam.gserviceaccount.com");
                    }),
                )),
            ),
            (
                "with an unverified email",
                Some(signed(
                    GOOGLE_KEY,
                    &claims_with(|claims| claims["email_verified"] = json!(false)),
                )),
            ),
            (
                "from another issuer",
                Some(signed(
                    GOOGLE_KEY,
                    &claims_with(|claims| claims["iss"] = json!("https://issuer.example")),
                )),
            ),
            (
                "expired",
                Some(signed(
                    GOOGLE_KEY,
                    &claims_with(|claims| {
                        claims["iat"] = json!(now() - 7_200);
                        claims["exp"] = json!(now() - 3_600);
                    }),
                )),
            ),
        ];
        for (case, token) in refused {
            assert_eq!(
                hook.deliver(token.as_deref(), &notice).await,
                StatusCode::UNAUTHORIZED,
                "a delivery {case} is refused"
            );
        }
    });
}

#[test]
fn a_signed_delivery_is_acknowledged_whatever_it_names() {
    run_on_engine_stack("gmail-push-acknowledged", || async {
        let hook = Hook::serve(true);
        let token = signed(GOOGLE_KEY, &google_claims());
        assert_eq!(
            hook.deliver(Some(&token), &delivery(MAILBOX, json!("4200")))
                .await,
            StatusCode::NO_CONTENT,
            "a notice for a mailbox this vault does not hold is acknowledged"
        );
        assert_eq!(
            hook.deliver(Some(&token), &delivery(MAILBOX, json!(4_201)))
                .await,
            StatusCode::NO_CONTENT,
            "a numeric history id reads too"
        );
        assert_eq!(
            hook.deliver(Some(&token), "not a delivery").await,
            StatusCode::NO_CONTENT,
            "an unreadable delivery is acknowledged, not delivered again"
        );
        let bare_issuer = signed(
            GOOGLE_KEY,
            &claims_with(|claims| claims["iss"] = json!("accounts.google.com")),
        );
        assert_eq!(
            hook.deliver(Some(&bare_issuer), &delivery(MAILBOX, json!("4202")))
                .await,
            StatusCode::NO_CONTENT,
            "Google's issuer without its scheme is Google's too"
        );
    });
}

#[test]
fn the_hook_is_served_only_while_the_host_sets_gmail_push() {
    run_on_engine_stack("gmail-push-unserved", || async {
        let hook = Hook::serve(false);
        let token = signed(GOOGLE_KEY, &google_claims());
        assert_eq!(
            hook.deliver(Some(&token), &delivery(MAILBOX, json!("4200")))
                .await,
            StatusCode::NOT_FOUND
        );
    });
}

/// The server settings a config file of `body` resolves to.
fn resolve(body: &str) -> anyhow::Result<SyncServerConfig> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("oneiron.toml");
    std::fs::write(&path, body)?;
    let args = ServeArgs {
        config: Some(path),
        ..Default::default()
    };
    let resolved = resolve_serve_config_with_sources(
        &args,
        EnvConfig::from_pairs(std::iter::empty::<(&str, &str)>())?,
        None,
    )?;
    Ok(resolved.sync_server_config())
}

#[test]
fn a_gmail_push_section_reaches_the_server_and_is_checked() -> anyhow::Result<()> {
    let section = format!(
        "[gmail_push]\ntopic = \"{TOPIC}\"\naudience = \"{AUDIENCE}\"\n\
         service_account = \"{SERVICE_ACCOUNT}\"\n"
    );
    assert_eq!(
        resolve(&section)?.gmail_push,
        Some(GmailPushConfig {
            topic: TOPIC.to_owned(),
            audience: AUDIENCE.to_owned(),
            service_account: SERVICE_ACCOUNT.to_owned(),
            jwks_uri: GOOGLE_OIDC_JWKS_URI.to_owned(),
        }),
        "the section reaches the server, with Google's key set by default"
    );
    assert_eq!(
        GOOGLE_OIDC_JWKS_URI,
        "https://www.googleapis.com/oauth2/v3/certs"
    );
    assert_eq!(resolve("")?.gmail_push, None, "absent, nothing is served");
    let refused = [
        (
            "a topic outside projects/<project>/topics/<topic>",
            section.replace(TOPIC, "gmail"),
        ),
        (
            "an http key set",
            format!("{section}jwks_uri = \"http://keys.example/certs\"\n"),
        ),
        (
            "an unknown key",
            format!("{section}region = \"asia-northeast1\"\n"),
        ),
    ];
    for (case, body) in refused {
        assert!(resolve(&body).is_err(), "{case} stops the server");
    }
    Ok(())
}
