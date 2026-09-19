use super::*;
#[test]
fn cache_isolates_triples_and_bad_issuer_fails_before_redemption() {
    let mut cache = OAuthTokenCache::default();
    let key = TokenCacheKey {
        vault_id: "v".into(),
        actor_ref: "a".into(),
        connector_ref: "connector-a".into(),
        issuer: "https://issuer.test".into(),
    };
    cache.register_issuer(&key).unwrap();
    let bad = AuthorizationResponse {
        iss: "https://attacker.test".into(),
        state: "state".into(),
        code: "code".into(),
    };
    assert_eq!(
        cache.redeem(&key, "state", &bad, 1, |_| panic!(
            "must reject before redemption"
        )),
        Err(OAuthClientError::IssuerMismatch)
    );
    let good = AuthorizationResponse {
        iss: key.issuer.clone(),
        ..bad
    };
    cache
        .redeem(&key, "state", &good, 1, |_| Ok(("token".into(), 10)))
        .unwrap();
    assert_eq!(cache.get(&key, 2), Some("token"));
    assert_eq!(cache.get(&key, 10), None);
    for other in [
        TokenCacheKey {
            vault_id: "other".into(),
            ..key.clone()
        },
        TokenCacheKey {
            actor_ref: "other".into(),
            ..key.clone()
        },
        TokenCacheKey {
            issuer: "https://other.test".into(),
            ..key.clone()
        },
    ] {
        assert_eq!(cache.get(&other, 2), None);
    }
    let independent = TokenCacheKey {
        connector_ref: "connector-b".into(),
        issuer: "https://provider-b.test".into(),
        ..key.clone()
    };
    cache.register_issuer(&independent).unwrap();
    cache
        .redeem(
            &independent,
            "state",
            &AuthorizationResponse {
                iss: independent.issuer.clone(),
                ..good.clone()
            },
            1,
            |_| Ok(("token-b".into(), 10)),
        )
        .unwrap();
    assert_eq!(cache.get(&key, 2), Some("token"));
    assert_eq!(cache.get(&independent, 2), Some("token-b"));
    let drift = TokenCacheKey {
        issuer: "https://other.test".into(),
        ..key.clone()
    };
    assert_eq!(
        cache.register_issuer(&drift),
        Err(OAuthClientError::IssuerDrift)
    );
    assert_eq!(cache.get(&key, 2), None);
    cache.revoke(&key.vault_id, &key.actor_ref, &key.connector_ref);
    cache.register_issuer(&drift).unwrap();
    assert_eq!(cache.get(&independent, 2), Some("token-b"));
    assert_eq!(
        cache.redeem(&drift, "state", &good, 2, |_| panic!("old issuer")),
        Err(OAuthClientError::IssuerMismatch)
    );
}
#[test]
fn client_document_has_native_web_and_no_forbidden_capabilities() {
    for (app, kind) in [
        (ClientApplication::Native, "native"),
        (ClientApplication::Web, "web"),
    ] {
        let document = client_metadata("https://oneiron.test", app).unwrap();
        assert_eq!(document["application_type"], kind);
        assert_eq!(document["cimd_draft"], CIMD_DRAFT);
        assert_eq!(document["token_endpoint_auth_method"], "none");
        assert!(document.get("sampling").is_none());
        assert!(document.get("roots").is_none());
        assert_eq!(document["grant_types"], json!(["authorization_code"]));
    }
}
