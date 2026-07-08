use super::*;

fn config() -> SyncServerConfig {
    SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        ..Default::default()
    }
}

#[test]
fn legacy_secret_grants_all_core_scopes() {
    let mut headers = HeaderMap::new();
    headers.insert(LEGACY_SECRET_HEADER, "secret".parse().unwrap());
    let auth = CoreAuth::from_headers(&headers, &config()).unwrap();

    assert_eq!(auth.principal(), "legacy-shared-secret");
    assert!(auth.require(CoreScope::Read).is_ok());
    assert!(auth.require(CoreScope::Write).is_ok());
    assert!(auth.require(CoreScope::Auth).is_ok());
    assert!(auth.require(CoreScope::CompanionProfileRead).is_ok());
    assert!(auth.require(CoreScope::CompanionAccessGrantWrite).is_ok());
    assert!(auth.require(CoreScope::CompanionRegisterRead).is_ok());
    assert!(auth.require(CoreScope::CompanionRegisterWrite).is_ok());
}

#[test]
fn legacy_secret_still_authenticates_with_unrelated_authorization_header() {
    let mut headers = HeaderMap::new();
    headers.insert(LEGACY_SECRET_HEADER, "secret".parse().unwrap());
    headers.insert(AUTHORIZATION, "Basic unrelated".parse().unwrap());
    let auth = CoreAuth::from_headers(&headers, &config()).unwrap();

    assert_eq!(auth.principal(), "legacy-shared-secret");
    assert!(auth.require(CoreScope::Write).is_ok());
}

#[test]
fn dev_mode_ignores_unrelated_authorization_header() {
    let config = SyncServerConfig {
        auth_secret: None,
        allow_unauthenticated: true,
        ..Default::default()
    };
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Basic unrelated".parse().unwrap());
    let auth = CoreAuth::from_headers(&headers, &config).unwrap();

    assert!(auth.require(CoreScope::Read).is_ok());
    assert!(auth.require(CoreScope::Write).is_ok());
}

#[test]
fn non_bearer_authorization_does_not_bypass_configured_secret() {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Basic unrelated".parse().unwrap());

    assert_eq!(
        CoreAuth::from_headers(&headers, &config())
            .unwrap_err()
            .code(),
        crate::error::ErrorCode::Unauthorized
    );
}

#[test]
fn bearer_token_extracts_scopes() {
    let mut headers = HeaderMap::new();
    headers.insert(
            AUTHORIZATION,
            "Bearer secret;scope=core:read,core:auth,companion:profile:read,companion:access-grant:write,companion:register:write"
                .parse()
                .unwrap(),
        );
    let auth = CoreAuth::from_headers(&headers, &config()).unwrap();

    assert_eq!(auth.principal(), "bearer");
    assert_eq!(auth.principal_ref(), None);
    assert!(auth.require(CoreScope::Read).is_ok());
    assert!(auth.require(CoreScope::Auth).is_ok());
    assert!(auth.require(CoreScope::CompanionProfileRead).is_ok());
    assert!(auth.require(CoreScope::CompanionAccessGrantWrite).is_ok());
    assert!(auth.require(CoreScope::CompanionRegisterWrite).is_ok());
    assert!(auth.require(CoreScope::Write).is_err());
    assert!(auth.require(CoreScope::CompanionRegisterRead).is_err());
}

#[test]
fn idempotency_principal_includes_auth_mode_and_scopes() {
    let mut legacy_headers = HeaderMap::new();
    legacy_headers.insert(LEGACY_SECRET_HEADER, "secret".parse().unwrap());
    let legacy_auth = CoreAuth::from_headers(&legacy_headers, &config()).unwrap();

    let mut read_headers = HeaderMap::new();
    read_headers.insert(
        AUTHORIZATION,
        "Bearer secret;scope=core:read".parse().unwrap(),
    );
    let read_auth = CoreAuth::from_headers(&read_headers, &config()).unwrap();

    let mut write_headers = HeaderMap::new();
    write_headers.insert(
        AUTHORIZATION,
        "Bearer secret;scope=core:write".parse().unwrap(),
    );
    let write_auth = CoreAuth::from_headers(&write_headers, &config()).unwrap();

    assert_ne!(
        legacy_auth.idempotency_principal(),
        write_auth.idempotency_principal()
    );
    assert_ne!(
        read_auth.idempotency_principal(),
        write_auth.idempotency_principal()
    );
    assert_eq!(
        legacy_auth.idempotency_principal(),
        "core:legacy-shared-secret:scopes=__implicit_all_scopes__"
    );
    assert!(read_auth.idempotency_principal().contains("core:read"));
    assert!(write_auth.idempotency_principal().contains("core:write"));
}

#[test]
fn bare_bearer_secret_bridges_to_all_core_scopes() {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Bearer secret".parse().unwrap());
    let auth = CoreAuth::from_headers(&headers, &config()).unwrap();

    assert!(auth.require(CoreScope::Read).is_ok());
    assert!(auth.require(CoreScope::Write).is_ok());
    assert!(auth.require(CoreScope::Auth).is_ok());
    assert!(auth.require(CoreScope::CompanionProfileRead).is_ok());
    assert!(auth.require(CoreScope::CompanionAccessGrantWrite).is_ok());
    assert!(auth.require(CoreScope::CompanionRegisterRead).is_ok());
    assert!(auth.require(CoreScope::CompanionRegisterWrite).is_ok());
    assert_eq!(
        auth.idempotency_principal(),
        "core:bearer:scopes=__implicit_all_scopes__"
    );
}

#[test]
fn bearer_token_extracts_bound_principal_ref() {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        "Bearer secret;scope=companion:profile:read;principal_ref=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .parse()
            .unwrap(),
    );
    let auth = CoreAuth::from_headers(&headers, &config()).unwrap();

    assert_eq!(
        auth.principal_ref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert!(auth.require(CoreScope::CompanionProfileRead).is_ok());
    assert_eq!(
        auth.idempotency_principal(),
        "core:bearer:principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:scopes=companion:profile:read"
    );
}

#[test]
fn bearer_token_rejects_malformed_principal_ref_claim() {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        "Bearer secret;scope=companion:profile:read;principal_ref=not-an-entity"
            .parse()
            .unwrap(),
    );

    assert_eq!(
        CoreAuth::from_headers(&headers, &config())
            .unwrap_err()
            .code(),
        crate::error::ErrorCode::Unauthorized
    );
}

#[test]
fn bearer_token_principal_ref_claim_requires_explicit_scope() {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        "Bearer secret;principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .unwrap(),
    );

    assert_eq!(
        CoreAuth::from_headers(&headers, &config())
            .unwrap_err()
            .code(),
        crate::error::ErrorCode::Unauthorized
    );
}

#[test]
fn implicit_all_idempotency_principal_does_not_collide_with_explicit_core_scopes() {
    let mut bare_headers = HeaderMap::new();
    bare_headers.insert(AUTHORIZATION, "Bearer secret".parse().unwrap());
    let bare_auth = CoreAuth::from_headers(&bare_headers, &config()).unwrap();

    let mut explicit_headers = HeaderMap::new();
    explicit_headers.insert(
        AUTHORIZATION,
        "Bearer secret;scope=core:read,core:write,core:auth"
            .parse()
            .unwrap(),
    );
    let explicit_auth = CoreAuth::from_headers(&explicit_headers, &config()).unwrap();

    assert_ne!(
        bare_auth.idempotency_principal(),
        explicit_auth.idempotency_principal()
    );
    assert_eq!(
        explicit_auth.idempotency_principal(),
        "core:bearer:scopes=core:read,core:write,core:auth"
    );
}
