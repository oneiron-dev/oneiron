use super::*;

const SECRET: &str = "secret";
/// Secret for the golden vectors. Pinned with the vectors themselves: the MAC
/// key is `derive_key(CORE_TOKEN_V2_KDF_CONTEXT, secret)`, so changing either
/// changes every token.
const VECTOR_SECRET: &str = "correct horse battery staple";

const VECTOR_OWNER: &str = "v2..326ad3492c855a6d722398f75f006241ce8808250d79f38ffd4af64470118743";
const VECTOR_SCOPED: &str =
    "v2.scope=core:read.1f166e678c06858ee6dca47da42e5bf257db95cadc993fa1f5db90f52370eda4";
const VECTOR_BOUND: &str = "v2.scope=companion:profile:read;principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.547000c78580b12473a643b569d46d4078fa9df6eab25a69cac5d72a80afc102";

/// In-memory stand-in for the persistent registry, so the crypto/grammar
/// tests state their own revocation facts instead of opening a vault.
#[derive(Default)]
struct TestRevocations {
    revoked: BTreeSet<String>,
    unreadable: bool,
}

impl TestRevocations {
    fn none() -> Self {
        Self::default()
    }

    fn with(jtis: &[&str]) -> Self {
        Self {
            revoked: jtis.iter().map(|jti| (*jti).to_owned()).collect(),
            unreadable: false,
        }
    }

    fn unreadable() -> Self {
        Self {
            revoked: BTreeSet::new(),
            unreadable: true,
        }
    }
}

impl RevokedTokenJtis for TestRevocations {
    fn is_revoked(&self, jti: &str) -> Result<bool, ()> {
        if self.unreadable {
            return Err(());
        }
        Ok(self.revoked.contains(jti))
    }
}

/// Most tests assert on the token grammar and MAC, where nothing is revoked.
fn live() -> TestRevocations {
    TestRevocations::none()
}

fn config() -> SyncServerConfig {
    config_with_secret(SECRET)
}

fn config_with_secret(secret: &str) -> SyncServerConfig {
    SyncServerConfig {
        auth_secret: Some(secret.to_owned()),
        ..Default::default()
    }
}

fn dev_config() -> SyncServerConfig {
    SyncServerConfig {
        auth_secret: None,
        allow_unauthenticated: true,
        ..Default::default()
    }
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
    headers
}

/// Authenticates a minted token against the standard test secret.
fn auth_for_claims(claims: &str) -> Result<CoreAuth, ApiError> {
    CoreAuth::from_headers(
        &bearer(&mint_core_token_v2(SECRET, claims)),
        &config(),
        &live(),
    )
}

fn assert_unauthorized(result: Result<CoreAuth, ApiError>, what: &str) {
    assert_eq!(
        result.expect_err(what).code(),
        crate::error::ErrorCode::Unauthorized,
        "{what} must fail closed with the uniform 401"
    );
}

/// T1 — the deleted header is now just an unknown header, with or without the
/// correct secret in it. Inverts the old `legacy_secret_grants_all_core_scopes`.
#[test]
fn legacy_secret_header_is_rejected() {
    let mut headers = HeaderMap::new();
    headers.insert("x-oneiron-secret", SECRET.parse().unwrap());

    assert_unauthorized(
        CoreAuth::from_headers(&headers, &config(), &live()),
        "legacy header must not authenticate",
    );
    assert_unauthorized(
        require_owner_auth(&headers, &config(), &live()),
        "legacy header must not reach owner-grade surfaces",
    );
}

/// T2 — the pinned wire format. These three literals are the contract: they
/// must both verify and be reproduced byte-for-byte by the mint helper.
#[test]
fn v2_golden_vectors_verify_and_mint_round_trips() {
    let config = config_with_secret(VECTOR_SECRET);

    let owner =
        CoreAuth::from_headers(&bearer(VECTOR_OWNER), &config, &live()).expect("owner vector");
    assert_eq!(owner.principal(), "bearer");
    assert_eq!(owner.principal_ref(), None);
    assert!(owner.require(CoreScope::Write).is_ok());
    assert_eq!(
        owner.idempotency_principal(),
        "core:bearer:scopes=__implicit_all_scopes__"
    );

    let scoped =
        CoreAuth::from_headers(&bearer(VECTOR_SCOPED), &config, &live()).expect("scoped vector");
    assert!(scoped.require(CoreScope::Read).is_ok());
    assert!(scoped.require(CoreScope::Write).is_err());
    assert_eq!(
        scoped.idempotency_principal(),
        "core:bearer:scopes=core:read"
    );

    let bound =
        CoreAuth::from_headers(&bearer(VECTOR_BOUND), &config, &live()).expect("bound vector");
    assert_eq!(
        bound.principal_ref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert!(bound.require(CoreScope::CompanionProfileRead).is_ok());
    assert_eq!(
        bound.idempotency_principal(),
        "core:bearer:principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:scopes=companion:profile:read"
    );

    for (claims, expected) in [
        ("", VECTOR_OWNER),
        ("scope=core:read", VECTOR_SCOPED),
        (
            "scope=companion:profile:read;principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            VECTOR_BOUND,
        ),
    ] {
        assert_eq!(
            mint_core_token_v2(VECTOR_SECRET, claims),
            expected,
            "mint must reproduce the pinned vector for claims {claims:?}"
        );
    }
}

/// T3 — the fusion gap itself: claims cannot be edited, widened, deleted, or
/// paired with another claims string's MAC.
#[test]
fn v2_claims_tamper_fails() {
    let scoped = mint_core_token_v2(SECRET, "scope=core:read");
    let mac = scoped.rsplit_once('.').expect("mac segment").1;

    let widened = format!("v2.scope=core:read,core:write.{mac}");
    let stripped = format!("v2..{mac}");
    let renarrowed = format!("v2.scope=core:write.{mac}");
    let bound = format!("v2.scope=core:read;principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.{mac}");
    let cross = format!(
        "v2.scope=core:read.{}",
        mint_core_token_v2(SECRET, "scope=core:write")
            .rsplit_once('.')
            .expect("mac segment")
            .1
    );

    for (token, what) in [
        (widened, "scope widened under a stale MAC"),
        (stripped, "claims deleted under a stale MAC"),
        (renarrowed, "scope swapped under a stale MAC"),
        (bound, "principal_ref appended under a stale MAC"),
        (cross, "MAC lifted from a different claims string"),
    ] {
        assert_unauthorized(
            CoreAuth::from_headers(&bearer(&token), &config(), &live()),
            &format!("{what} must not authenticate"),
        );
    }
}

/// T4 — every malformed MAC shape exits through the same 401, so the response
/// is not a verification oracle.
#[test]
fn v2_mac_tamper_fails() {
    let token = mint_core_token_v2(SECRET, "scope=core:read");
    let (framed, mac) = token.rsplit_once('.').expect("mac segment");

    let mut flipped: Vec<char> = mac.chars().collect();
    flipped[0] = if flipped[0] == 'a' { 'b' } else { 'a' };
    let flipped: String = flipped.into_iter().collect();

    for (token, what) in [
        (format!("{framed}.{flipped}"), "flipped hex digit"),
        (format!("{framed}.{}", &mac[..63]), "truncated mac"),
        (format!("{framed}.{}", mac.to_uppercase()), "uppercase hex"),
        (format!("{framed}."), "empty mac"),
        (format!("{framed}.{mac}{mac}"), "over-long mac"),
        ("v2.scope=core:read".to_owned(), "missing mac segment"),
        (
            format!("v3.scope=core:read.{mac}"),
            "unknown version prefix",
        ),
    ] {
        assert_unauthorized(
            CoreAuth::from_headers(&bearer(&token), &config(), &live()),
            &format!("{what} must not authenticate"),
        );
    }
}

/// T5 — the v1 grammar is dead outright, with no acceptance window. Its
/// tokens embedded the trust root; nothing that shape may authenticate.
#[test]
fn v1_grammar_is_dead() {
    for token in [
        "secret;scope=core:read",
        "secret;",
        "secret;scope=core:read;principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        assert_unauthorized(
            CoreAuth::from_headers(&bearer(token), &config(), &live()),
            &format!("v1 token {token:?} must not authenticate"),
        );
    }
}

/// T6 — the bare trust root over the standard header stays owner-grade.
#[test]
fn bare_secret_bearer_is_owner_grade() {
    let headers = bearer(SECRET);
    let auth = CoreAuth::from_headers(&headers, &config(), &live()).expect("bare secret");

    for scope in [
        CoreScope::Read,
        CoreScope::Write,
        CoreScope::Auth,
        CoreScope::CompanionProfileRead,
        CoreScope::CompanionAccessGrantWrite,
        CoreScope::CompanionRegisterRead,
        CoreScope::CompanionRegisterWrite,
    ] {
        assert!(auth.require(scope).is_ok(), "{scope:?} must be granted");
    }
    assert!(auth.is_owner_grade());
    assert_eq!(
        auth.idempotency_principal(),
        "core:bearer:scopes=__implicit_all_scopes__"
    );
    assert!(require_owner_auth(&headers, &config(), &live()).is_ok());
}

/// T7 — an empty-claims token grants everything and reaches the full-vault
/// surfaces, since it asserts no narrowing.
#[test]
fn empty_claims_v2_token_is_owner_grade() {
    let headers = bearer(&mint_core_token_v2(SECRET, ""));
    let auth = require_owner_auth(&headers, &config(), &live()).expect("empty-claims token");

    assert!(auth.require(CoreScope::Write).is_ok());
    assert!(auth.is_owner_grade());
    assert_eq!(
        auth.idempotency_principal(),
        "core:bearer:scopes=__implicit_all_scopes__"
    );
}

/// T8 — the owner-grade boundary. Scoped tokens authenticate on `/v1` with
/// exactly their claimed scopes but never reach `/ws` or legacy `/api/*`,
/// and never read as owner-grade at the disclosure/consent gates.
///
/// Owner-grade requires BOTH narrowing axes absent. A `scope=…` token with no
/// `principal_ref` is still a delegated instrument: holding a subset of the
/// owner's capabilities is not evidence the owner is holding it. The earlier
/// `principal_ref`-only predicate classified this credential as owner-grade,
/// which suppressed the disclosure absence-clamp for delegated read-only
/// tokens — the exact credential most likely to be handed to a third party.
#[test]
fn scoped_v2_token_is_not_owner_grade() {
    let scoped = bearer(&mint_core_token_v2(SECRET, "scope=core:read"));
    let auth = CoreAuth::from_headers(&scoped, &config(), &live()).expect("scoped token");
    assert!(auth.require(CoreScope::Read).is_ok());
    assert!(auth.require(CoreScope::Write).is_err());
    assert_eq!(auth.principal_ref(), None);
    assert!(
        !auth.is_owner_grade(),
        "a scope list narrows the credential even with no principal_ref"
    );
    assert_unauthorized(
        require_owner_auth(&scoped, &config(), &live()),
        "scoped token on a full-vault surface",
    );

    let bound = bearer(&mint_core_token_v2(
        SECRET,
        "scope=companion:profile:read;principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ));
    let auth = CoreAuth::from_headers(&bound, &config(), &live()).expect("bound token");
    assert_eq!(
        auth.principal_ref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert!(!auth.is_owner_grade());
    assert_unauthorized(
        require_owner_auth(&bound, &config(), &live()),
        "principal-bound token on a full-vault surface",
    );
}

/// T8b — `is_owner_grade` is exactly the `require_owner_auth` admission rule,
/// across every credential shape the server accepts. One predicate, one
/// definition: a second reader of the old `principal_ref`-only rule cannot
/// reappear without failing here.
#[test]
fn owner_grade_predicate_matches_the_full_vault_boundary() {
    let cases = [
        (bearer(SECRET), true, "bare trust root"),
        (
            bearer(&mint_core_token_v2(SECRET, "")),
            true,
            "empty claims",
        ),
        (
            bearer(&mint_core_token_v2(SECRET, "scope=core:read")),
            false,
            "read-only scope, no principal_ref",
        ),
        (
            bearer(&mint_core_token_v2(
                SECRET,
                "scope=core:read,core:write,core:auth,companion:profile:read,\
                 companion:access-grant:write,companion:register:read,\
                 companion:register:write",
            )),
            false,
            "every scope listed explicitly is still a delegation",
        ),
        (
            bearer(&mint_core_token_v2(
                SECRET,
                "scope=core:read;principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )),
            false,
            "principal-bound",
        ),
    ];

    for (headers, expected, what) in cases {
        let auth = CoreAuth::from_headers(&headers, &config(), &live()).expect(what);
        assert_eq!(auth.is_owner_grade(), expected, "is_owner_grade for {what}");
        assert_eq!(
            require_owner_auth(&headers, &config(), &live()).is_ok(),
            expected,
            "require_owner_auth must agree with is_owner_grade for {what}"
        );
    }

    // Dev mode agrees on both arms of the same rule.
    let dev = dev_config();
    assert!(
        CoreAuth::from_headers(&HeaderMap::new(), &dev, &live())
            .expect("dev fallthrough")
            .is_owner_grade(),
        "the dev fallthrough asserts no narrowing"
    );
    assert!(
        !CoreAuth::from_headers(&bearer("v2.scope=core:read."), &dev, &live())
            .expect("dev scoped token")
            .is_owner_grade(),
        "a dev scoped token is narrowed like any other"
    );
}

/// Guards the invariant that makes `is_owner_grade`'s two conjuncts
/// independently load-bearing rather than one redundant clause.
///
/// TODAY the grammar refuses `principal_ref` without `scope` (T9), so
/// `principal_ref.is_some()` already implies `!implicit_all_scopes` and
/// either conjunct alone would compute the same answer. That equivalence is
/// a property of the GRAMMAR, not of the predicate: relaxing the grammar to
/// admit a bare `principal_ref` would silently make an
/// `implicit_all_scopes`-only predicate classify a principal-bound token as
/// owner-grade. This pins the coupling so such a relaxation fails HERE, at
/// the sentence that explains it, instead of at a disclosure gate.
#[test]
fn owner_grade_conjuncts_are_not_redundant() {
    assert_unauthorized(
        auth_for_claims("principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "an implicit-all-scopes token carrying principal_ref must not exist",
    );

    // Every credential the server DOES accept satisfies the implication the
    // equivalence rests on: bound implies narrowed. An empty scope LIST is
    // still a list — it narrows to zero capabilities rather than widening to
    // all of them.
    for claims in [
        "",
        "scope=core:read",
        "scope=core:read;principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;scope=",
    ] {
        let auth = auth_for_claims(claims).expect("accepted claims");
        assert!(
            !(auth.principal_ref.is_some() && auth.implicit_all_scopes),
            "principal_ref without a scope list must be unreachable for {claims:?}"
        );
        assert_eq!(
            auth.is_owner_grade(),
            claims.is_empty(),
            "only empty claims mint an owner-grade token: {claims:?}"
        );
    }
}

/// T9 — the claims grammar is unchanged; a valid MAC does not buy a token
/// past the grammar rules.
#[test]
fn claims_grammar_preserved_under_v2() {
    for (claims, what) in [
        ("scope=core:read;audience=other", "unknown claim key"),
        ("audience=other", "unknown claim key alone"),
        (
            "principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "principal_ref without scope",
        ),
        (
            "scope=companion:profile:read;principal_ref=not-an-entity",
            "malformed principal_ref",
        ),
        ("scope=core:admin", "unknown scope"),
        ("scope", "claim without a value"),
    ] {
        assert_unauthorized(
            auth_for_claims(claims),
            &format!("{what} must not authenticate even with a valid MAC"),
        );
    }

    let multi = auth_for_claims("scope=core:read,core:auth").expect("multi-scope claims");
    assert!(multi.require(CoreScope::Read).is_ok());
    assert!(multi.require(CoreScope::Auth).is_ok());
    assert!(multi.require(CoreScope::Write).is_err());
}

/// T10 — dev mode keeps its capabilities and speaks the same token shape;
/// only the MAC goes unverified, because no key exists to verify it against.
#[test]
fn dev_mode_v2_shape() {
    let config = dev_config();

    let absent =
        CoreAuth::from_headers(&HeaderMap::new(), &config, &live()).expect("no credential in dev");
    assert!(absent.require(CoreScope::Write).is_ok());
    assert_eq!(absent.principal(), "legacy-shared-secret");

    let scoped = CoreAuth::from_headers(&bearer("v2.scope=core:read."), &config, &live())
        .expect("dev scoped token");
    assert_eq!(scoped.principal(), "dev-bearer");
    assert!(scoped.require(CoreScope::Read).is_ok());
    assert!(scoped.require(CoreScope::Write).is_err());
    assert_unauthorized(
        require_owner_auth(&bearer("v2.scope=core:read."), &config, &live()),
        "dev scoped token on a full-vault surface",
    );

    // The hard break applies uniformly: dev mode does not accept v1 either.
    for token in ["secret", "scope=core:read", "secret;scope=core:read"] {
        assert_unauthorized(
            CoreAuth::from_headers(&bearer(token), &config, &live()),
            &format!("non-v2 dev bearer {token:?}"),
        );
    }

    // An unrelated scheme is not a bearer credential at all.
    assert!(
        CoreAuth::from_headers(&unrelated_scheme_headers(), &config, &live())
            .expect("unrelated scheme falls through in dev")
            .require(CoreScope::Write)
            .is_ok()
    );
}

/// T11 — rotation semantics. Replacing the secret rewraps the MAC key, so
/// every token minted under the old one stops verifying. Revoking a single
/// token is a separate, explicit act, never a side effect of rotation.
#[test]
fn rotation_invalidates_minted_tokens() {
    let token = mint_core_token_v2(SECRET, "scope=core:read");
    let rotated = config_with_secret("rotated-secret");

    assert!(CoreAuth::from_headers(&bearer(&token), &config(), &live()).is_ok());
    assert_unauthorized(
        CoreAuth::from_headers(&bearer(&token), &rotated, &live()),
        "token minted under the previous secret",
    );
    assert_unauthorized(
        CoreAuth::from_headers(&bearer(SECRET), &rotated, &live()),
        "previous bare secret",
    );

    // Credentials minted under the new secret work immediately.
    let reminted = mint_core_token_v2("rotated-secret", "scope=core:read");
    assert!(CoreAuth::from_headers(&bearer(&reminted), &rotated, &live()).is_ok());
}

/// T12 — fail-closed on every wrong- or empty-secret configuration.
#[test]
fn wrong_secret_and_empty_secret_fail_closed() {
    assert_unauthorized(
        CoreAuth::from_headers(&bearer("wrong"), &config(), &live()),
        "wrong bare secret",
    );
    assert_unauthorized(
        CoreAuth::from_headers(
            &bearer(&mint_core_token_v2("wrong", "")),
            &config(),
            &live(),
        ),
        "token minted under a foreign secret",
    );

    let empty = config_with_secret("");
    for token in [
        "secret".to_owned(),
        mint_core_token_v2("", "scope=core:read"),
    ] {
        assert_unauthorized(
            CoreAuth::from_headers(&bearer(&token), &empty, &live()),
            "empty configured secret must refuse everything",
        );
    }
    assert_unauthorized(
        CoreAuth::from_headers(&HeaderMap::new(), &empty, &live()),
        "empty configured secret with no credential",
    );

    // Secret configured but the caller presents nothing: no dev fallthrough.
    assert_unauthorized(
        CoreAuth::from_headers(&HeaderMap::new(), &config(), &live()),
        "no credential against a configured secret",
    );
    assert_unauthorized(
        CoreAuth::from_headers(&unrelated_scheme_headers(), &config(), &live()),
        "unrelated auth scheme against a configured secret",
    );
}

fn unrelated_scheme_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Basic unrelated".parse().unwrap());
    headers
}

/// The MAC key is domain-separated: the same secret under a different
/// derive_key context yields a different MAC, so the connector-registry key
/// and the token key cannot be confused for one another.
#[test]
fn token_mac_is_domain_separated_from_other_secret_uses() {
    let token_mac = core_token_mac(SECRET, "scope=core:read");
    let other_context = blake3::derive_key("oneiron-server other context", SECRET.as_bytes());
    let other_mac = *blake3::keyed_hash(&other_context, b"scope=core:read").as_bytes();

    assert_ne!(token_mac, other_mac);
    assert_ne!(
        token_mac,
        *blake3::hash(b"scope=core:read").as_bytes(),
        "the MAC must be keyed, not a bare digest of the claims"
    );
}

/// Idempotency partitions stay keyed to the effective grant, so a narrowed
/// token can never replay into an owner-grade entry.
#[test]
fn idempotency_principal_partitions_by_effective_grant() {
    let owner = CoreAuth::from_headers(&bearer(SECRET), &config(), &live()).expect("owner");
    let read = auth_for_claims("scope=core:read").expect("read token");
    let write = auth_for_claims("scope=core:write").expect("write token");
    let bound = auth_for_claims("scope=core:read;principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .expect("bound token");

    let principals = [
        owner.idempotency_principal(),
        read.idempotency_principal(),
        write.idempotency_principal(),
        bound.idempotency_principal(),
    ];
    for (i, left) in principals.iter().enumerate() {
        for right in &principals[i + 1..] {
            assert_ne!(left, right, "distinct grants must not share a partition");
        }
    }
    assert_eq!(
        owner.idempotency_principal(),
        "core:bearer:scopes=__implicit_all_scopes__"
    );
}

/// F1 — a trust root that happens to be shaped like a token is still the
/// trust root.
///
/// The secret is an opaque operator-chosen string; `v2.` is framing this code
/// reserves, not a namespace the operator agreed to avoid. Judging the root
/// as a token compared its own tail against a MAC over its own head, so owner
/// auth broke outright for these secrets — the credential was misclassified,
/// not merely inconvenienced.
#[test]
fn v2_shaped_trust_root_authenticates_as_the_root() {
    for secret in [
        "v2.something.rest",
        // The exact shape of a real token, and a well-formed one: even a
        // secret that would parse cleanly as claims must not be parsed.
        "v2.scope=core:read.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "v2..",
        "v2.a.b.c",
    ] {
        let config = config_with_secret(secret);
        let auth = CoreAuth::from_headers(&bearer(secret), &config, &live()).unwrap_or_else(|_| {
            panic!("v2-shaped secret {secret:?} must authenticate as the root")
        });

        assert!(
            auth.is_owner_grade(),
            "{secret:?} is the trust root, not a delegated token"
        );
        assert!(auth.require(CoreScope::Write).is_ok());
        assert_eq!(auth.principal_ref(), None);
        assert!(require_owner_auth(&bearer(secret), &config, &live()).is_ok());
        assert_eq!(
            auth.idempotency_principal(),
            "core:bearer:scopes=__implicit_all_scopes__",
            "{secret:?} must partition as the owner, not as its own claims"
        );
    }
}

/// The exact-match arm is a match on the ROOT, not a bypass of verification:
/// tokens minted under a v2-shaped secret still verify normally, and a
/// near-miss of the root is still refused.
#[test]
fn v2_shaped_root_still_mints_and_refuses_normally() {
    const SECRET_V2: &str = "v2.something.rest";
    let config = config_with_secret(SECRET_V2);

    let scoped = mint_core_token_v2(SECRET_V2, "scope=core:read");
    let auth = CoreAuth::from_headers(&bearer(&scoped), &config, &live()).expect("scoped token");
    assert!(auth.require(CoreScope::Read).is_ok());
    assert!(auth.require(CoreScope::Write).is_err());
    assert!(
        !auth.is_owner_grade(),
        "a token minted under a v2-shaped root is still a delegation"
    );

    for token in [
        "v2.something.res",
        "v2.something.restx",
        "v2.something.",
        "V2.something.rest",
    ] {
        assert_unauthorized(
            CoreAuth::from_headers(&bearer(token), &config, &live()),
            &format!("{token:?} is not the configured root"),
        );
    }
}

/// F2 — the C1 rider's explicit revocation act. A revoked token's bearer is
/// refused while a sibling minted from identical claims keeps working, so
/// revocation is per-token and not a scope- or claims-wide effect.
#[test]
fn revoked_jti_is_refused_while_its_sibling_passes() {
    let (revoked_token, revoked_jti) = mint_identified_core_token_v2(SECRET, "scope=core:read");
    let (sibling_token, sibling_jti) = mint_identified_core_token_v2(SECRET, "scope=core:read");

    assert_ne!(
        revoked_jti, sibling_jti,
        "identical claims must mint distinct identities"
    );
    assert_ne!(
        revoked_token, sibling_token,
        "minting is no longer a pure function of claims and secret"
    );

    // Both are live before the act.
    let registry = TestRevocations::none();
    assert!(CoreAuth::from_headers(&bearer(&revoked_token), &config(), &registry).is_ok());
    assert!(CoreAuth::from_headers(&bearer(&sibling_token), &config(), &registry).is_ok());

    let registry = TestRevocations::with(&[&revoked_jti]);
    assert_unauthorized(
        CoreAuth::from_headers(&bearer(&revoked_token), &config(), &registry),
        "a revoked token must not authenticate",
    );
    assert!(
        CoreAuth::from_headers(&bearer(&sibling_token), &config(), &registry).is_ok(),
        "revoking one token must not revoke its sibling"
    );
}

/// Revocation binds to the token's identity, not to its capabilities: an
/// owner-grade token is as revocable as a scoped one, and the check runs
/// before the owner-grade admission rather than only on the /v1 plane.
#[test]
fn revocation_applies_to_owner_grade_tokens_and_full_vault_surfaces() {
    let (token, jti) = mint_identified_core_token_v2(SECRET, "");
    let headers = bearer(&token);

    let live_auth =
        CoreAuth::from_headers(&headers, &config(), &live()).expect("identified owner token");
    assert!(
        live_auth.is_owner_grade(),
        "a jti is identity, not narrowing — it must not demote the token"
    );
    assert!(require_owner_auth(&headers, &config(), &live()).is_ok());

    let registry = TestRevocations::with(&[&jti]);
    assert_unauthorized(
        CoreAuth::from_headers(&headers, &config(), &registry),
        "a revoked owner-grade token",
    );
    assert_unauthorized(
        require_owner_auth(&headers, &config(), &registry),
        "a revoked owner-grade token on a full-vault surface",
    );
}

/// Fail-closed on an unreadable registry. An authentic MAC proves the token
/// was minted, never that it is still live, so "cannot check" must not
/// resolve to "still live".
#[test]
fn unreadable_revocation_registry_refuses_identified_tokens() {
    let (identified, _jti) = mint_identified_core_token_v2(SECRET, "scope=core:read");

    assert_unauthorized(
        CoreAuth::from_headers(
            &bearer(&identified),
            &config(),
            &TestRevocations::unreadable(),
        ),
        "an identified token whose liveness cannot be established",
    );

    // A token with no identity consults nothing, so it is unaffected — the
    // registry is read only when there is an id to look up.
    assert!(
        CoreAuth::from_headers(
            &bearer(&mint_core_token_v2(SECRET, "scope=core:read")),
            &config(),
            &TestRevocations::unreadable(),
        )
        .is_ok(),
        "an unidentified token performs no lookup"
    );
    assert!(
        CoreAuth::from_headers(&bearer(SECRET), &config(), &TestRevocations::unreadable()).is_ok(),
        "the bare trust root performs no lookup"
    );
}

/// The `jti` claim rides the same MAC as every other claim: it cannot be
/// added, edited, or stripped to shake off a revocation.
#[test]
fn jti_is_mac_covered_and_shape_checked() {
    let (token, jti) = mint_identified_core_token_v2(SECRET, "scope=core:read");
    let mac = token.rsplit_once('.').expect("mac segment").1;
    let registry = TestRevocations::with(&[&jti]);

    for (tampered, what) in [
        (
            format!("v2.scope=core:read.{mac}"),
            "jti stripped under a stale MAC",
        ),
        (
            format!("v2.scope=core:read;jti={}.{mac}", "0".repeat(32)),
            "jti swapped under a stale MAC",
        ),
    ] {
        assert_unauthorized(
            CoreAuth::from_headers(&bearer(&tampered), &config(), &registry),
            &format!("{what} must not authenticate"),
        );
    }

    // Malformed ids are refused at the grammar, even with a valid MAC, so the
    // registry has exactly one spelling per token to match against.
    for bad in [
        "",
        "0123456789abcdef",
        &"0".repeat(33),
        &"A".repeat(32),
        &"g".repeat(32),
    ] {
        assert_unauthorized(
            auth_for_claims(&format!("scope=core:read;jti={bad}")),
            &format!("malformed jti {bad:?}"),
        );
    }
}

/// Dev mode consults the registry too: the MAC goes unverified there because
/// no key exists, but a revocation an operator performed is real state.
#[test]
fn dev_mode_honours_revocation() {
    let dev = dev_config();
    let jti = "0".repeat(32);
    let token = format!("v2.scope=core:read;jti={jti}.");

    assert!(CoreAuth::from_headers(&bearer(&token), &dev, &live()).is_ok());
    assert_unauthorized(
        CoreAuth::from_headers(&bearer(&token), &dev, &TestRevocations::with(&[&jti])),
        "a revoked jti in dev mode",
    );
}

/// The registry key is derived from the id alone, so the CLI writes exactly
/// what the verify path reads.
#[test]
fn revocation_registry_key_is_namespaced_and_id_keyed() {
    let jti = mint_token_jti();

    assert_eq!(
        revoked_token_jti_key(&jti),
        format!("auth:revoked-token-jti:{jti}")
    );
    assert_ne!(revoked_token_jti_key(&jti), revoked_token_jti_key("other"));
    assert_eq!(jti.len(), CORE_TOKEN_JTI_LEN);
    assert!(
        parse_jti(&jti).is_ok(),
        "minted ids must satisfy the grammar"
    );
}
