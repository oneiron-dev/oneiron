//! Authentication tests use real logged mints and holder signatures.
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, SlipCaveat, SlipClaims};
use oneiron::federation::{
    OrgAdminPower, Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling,
};

mod pairing;

const SECRET: &str = "retained-auth-fixture-secret";

struct Fixture {
    vault: Arc<oneiron::Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    holder: SigningKey,
    actor: oneiron::EntityId,
    config: SyncServerConfig,
    _dir: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        Self::with_secret(SECRET)
    }
    fn with_secret(secret: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap());
        let issuer = HostSlipIssuer::from_secret(secret.as_bytes()).unwrap();
        let root = vault.ensure_host_root_slip(&issuer).unwrap();
        Self {
            vault,
            issuer,
            root,
            holder: SigningKey::from_bytes(&[82; 32]),
            actor: oneiron::EntityId::now(),
            config: config_with_secret(secret),
            _dir: dir,
        }
    }
    fn mint(&self, configure: impl FnOnce(&mut SlipClaims)) -> CapabilitySlip {
        let mut claims = self.root.claims.clone();
        claims.slip_id = *blake3::hash(oneiron::EntityId::now().as_bytes()).as_bytes();
        claims.holder_ref = self.actor.to_hex();
        claims.binding_key = self.holder.verifying_key().to_bytes();
        configure(&mut claims);
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .unwrap()
    }
    fn headers(&self, slip: &CapabilitySlip) -> HeaderMap {
        let mut headers = bearer(&slip.to_token().unwrap());
        headers.insert(
            "x-oneiron-binding",
            proof_json(slip, &self.holder).parse().unwrap(),
        );
        headers
    }
    fn auth(&self, slip: &CapabilitySlip) -> Result<CoreAuth, ApiError> {
        CoreAuth::from_headers(&self.headers(slip), &self.config, self.vault.as_ref())
    }
    fn register(&self, actor: oneiron::EntityId) {
        let body = rmp_serde::to_vec_named(
            &serde_json::json!({"txt":"registered pairing actor","spkr":"user","at":100}),
        )
        .unwrap();
        self.vault
            .put_entity(
                &actor,
                oneiron::registry::ENTITY_TYPE_TURN,
                oneiron::TimeRange {
                    start: 100,
                    end: 100,
                },
                100,
                &body,
            )
            .unwrap();
    }
}
fn config_with_secret(secret: &str) -> SyncServerConfig {
    SyncServerConfig {
        auth_secret: Some(secret.to_owned()),
        ..Default::default()
    }
}
fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
    headers
}
fn proof_json(slip: &CapabilitySlip, holder: &SigningKey) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce = oneiron::EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature = holder.sign(&slip.binding_transcript(challenge.as_bytes()).unwrap());
    let signature: String = signature
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    serde_json::json!({"timestamp":timestamp,"nonce":nonce,"signature":signature}).to_string()
}
fn verbs(names: &[&str]) -> ScopeAxis<String> {
    ScopeAxis::Some(names.iter().map(|name| (*name).to_owned()).collect())
}
fn assert_unauthorized(result: Result<CoreAuth, ApiError>) {
    assert_eq!(
        result.unwrap_err().code(),
        crate::error::ErrorCode::Unauthorized
    );
}

#[test]
fn legacy_headers_and_unlogged_v1_v2_tokens_never_authenticate() {
    let fixture = Fixture::new();
    let mut old_header = HeaderMap::new();
    old_header.insert("x-oneiron-secret", SECRET.parse().unwrap());
    assert_unauthorized(CoreAuth::from_headers(
        &old_header,
        &fixture.config,
        fixture.vault.as_ref(),
    ));
    for token in [
        format!("{SECRET};scope=core:read"),
        mint_core_token_v2(SECRET, ""),
        mint_core_token_v2(SECRET, "scope=core:read"),
        mint_core_token_v2(
            SECRET,
            "scope=core:read;principal_ref=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        "v2..326ad3492c855a6d722398f75f006241ce8808250d79f38ffd4af64470118743".to_owned(),
        "v2.scope=core:read.".to_owned(),
    ] {
        let headers = bearer(&token);
        assert_unauthorized(CoreAuth::from_headers(
            &headers,
            &fixture.config,
            fixture.vault.as_ref(),
        ));
        assert_unauthorized(require_owner_auth(
            &headers,
            &fixture.config,
            fixture.vault.as_ref(),
        ));
    }
}

#[test]
fn bare_secret_is_a_revocable_logged_root_not_an_org_credential() {
    let fixture = Fixture::new();
    let headers = bearer(SECRET);
    let auth = require_owner_auth(&headers, &fixture.config, fixture.vault.as_ref()).unwrap();
    assert_eq!(auth.principal_ref(), None);
    assert_eq!(
        auth.verified_slip().unwrap().claims().slip_id,
        fixture.root.claims.slip_id
    );
    assert_eq!(
        auth.jti(),
        Some(
            fixture
                .root
                .claims
                .slip_id
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                .as_str()
        )
    );
    assert!(auth.require(CoreScope::Read).is_ok());
    assert!(auth.require(CoreScope::Write).is_ok());
    assert!(!auth.has_scope(CoreScope::OrgAdmin(OrgAdminPower::AddMember)));
    assert!(auth.credential_is_live(fixture.vault.as_ref()));
    assert!(!is_revoked_or_unreadable(
        auth.jti().unwrap(),
        fixture.vault.as_ref()
    ));
    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, fixture.root.claims.slip_id)
        .unwrap();
    assert!(!auth.credential_is_live(fixture.vault.as_ref()));
    assert!(is_revoked_or_unreadable(
        auth.jti().unwrap(),
        fixture.vault.as_ref()
    ));
    assert_unauthorized(require_owner_auth(
        &headers,
        &fixture.config,
        fixture.vault.as_ref(),
    ));
}

#[test]
fn identified_exact_top_slips_are_owner_grade_and_individually_revocable() {
    let fixture = Fixture::new();
    let slip = fixture.mint(|claims| claims.actor_class = Some("human".into()));
    let sibling = fixture.mint(|_| {});
    let auth = require_owner_auth(
        &fixture.headers(&slip),
        &fixture.config,
        fixture.vault.as_ref(),
    )
    .unwrap();
    assert!(auth.is_owner_grade());
    assert_eq!(auth.principal_ref(), Some(fixture.actor.to_hex().as_str()));
    assert_eq!(auth.actor_class(), Some("human"));
    assert!(!auth.has_scope(CoreScope::OrgAdmin(OrgAdminPower::AddMember)));
    assert_ne!(auth.jti(), fixture.auth(&sibling).unwrap().jti());
    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, slip.claims.slip_id)
        .unwrap();
    assert!(!auth.credential_is_live(fixture.vault.as_ref()));
    assert!(is_revoked_or_unreadable(
        auth.jti().unwrap(),
        fixture.vault.as_ref()
    ));
    assert_unauthorized(require_owner_auth(
        &fixture.headers(&slip),
        &fixture.config,
        fixture.vault.as_ref(),
    ));
    assert!(
        require_owner_auth(
            &fixture.headers(&sibling),
            &fixture.config,
            fixture.vault.as_ref()
        )
        .is_ok()
    );
    assert!(require_owner_auth(&bearer(SECRET), &fixture.config, fixture.vault.as_ref()).is_ok());
}

#[test]
fn every_capability_axis_and_offline_caveat_excludes_owner_grade() {
    let fixture = Fixture::new();
    let reference = ScopeId(fixture.actor);
    let mut cases = Vec::new();
    let mut scope = Scope::top();
    scope.verbs = verbs(&["read"]);
    cases.push(scope);
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([reference]));
    cases.push(scope);
    let mut scope = Scope::top();
    scope.facets = ScopeAxis::Some(BTreeSet::from([reference]));
    cases.push(scope);
    let mut scope = Scope::top();
    scope.bands = ScopeAxis::Some(BTreeSet::from([0]));
    cases.push(scope);
    let mut scope = Scope::top();
    scope.audience = ScopeAxis::Some(BTreeSet::from([reference]));
    cases.push(scope);
    let mut scope = Scope::top();
    scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Private);
    cases.push(scope);
    for scope in cases {
        let slip = fixture.mint(|claims| claims.scope = scope);
        let auth = fixture.auth(&slip).unwrap();
        assert!(!auth.is_owner_grade());
        assert_unauthorized(require_owner_auth(
            &fixture.headers(&slip),
            &fixture.config,
            fixture.vault.as_ref(),
        ));
    }
    // An explicit inventory of all current HTTP verbs is still not Scope::top.
    let slip = fixture.mint(|claims| {
        claims.scope.verbs = ScopeAxis::Some(
            CoreScope::all()
                .into_iter()
                .filter(|scope| !matches!(scope, CoreScope::OrgAdmin(_)))
                .map(|scope| scope.as_str().to_owned())
                .collect(),
        );
    });
    assert!(!fixture.auth(&slip).unwrap().is_owner_grade());
    for record_bound in [true, false] {
        let slip = fixture.mint(|claims| {
            if record_bound {
                claims.records.insert("named-record".into());
            } else {
                claims.channels.insert("named-channel".into());
            }
        });
        let auth = fixture.auth(&slip).unwrap();
        assert!(!auth.is_owner_grade());
        assert!(auth.require_unrestricted_record_scope().is_err());
    }
    let mut slip = fixture.mint(|_| {});
    slip.attenuate(SlipCaveat {
        ttl_secs: Some(30),
        ..Default::default()
    })
    .unwrap();
    assert!(!fixture.auth(&slip).unwrap().is_owner_grade());
    let single_use = fixture.mint(|claims| claims.single_use = true);
    assert_unauthorized(fixture.auth(&single_use));
}

#[test]
fn scoped_slips_enforce_verbs_and_refuse_adapters_without_record_scope() {
    let fixture = Fixture::new();
    let slip = fixture.mint(|claims| claims.scope.verbs = verbs(&["read"]));
    let auth = fixture.auth(&slip).unwrap();
    assert!(auth.require(CoreScope::Read).is_ok());
    assert!(auth.require(CoreScope::Write).is_err());
    assert!(auth.require_unrestricted_record_scope().is_ok());
    let mut narrow = slip;
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(fixture.actor)]));
    narrow
        .attenuate(SlipCaveat {
            scope: Some(scope),
            ..Default::default()
        })
        .unwrap();
    let auth = fixture.auth(&narrow).unwrap();
    assert!(auth.require(CoreScope::Read).is_ok());
    assert!(auth.require_unrestricted_record_scope().is_err());
    assert!(auth.require(CoreScope::Write).is_err());
}

#[test]
fn org_slips_are_closed_identified_and_never_owner_grade() {
    let fixture = Fixture::new();
    let org = oneiron::EntityId::now().to_hex();
    let slip = fixture.mint(|claims| {
        claims.org_ref = Some(org.clone());
        claims.scope.verbs = verbs(&["org:add-member"]);
    });
    let auth = fixture.auth(&slip).unwrap();
    assert_eq!(auth.org_ref(), Some(org.as_str()));
    assert_eq!(
        auth.require_registered_principal().unwrap(),
        fixture.actor.to_hex()
    );
    assert!(
        auth.require(CoreScope::OrgAdmin(OrgAdminPower::AddMember))
            .is_ok()
    );
    assert!(
        auth.require(CoreScope::OrgAdmin(OrgAdminPower::AssignRole))
            .is_err()
    );
    assert!(auth.require(CoreScope::Read).is_err());
    assert!(auth.require(CoreScope::Write).is_err());
    assert_unauthorized(require_owner_auth(
        &fixture.headers(&slip),
        &fixture.config,
        fixture.vault.as_ref(),
    ));
    for scope in [
        ScopeAxis::All,
        ScopeAxis::Bottom,
        verbs(&["org:root"]),
        verbs(&["org:add-member", "read"]),
        verbs(&["org:add-member", "core:auth"]),
        verbs(&["org:add-member", "companion:profile:read"]),
    ] {
        let slip = fixture.mint(|claims| {
            claims.org_ref = Some(org.clone());
            claims.scope.verbs = scope;
        });
        assert_unauthorized(fixture.auth(&slip));
    }
    let missing_org = fixture.mint(|claims| claims.scope.verbs = verbs(&["org:add-member"]));
    assert_unauthorized(fixture.auth(&missing_org));
    let missing_admin = fixture.mint(|claims| {
        claims.scope.verbs = verbs(&["org:add-member"]);
        claims.org_ref = Some(org);
        claims.holder_ref = "host".into();
    });
    assert_unauthorized(fixture.auth(&missing_admin));
    assert_unauthorized(CoreAuth::from_headers(
        &fixture.headers(&slip),
        &config_with_secret("independent-member-root"),
        fixture.vault.as_ref(),
    ));
}

#[test]
fn slip_tampering_wrong_holder_and_stale_or_missing_proofs_fail_closed() {
    let fixture = Fixture::new();
    let slip = fixture.mint(|claims| claims.scope.verbs = verbs(&["read"]));
    assert_unauthorized(CoreAuth::from_headers(
        &bearer(&slip.to_token().unwrap()),
        &fixture.config,
        fixture.vault.as_ref(),
    ));
    let mut headers = fixture.headers(&slip);
    headers.insert(
        "x-oneiron-binding",
        proof_json(&slip, &SigningKey::from_bytes(&[83; 32]))
            .parse()
            .unwrap(),
    );
    assert_unauthorized(CoreAuth::from_headers(
        &headers,
        &fixture.config,
        fixture.vault.as_ref(),
    ));
    let mut proof: serde_json::Value =
        serde_json::from_str(&proof_json(&slip, &fixture.holder)).unwrap();
    proof["timestamp"] = serde_json::json!(0);
    headers.insert("x-oneiron-binding", proof.to_string().parse().unwrap());
    assert_unauthorized(CoreAuth::from_headers(
        &headers,
        &fixture.config,
        fixture.vault.as_ref(),
    ));
    let mut tampered = slip.clone();
    tampered.claims.scope = Scope::top();
    assert_unauthorized(fixture.auth(&tampered));
    let mut tampered = slip.clone();
    tampered.claims.slip_id = fixture.root.claims.slip_id;
    assert_unauthorized(fixture.auth(&tampered));
    assert_unauthorized(CoreAuth::from_bind_token(
        &slip.to_token().unwrap(),
        &fixture.config,
        fixture.vault.as_ref(),
    ));
}

#[test]
fn v2_shaped_secrets_are_still_verified_through_the_logged_root() {
    for secret in ["v2.something.rest", "v2.slip.not-a-slip"] {
        let fixture = Fixture::with_secret(secret);
        let auth =
            require_owner_auth(&bearer(secret), &fixture.config, fixture.vault.as_ref()).unwrap();
        assert!(auth.is_owner_grade());
        assert!(auth.jti().is_some());
        let scoped = fixture.mint(|claims| claims.scope.verbs = verbs(&["read"]));
        assert!(!fixture.auth(&scoped).unwrap().is_owner_grade());
        assert_unauthorized(CoreAuth::from_headers(
            &bearer(&format!("{secret}x")),
            &fixture.config,
            fixture.vault.as_ref(),
        ));
    }
}

#[test]
fn wrong_or_empty_secret_and_absent_credentials_fail_closed() {
    let fixture = Fixture::new();
    let slip = fixture.mint(|_| {});
    for secret in ["unrecognized-host", ""] {
        let config = config_with_secret(secret);
        assert_unauthorized(CoreAuth::from_headers(
            &fixture.headers(&slip),
            &config,
            fixture.vault.as_ref(),
        ));
        assert_unauthorized(CoreAuth::from_headers(
            &bearer(secret),
            &config,
            fixture.vault.as_ref(),
        ));
    }
    assert_unauthorized(CoreAuth::from_headers(
        &HeaderMap::new(),
        &fixture.config,
        fixture.vault.as_ref(),
    ));
}

#[test]
fn idempotency_partitions_follow_the_verified_credential_and_attenuation() {
    let fixture = Fixture::new();
    let root = fixture.mint(|_| {});
    let mut read = root.clone();
    let mut scope = Scope::top();
    scope.verbs = verbs(&["read"]);
    read.attenuate(SlipCaveat {
        scope: Some(scope),
        ..Default::default()
    })
    .unwrap();
    let mut write = root.clone();
    let mut scope = Scope::top();
    scope.verbs = verbs(&["write"]);
    write
        .attenuate(SlipCaveat {
            scope: Some(scope),
            ..Default::default()
        })
        .unwrap();
    let sibling = fixture.mint(|claims| claims.scope.verbs = verbs(&["read"]));
    let principals: BTreeSet<_> = [root, read, write, sibling]
        .iter()
        .map(|slip| fixture.auth(slip).unwrap().idempotency_principal())
        .collect();
    assert_eq!(principals.len(), 4);
}

#[test]
fn development_hatch_does_not_mint_authority_and_honours_explicit_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::default()).unwrap();
    let config = SyncServerConfig {
        allow_unauthenticated: true,
        ..Default::default()
    };
    let auth = require_owner_auth(&HeaderMap::new(), &config, &vault).unwrap();
    assert!(auth.verified_slip().is_none());
    assert!(vault.authority_fold().unwrap().vault_id.is_none());
    let jti = mint_token_jti();
    let token = format!("v2.scope=core:read;jti={jti}.");
    let auth = CoreAuth::from_headers(&bearer(&token), &config, &vault).unwrap();
    assert!(auth.require(CoreScope::Read).is_ok());
    assert!(!auth.is_owner_grade());
    assert!(revoke_token_jti(&vault, &jti).unwrap());
    assert!(!revoke_token_jti(&vault, &jti).unwrap());
    assert_unauthorized(CoreAuth::from_headers(&bearer(&token), &config, &vault));
    assert!(!auth.credential_is_live(&vault));
    assert!(vault.authority_fold().unwrap().vault_id.is_none());
}

#[test]
fn revocation_registry_key_is_namespaced_and_id_keyed() {
    let jti = mint_token_jti();
    assert_eq!(
        revoked_token_jti_key(&jti),
        format!("auth:revoked-token-jti:{jti}")
    );
    assert_ne!(revoked_token_jti_key(&jti), revoked_token_jti_key("other"));
    assert!(parse_jti(&jti).is_ok());
}

#[test]
fn later_host_fork_revokes_cached_owner_auth_and_its_session_jti() {
    use oneiron::authority::{
        AUTHORITY_LOG_SCHEMA_VERSION, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        AuthoritySignatureSuite, authority_transcript,
    };
    let fixture = Fixture::new();
    let auth =
        require_owner_auth(&bearer(SECRET), &fixture.config, fixture.vault.as_ref()).unwrap();
    let parent = fixture.vault.authority_fold().unwrap().slips.mints[&fixture.root.claims.slip_id]
        .entry_hash;
    let signing = SigningKey::from_bytes(&blake3::derive_key(
        "oneiron/host-authority-signing/v2",
        SECRET.as_bytes(),
    ));
    let at = oneiron::TimeRange {
        start: fixture.root.claims.issued_at,
        end: fixture.root.claims.issued_at,
    };
    let mut rows = Vec::new();
    for id in [[71; 32], [72; 32]] {
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(fixture.root.claims.vault_id),
            seq: 2,
            parent_hashes: vec![parent],
            op: AuthorityOp::SlipRevoke { slip_id: id },
            signer: AuthoritySignature {
                suite: AuthoritySignatureSuite::Ed25519,
                public_key: fixture.issuer.public_key(),
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: at.start,
        };
        entry.signer.signature = signing
            .sign(&authority_transcript(&entry).unwrap())
            .to_bytes()
            .to_vec();
        rows.push((entry, at, at.start));
    }
    fixture.vault.put_authority_log_entries(&rows).unwrap();
    assert!(!auth.credential_is_live(fixture.vault.as_ref()));
    assert!(is_revoked_or_unreadable(
        auth.jti().unwrap(),
        fixture.vault.as_ref()
    ));
    assert_unauthorized(require_owner_auth(
        &bearer(SECRET),
        &fixture.config,
        fixture.vault.as_ref(),
    ));
}

#[test]
fn reconnect_identity_keeps_exact_instrument_not_remaining_ttl() {
    struct At<'a> {
        fixture: &'a Fixture,
        now: u64,
    }
    impl RevokedTokenJtis for At<'_> {
        fn is_revoked(&self, jti: &str) -> Result<bool, ()> {
            self.fixture.vault.is_revoked(jti)
        }
        fn verify_slip(
            &self,
            secret: &str,
            slip: &CapabilitySlip,
            timestamp: u64,
            nonce: &[u8],
            signature: &[u8],
        ) -> Result<oneiron::authority::VerifiedSlip, ()> {
            let fold = self.fixture.vault.authority_fold().map_err(drop)?;
            let nonce = std::str::from_utf8(nonce).map_err(drop)?;
            let challenge = format!("oneiron-request:{timestamp}:{nonce}");
            slip.verify(
                secret.as_bytes(),
                &fold,
                self.now,
                challenge.as_bytes(),
                signature,
            )
            .map_err(drop)
        }
    }
    let fixture = Fixture::new();
    let slip = fixture.mint(|claims| claims.actor_class = Some("human".to_owned()));
    let token = slip.to_token().unwrap();
    let first = CoreAuth::from_headers(
        &fixture.headers(&slip),
        &fixture.config,
        &At {
            fixture: &fixture,
            now: slip.claims.issued_at,
        },
    )
    .unwrap();
    let later = CoreAuth::from_headers(
        &fixture.headers(&slip),
        &fixture.config,
        &At {
            fixture: &fixture,
            now: slip.claims.issued_at + 20,
        },
    )
    .unwrap();
    assert!(first.same_authority(&later));
    assert_eq!(first.idempotency_principal(), later.idempotency_principal());
    let mut narrowed = CapabilitySlip::from_token(&token).unwrap();
    narrowed
        .attenuate(SlipCaveat {
            ttl_secs: Some(30),
            ..Default::default()
        })
        .unwrap();
    let narrowed_auth = CoreAuth::from_headers(
        &fixture.headers(&narrowed),
        &fixture.config,
        &At {
            fixture: &fixture,
            now: slip.claims.issued_at + 20,
        },
    )
    .unwrap();
    assert!(!first.same_authority(&narrowed_auth));
    assert_ne!(
        first.idempotency_principal(),
        narrowed_auth.idempotency_principal()
    );
}
