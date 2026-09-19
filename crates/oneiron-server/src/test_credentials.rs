//! Request fixtures mint real logged slips before crossing the production router.
//! A request recipe is never a credential and is never sent to the router.
use crate::server::SyncServer;
use axum::body::Body;
use axum::http::{Request, header::AUTHORIZATION};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::federation::{Scope, ScopeAxis};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const RECIPE_PREFIX: &str = "OneironTestCredential ";

pub(crate) fn credential(server: &SyncServer, recipe: &str) -> (CapabilitySlip, SigningKey) {
    let fields: BTreeMap<_, _> = recipe
        .split(';')
        .filter(|part| !part.is_empty())
        .map(|part| part.split_once('=').expect("credential recipe key/value"))
        .collect();
    let secret = server
        .config
        .auth_secret
        .as_deref()
        .expect("authenticated fixture needs a configured host root");
    let issuer = HostSlipIssuer::from_secret(secret.as_bytes()).unwrap();
    let identity = fields.get("jti").copied().unwrap_or(recipe);
    let id = *blake3::hash(format!("oneiron/test-slip/id/{identity}").as_bytes()).as_bytes();
    let key = SigningKey::from_bytes(
        blake3::hash(format!("oneiron/test-slip/binding/{identity}").as_bytes()).as_bytes(),
    );
    let holder_ref = fields
        .get("principal_ref")
        .copied()
        .unwrap_or("host")
        .to_owned();
    let actor_class = fields.get("actor_class").map(|value| value.to_string());
    let org_ref = fields.get("org_ref").map(|value| value.to_string());
    let mut scope = Scope::top();
    if let Some(scopes) = fields.get("scope") {
        scope.verbs = ScopeAxis::Some(
            scopes
                .split(',')
                .map(|scope| {
                    match scope.trim() {
                        "core:read" => "read",
                        "core:write" => "write",
                        other => other,
                    }
                    .to_owned()
                })
                .collect::<BTreeSet<_>>(),
        );
    }
    let cache = format!("test:api:slip:{}", hex(&id));
    if let Some(bytes) = server.vault().sync_state_get(&cache).unwrap() {
        let slip = CapabilitySlip::from_token(std::str::from_utf8(&bytes).unwrap()).unwrap();
        assert_eq!(
            slip.claims.holder_ref, holder_ref,
            "one fixture id cannot silently change principal"
        );
        assert_eq!(slip.claims.actor_class, actor_class);
        assert_eq!(slip.claims.org_ref, org_ref);
        assert_eq!(
            slip.claims.scope, scope,
            "attenuate a slip explicitly instead of reusing an id with new authority"
        );
        assert_eq!(slip.claims.binding_key, key.verifying_key().to_bytes());
        return (slip, key);
    }
    let root = server.vault().ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims;
    claims.slip_id = id;
    claims.parent_id = None;
    claims.holder_ref = holder_ref;
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = actor_class;
    claims.org_ref = org_ref;
    claims.scope = scope;
    let slip = server
        .vault()
        .mint_capability_slip(&issuer, claims)
        .unwrap();
    server
        .vault()
        .sync_state_put(&cache, slip.to_token().unwrap().as_bytes())
        .unwrap();
    (slip, key)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub(crate) fn bind_request(server: &SyncServer, request: Request<Body>) -> Request<Body> {
    let Some(recipe) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix(RECIPE_PREFIX))
        .map(str::to_owned)
    else {
        return request;
    };
    let (slip, key) = credential(server, &recipe);
    bind_slip_request(&slip, &key, request)
}
pub(crate) fn bind_slip_request(
    slip: &CapabilitySlip,
    key: &SigningKey,
    mut request: Request<Body>,
) -> Request<Body> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let nonce = oneiron::EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature = hex(&key
        .sign(&slip.binding_transcript(challenge.as_bytes()).unwrap())
        .to_bytes());
    request.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {}", slip.to_token().unwrap())
            .parse()
            .unwrap(),
    );
    request.headers_mut().insert(
        "x-oneiron-binding",
        serde_json::json!({"timestamp":timestamp,"nonce":nonce,"signature":signature})
            .to_string()
            .parse()
            .unwrap(),
    );
    request
}
pub(crate) fn revoke(server: &SyncServer, recipe: &str) {
    let (slip, _) = credential(server, recipe);
    let issuer =
        HostSlipIssuer::from_secret(server.config.auth_secret.as_ref().unwrap().as_bytes())
            .unwrap();
    server
        .vault()
        .revoke_capability_slip(&issuer, slip.claims.slip_id)
        .unwrap();
}

pub(crate) fn authenticate(server: &SyncServer, recipe: &str) -> crate::auth::CoreAuth {
    let request = Request::builder()
        .header(
            AUTHORIZATION,
            format!(
                "{RECIPE_PREFIX}{}",
                recipe.strip_prefix(RECIPE_PREFIX).unwrap_or(recipe)
            ),
        )
        .body(Body::empty())
        .unwrap();
    let request = bind_request(server, request);
    crate::auth::CoreAuth::from_headers(request.headers(), &server.config, server.vault().as_ref())
        .unwrap()
}
pub(crate) fn bind_payload(server: &SyncServer, recipe: &str) -> serde_json::Value {
    let request = Request::builder()
        .header(
            AUTHORIZATION,
            format!(
                "{RECIPE_PREFIX}{}",
                recipe.strip_prefix(RECIPE_PREFIX).unwrap_or(recipe)
            ),
        )
        .body(Body::empty())
        .unwrap();
    let request = bind_request(server, request);
    serde_json::json!({"token":request.headers()[AUTHORIZATION].to_str().unwrap().strip_prefix("Bearer ").unwrap(),"binding":serde_json::from_str::<serde_json::Value>(request.headers()["x-oneiron-binding"].to_str().unwrap()).unwrap()})
}
