//! Request fixtures mint real logged slips before crossing the production router.
//! A request recipe is never a credential and is never sent to the router.
use crate::server::SyncServer;
use axum::body::Body;
use axum::http::{Request, header::AUTHORIZATION};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const RECIPE_PREFIX: &str = "OneironTestCredential ";

/// The host issuer seed a fixture install holds for the host `secret` its
/// server is configured with. Since FIX-LIST 3018 `SyncServer::new` roots a
/// vault with this install's own seed from its keystore, never with one the
/// secret derives, so a fixture that rebuilds the root needs the seed.
pub(crate) fn fixture_host_issuer_seed(secret: &[u8]) -> [u8; 32] {
    blake3::derive_key("oneiron-server/test/host-issuer-seed/v1", secret)
}

/// A this-device-only keystore for in-process test servers: the empty host
/// issuer seed slot takes `host_seed` on its first `create`, in place of the
/// fresh seed `Vault::bootstrap_host_slip_issuer` draws. Every other slot
/// behaves as `MemoryKeystore`. It stands in for the keystore `oneiron serve`
/// installs at open.
struct FixtureHostSeedKeystore {
    inner: oneiron_keystore::MemoryKeystore,
    host_seed: [u8; 32],
}

impl oneiron_keystore::DeviceKeystore for FixtureHostSeedKeystore {
    fn get(
        &self,
        slot: &oneiron_keystore::KeystoreSlot,
    ) -> oneiron_keystore::Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
        self.inner.get(slot)
    }

    fn create(
        &self,
        slot: &oneiron_keystore::KeystoreSlot,
        secret: &[u8; 32],
    ) -> oneiron_keystore::Result<()> {
        if slot.kind == oneiron_keystore::SlotKind::HostIssuerSeed {
            self.inner.create(slot, &self.host_seed)
        } else {
            self.inner.create(slot, secret)
        }
    }

    fn delete(&self, slot: &oneiron_keystore::KeystoreSlot) -> oneiron_keystore::Result<()> {
        self.inner.delete(slot)
    }

    fn replace(
        &self,
        slot: &oneiron_keystore::KeystoreSlot,
        secret: &[u8; 32],
    ) -> oneiron_keystore::Result<bool> {
        self.inner.replace(slot, secret)
    }

    fn locality(&self) -> oneiron_keystore::KeystoreLocality {
        oneiron_keystore::KeystoreLocality::ThisDeviceOnly
    }
}

/// Installs the fixture keystore on `vault` before `SyncServer::new`, as
/// `oneiron serve` installs its keystore at open: the server then roots the
/// vault with [`fixture_host_issuer_seed`] of `secret` (an empty `secret`
/// when the config names none), and deletes and other signing doors find
/// their keys.
pub(crate) fn install_fixture_keystore(vault: &oneiron::Vault, secret: &[u8]) {
    vault.install_device_keystore(std::sync::Arc::new(FixtureHostSeedKeystore {
        inner: oneiron_keystore::MemoryKeystore::new(),
        host_seed: fixture_host_issuer_seed(secret),
    }));
}

/// [`SyncServer::new`] over `vault` once [`install_fixture_keystore`] holds
/// the seed of the secret `config` names, as `oneiron serve` installs its
/// keystore before it serves: a server with an `auth_secret` then roots the
/// vault, and [`host_issuer`] finds that root.
pub(crate) fn server_with_fixture_keystore(
    vault: std::sync::Arc<oneiron::Vault>,
    config: crate::config::SyncServerConfig,
) -> Result<SyncServer, oneiron::Error> {
    install_fixture_keystore(
        &vault,
        config.auth_secret.as_deref().unwrap_or_default().as_bytes(),
    );
    SyncServer::new(vault, config)
}

/// The host issuer that roots `vault`, rebuilt from the `secret` its fixture
/// configured, with its authority-log signing key: the install seed
/// [`install_fixture_keystore`] gave the server, or, for a vault a fixture
/// rooted itself with `HostSlipIssuer::from_secret`, the secret. The root is
/// the candidate that signed a valid entry of the vault's authority log.
pub(crate) fn rooting_host_issuer(
    vault: &oneiron::Vault,
    secret: &[u8],
) -> (HostSlipIssuer, SigningKey) {
    use oneiron::authority::{HOST_ISSUER_SIGNING_CONTEXT, authority_entry_hash};

    let seed = fixture_host_issuer_seed(secret);
    let candidates = [
        (
            HostSlipIssuer::from_seed(&seed).expect("fixture seed issuer"),
            SigningKey::from_bytes(&blake3::derive_key(HOST_ISSUER_SIGNING_CONTEXT, &seed)),
        ),
        (
            HostSlipIssuer::from_secret(secret).expect("secret issuer"),
            SigningKey::from_bytes(&blake3::derive_key(
                "oneiron/host-authority-signing/v2",
                secret,
            )),
        ),
    ];
    let fold = vault.authority_fold().expect("authority fold");
    let mut signers = Vec::new();
    for row in vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_AUTHORITY_LOG)
        .expect("authority rows")
    {
        let entry = vault
            .get_authority_log_entry(&row)
            .expect("authority read")
            .expect("authority row decodes");
        if fold
            .valid_entries
            .contains(&authority_entry_hash(&entry).expect("entry hash"))
        {
            signers.push(entry.signer.public_key);
        }
    }
    let (issuer, signing) = candidates
        .into_iter()
        .find(|(issuer, _)| signers.contains(&issuer.public_key()))
        .expect(
            "no valid authority entry is signed by the host issuer this secret makes: \
             the vault is unrooted (install_fixture_keystore before SyncServer::new) \
             or rooted by another host",
        );
    assert_eq!(
        signing.verifying_key().to_bytes(),
        issuer.binding_key(),
        "fixture host-key re-derivation must match the issuer"
    );
    (issuer, signing)
}

/// The host root the server's vault is rooted under.
pub(crate) fn host_issuer(server: &SyncServer) -> HostSlipIssuer {
    let secret = server
        .config
        .auth_secret
        .as_deref()
        .expect("authenticated fixture needs a configured host root");
    rooting_host_issuer(server.vault(), secret.as_bytes()).0
}

pub(crate) fn credential(server: &SyncServer, recipe: &str) -> (CapabilitySlip, SigningKey) {
    let fields: BTreeMap<_, _> = recipe
        .split(';')
        .filter(|part| !part.is_empty())
        .map(|part| part.split_once('=').expect("credential recipe key/value"))
        .collect();
    let issuer = host_issuer(server);
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
    let actor_class = fields.get("actor_class").map(ToString::to_string);
    let org_ref = fields.get("org_ref").map(ToString::to_string);
    let records: BTreeSet<String> = fields
        .get("records")
        .map(|records| records.split(',').map(str::to_owned).collect())
        .unwrap_or_default();
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
    if let Some(bands) = fields.get("bands") {
        scope.bands = ScopeAxis::Some(
            bands
                .split(',')
                .map(|band| band.trim().parse().expect("credential recipe band"))
                .collect(),
        );
    }
    let cache = format!("test:api:slip:{}", hex(&id));
    if let Some(facets) = fields.get("facets") {
        scope.facets = ScopeAxis::Some(
            facets
                .split(',')
                .map(|facet| {
                    ScopeId(
                        oneiron::EntityId::from_hex(facet.trim()).expect("credential recipe facet"),
                    )
                })
                .collect(),
        );
    }
    if let Some(bytes) = server.vault().sync_state_get(&cache).unwrap() {
        let slip = CapabilitySlip::from_token(std::str::from_utf8(&bytes).unwrap()).unwrap();
        assert_eq!(
            slip.claims.holder_ref, holder_ref,
            "one fixture id cannot silently change principal"
        );
        assert_eq!(slip.claims.actor_class, actor_class);
        assert_eq!(slip.claims.org_ref, org_ref);
        assert_eq!(slip.claims.records, records);
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
    claims.records = records;
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
    bind_slip_request(server, &slip, &key, request)
}
pub(crate) fn bind_slip_request(
    server: &SyncServer,
    slip: &CapabilitySlip,
    key: &SigningKey,
    mut request: Request<Body>,
) -> Request<Body> {
    // Freshness is judged on the vault's recording clock, the wall time a
    // holder signs on; a test that steps that clock signs on the stepped one.
    let timestamp = server.vault().now_recorded_at();
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
/// Signs a real top-scope slip for a WebSocket upgrade test.
pub(crate) fn bind_ws_request(server: &SyncServer, request: &mut Request<()>, recipe: &str) {
    let (slip, key) = credential(server, recipe);
    let signed = bind_slip_request(
        server,
        &slip,
        &key,
        Request::builder().body(Body::empty()).unwrap(),
    );
    for name in ["authorization", "x-oneiron-binding"] {
        request
            .headers_mut()
            .insert(name, signed.headers()[name].clone());
    }
}

/// Engine-level reads carry the logged host root, as the authenticated server
/// does. A plain actor key reads nothing until a trusted manifest grants it.
pub(crate) fn host_reader(vault: &oneiron::Vault) -> oneiron::claim::ScopedReadActorKey {
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-host-reader").unwrap();
    let proof = vault.verified_host_root_slip(&issuer).unwrap();
    oneiron::claim::ScopedReadActorKey::from_verified_slip(&proof).unwrap()
}
pub(crate) fn revoke(server: &SyncServer, recipe: &str) {
    let (slip, _) = credential(server, recipe);
    let issuer = host_issuer(server);
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

/// Binds `actor` as a human owner under the host root `secret` names.
///
/// The host signing key is re-derived by [`rooting_host_issuer`] from the
/// seed `SyncServer::new` rooted the genesis with; the re-derivation is
/// pinned against `HostSlipIssuer::binding_key` so a core KDF move fails
/// loudly here instead of minting a signature the fold would reject.
pub(crate) fn bind_owner(vault: &oneiron::Vault, secret: &str, actor: oneiron::EntityId) {
    bind_actor(vault, secret, actor, "human");
}

/// The op that gives `host_key` the live binding `(actor, actor_class)`, or
/// `None` when it holds it already. The key holds one live binding, and a
/// self-hosted root binds the vault's embedded owner (H149), so a fixture
/// that names another actor rebinds the key one epoch on.
pub(crate) fn binding_op(
    fold: &oneiron::authority::AuthorityFold,
    host_key: &oneiron::authority::AuthorityKey,
    actor: oneiron::EntityId,
    actor_class: &str,
) -> Option<oneiron::authority::AuthorityOp> {
    use oneiron::authority::{ActorBindingStatus, AuthorityOp};
    let held = fold.actor_bindings.get(host_key);
    let live = held.filter(|binding| binding.status == ActorBindingStatus::Active);
    if live.is_some_and(|binding| binding.actor_ref == actor && binding.actor_class == actor_class)
    {
        return None;
    }
    let epoch = held.map_or(1, |binding| binding.epoch + 1);
    let (authority_key, actor_ref, actor_class) = (host_key.clone(), actor, actor_class.to_owned());
    Some(if live.is_some() {
        AuthorityOp::RebindActor {
            authority_key,
            actor_ref,
            actor_class,
            epoch,
        }
    } else {
        AuthorityOp::BindActor {
            authority_key,
            actor_ref,
            actor_class,
            epoch,
        }
    })
}

/// Binds `actor` with `actor_class` under the host root `secret` names
/// ([`rooting_host_issuer`]), as [`bind_owner`] binds a human owner.
pub(crate) fn bind_actor(
    vault: &oneiron::Vault,
    secret: &str,
    actor: oneiron::EntityId,
    actor_class: &str,
) {
    use ed25519_dalek::Signer;
    use oneiron::TimeRange;
    use oneiron::authority::{
        AUTHORITY_LOG_SCHEMA_VERSION, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        actor_binding_is_active, authority_entry_hash, authority_transcript,
    };
    use std::collections::BTreeSet;

    let (issuer, signing) = rooting_host_issuer(vault, secret.as_bytes());
    let host_key = issuer.public_key();
    let fold = vault.authority_fold().expect("authority fold");
    let vault_id = fold.vault_id.expect("host root bootstrapped");
    let Some(op) = binding_op(&fold, &host_key, actor, actor_class) else {
        return;
    };
    let mut heads: BTreeSet<[u8; 32]> = fold.valid_entries.iter().copied().collect();
    let mut seq = 0u64;
    let rows = vault
        .entities_by_type(oneiron::registry::ENTITY_TYPE_AUTHORITY_LOG)
        .expect("authority rows");
    for row in rows {
        let entry = vault
            .get_authority_log_entry(&row)
            .expect("authority read")
            .expect("authority row decodes");
        let hash = authority_entry_hash(&entry).expect("entry hash");
        if !fold.valid_entries.contains(&hash) {
            continue;
        }
        // A world's side entry is never a main-log head, and retires none.
        if matches!(
            entry.op,
            AuthorityOp::WorldPrivacy(_) | AuthorityOp::WorldKeyWraps(_)
        ) {
            heads.remove(&hash);
            continue;
        }
        for parent in &entry.parent_hashes {
            heads.remove(parent);
        }
        if entry.signer.public_key == host_key {
            seq = seq.max(entry.seq.saturating_add(1));
        }
    }
    assert!(!heads.is_empty(), "a rooted log always has a head");
    let now = vault.now_recorded_at();
    let mut bind = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: heads.into_iter().collect(),
        op,
        signer: AuthoritySignature {
            suite: host_key.suite(),
            public_key: host_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: now,
    };
    bind.signer.signature = signing
        .sign(&authority_transcript(&bind).expect("bind transcript"))
        .to_bytes()
        .to_vec();
    vault
        .put_authority_log_entry(
            &bind,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .expect("actor binding lands");
    assert!(
        actor_binding_is_active(
            &vault.authority_fold().expect("refold"),
            &actor,
            actor_class
        ),
        "fixture actor binding must fold active"
    );
}

/// The vault's embedded owner, authenticated as the owner's own act: what an
/// owner-only engine door takes, such as a booking rule amendment since
/// 439971c2702 (#4292).
pub(crate) fn embedded_owner(vault: &oneiron::Vault) -> oneiron::consent::AuthenticatedOwner {
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(
            actor,
            &actor.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("authenticate the embedded owner")
}
