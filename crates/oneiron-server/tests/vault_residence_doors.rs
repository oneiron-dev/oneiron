//! The `vault.residence` doors (ARCH-0023b's residence,
//! oneiron/sync/oneiron-arch-0023b-crdt-sync-implementation-v1.md), each
//! entered at its facade route as the app serves it:
//!
//! - :486 "Every machine except the home node syncs what it opened." and
//!   "Sync all is the switch, on the phone or on any machine.": a row naming a
//!   machine this host runs no connection for waits as the owner's directive
//!   to it, one per pending act; on the machine's own connection the switch
//!   to sync all applies, drops the opened read caches and stays chosen.
//! - :486 "a device follows only the projects it picks": the owner's world
//!   pick is what the machine records, and a pick past the cap is refused.
//! - :490 "A body that was opened stays readable offline and after a crash,
//!   while a neighbour that was never opened stays remote.": an opened item
//!   reads from this machine while its home is unreachable, again through a
//!   new connection, and a never-opened neighbour is refused on the machine.
//! - :502 "Unsynced edits are never evicted." beside :486 "unopened copies are
//!   pruned after a while": a prune drops only the read caches last touched
//!   before its cutoff; a copy touched at the cutoff and a row this machine
//!   wrote stay.
//! - Every row of the family is a host door whose proof is the owner's
//!   (scripts/sdk/verbs/vault.residence.*.json, `host_door_proof: owner`): no
//!   person or agent but the owner opens one, and a credential short of
//!   `core:write` stops at the scope guard of every write door.
//!
//! The applied leg runs on this host's own machine connection, registered
//! through `oneiron_server::test_doors::residence_connection` as the device
//! sync loop registers it. Its home is never reachable here, so every applied
//! row is one the machine answers offline. Not covered: a process restart
//! over the same store (the in-process server keeps its vault open; the new
//! connection below reads only what the store holds), the elected home's own
//! answers (no public path elects this install), the switch back to
//! sync-what-you-opened over windows held in full (each needs the home's
//! grant again), and the demotion half of :502 (no door demotes).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron-server
//! --all-features --features oneiron/test-support,oneiron/test-hooks --test
//! vault_residence_doors`.

#![cfg(all(unix, oneiron_test_support))]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    ActSurface, AgentTier, CapabilitySlip, HostSlipIssuer, MachineOwnership, MachineRole,
    holder_proof_challenge,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::residence::{WindowIndexEntry, load_device_world_pick};
use oneiron::sync::{SyncResidenceMode, WindowManager};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::residence_connection::register_residence_connection;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const MODE: &str = "vault.residence.mode";
const WORLDS: &str = "vault.residence.worlds";
const OPEN: &str = "vault.residence.open";
const INDEX: &str = "vault.residence.index";
const PRUNE: &str = "vault.residence.prune";
const DIRECTIVES: &str = "vault.residence.directives";

/// The family's doors that write: each takes `core:write` at its scope
/// guard.
const WRITE_DOORS: [&str; 4] = [MODE, WORLDS, OPEN, PRUNE];

/// The month window every opened item here comes from.
const WINDOW: &str = "2026-10";

/// The window document a first touch caches beside an item's row; a
/// MESSAGE's document is never read as a note, so its bytes are opaque.
const DOCUMENT: &[u8] = b"the window document the home sent";

/// A fixed recorded-clock cutoff (E2E memory.test.ts setup's 1769947200).
const CUTOFF: u64 = 1_769_947_200;

const READ_WRITE: &[&str] = &["core:read", "core:write"];
const READ_ONLY: &[&str] = &["core:read"];

struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
    owner: EntityId,
}

/// A caller on its own slip, signed by its own key.
struct Principal {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// Who sends a request.
#[derive(Clone, Copy)]
enum Caller<'a> {
    /// The host root slip: on a self-hosted vault it acts as the owner.
    Root,
    As(&'a Principal),
}

/// One reply: its status and its JSON (a body that is no JSON reads as its
/// text).
struct Reply {
    status: StatusCode,
    body: Value,
}

impl Reply {
    /// The body of a 200, or a failure naming the call and the reply.
    fn ok(self, call: &str) -> Value {
        assert_eq!(self.status, StatusCode::OK, "{call} answered {}", self.body);
        self.body
    }

    /// Asserts a 403 FORBIDDEN whose message holds `words`.
    fn forbidden(&self, call: &str, words: &str) {
        assert_eq!(
            self.status,
            StatusCode::FORBIDDEN,
            "{call} answered {}",
            self.body
        );
        assert_eq!(
            self.body["error"]["code"], "FORBIDDEN",
            "{call}: {}",
            self.body
        );
        assert!(
            self.message().contains(words),
            "{call} must name `{words}`: {}",
            self.body
        );
    }

    /// Asserts a 400 BAD_REQUEST whose message holds `words`.
    fn bad_request(&self, call: &str, words: &str) {
        assert_eq!(
            self.status,
            StatusCode::BAD_REQUEST,
            "{call} answered {}",
            self.body
        );
        assert_eq!(
            self.body["error"]["code"], "BAD_REQUEST",
            "{call}: {}",
            self.body
        );
        assert!(
            self.message().contains(words),
            "{call} must name `{words}`: {}",
            self.body
        );
    }

    /// Asserts the 400 a machine's refusal of `verb`'s step answers.
    fn refused_on_the_machine(&self, call: &str, verb: &str) {
        self.bad_request(call, &format!("{verb} was refused on the machine"));
    }

    fn message(&self) -> &str {
        self.body["error"]["message"].as_str().unwrap_or_default()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The `sync_state` key of `family` for `item`.
fn cache_key(family: &str, item: EntityId) -> String {
    format!("{family}{}", item.to_hex())
}

impl Host {
    fn new(secret: &str) -> Self {
        let dir = tempfile::tempdir().expect("a temporary vault directory");
        let vault =
            Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open fresh vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some(secret.into()),
                    ..Default::default()
                },
            )
            .expect("create the vault's server"),
        );
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let token = slip.to_token().expect("owner slip token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        Self {
            _dir: dir,
            vault,
            app: build_app(server),
            issuer,
            slip,
            token,
            owner,
        }
    }

    /// `caller`'s call to `verb` at its facade route, with `input` as its JSON.
    async fn call(&self, caller: Caller<'_>, verb: &str, input: Value) -> Reply {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let (token, signature) = match caller {
            Caller::Root => (
                self.token.clone(),
                hex(&self
                    .issuer
                    .binding_proof(&self.slip, &challenge)
                    .expect("owner holder proof")),
            ),
            Caller::As(principal) => (
                principal.slip.to_token().expect("caller slip token"),
                hex(&principal
                    .key
                    .sign(
                        &principal
                            .slip
                            .binding_transcript(&challenge)
                            .expect("caller binding transcript"),
                    )
                    .to_bytes()),
            ),
        };
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("the request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the app's response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the response body");
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Reply { status, body }
    }

    /// The owner's call to `verb`, which must answer 200.
    async fn owner_ok(&self, verb: &str, input: Value) -> Value {
        self.call(Caller::Root, verb, input).await.ok(verb)
    }

    /// The owner's verified proof.
    fn owner_proof(&self) -> oneiron::consent::AuthenticatedOwner {
        self.vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof")
    }

    /// A row of `kind` whose MessagePack body is the one-field map
    /// `field: value`.
    fn row(&self, kind: u8, field: &str, value: &str) -> EntityId {
        let id = EntityId::now();
        let now = self.vault.now_recorded_at();
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(rmpv::Value::from(field), rmpv::Value::from(value))]),
        )
        .expect("the row's body");
        self.vault
            .put_entity(
                &id,
                kind,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .expect("the row");
        id
    }

    /// A MESSAGE this vault holds, saying `words`: its id and its stored
    /// bytes, as a home sends them on a first touch.
    fn home_row(&self, words: &str) -> (EntityId, Vec<u8>) {
        let id = self.row(ENTITY_TYPE_MESSAGE, "content", words);
        let raw = self
            .vault
            .get_raw(&id)
            .expect("read the home's row")
            .expect("the home holds its row");
        (id, raw)
    }

    /// A second install the owner enrolled as theirs, which runs no
    /// connection on this host: its directory, held so its files outlive the
    /// test, and its machine id.
    fn enrolled_machine(&self) -> (tempfile::TempDir, EntityId) {
        let dir = tempfile::tempdir().expect("the second install's directory");
        let install =
            Vault::open(dir.path(), VaultConfig::device()).expect("open the second install");
        install.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let vault_id = self
            .vault
            .authority_vault_id()
            .expect("read the vault id")
            .expect("a rooted vault");
        let key = install
            .machine_encryption_key(vault_id)
            .expect("its encryption key");
        let request = install
            .machine_enrolment_request(vault_id, key)
            .expect("its enrolment request");
        self.vault
            .enroll_machine(
                &self.owner_proof(),
                ActSurface::ThisInstall,
                &request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("the owner enrols it");
        (dir, request.machine)
    }

    /// A sync connection over this vault, configured as a device's: it runs
    /// the persisted residence choice, sync-what-you-opened when none.
    fn connection(&self) -> SyncConnection {
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&self.vault),
            Arc::new(Materializer::new()),
            "vault-residence-doors",
        ));
        SyncConnection::new(manager, ConnectionConfig::default())
            .expect("the machine's sync connection")
    }

    /// This install's own machine, its connection registered for it as the
    /// device sync loop registers the one it runs. Its home is unreachable.
    fn connect(&self) -> (EntityId, Arc<SyncConnection>) {
        let machine = self
            .vault
            .local_machine()
            .expect("read this install's machine")
            .expect("this install's machine")
            .id;
        let connection = Arc::new(self.connection());
        register_residence_connection(machine, &connection);
        (machine, connection)
    }

    /// The read cache a first touch at the home leaves for `item` in
    /// [`WINDOW`] (SyncClient::fetch_item): the row's bytes, its window
    /// document, the window it came from, and its last touch at `touched`
    /// (recorded-clock seconds).
    fn seed_opened(&self, item: EntityId, raw: &[u8], touched: u64) {
        for (key, value) in [
            (cache_key("ri:b:", item), raw.to_vec()),
            (cache_key("ri:d:", item), DOCUMENT.to_vec()),
            (cache_key("ro:e:", item), WINDOW.as_bytes().to_vec()),
            (cache_key("rt:e:", item), touched.to_be_bytes().to_vec()),
        ] {
            self.vault
                .sync_state_put(&key, &value)
                .expect("seed the read cache");
        }
    }

    /// The thin index row a home sends for `item` in [`WINDOW`].
    fn seed_index(&self, item: EntityId, title: &str, learned_at: u64) {
        let entry = WindowIndexEntry {
            entity_id: item.to_hex(),
            title: Some(title.to_owned()),
            learned_at,
            content_world: Default::default(),
        };
        self.vault
            .sync_state_put(
                &format!("ri:w:{WINDOW}:{}", item.to_hex()),
                &rmp_serde::to_vec(&entry).expect("encode the index row"),
            )
            .expect("seed the thin index");
    }

    /// Whether this machine still holds a read cache of `item`.
    fn caches(&self, item: EntityId) -> bool {
        self.vault
            .sync_state_get(&cache_key("ro:e:", item))
            .expect("read the opened marker")
            .is_some()
            || self
                .vault
                .sync_state_get(&cache_key("ri:b:", item))
                .expect("read the cached row")
                .is_some()
    }

    /// `holder`'s own slip as a `class` caller holding `verbs`, signed by
    /// the key `seed` makes.
    fn principal(&self, holder: EntityId, class: &str, seed: u8, verbs: &[&str]) -> Principal {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.slip.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = holder.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some(class.to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
        claims.slip_id = [seed; 32];
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("mint the caller's slip");
        Principal { slip, key }
    }

    /// A live PERSON named `name`, on a human slip of its own.
    fn person(&self, name: &str, seed: u8) -> Principal {
        let id = self.row(ENTITY_TYPE_PERSON, "name", name);
        self.principal(id, "human", seed, READ_WRITE)
    }

    /// The vault's own agent `name`, bound at `tier`, on a slip of its own
    /// holding `verbs`.
    fn agent(&self, name: &str, seed: u8, tier: AgentTier, verbs: &[&str]) -> Principal {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("the vault's own agent");
        self.vault
            .bind_and_grant_agent_principal(
                &self.issuer,
                &self.owner_proof(),
                agent,
                tier.ceiling(),
            )
            .expect("bind the vault's own agent");
        self.principal(agent, "agent", seed, verbs)
    }
}

/// ARCH-0023b :486 "Every machine except the home node syncs what it
/// opened." The owner's rows naming a machine this host runs no connection
/// for each wait as one directive to it, holding the act the row asked for,
/// with no result yet; a row repeated while its directive waits answers the
/// same directive. A machine the owner never enrolled takes no directive,
/// and a malformed window or directive read is refused before any.
#[test]
fn a_row_for_a_machine_this_host_never_reaches_waits_as_one_directive_per_act() {
    run_on_engine_stack("residence-doors-queued", || async {
        let host = Host::new("vault-residence-doors-queued");
        let (_install, machine) = host.enrolled_machine();
        let machine = machine.to_hex();
        let item = EntityId::now().to_hex();
        let world = EntityId::now().to_hex();
        let rows: Vec<(&str, Value, Value)> = vec![
            (
                MODE,
                json!({"machine": machine, "mode": "opened"}),
                json!({"kind": "sync_opened"}),
            ),
            (
                MODE,
                json!({"machine": machine, "mode": "all"}),
                json!({"kind": "sync_all"}),
            ),
            (
                WORLDS,
                json!({"machine": machine, "worlds": [world]}),
                json!({"kind": "follow", "worlds": [world]}),
            ),
            (
                OPEN,
                json!({"machine": machine, "window": WINDOW, "item": item}),
                json!({"kind": "open", "window": WINDOW, "item": item}),
            ),
            (INDEX, json!({"machine": machine}), json!({"kind": "index"})),
            (
                PRUNE,
                json!({"machine": machine, "before": CUTOFF}),
                json!({"kind": "prune", "before": CUTOFF}),
            ),
        ];

        let mut waiting: BTreeMap<String, Value> = BTreeMap::new();
        for (verb, input, act) in &rows {
            let answer = host.owner_ok(verb, input.clone()).await;
            assert_eq!(answer["state"], "queued", "{verb}: {answer}");
            assert_eq!(answer["machine"], machine, "{verb}: {answer}");
            let directive = answer["directive"]
                .as_str()
                .unwrap_or_else(|| panic!("{verb} names its directive: {answer}"))
                .to_owned();
            assert!(
                waiting.insert(directive, act.clone()).is_none(),
                "{verb} {act} waits as a directive of its own: {answer}"
            );
        }

        // The same open again, while its directive waits: the same directive.
        let (_, open, open_act) = &rows[3];
        let again = host.owner_ok(OPEN, open.clone()).await;
        assert_eq!(again["state"], "queued", "{again}");
        let repeated = again["directive"].as_str().expect("a directive id");
        assert_eq!(waiting.get(repeated), Some(open_act), "{again}");

        // Each directive reads back with its act, its machine and no result.
        let listed = host.owner_ok(DIRECTIVES, json!({"machine": machine})).await;
        let listed = listed.as_array().expect("a directive list");
        assert_eq!(listed.len(), rows.len(), "one per act: {listed:?}");
        for row in listed {
            let directive = row["directive"].as_str().expect("a directive id");
            assert_eq!(
                waiting.get(directive),
                Some(&row["act"]),
                "the act its row asked for: {row}"
            );
            assert_eq!(row["machine"], machine, "{row}");
            assert_eq!(row["result"], Value::Null, "nothing ran yet: {row}");
        }
        let one = host
            .owner_ok(DIRECTIVES, json!({"directive": repeated}))
            .await;
        assert_eq!(one.as_array().map(Vec::len), Some(1), "{one}");
        assert_eq!(&one[0]["act"], open_act, "{one}");

        // A machine the owner never enrolled takes no directive.
        let stranger = EntityId::now().to_hex();
        host.call(
            Caller::Root,
            MODE,
            json!({"machine": stranger, "mode": "all"}),
        )
        .await
        .bad_request(
            MODE,
            "a residence directive names one of the owner's machines",
        );
        assert_eq!(
            host.owner_ok(DIRECTIVES, json!({"machine": stranger}))
                .await,
            json!([])
        );

        // A malformed row is refused before anything waits.
        host.call(
            Caller::Root,
            OPEN,
            json!({"machine": machine, "window": "October", "item": item}),
        )
        .await
        .bad_request(OPEN, "window must be YYYY-MM");
        host.call(
            Caller::Root,
            DIRECTIVES,
            json!({"machine": machine, "directive": repeated}),
        )
        .await
        .bad_request(
            DIRECTIVES,
            "vault.residence.directives names exactly one of machine or directive",
        );
        let after = host.owner_ok(DIRECTIVES, json!({"machine": machine})).await;
        assert_eq!(after.as_array().map(Vec::len), Some(rows.len()), "{after}");
    })
}

/// ARCH-0023b :486 "Sync all is the switch, on the phone or on any machine."
/// On the machine's own connection the owner's switch applies at once: a
/// machine syncing what it opened serves its thin index; the switch to sync
/// all drops its opened read caches, stops serving that index, and stays
/// chosen for the next connection over the same store. Nothing waits as a
/// directive for a machine the host reaches.
#[test]
fn the_switch_to_sync_all_applies_on_the_machine_and_drops_its_opened_copies() {
    run_on_engine_stack("residence-doors-switch", || async {
        let host = Host::new("vault-residence-doors-switch");
        let home = Host::new("vault-residence-doors-switch-home");
        let (item, raw) = home.home_row("the harbour log the phone opened once");
        let (machine, connection) = host.connect();
        let machine_hex = machine.to_hex();
        host.seed_opened(item, &raw, CUTOFF);
        host.seed_index(item, "Harbour log", CUTOFF);

        let opened = host
            .owner_ok(MODE, json!({"machine": machine_hex, "mode": "opened"}))
            .await;
        assert_eq!(
            opened,
            json!({
                "state": "applied", "mode": "opened", "retained": [], "unsynced": [],
                "pruned_items": 0,
            })
        );
        let index = host.owner_ok(INDEX, json!({"machine": machine_hex})).await;
        assert_eq!(
            index,
            json!({
                "state": "applied",
                "windows": [{
                    "window": WINDOW,
                    "items": [{"entity_id": item.to_hex(), "title": "Harbour log", "learned_at": CUTOFF}],
                }],
            })
        );

        let all = host
            .owner_ok(MODE, json!({"machine": machine_hex, "mode": "all"}))
            .await;
        assert_eq!(
            all,
            json!({
                "state": "applied", "mode": "all", "retained": [], "unsynced": [],
                "pruned_items": 1,
            })
        );
        assert_eq!(connection.residence_mode(), SyncResidenceMode::All);
        assert!(!host.caches(item), "sync all drops the opened read cache");
        host.call(Caller::Root, INDEX, json!({"machine": machine_hex}))
            .await
            .refused_on_the_machine(INDEX, INDEX);

        // The choice stays: a new connection over this store runs sync all.
        assert_eq!(host.connection().residence_mode(), SyncResidenceMode::All);
        assert_eq!(
            host.owner_ok(DIRECTIVES, json!({"machine": machine_hex}))
                .await,
            json!([]),
            "a reached machine takes the row itself, never a directive"
        );
    })
}

/// ARCH-0023b :490 "A body that was opened stays readable offline and after
/// a crash, while a neighbour that was never opened stays remote." With its
/// home unreachable, the machine opens an item it opened before from its own
/// read cache, and stamps the touch; a neighbour it never opened is refused
/// on the machine and leaves nothing cached. A new connection over the same
/// store (the machine's sync started again) opens the same body.
#[test]
fn an_opened_body_reads_on_the_machine_offline_and_a_neighbour_stays_remote() {
    run_on_engine_stack("residence-doors-offline-open", || async {
        let host = Host::new("vault-residence-doors-offline-open");
        let home = Host::new("vault-residence-doors-offline-open-home");
        let (item, raw) = home.home_row("the tide table opened on the boat");
        let (neighbour, _) = home.home_row("the crew list nobody opened here");
        let (machine, connection) = host.connect();
        let machine_hex = machine.to_hex();
        host.seed_opened(item, &raw, CUTOFF);
        let open = json!({"machine": machine_hex, "window": WINDOW, "item": item.to_hex()});

        let first = host.owner_ok(OPEN, open.clone()).await;
        assert_eq!(first["state"], "applied", "{first}");
        assert_eq!(first["item"], item.to_hex(), "{first}");
        assert_eq!(first["window"], WINDOW, "{first}");
        assert_eq!(first["residence"], "thin", "{first}");
        assert_eq!(first["source"], "local", "read on this machine: {first}");
        assert_eq!(first["bytes"], json!(raw.len() + DOCUMENT.len()), "{first}");
        let touched = host
            .vault
            .sync_state_get(&cache_key("rt:e:", item))
            .expect("read the touch")
            .expect("the open's touch");
        let touched = u64::from_be_bytes(touched.try_into().expect("an 8-byte touch"));
        assert!(touched > CUTOFF, "an open stamps its touch: {touched}");

        host.call(
            Caller::Root,
            OPEN,
            json!({"machine": machine_hex, "window": WINDOW, "item": neighbour.to_hex()}),
        )
        .await
        .refused_on_the_machine(OPEN, OPEN);
        assert!(!host.caches(neighbour), "the neighbour stays remote");

        drop(connection);
        let (_, _restarted) = host.connect();
        let again = host.owner_ok(OPEN, open).await;
        assert_eq!(again, first, "the same body through a new connection");
    })
}

/// ARCH-0023b :502 "Unsynced edits are never evicted." beside :486
/// "unopened copies are pruned after a while". The owner's prune drops each
/// read cache last touched before its cutoff and keeps one touched at it; a
/// row this machine wrote and never synced is no cache and stays. Both kept
/// items still open on the machine; the dropped one is remote again.
#[test]
fn a_prune_drops_only_copies_untouched_since_its_cutoff_and_never_a_local_edit() {
    run_on_engine_stack("residence-doors-prune", || async {
        let host = Host::new("vault-residence-doors-prune");
        let home = Host::new("vault-residence-doors-prune-home");
        let (stale, stale_raw) = home.home_row("a rota opened last winter");
        let (fresh, fresh_raw) = home.home_row("a rota opened at the cutoff");
        let (machine, _connection) = host.connect();
        let machine_hex = machine.to_hex();
        host.seed_opened(stale, &stale_raw, CUTOFF - 1);
        host.seed_opened(fresh, &fresh_raw, CUTOFF);
        let edit = host.row(
            ENTITY_TYPE_MESSAGE,
            "content",
            "a line written on this machine that never reached its home",
        );
        let edit_raw = host
            .vault
            .get_raw(&edit)
            .expect("read the edit")
            .expect("the edit");

        assert_eq!(
            host.owner_ok(PRUNE, json!({"machine": machine_hex, "before": 0}))
                .await,
            json!({"state": "applied", "dropped": 0}),
            "nothing was touched before zero"
        );
        assert_eq!(
            host.owner_ok(PRUNE, json!({"machine": machine_hex, "before": CUTOFF}))
                .await,
            json!({"state": "applied", "dropped": 1})
        );
        assert!(!host.caches(stale), "the stale copy is dropped");
        assert!(host.caches(fresh), "the copy touched at the cutoff stays");
        assert_eq!(
            host.vault.get_raw(&edit).expect("read the edit"),
            Some(edit_raw.clone()),
            "the unsynced edit stays as written"
        );

        let open = |item: EntityId| json!({"machine": machine_hex, "window": WINDOW, "item": item.to_hex()});
        let kept = host.owner_ok(OPEN, open(fresh)).await;
        assert_eq!(kept["residence"], "thin", "{kept}");
        assert_eq!(kept["source"], "local", "{kept}");
        let written = host.owner_ok(OPEN, open(edit)).await;
        assert_eq!(written["residence"], "resident", "{written}");
        assert_eq!(written["source"], "local", "{written}");
        assert_eq!(written["bytes"], json!(edit_raw.len()), "{written}");
        host.call(Caller::Root, OPEN, open(stale))
            .await
            .refused_on_the_machine(OPEN, OPEN);
    })
}

/// ARCH-0023b :486 "a device follows only the projects it picks". The
/// owner's world pick applies on the machine as the set it names, replacing
/// the pick before, and an empty pick follows none; a pick past the cap is
/// refused on the machine and leaves the pick before.
#[test]
fn the_owner_picks_the_worlds_a_machine_follows_up_to_the_cap() {
    run_on_engine_stack("residence-doors-worlds", || async {
        let host = Host::new("vault-residence-doors-worlds");
        let (machine, _connection) = host.connect();
        let machine_hex = machine.to_hex();
        let first = EntityId::now();
        let second = EntityId::now();
        let pick: BTreeSet<EntityId> = [first, second].into_iter().collect();
        let named: Vec<String> = pick.iter().map(EntityId::to_hex).collect();

        let picked = host
            .owner_ok(
                WORLDS,
                json!({
                    "machine": machine_hex,
                    "worlds": [second.to_hex(), first.to_hex(), second.to_hex()],
                }),
            )
            .await;
        assert_eq!(picked, json!({"state": "applied", "worlds": named}));
        assert_eq!(
            load_device_world_pick(&host.vault).expect("read the pick"),
            pick
        );

        let none = host
            .owner_ok(WORLDS, json!({"machine": machine_hex, "worlds": []}))
            .await;
        assert_eq!(none, json!({"state": "applied", "worlds": []}));
        assert!(
            load_device_world_pick(&host.vault)
                .expect("read the pick")
                .is_empty(),
            "an empty pick follows none"
        );

        host.call(
            Caller::Root,
            WORLDS,
            json!({"machine": machine_hex, "worlds": [first.to_hex()]}),
        )
        .await
        .ok(WORLDS);
        let too_many: Vec<String> = (0..257).map(|_| EntityId::now().to_hex()).collect();
        let refused = host
            .call(
                Caller::Root,
                WORLDS,
                json!({"machine": machine_hex, "worlds": too_many}),
            )
            .await;
        refused.refused_on_the_machine(WORLDS, WORLDS);
        refused.bad_request(WORLDS, "a world pick names too many worlds");
        assert_eq!(
            load_device_world_pick(&host.vault).expect("read the pick"),
            [first].into_iter().collect::<BTreeSet<_>>(),
            "the pick before stays"
        );
    })
}

/// Every row of the family is the owner's (`host_door_proof: owner`). A
/// PERSON and a FullAccess agent, each holding `core:read` and `core:write`,
/// are refused at all six doors as the owner's; a ReadOnly agent holding only
/// `core:read` stops at the scope guard of the four write doors and is
/// refused as the owner's at the two reads. No refused row queues a
/// directive; the same row then waits for the owner.
#[test]
fn no_residence_door_opens_for_anyone_but_the_owner() {
    run_on_engine_stack("residence-doors-owner-only", || async {
        let host = Host::new("vault-residence-doors-owner-only");
        let (_install, machine) = host.enrolled_machine();
        let machine = machine.to_hex();
        let mina = host.person("Mina Okafor", 0xa1);
        let keeper = host.agent("residence-keeper", 0xa2, AgentTier::FullAccess, READ_WRITE);
        let reader = host.agent("residence-reader", 0xa3, AgentTier::ReadOnly, READ_ONLY);
        let doors: Vec<(&str, Value)> = vec![
            (MODE, json!({"machine": machine, "mode": "all"})),
            (
                WORLDS,
                json!({"machine": machine, "worlds": [EntityId::now().to_hex()]}),
            ),
            (
                OPEN,
                json!({"machine": machine, "window": WINDOW, "item": EntityId::now().to_hex()}),
            ),
            (INDEX, json!({"machine": machine})),
            (PRUNE, json!({"machine": machine, "before": CUTOFF})),
            (DIRECTIVES, json!({"machine": machine})),
        ];

        for caller in [&mina, &keeper] {
            for (verb, input) in &doors {
                host.call(Caller::As(caller), verb, input.clone())
                    .await
                    .forbidden(verb, &format!("{verb} is the vault owner's"));
            }
        }
        for (verb, input) in &doors {
            let reply = host.call(Caller::As(&reader), verb, input.clone()).await;
            if WRITE_DOORS.contains(verb) {
                reply.forbidden(verb, "required scope");
            } else {
                reply.forbidden(verb, &format!("{verb} is the vault owner's"));
            }
        }

        assert_eq!(
            host.owner_ok(DIRECTIVES, json!({"machine": machine})).await,
            json!([]),
            "no refused row queued a directive"
        );
        let (_, mode) = &doors[0];
        let queued = host.owner_ok(MODE, mode.clone()).await;
        assert_eq!(queued["state"], "queued", "{queued}");
    })
}
