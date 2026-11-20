//! Promise tests for the pack doors (ruling L4-23 = A: each test proves a
//! promise at its door): `vault.packs.put`, `.get`, `.preview`, `.remove`,
//! `.install`, `.sync`, `.hooks.list`, `.hooks.bind`, `.hooks.grant.get` and
//! `.hooks.grant.set`, `.connector.get`, `.sections.grant` and
//! `.sections.revoke`, each entered at its generated HTTP facade route,
//! `POST /v1/core/facade/<verb>`.
//!
//! The promises, one test each:
//! - The installed packs and their hooks answer their owner alone: a person,
//!   an agent that holds no grant and another vault's credential are refused
//!   at every owner door of the family, the refusal is the same for a pack or
//!   a binding that exists and one that does not, and a refused remove, bind,
//!   grant or put moves nothing. The owner's remove lands and stops the hook.
//! - A hook reads under the grant its owner sets (canon ARCH-0080 :343-344,
//!   "Every hook has a grant. The owner can set or change it by hand at any
//!   time"; "The default grant is the author's ceiling. For the owner's
//!   hooks, that is the owner's own reach"): the owner's hook starts at that
//!   ceiling, no other caller sets or reads its grant, and the owner's own
//!   narrowing lands where the hook list and the grant read both show it.
//! - An agent puts the local pack alone (ARCH-0080 :439, "The owner and
//!   resident agents write into it with `vault.packs.put`"; :495, an agent's
//!   hook lands "Active at its ceiling"; :344, "For an agent's hook, it is
//!   that agent's ceiling"): an agent's put under the owner's pack name is
//!   refused and replaces nothing; a person's put is refused with the agent's
//!   path beside it; the agent's own put of `local` lands, its hook bound as
//!   the agent's and reading at the agent's reach, never the owner's.
//!
//! Left out: the success paths that need a hub, a sandbox or a live endpoint
//! (install, sync, hooks.qualify, the connector doors), the guided setup
//! doors and the plugin section offer, which later files cover.
//!
//! The owner calls on the host-root credential of a profiled install, as a
//! serving start enrols it; a person and an agent on a slip of their own,
//! signed by their own key. The packs are sent as files, as the facade takes
//! them. Deterministic: an in-process vault and router (`oneshot`), no TCP
//! port, no sleep, no hub, no hook run.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_packs_owner_doors`.

#![cfg(all(unix, oneiron_test_support))]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    AgentTier, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const PUT: &str = "vault.packs.put";
const GET: &str = "vault.packs.get";
const PREVIEW: &str = "vault.packs.preview";
const REMOVE: &str = "vault.packs.remove";
const INSTALL: &str = "vault.packs.install";
const SYNC: &str = "vault.packs.sync";
const HOOKS_LIST: &str = "vault.packs.hooks.list";
const HOOKS_BIND: &str = "vault.packs.hooks.bind";
const GRANT_GET: &str = "vault.packs.hooks.grant.get";
const GRANT_SET: &str = "vault.packs.hooks.grant.set";
const CONNECTOR_GET: &str = "vault.packs.connector.get";
const SECTIONS_GRANT: &str = "vault.packs.sections.grant";
const SECTIONS_REVOKE: &str = "vault.packs.sections.revoke";

/// The owner's pack: an author-scoped name, as a hub pack has.
const PACK: &str = "example.packsdoors";
/// Its one fact hook.
const HOOK: &str = "fact-note";
/// The predicate the hook watches: no refusal may name it.
const WATCHED: &str = "example.packsdoors.input";
/// The vault's own pack, which vault open creates.
const LOCAL: &str = "local";
/// The hook the agent writes into `local`.
const LOCAL_HOOK: &str = "agent-note";
/// The suggestion a pack setup door's refusal adds to the owner's.
const AGENT_PATH: &str =
    "Or present an agent's own slip: an agent acting for the owner may call this door.";

/// One served vault: the owner on the host root of a profiled install.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

/// A person or an agent on its own slip, signed by its own key.
struct Principal {
    id: EntityId,
    slip: CapabilitySlip,
    key: SigningKey,
}

/// Who sends a request: this vault's owner on the host root, another
/// vault's owner on that vault's host root, or a principal.
#[derive(Clone, Copy)]
enum Caller<'a> {
    Owner,
    Stranger(&'a Host),
    As(&'a Principal),
}

/// One reply: its status and its JSON.
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

    /// Asserts `verb`'s owner refusal of `caller`: another vault's
    /// credential is refused before any door (401 or 403); a person or an
    /// agent of this vault meets the door's `<verb> is the vault owner's`.
    fn refused(&self, call: &str, verb: &str, caller: Caller<'_>) {
        if matches!(caller, Caller::Stranger(_)) {
            assert!(
                matches!(
                    self.status,
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                ),
                "{call} answered {}",
                self.body
            );
            return;
        }
        assert_eq!(
            self.status,
            StatusCode::FORBIDDEN,
            "{call} answered {}",
            self.body
        );
        assert_eq!(self.body["error"]["code"], "FORBIDDEN", "{call}");
        assert_eq!(
            self.body["error"]["message"],
            format!("{verb} is the vault owner's"),
            "{call}"
        );
    }

    /// Asserts a pack setup door's refusal of a person: the owner's refusal,
    /// with the agent's path beside it.
    fn refused_with_agent_path(&self, call: &str, verb: &str, caller: Caller<'_>) {
        self.refused(call, verb, caller);
        assert!(
            self.body["error"]["suggestions"]
                .as_array()
                .is_some_and(|suggestions| suggestions.iter().any(|line| line == AGENT_PATH)),
            "{call} names the agent's path: {}",
            self.body
        );
    }

    /// The refusal as a caller can compare it: status, code, message and
    /// suggestions. The request id differs per call.
    fn refusal(&self) -> Value {
        let error = &self.body["error"];
        json!({
            "status": self.status.as_u16(),
            "code": error["code"],
            "message": error["message"],
            "suggestions": error["suggestions"],
        })
    }

    /// Asserts that the reply holds none of `words`.
    fn holds_none(&self, call: &str, words: &[&str]) {
        let text = self.body.to_string();
        for word in words {
            assert!(!text.contains(word), "{call} holds `{word}`: {text}");
        }
    }
}

/// A host whose vault serves the facade; its owner is the vault's embedded
/// owner, on the host root. The install's signing keys load as a serving
/// start loads them.
fn host() -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-packs-owner-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    Host {
        _dir: dir,
        vault,
        app: build_app(server),
        issuer,
        owner,
        owner_slip,
        owner_token,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One text file of a pack folder, as the facade takes it.
fn file(path: &str, text: &str) -> Value {
    json!({"path": path, "text": text})
}

/// The owner's pack: one fact hook on [`WATCHED`] claims whose body is
/// `body`.
fn hook_pack(body: &str) -> Value {
    json!([
        file(
            "PACK.md",
            "---\nname: example.packsdoors\ndescription: One fact hook the door tests bind.\n\
             version: 1.0.0\nkind: capability\nhooks: [\"fact-note\"]\n---\n\
             A pack whose one fact hook the owner's put binds.\n",
        ),
        file(
            "hooks/fact-note/HOOK.md",
            "---\nname: fact-note\nversion: 1.0.0\n\
             verbs: [\"claim.landed:example.packsdoors.input\"]\nactors: [\"human\"]\n\
             phase: fact\noutcomes: [\"propose\"]\n---\nPropose one note per landed input claim.\n",
        ),
        file("hooks/fact-note/body.js", body),
        file(
            "hooks/fact-note/intent.md",
            "Propose one note per landed input claim.\n",
        ),
    ])
}

/// The owner's hook body.
const BODY_JS: &str = concat!(
    "return {\n",
    "  kind: \"propose\",\n",
    "  claim: {\n",
    "    subject: input.claim.subject,\n",
    "    predicate: \"example.packsdoors.note\",\n",
    "    confidence: 1,\n",
    "    value: { note: input.claim.value }\n",
    "  }\n",
    "};\n",
);

/// A changed body: a put or a preview of it would replace the owner's hook.
const OTHER_BODY_JS: &str = "return { kind: \"nothing\" };\n";

/// A pack under the owner's pack name with no hook: put by anyone but the
/// owner, it would take the owner's pack over.
fn takeover_pack() -> Value {
    json!([file(
        "PACK.md",
        "---\nname: example.packsdoors\ndescription: The same name with no hook.\nversion: 2.0.0\n\
         kind: capability\n---\nA pack that would replace the owner's.\n",
    )])
}

/// The vault's `local` pack with one fact hook of the agent's own, which
/// does nothing.
fn local_pack() -> Value {
    json!([
        file(
            "PACK.md",
            "---\nname: local\ndescription: This vault's own hooks.\nversion: 1\n\
             kind: capability\nhooks: [\"agent-note\"]\n---\nLocal pack.\n",
        ),
        file(
            "hooks/agent-note/HOOK.md",
            "---\nname: agent-note\nversion: 1.0.0\n\
             verbs: [\"claim.landed:example.packsdoors.local\"]\nphase: fact\n\
             outcomes: [\"nothing\"]\n---\nagent-note watches its input.\n",
        ),
        file(
            "hooks/agent-note/intent.md",
            "Watch example.packsdoors.local claims and do nothing.\n",
        ),
        file("hooks/agent-note/body.js", "return {kind: \"nothing\"};"),
    ])
}

/// An install input that decodes: a hub ref to a hub this vault never
/// configured. The owner door refuses before any fetch.
fn install_input() -> Value {
    json!({
        "hub_ref": {
            "hub_id": EntityId::now().to_hex(),
            "ref_string": ".",
            "pin": {"type": "commit", "value": "0123456789abcdef0123456789abcdef01234567"},
        },
        "publisher": "example",
    })
}

/// A grant whose reader is `reader` of `class`, showing `predicates` only.
fn grant(reader: &Value, class: &str, predicates: &[&str]) -> Value {
    json!({
        "reader": reader,
        "reader_class": class,
        "predicates": predicates,
        "worlds": [],
    })
}

impl Host {
    fn owner_proof(&self) -> AuthenticatedOwner {
        self.vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof")
    }

    /// `holder`'s own slip as a `class` caller that allows `verbs`, signed
    /// by the key `seed` makes.
    fn principal(&self, holder: EntityId, class: &str, seed: u8, verbs: &[&str]) -> Principal {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.owner_slip.claims.clone();
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
        Principal {
            id: holder,
            slip,
            key,
        }
    }

    /// A person named `name` whom this vault knows, on a read-and-write
    /// human slip of their own.
    fn person(&self, name: &str, seed: u8) -> Principal {
        let id = EntityId::now();
        let now = self.vault.now_recorded_at();
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
        )
        .expect("the person's PERSON body");
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .expect("the person's PERSON row");
        self.principal(id, "human", seed, &["core:read", "core:write"])
    }

    /// The vault's own agent `name`, bound with full access, on its own
    /// read-and-write slip. It holds no grant.
    fn agent(&self, name: &str, seed: u8) -> Principal {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("the vault's own agent");
        self.vault
            .bind_and_grant_agent_principal(
                &self.issuer,
                &self.owner_proof(),
                agent,
                AgentTier::FullAccess.ceiling(),
            )
            .expect("bind the vault's own agent");
        self.principal(agent, "agent", seed, &["core:read", "core:write"])
    }

    /// `caller`'s call to `verb` at its facade route, sent to this host.
    async fn send(&self, caller: Caller<'_>, verb: &str, input: Value) -> Reply {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let root = |host: &Host| {
            (
                host.owner_token.clone(),
                hex(&host
                    .issuer
                    .binding_proof(&host.owner_slip, &challenge)
                    .expect("owner holder proof")),
            )
        };
        let (token, signature) = match caller {
            Caller::Owner => root(self),
            Caller::Stranger(other) => root(other),
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
        let binding =
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("facade response body");
        // An authentication refusal may answer text, not the JSON envelope.
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Reply { status, body }
    }

    /// The owner's 200 answer at `verb`.
    async fn owner_call(&self, verb: &str, input: Value) -> Value {
        self.send(Caller::Owner, verb, input).await.ok(verb)
    }

    /// The owner's put of the hook pack; answers its install receipt.
    async fn put_owner_pack(&self) -> Value {
        let put = self
            .owner_call(PUT, json!({"files": hook_pack(BODY_JS)}))
            .await;
        assert_eq!(put["outcome"], "installed", "{put}");
        assert_eq!(put["receipt"]["pack_name"], PACK, "{put}");
        assert_eq!(put["receipt"]["status"], "active", "{put}");
        put["receipt"].clone()
    }

    /// The installed receipt of the pack `name`, or null.
    async fn pack(&self, name: &str) -> Value {
        self.owner_call(GET, json!({"name": name})).await
    }

    /// The hook list row of `hook` in `pack`.
    async fn hook_row(&self, pack: &str, hook: &str) -> Value {
        let rows = self.owner_call(HOOKS_LIST, json!({})).await;
        let mut matching = rows
            .as_array()
            .expect("the hook list")
            .iter()
            .filter(|row| row["binding"]["pack"] == pack && row["binding"]["hook"] == hook);
        let row = matching
            .next()
            .unwrap_or_else(|| panic!("{pack}/{hook} is bound: {rows}"))
            .clone();
        assert!(matching.next().is_none(), "one binding: {rows}");
        row
    }
}

/// The installed packs and their hooks answer their owner alone. A person on
/// their own slip, a full-access agent that holds no grant and another
/// vault's owner are refused at every owner door of the family: the pack
/// reads (get, preview, the hook list, a hook's grant), its acts (remove,
/// install, sync, the hook bind, a hook's grant set) and the connector and
/// section doors. No refusal names the pack, its hook or its binding, and a
/// refusal is the same for what exists and what does not. A person's put is
/// refused with the agent's path beside it. Nothing a refused call names
/// moves; the owner's own remove lands and stops the hook.
#[test]
fn the_installed_packs_answer_their_owner_alone() {
    run_on_engine_stack("packs-owner-doors", || async {
        let (home, elsewhere) = (host(), host());
        let installed = home.put_owner_pack().await;
        let pack = home.pack(PACK).await;
        assert_eq!(pack["pack_name"], PACK, "{pack}");
        assert_eq!(pack["content_hash"], installed["content_hash"], "{pack}");
        let row = home.hook_row(PACK, HOOK).await;
        assert_eq!(
            row["binding"]["enabled"], true,
            "the owner's hook runs: {row}"
        );
        let binding = row["id"].as_str().expect("the binding id").to_owned();
        let hooks = home.owner_call(HOOKS_LIST, json!({})).await;
        let held = home
            .owner_call(GRANT_GET, json!({"binding": binding}))
            .await;
        let person = home.person("Mina Okafor", 0x61);
        let agent = home.agent("packs-doors-agent", 0x62);
        let made_up = EntityId::now().to_hex();
        let narrowed = grant(&row["binding"]["owner"], "human", &[WATCHED]);

        let doors = [
            (GET, json!({"name": PACK})),
            (PREVIEW, json!({"files": hook_pack(OTHER_BODY_JS)})),
            (REMOVE, json!({"pack": PACK})),
            (INSTALL, install_input()),
            (SYNC, json!({"name": PACK})),
            (HOOKS_LIST, json!({})),
            (HOOKS_BIND, json!({"pack": PACK})),
            (GRANT_GET, json!({"binding": binding})),
            (GRANT_SET, json!({"binding": binding, "grant": narrowed})),
            (CONNECTOR_GET, json!({"connector": PACK})),
            (SECTIONS_GRANT, json!({"claim_ref": made_up})),
            (SECTIONS_REVOKE, json!({"claim_ref": made_up})),
        ];
        for (who, caller) in [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&elsewhere)),
        ] {
            for (verb, input) in &doors {
                let call = format!("{who} at {verb}");
                let reply = home.send(caller, verb, input.clone()).await;
                reply.refused(&call, verb, caller);
                reply.holds_none(&call, &[PACK, HOOK, binding.as_str(), WATCHED]);
            }
        }

        // A refusal names nothing: the same for a pack or a binding that
        // exists and one that does not.
        for (who, caller) in [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
        ] {
            for (verb, real, absent) in [
                (
                    GET,
                    json!({"name": PACK}),
                    json!({"name": "example.absent"}),
                ),
                (
                    REMOVE,
                    json!({"pack": PACK}),
                    json!({"pack": "example.absent"}),
                ),
                (
                    GRANT_GET,
                    json!({"binding": binding}),
                    json!({"binding": made_up}),
                ),
            ] {
                assert_eq!(
                    home.send(caller, verb, real).await.refusal(),
                    home.send(caller, verb, absent).await.refusal(),
                    "{who} at {verb}: a refusal is the same for what exists and what does not"
                );
            }
        }

        // The put is the pack setup door: a person is refused with the
        // agent's path beside the owner's; another vault's owner never
        // reaches it.
        let replace = json!({"files": hook_pack(OTHER_BODY_JS)});
        home.send(Caller::As(&person), PUT, replace.clone())
            .await
            .refused_with_agent_path("person at the put", PUT, Caller::As(&person));
        home.send(Caller::Stranger(&elsewhere), PUT, replace)
            .await
            .refused(
                "another vault's owner at the put",
                PUT,
                Caller::Stranger(&elsewhere),
            );

        assert_eq!(
            home.pack(PACK).await,
            pack,
            "a refused put or remove moves nothing"
        );
        assert_eq!(
            home.owner_call(HOOKS_LIST, json!({})).await,
            hooks,
            "a refused bind or grant moves no hook"
        );
        assert_eq!(
            home.owner_call(GRANT_GET, json!({"binding": binding}))
                .await,
            held,
            "a refused grant set moves no grant"
        );

        let removed = home.owner_call(REMOVE, json!({"pack": PACK})).await;
        assert_eq!(removed["pack_name"], PACK, "{removed}");
        assert_eq!(
            home.pack(PACK).await,
            Value::Null,
            "the owner's remove lands"
        );
        let after = home.hook_row(PACK, HOOK).await;
        assert_eq!(
            after["binding"]["enabled"], false,
            "the removed pack's hook stops: {after}"
        );
    });
}

/// A hook reads under the grant its owner sets: canon
/// `oneiron/agents/oneiron-arch-0080-runtime-hooks-v1.md:343`, "Every hook
/// has a grant. The owner can set or change it by hand at any time", and
/// :344, "The default grant is the author's ceiling. For the owner's hooks,
/// that is the owner's own reach". The owner's hook starts at the owner's
/// reach. A person, a full-access agent that holds no grant and another
/// vault's owner are refused when they set it to read as themselves, the
/// refusal is the same for a binding that does not exist, and the grant
/// stays. The owner's narrowing to the watched predicate lands; the grant
/// read and the hook list both show it, and no other caller reads it.
#[test]
fn a_hook_reads_under_the_grant_its_owner_sets() {
    run_on_engine_stack("packs-hook-grant", || async {
        let (home, elsewhere) = (host(), host());
        home.put_owner_pack().await;
        let row = home.hook_row(PACK, HOOK).await;
        let binding = row["id"].as_str().expect("the binding id").to_owned();
        assert_eq!(row["binding"]["author"], json!({"kind": "owner"}), "{row}");
        let owner = row["binding"]["owner"].clone();
        let ceiling = grant(&owner, "human", &[]);
        assert_eq!(
            row["grant"], ceiling,
            "the owner's hook reads at the owner's own reach: {row}"
        );
        assert_eq!(
            home.owner_call(GRANT_GET, json!({"binding": binding}))
                .await,
            json!({"binding": binding, "grant": ceiling})
        );
        let person = home.person("Tomas Rell", 0x71);
        let agent = home.agent("hook-grant-agent", 0x72);

        for (who, caller, reader, class) in [
            ("person", Caller::As(&person), person.id.to_hex(), "human"),
            ("agent", Caller::As(&agent), agent.id.to_hex(), "agent"),
            (
                "another vault's owner",
                Caller::Stranger(&elsewhere),
                elsewhere.owner.to_hex(),
                "human",
            ),
        ] {
            let call = format!("{who} at {GRANT_SET}");
            let own = grant(&json!(reader), class, &[]);
            let reply = home
                .send(caller, GRANT_SET, json!({"binding": binding, "grant": own}))
                .await;
            reply.refused(&call, GRANT_SET, caller);
            reply.holds_none(&call, &[binding.as_str(), PACK, HOOK]);
            if !matches!(caller, Caller::Stranger(_)) {
                let absent = home
                    .send(
                        caller,
                        GRANT_SET,
                        json!({"binding": EntityId::now().to_hex(), "grant": own}),
                    )
                    .await;
                assert_eq!(
                    reply.refusal(),
                    absent.refusal(),
                    "{call}: the same refusal for a binding that does not exist"
                );
            }
        }
        assert_eq!(
            home.owner_call(GRANT_GET, json!({"binding": binding}))
                .await["grant"],
            ceiling,
            "a refused grant set moves no grant"
        );

        let narrowed = grant(&owner, "human", &[WATCHED]);
        assert_eq!(
            home.owner_call(GRANT_SET, json!({"binding": binding, "grant": narrowed}))
                .await,
            json!({"binding": binding, "grant": narrowed}),
            "the owner's narrowing lands"
        );
        assert_eq!(
            home.owner_call(GRANT_GET, json!({"binding": binding}))
                .await,
            json!({"binding": binding, "grant": narrowed})
        );
        assert_eq!(home.hook_row(PACK, HOOK).await["grant"], narrowed);

        for (who, caller) in [
            ("person", Caller::As(&person)),
            ("agent", Caller::As(&agent)),
            ("another vault's owner", Caller::Stranger(&elsewhere)),
        ] {
            let call = format!("{who} at {GRANT_GET}");
            let reply = home
                .send(caller, GRANT_GET, json!({"binding": binding}))
                .await;
            reply.refused(&call, GRANT_GET, caller);
            reply.holds_none(&call, &[WATCHED, binding.as_str()]);
        }
    });
}

/// An agent puts the local pack alone: canon
/// `oneiron/agents/oneiron-arch-0080-runtime-hooks-v1.md:439`, "The owner
/// and resident agents write into it with `vault.packs.put`"; :495, an
/// agent's hook that widens nothing lands "Active at its ceiling"; :344,
/// "For an agent's hook, it is that agent's ceiling". A full-access agent's
/// put under the owner's pack name is refused and leaves the owner's pack
/// and hook as they were. A person's put of `local` is refused with the
/// agent's path beside the owner's, and another vault's owner never reaches
/// the door; `local` stays as vault open made it. The agent's own put of
/// `local` lands: its hook binds as the agent's and reads at the agent's
/// reach, not the owner's, and the owner's pack stays.
#[test]
fn an_agent_puts_the_local_pack_alone() {
    run_on_engine_stack("packs-local-agent", || async {
        let (home, elsewhere) = (host(), host());
        home.put_owner_pack().await;
        let pack = home.pack(PACK).await;
        let owner_row = home.hook_row(PACK, HOOK).await;
        let local = home.pack(LOCAL).await;
        assert_eq!(
            local["pack_name"], LOCAL,
            "vault open makes `local`: {local}"
        );
        let person = home.person("Ada Lune", 0x81);
        let agent = home.agent("local-pack-agent", 0x82);

        let takeover = home
            .send(Caller::As(&agent), PUT, json!({"files": takeover_pack()}))
            .await;
        assert_eq!(
            takeover.status,
            StatusCode::BAD_REQUEST,
            "the agent's put of the owner's pack: {}",
            takeover.body
        );
        assert!(
            takeover.body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("an agent puts the local pack only")),
            "{}",
            takeover.body
        );
        assert_eq!(home.pack(PACK).await, pack, "the owner's pack stays");
        assert_eq!(home.hook_row(PACK, HOOK).await, owner_row);

        home.send(Caller::As(&person), PUT, json!({"files": local_pack()}))
            .await
            .refused_with_agent_path("person at the put of local", PUT, Caller::As(&person));
        home.send(
            Caller::Stranger(&elsewhere),
            PUT,
            json!({"files": local_pack()}),
        )
        .await
        .refused(
            "another vault's owner at the put of local",
            PUT,
            Caller::Stranger(&elsewhere),
        );
        assert_eq!(home.pack(LOCAL).await, local, "a refused put moves nothing");

        let put = home
            .send(Caller::As(&agent), PUT, json!({"files": local_pack()}))
            .await
            .ok("the agent's put of local");
        assert_eq!(put["outcome"], "installed", "{put}");
        assert_eq!(put["receipt"]["pack_name"], LOCAL, "{put}");
        assert_ne!(
            home.pack(LOCAL).await["content_hash"],
            local["content_hash"],
            "the agent's put replaces `local`"
        );
        let row = home.hook_row(LOCAL, LOCAL_HOOK).await;
        let agent_ref = json!(agent.id.to_hex());
        assert_eq!(
            row["binding"]["author"],
            json!({"kind": "agent", "agent": agent_ref}),
            "the hook binds as its agent: {row}"
        );
        assert_eq!(
            row["grant"],
            grant(&agent_ref, "agent", &[]),
            "the agent's hook reads at the agent's reach: {row}"
        );
        assert_ne!(row["grant"]["reader"], owner_row["binding"]["owner"]);
        assert_eq!(home.pack(PACK).await, pack, "the owner's pack stays");
        assert_eq!(home.hook_row(PACK, HOOK).await, owner_row);
    });
}
