//! The `vault.people` doors (ARCH-0067's People,
//! oneiron/agents/oneiron-arch-0067-context-board-v1.md), each entered at its
//! facade route as the app serves it:
//!
//! - :152 "It holds humans and agents.", and :170 "Rows are keyed TOON:
//!   `pr<n>: name,kind,role,about`. The kind is `human` or `agent`.": one
//!   roster with one `pr` handle per person, a human as its own PERSON and an
//!   agent as the model PERSON its definition is born with.
//! - The create row (scripts/sdk/verbs/vault.people.create.json): "The owner
//!   creates a distinct PERSON with declared identity hints and existing
//!   identity-evidence refs, looking before minting an opaque id without
//!   selecting or merging a namesake." Only the owner creates; a namesake is
//!   a new person, and its create names the people the index already held.
//! - :170 "Another vault's people are vault-fenced and never merge.": two
//!   vaults in one process, a namesake in each.
//! - :171 "Overflow renders `more: +N · vault.people.list(vault, page)`.": a
//!   page holds fifty persons and counts the rest.
//! - :174 "The renderer shows the highest line at or below the reader's
//!   ceiling.": a reader whose model channel sits below a person's name band
//!   reads the bare handle, until the owner raises that connection's ceiling
//!   (DEC-0006's names dial, `vault.disclosure.ceiling.set`).
//!
//! Not covered here: the Dreamer's `about` lines themselves (:174 "The
//! Dreamer writes each line only from facts at or below its band."). They
//! are written by the `dreamer.person_about` job into a crate-private table
//! that no public path or test door seeds, so every reader here reads
//! `about: null`.
//!
//! `cargo test -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks --test vault_people_doors`.

#![cfg(unix)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
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
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const CREATE: &str = "vault.people.create";
const GET: &str = "vault.people.get";
const LIST: &str = "vault.people.list";
const CEILING_SET: &str = "vault.disclosure.ceiling.set";

/// Rows on one `vault.people.list` page (memory/people_verbs.rs
/// `PEOPLE_PAGE_SIZE`).
const PAGE: usize = 50;

const MARA: &str = "Mara Lindqvist";
const NOOR: &str = "Noor Haddad";
const ROBIN: &str = "Robin Achebe";
const SCRIBE: &str = "People Scribe";

const READ_WRITE: &[&str] = &["core:read", "core:write"];
const READ_ONLY: &[&str] = &["core:read"];
const WRITE_ONLY: &[&str] = &["core:write"];

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
    id: EntityId,
    slip: CapabilitySlip,
    key: SigningKey,
}

/// Who sends a request.
#[derive(Clone, Copy)]
enum Caller<'a> {
    /// The host root slip: on a self-hosted vault it acts as the owner.
    Root,
    /// Another vault's host root slip, presented at this vault's app.
    RootOf(&'a Host),
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

    /// Asserts `status` with error `code` and a message holding `words`.
    fn refused(&self, call: &str, status: StatusCode, code: &str, words: &str) {
        assert_eq!(self.status, status, "{call} answered {}", self.body);
        assert_eq!(self.body["error"]["code"], code, "{call}: {}", self.body);
        assert!(
            self.body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(words)),
            "{call} must name `{words}`: {}",
            self.body
        );
    }

    fn forbidden(&self, call: &str, words: &str) {
        self.refused(call, StatusCode::FORBIDDEN, "FORBIDDEN", words);
    }

    fn not_found(&self, call: &str, words: &str) {
        self.refused(call, StatusCode::NOT_FOUND, "NOT_FOUND", words);
    }

    /// Asserts a 400 whose reply holds `words`.
    fn bad_request(&self, call: &str, words: &str) {
        assert_eq!(
            self.status,
            StatusCode::BAD_REQUEST,
            "{call} answered {}",
            self.body
        );
        assert!(
            self.body.to_string().contains(words),
            "{call} must name `{words}`: {}",
            self.body
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The rows of one `vault.people.list` page.
fn people(page: &Value) -> Vec<Value> {
    page["people"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("a people page holds no `people` array: {page}"))
}

/// The PERSON id a create answered.
fn person_id(created: &Value) -> String {
    created["person"]["id_hex"]
        .as_str()
        .unwrap_or_else(|| panic!("a create answers its PERSON's id: {created}"))
        .to_owned()
}

/// The row of PERSON `person` in `rows`.
fn row_of<'a>(rows: &'a [Value], person: &str) -> &'a Value {
    rows.iter()
        .find(|row| row["person"] == person)
        .unwrap_or_else(|| panic!("the roster holds no row for {person}: {rows:?}"))
}

/// The rows of `rows` named `name`.
fn named<'a>(rows: &'a [Value], name: &str) -> Vec<&'a Value> {
    rows.iter().filter(|row| row["name"] == name).collect()
}

/// The PERSON ids of `rows`.
fn persons(rows: &[&Value]) -> BTreeSet<String> {
    rows.iter()
        .map(|row| {
            row["person"]
                .as_str()
                .unwrap_or_else(|| panic!("a row names its PERSON: {row}"))
                .to_owned()
        })
        .collect()
}

/// The number of a `pr<n>` handle; any other handle fails the test.
fn handle_number(row: &Value) -> u64 {
    row["handle"]
        .as_str()
        .and_then(|handle| handle.strip_prefix("pr"))
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|digits| digits.parse().ok())
        .unwrap_or_else(|| panic!("a person's handle is a bare `pr<n>`: {row}"))
}

/// Asserts each row has a `pr<n>` handle and a kind of `human` or `agent`,
/// and that the rows run in strictly rising handle order.
fn assert_rows_keyed_in_handle_order(rows: &[Value]) {
    let mut last = None;
    for row in rows {
        let number = handle_number(row);
        assert!(
            row["kind"] == "human" || row["kind"] == "agent",
            "a person's kind is `human` or `agent`: {row}"
        );
        assert!(
            last.is_none_or(|last| last < number),
            "rows run in rising handle order: {rows:?}"
        );
        last = Some(number);
    }
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
            Caller::RootOf(other) => (
                other.token.clone(),
                hex(&other
                    .issuer
                    .binding_proof(&other.slip, &challenge)
                    .expect("the other vault's holder proof")),
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

    /// The owner's verified proof, for binding the vault's own agents.
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

    /// A create input for `name` (and `aliases`), citing a witnessed message
    /// of its own: "A name alone is not identity evidence."
    fn person_input(&self, name: &str, aliases: &[&str]) -> Value {
        let evidence = self.row(
            ENTITY_TYPE_MESSAGE,
            "content",
            &format!("{name} introduced themself at the reading group"),
        );
        json!({
            "identity": {"name": name, "aliases": aliases},
            "identity_evidence_refs": [evidence.to_hex()],
            "occurred_at": self.vault.now_recorded_at(),
        })
    }

    /// The owner creates the person `name`.
    async fn create(&self, name: &str) -> Value {
        let input = self.person_input(name, &[]);
        self.owner_ok(CREATE, input).await
    }

    /// The owner defines the custom agent `display_name`; answers its
    /// AGENT_DEF id.
    async fn define_agent(&self, display_name: &str) -> String {
        let agent = EntityId::now().to_hex();
        let created = self
            .owner_ok(
                "vault.agents.create",
                json!({
                    "agent_def_ref": agent,
                    "definition": {
                        "agent_id": "people-scribe",
                        "display_name": display_name,
                        "desc": "writes the reading group's minutes",
                        "version": "1",
                    },
                }),
            )
            .await;
        assert_eq!(created["agent_def_ref"], agent, "{created}");
        agent
    }

    /// One `vault.people.list` page as `caller` reads it.
    async fn list(&self, caller: Caller<'_>, input: Value) -> Value {
        self.call(caller, LIST, input).await.ok(LIST)
    }

    /// Every row of `caller`'s roster, page after page.
    async fn roster(&self, caller: Caller<'_>) -> Vec<Value> {
        let mut rows = Vec::new();
        for page in 0..20 {
            let listed = self.list(caller, json!({"page": page})).await;
            rows.extend(people(&listed));
            if listed["more"] == 0 {
                return rows;
            }
        }
        panic!("a roster of this test fits twenty pages");
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
        Principal {
            id: holder,
            slip,
            key,
        }
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

/// ARCH-0067 :152: "The prefix's `agents` roster index is now `people`. It
/// holds humans and agents." :170: "Rows are keyed TOON: `pr<n>:
/// name,kind,role,about`. The kind is `human` or `agent`." A person the owner
/// creates lists as a human contact under its own PERSON; a custom agent the
/// owner defines lists as an agent under the model PERSON its definition is
/// born with, spoken for by the definition. Each `get` of a listed handle
/// answers that row, an unknown handle answers 404, and a credential that
/// carries no read reads no one.
#[test]
fn the_roster_holds_humans_and_agents_each_under_one_pr_handle() {
    run_on_engine_stack("people-doors-roster", || async {
        let host = Host::new("vault-people-doors-roster");
        let created = host.create(MARA).await;
        let mara = person_id(&created);
        assert_eq!(created["owner_ref"], host.owner.to_hex(), "{created}");
        assert_eq!(created["prior_candidate_refs"], json!([]), "{created}");
        let scribe = host.define_agent(SCRIBE).await;

        let page = host.list(Caller::Root, json!({})).await;
        assert_eq!(page["page"], 0, "{page}");
        assert_eq!(page["more"], 0, "{page}");
        let rows = people(&page);
        assert_rows_keyed_in_handle_order(&rows);

        let human = row_of(&rows, &mara);
        assert_eq!(human["kind"], "human", "{human}");
        assert_eq!(human["name"], MARA, "{human}");
        assert_eq!(human["role"], "contact", "{human}");
        assert_eq!(human["actors"], json!([mara]), "{human}");
        assert!(human["about"].is_null(), "{human}");

        let agent = rows
            .iter()
            .find(|row| row["actors"] == json!([scribe]))
            .unwrap_or_else(|| panic!("the roster holds the defined agent: {rows:?}"));
        assert_eq!(agent["kind"], "agent", "{agent}");
        assert_eq!(agent["name"], SCRIBE, "{agent}");
        assert_eq!(agent["role"], "custom", "{agent}");
        assert_ne!(
            agent["person"], scribe,
            "an agent is a person through its own model PERSON, not its definition: {agent}"
        );
        assert_ne!(agent["handle"], human["handle"], "{rows:?}");

        for row in [human, agent] {
            let got = host
                .call(Caller::Root, GET, json!({"pr": row["handle"]}))
                .await
                .ok(GET);
            assert_eq!(&got, row, "a get answers the listed row");
        }
        host.call(Caller::Root, GET, json!({"pr": "pr999999"}))
            .await
            .not_found(GET, "no person pr999999");

        let writer = host.agent("people-writer", 0x93, AgentTier::FullAccess, WRITE_ONLY);
        host.call(Caller::As(&writer), LIST, json!({}))
            .await
            .forbidden("a write-only credential's list", "required scope");
        host.call(Caller::As(&writer), GET, json!({"pr": human["handle"]}))
            .await
            .forbidden("a write-only credential's get", "required scope");
    });
}

/// The create row: "The owner creates a distinct PERSON with declared
/// identity hints and existing identity-evidence refs" (host_door_proof
/// owner). A live PERSON and a full-access agent, each on a slip that may
/// write, are refused as not the owner; a read-only agent is refused at the
/// write scope. A refused create makes no one. The owner's create needs a
/// name and evidence, answers the new PERSON, and that person then lists as
/// a human contact.
#[test]
fn only_the_owner_creates_a_person_and_the_new_person_then_lists() {
    run_on_engine_stack("people-doors-owner-create", || async {
        let host = Host::new("vault-people-doors-owner-create");
        let mina = host.person("Mina Okafor", 0x91);
        let keeper = host.agent("people-keeper", 0x92, AgentTier::FullAccess, READ_WRITE);
        let reader = host.agent("people-reader", 0x94, AgentTier::ReadOnly, READ_ONLY);
        let input = host.person_input(NOOR, &[]);

        for (who, caller) in [
            ("a person's create", Caller::As(&mina)),
            ("a full-access agent's create", Caller::As(&keeper)),
        ] {
            host.call(caller, CREATE, input.clone())
                .await
                .forbidden(who, "vault.people.create is the vault owner's");
        }
        host.call(Caller::As(&reader), CREATE, input.clone())
            .await
            .forbidden("a read-only agent's create", "required scope");
        assert!(
            named(&host.roster(Caller::Root).await, NOOR).is_empty(),
            "a refused create makes no one"
        );

        let mut nameless = input.clone();
        nameless["identity"] = json!({"aliases": ["Noor"]});
        host.call(Caller::Root, CREATE, nameless)
            .await
            .bad_request("a nameless create", "PERSON creation requires name");
        let mut unevidenced = input.clone();
        unevidenced["identity_evidence_refs"] = json!([]);
        host.call(Caller::Root, CREATE, unevidenced)
            .await
            .bad_request(
                "a create citing no evidence",
                "PERSON creation requires identity evidence refs",
            );
        assert!(named(&host.roster(Caller::Root).await, NOOR).is_empty());

        let created = host.owner_ok(CREATE, input.clone()).await;
        assert_eq!(created["identity"]["name"], NOOR, "{created}");
        assert_eq!(
            created["identity_evidence_refs"], input["identity_evidence_refs"],
            "{created}"
        );
        assert_eq!(created["owner_ref"], host.owner.to_hex(), "{created}");
        assert!(
            created["recorded_at"].as_u64().is_some_and(|at| at > 0),
            "{created}"
        );
        let noor = person_id(&created);
        let rows = host.roster(Caller::Root).await;
        let row = row_of(&rows, &noor);
        assert_eq!(row["kind"], "human", "{row}");
        assert_eq!(row["name"], NOOR, "{row}");
        assert_eq!(row["role"], "contact", "{row}");
        assert_eq!(named(&rows, NOOR).len(), 1, "{rows:?}");
    });
}

/// The create row: "looking before minting an opaque id without selecting or
/// merging a namesake"; `PersonCreated.prior_candidate_refs`: "These people
/// were not selected or merged; the owner explicitly created a distinct
/// record." A second create of the same name mints a new person and names
/// the first as a prior candidate; a create whose alias is that name names
/// both. The roster then holds each as its own person under its own handle.
#[test]
fn a_namesake_is_a_new_person_and_its_create_names_the_earlier_one() {
    run_on_engine_stack("people-doors-namesake", || async {
        let host = Host::new("vault-people-doors-namesake");
        let first = host.create(ROBIN).await;
        assert_eq!(first["prior_candidate_refs"], json!([]), "{first}");
        let first = person_id(&first);

        let second = host.create(ROBIN).await;
        let second_id = person_id(&second);
        assert_ne!(second_id, first, "a namesake is a new person: {second}");
        assert_eq!(
            second["prior_candidate_refs"],
            json!([first]),
            "the create names the namesake it did not merge: {second}"
        );

        let aliased = host
            .owner_ok(CREATE, host.person_input("R. Achebe", &["robin achebe"]))
            .await;
        let aliased_id = person_id(&aliased);
        let prior: BTreeSet<String> = aliased["prior_candidate_refs"]
            .as_array()
            .unwrap_or_else(|| panic!("a create names its prior candidates: {aliased}"))
            .iter()
            .filter_map(|reference| reference.as_str().map(str::to_owned))
            .collect();
        assert_eq!(
            prior,
            BTreeSet::from([first.clone(), second_id.clone()]),
            "{aliased}"
        );

        let rows = host.roster(Caller::Root).await;
        let robins = named(&rows, ROBIN);
        assert_eq!(
            persons(&robins),
            BTreeSet::from([first.clone(), second_id.clone()]),
            "{rows:?}"
        );
        assert_ne!(robins[0]["handle"], robins[1]["handle"], "{rows:?}");
        assert_eq!(row_of(&rows, &aliased_id)["name"], "R. Achebe");
    });
}

/// ARCH-0067 :170: "The block is grouped per vault, like `vaults` and
/// `skills`. Another vault's people are vault-fenced and never merge." Two
/// vaults in one process each create the same name. Each roster holds its own
/// person alone, under its own vault tag; a get of the other vault's handle
/// never answers the other vault's person; a list naming the other vault's
/// tag answers 404; the other vault's own root credential reads nothing here.
#[test]
fn another_vaults_people_are_fenced_and_never_merge() {
    run_on_engine_stack("people-doors-fence", || async {
        let a = Host::new("vault-people-doors-fence-a");
        let b = Host::new("vault-people-doors-fence-b");
        let in_a = person_id(&a.create(ROBIN).await);
        let in_b = person_id(&b.create(ROBIN).await);
        assert_ne!(in_a, in_b);

        let a_tag = a.list(Caller::Root, json!({})).await["vault"]
            .as_str()
            .expect("a page names its vault")
            .to_owned();
        let b_tag = b.list(Caller::Root, json!({})).await["vault"]
            .as_str()
            .expect("a page names its vault")
            .to_owned();
        assert_ne!(
            a_tag, b_tag,
            "each vault's people are grouped under its own tag"
        );

        let a_rows = a.roster(Caller::Root).await;
        let b_rows = b.roster(Caller::Root).await;
        assert_eq!(
            persons(&named(&a_rows, ROBIN)),
            BTreeSet::from([in_a.clone()])
        );
        assert_eq!(
            persons(&named(&b_rows, ROBIN)),
            BTreeSet::from([in_b.clone()])
        );
        assert!(a_rows.iter().all(|row| row["person"] != in_b), "{a_rows:?}");
        assert!(b_rows.iter().all(|row| row["person"] != in_a), "{b_rows:?}");

        let b_handle = row_of(&b_rows, &in_b)["handle"].clone();
        let crossed = a.call(Caller::Root, GET, json!({"pr": b_handle})).await;
        match crossed.status {
            StatusCode::OK => assert_ne!(
                crossed.body["person"], in_b,
                "a handle names this vault's person, never another's"
            ),
            StatusCode::NOT_FOUND => {}
            status => panic!(
                "a get of another vault's handle answered {status}: {}",
                crossed.body
            ),
        }

        a.call(Caller::Root, LIST, json!({"vault": b_tag}))
            .await
            .not_found(LIST, &format!("this vault is {a_tag}, not {b_tag}"));
        b.call(Caller::Root, LIST, json!({"vault": a_tag}))
            .await
            .not_found(LIST, &format!("this vault is {b_tag}, not {a_tag}"));
        let own = a.list(Caller::Root, json!({"vault": a_tag})).await;
        assert_eq!(own["vault"], a_tag, "{own}");

        let foreign = a.call(Caller::RootOf(&b), LIST, json!({})).await;
        assert!(
            foreign.status == StatusCode::UNAUTHORIZED || foreign.status == StatusCode::FORBIDDEN,
            "another vault's credential answered {}: {}",
            foreign.status,
            foreign.body
        );
        assert!(
            !foreign.body.to_string().contains(&in_a),
            "{}",
            foreign.body
        );
    });
}

/// ARCH-0067 :171: "Overflow renders `more: +N · vault.people.list(vault,
/// page)`." and `PeoplePage.more`: "Rows on later pages." With fifty-five
/// more persons than a fresh vault holds, page 0 holds fifty and counts the
/// rest, page 1 holds the rest in rising handle order with none counted
/// after it, and a page past the end is empty.
#[test]
fn a_roster_page_holds_fifty_and_counts_the_rest() {
    run_on_engine_stack("people-doors-paging", || async {
        let host = Host::new("vault-people-doors-paging");
        let seeded: BTreeSet<String> = (0..55)
            .map(|n| {
                host.row(ENTITY_TYPE_PERSON, "name", &format!("Paged Person {n:02}"))
                    .to_hex()
            })
            .collect();

        let first = host.list(Caller::Root, json!({"page": 0})).await;
        let first_rows = people(&first);
        assert_eq!(first_rows.len(), PAGE, "{first}");
        let more = usize::try_from(first["more"].as_u64().expect("a page counts the rest"))
            .expect("a small count");
        assert!(
            PAGE + more >= seeded.len() && more <= PAGE,
            "page 0 counts every later row: {first}"
        );

        let second = host.list(Caller::Root, json!({"page": 1})).await;
        assert_eq!(second["page"], 1, "{second}");
        let second_rows = people(&second);
        assert_eq!(second_rows.len(), more, "{second}");
        assert_eq!(second["more"], 0, "{second}");

        let both: Vec<Value> = first_rows.iter().chain(&second_rows).cloned().collect();
        assert_rows_keyed_in_handle_order(&both);
        let listed = persons(&both.iter().collect::<Vec<_>>());
        assert_eq!(listed.len(), both.len(), "no person is on two pages");
        assert!(
            seeded.is_subset(&listed),
            "every seeded person is on one page"
        );

        let past = host.list(Caller::Root, json!({"page": 2})).await;
        assert_eq!(past["people"], json!([]), "{past}");
        assert_eq!(past["more"], 0, "{past}");
    });
}

/// ARCH-0067 :174: "The renderer shows the highest line at or below the
/// reader's ceiling." A person's name with no name claim sits in the
/// sensitive band (disclosure: `person_name_claim_in` absent). The owner's
/// channel admits it by default; an agent's sits at public, so the agent's
/// get and list show the person under the bare handle, with no about line.
/// The owner raising that connection's ceiling shows the name; lowering it
/// hides it again. No read authority changes: the agent reads the same row
/// throughout.
#[test]
fn a_reader_below_a_names_band_sees_the_bare_handle_until_the_owner_raises_its_ceiling() {
    run_on_engine_stack("people-doors-names-band", || async {
        let host = Host::new("vault-people-doors-names-band");
        let mara = person_id(&host.create(MARA).await);
        let reader = host.agent("people-reader", 0x95, AgentTier::FullAccess, READ_WRITE);

        let owner_rows = host.roster(Caller::Root).await;
        let owner_row = row_of(&owner_rows, &mara).clone();
        assert_eq!(owner_row["name"], MARA, "{owner_row}");
        let handle = owner_row["handle"]
            .as_str()
            .expect("a person's handle")
            .to_owned();
        let assert_masked = |row: &Value, at: &str| {
            assert_eq!(row["person"], mara, "{at}: {row}");
            assert_eq!(row["handle"], handle, "{at}: {row}");
            assert_eq!(row["name"], handle, "{at} names the bare handle: {row}");
            assert!(row["about"].is_null(), "{at}: {row}");
        };

        let got = host
            .call(Caller::As(&reader), GET, json!({"pr": handle}))
            .await
            .ok(GET);
        assert_masked(&got, "the agent's get");
        let reader_rows = host.roster(Caller::As(&reader)).await;
        assert_masked(row_of(&reader_rows, &mara), "the agent's list");
        assert!(
            !serde_json::to_string(&reader_rows)
                .expect("the rows' text")
                .contains(MARA),
            "the agent's roster carries the name nowhere: {reader_rows:?}"
        );

        let connection = format!("agent:{}", reader.id.to_hex());
        host.owner_ok(
            CEILING_SET,
            json!({"connection": connection, "ceiling": "restricted"}),
        )
        .await;
        let raised = host
            .call(Caller::As(&reader), GET, json!({"pr": handle}))
            .await
            .ok(GET);
        assert_eq!(raised["person"], mara, "{raised}");
        assert_eq!(
            raised["name"], MARA,
            "a raised ceiling shows the name: {raised}"
        );

        host.owner_ok(
            CEILING_SET,
            json!({"connection": connection, "ceiling": "public"}),
        )
        .await;
        let lowered = host
            .call(Caller::As(&reader), GET, json!({"pr": handle}))
            .await
            .ok(GET);
        assert_masked(
            &lowered,
            "the agent's get after the owner lowers its ceiling",
        );

        let owner_get = host
            .call(Caller::Root, GET, json!({"pr": handle}))
            .await
            .ok(GET);
        assert_eq!(owner_get, owner_row, "the owner reads the name throughout");
    });
}
