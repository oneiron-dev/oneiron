//! Restriction wave 21: the page sizes and text cuts of five verbs are vault-scoped owner
//! Setting keys whose defaults are the bounds those verbs always applied. Each test below pins one
//! default exactly as before the change, then sets the key past the old bound through
//! `vault.settings.set` and checks the formerly cut answer now stands whole; the last test pins
//! the set-time checks of the page-max and byte-count keys. Every key is set by name, so on a
//! tree without the keys each set is refused as an unknown key and the test fails.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test page_and_cut_setting_keys`
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use oneiron::authority::{HostSlipIssuer, MachineRole, SupportHolderClass};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId, SensitivityCeiling};
use oneiron::lens::{
    GeneratedLens, LensAtom, LensAtomId, LensDefaultRequest, LensDossierSource, LensListRequest,
    LensNode, LensProposeRequest, LensSlot, LensText, ResolveRecordRefRequest, ThrobberAtom,
};
use oneiron::memory::{Memory, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::runtime_hooks::{HookBodyRun, HookBodyRuntime, HookRunContext};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{
    PackInstallDisposition, WEAVE_LENS_PACK_NAME, WEAVE_REPORT_LENS,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    HooksReplayRequest, SupportGrantListRequest, SupportGrantMintRequest, list_support_grants_as,
    mint_support_grant_as, replay_hooks_as_owner_listing,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const SET: &str = "vault.settings.set";
const T0: u64 = 1_790_000_000;

/// The pack the owner puts to bind one hook: an author-scoped name, as a hub pack has.
const PACK: &str = "example.hookfloor";
/// Its one hook.
const HOOK: &str = "fact-note";

const PACK_MD: &str = "---
name: example.hookfloor
description: One fact hook the owner binds.
version: 1.0.0
kind: capability
hooks: [\"fact-note\"]
---
A pack whose one fact hook the owner's put binds.
";

const HOOK_MD: &str = "---
name: fact-note
version: 1.0.0
verbs: [\"claim.landed:example.hookfloor.input\"]
actors: [\"human\"]
phase: fact
outcomes: [\"propose\"]
---
Propose one note per landed input claim.
";

const BODY_JS: &str = "return {
  kind: \"propose\",
  claim: {
    subject: input.claim.subject,
    predicate: \"example.hookfloor.note\",
    confidence: 1,
    value: { note: input.claim.value }
  }
};
";

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned: the
    /// writer lease is what lets the owner's handle call the owner verbs by name.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            issuer,
            owner,
            owner_proof,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }
}

/// Sets the vault-scoped `key` to `value` as the owner, through the public verb. At the base the
/// key is unknown, so this is refused and the calling test fails: the expected red.
fn set_key(memory: &Memory<'_>, key: &str, value: Value) -> Value {
    let applied = invoke(
        memory,
        SET,
        json!({ "key": key, "scope": { "kind": "vault" }, "value": value }),
    )
    .unwrap_or_else(|error| panic!("vault.settings.set {key} applies: {error:?}"));
    assert_eq!(
        applied["status"],
        json!("applied"),
        "{key} applies: {applied}"
    );
    applied
}

/// The refusal text of a vault-scoped set of `key` to `value` that must not apply.
fn refused(memory: &Memory<'_>, key: &str, value: Value) -> String {
    format!(
        "{:?}",
        invoke(
            memory,
            SET,
            json!({ "key": key, "scope": { "kind": "vault" }, "value": value }),
        )
        .expect_err("the set is refused")
    )
}

/// Lower hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = char::from_digit(u32::from(*byte >> 4), 16).expect("a hex digit");
        let low = char::from_digit(u32::from(*byte & 15), 16).expect("a hex digit");
        out.push(high);
        out.push(low);
    }
    out
}

/// A hook body runtime that answers an empty outcome. The replay test reads the page bound, which
/// the engine computes before any body runs, so the body never matters here.
struct StubRuntime;

impl HookBodyRuntime for StubRuntime {
    fn run_hook(
        &self,
        _body: &str,
        _input: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        Ok(HookBodyRun {
            outcome_json: "{}".to_owned(),
            fuel_used: None,
            host_calls: 0,
        })
    }
}

/// The node `id` in the tree under `node`, itself included.
fn node_by_id<'a>(node: &'a LensNode, id: &str) -> Option<&'a LensNode> {
    if node.id.as_str() == id {
        return Some(node);
    }
    node.children.iter().find_map(|child| node_by_id(child, id))
}

/// The default projection of `request`, as the owner reads it.
fn default_projection(me: &Memory<'_>, request: LensDefaultRequest) -> LensNode {
    me.lenses_default_framed(request)
        .expect("the default projection composes")
        .value
        .card
        .tree
        .root()
        .clone()
}

/// The ledger "value" cell and the dossier section lines of one default projection.
fn ledger_and_dossier_cuts(me: &Memory<'_>, request: LensDefaultRequest) -> (String, Vec<String>) {
    let root = default_projection(me, request);
    let find =
        |id: &str| node_by_id(&root, id).unwrap_or_else(|| panic!("the card holds node {id}"));
    let ledger = match &find("default-vault-ledger-0").atom {
        LensAtom::LedgerRow(row) => row
            .cells
            .iter()
            .find(|cell| cell.label.as_str() == "value")
            .expect("the ledger row holds a value cell")
            .value
            .as_str()
            .to_owned(),
        other => panic!("node default-vault-ledger-0 is a ledger row: {other:?}"),
    };
    let dossier = match &find("default-vault-dossier-0").atom {
        LensAtom::DossierSection(section) => section
            .lines
            .iter()
            .map(LensText::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        other => panic!("node default-vault-dossier-0 is a dossier section: {other:?}"),
    };
    (ledger, dossier)
}

/// The thread entry body of one default projection.
fn thread_cut(me: &Memory<'_>, request: LensDefaultRequest) -> String {
    let root = default_projection(me, request);
    match &node_by_id(&root, "thread-entry-0")
        .expect("the card holds node thread-entry-0")
        .atom
    {
        LensAtom::ThreadEntry(entry) => entry.body.as_str().to_owned(),
        other => panic!("node thread-entry-0 is a thread entry: {other:?}"),
    }
}

#[test]
fn support_grant_list_page_max_lists_past_500() {
    let fx = Fixture::rooted();
    let holder = EntityId::now();
    let at = fx.vault.now_recorded_at();
    fx.vault
        .put_entity(
            &holder,
            ENTITY_TYPE_PERSON,
            TimeRange { start: at, end: at },
            at,
            b"support holder",
        )
        .expect("a live holder PERSON");
    let holder_key = SigningKey::from_bytes(&[0x2a; 32])
        .verifying_key()
        .to_bytes();
    let scope = Scope {
        worlds: ScopeAxis::Some(BTreeSet::from([ScopeId(EntityId::now())])),
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
        audience: ScopeAxis::All,
        verbs: ScopeAxis::Some(BTreeSet::from(["read".to_owned()])),
        sensitivity: SensitivityCeiling::TOP,
    };
    for _ in 0..501 {
        mint_support_grant_as(
            &fx.vault,
            &fx.owner_proof,
            &fx.issuer,
            SupportGrantMintRequest {
                holder,
                holder_class: SupportHolderClass::Human,
                holder_key: hex(&holder_key),
                scope: scope.clone(),
                records: Vec::new(),
                ttl_secs: None,
                purpose: "wave-21 page probe".to_owned(),
                ticket_ref: None,
                comm: None,
                repairs: BTreeSet::new(),
            },
        )
        .expect("the owner mints a support grant");
    }
    let listed = |limit: Option<u32>| {
        list_support_grants_as(
            &fx.vault,
            &fx.owner_proof,
            SupportGrantListRequest {
                include_inactive: false,
                limit,
            },
        )
        .expect("the owner lists support grants")
        .grants
        .len()
    };
    assert_eq!(listed(None), 500);
    assert_eq!(listed(Some(600)), 500);
    set_key(&fx.as_owner(), "support_grants.list.page_max", json!(600));
    assert_eq!(listed(None), 501);
    assert_eq!(listed(Some(600)), 501);
}

#[test]
fn hooks_replay_page_max_serves_past_256() {
    let fx = Fixture::rooted();
    let files = vec![
        HubFile::new("PACK.md", PACK_MD),
        HubFile::new(format!("hooks/{HOOK}/HOOK.md"), HOOK_MD),
        HubFile::new(format!("hooks/{HOOK}/body.js"), BODY_JS),
    ];
    match fx.vault.put_pack(&fx.owner_proof, files) {
        Ok(PackInstallDisposition::Installed(receipt)) => {
            assert_eq!(receipt.pack_name, PACK);
        }
        other => panic!("the owner's put installs the pack and binds its hook: {other:?}"),
    }
    let binding = fx
        .vault
        .pack_hook_bindings()
        .expect("hook bindings")
        .into_iter()
        .find(|(_, bound)| bound.pack == PACK)
        .map(|(id, _)| id.to_hex())
        .expect("the pack's hook binding");
    let request = HooksReplayRequest {
        binding,
        since: None,
        limit: Some(300),
        cursor: None,
    };
    let runtime = StubRuntime;
    let (page, _) =
        replay_hooks_as_owner_listing(&fx.vault, &fx.owner_proof, &runtime, None, &request)
            .expect("the owner replays the hook");
    assert_eq!(page.effective_limit, 256);
    assert!(page.limit_clamped);
    set_key(&fx.as_owner(), "hooks.replay.page_max", json!(300));
    let (page, _) =
        replay_hooks_as_owner_listing(&fx.vault, &fx.owner_proof, &runtime, None, &request)
            .expect("the owner replays the hook");
    assert_eq!(page.effective_limit, 300);
    assert!(!page.limit_clamped);
}

#[test]
fn lens_list_page_max_pages_past_200() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let entry = fx
        .vault
        .pack_lens(WEAVE_LENS_PACK_NAME, WEAVE_REPORT_LENS)
        .expect("the seeded weave lens with its slot");
    let root = LensNode::with_fallback_text(
        LensAtomId::new("root").expect("a root id"),
        LensAtom::Throbber(ThrobberAtom {
            label: LensText::new("loading").expect("a label"),
        }),
        LensText::new("loading").expect("a fallback"),
    );
    let compiled = GeneratedLens::new(root).expect("a current lens tree");
    for _ in 0..201 {
        me.lenses_propose(LensProposeRequest {
            slot: LensSlot {
                pack_name: entry.pack_name.clone(),
                skill_id: entry.skill_id.clone(),
            },
            pack_content_hash: entry.content_hash.clone(),
            compiled: compiled.clone(),
            intent_prompt: "page-max probe".to_owned(),
            trigger: None,
            scope: None,
        })
        .expect("the owner proposes a lens");
    }
    let rows = |limit: Option<u32>| {
        me.lenses_list(LensListRequest {
            pack_name: None,
            after: None,
            limit,
            with_compiled: false,
        })
        .expect("the owner lists lens proposals")
        .rows
        .len()
    };
    assert_eq!(rows(None), 200);
    assert_eq!(rows(Some(300)), 200);
    set_key(&me, "lenses.list.page_max", json!(300));
    assert_eq!(rows(None), 201);
    assert_eq!(rows(Some(300)), 201);
}

#[test]
fn refs_resolve_snippet_chars_carries_a_longer_snippet() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let id = EntityId::now();
    let text = "x".repeat(400);
    let body = rmpv::Value::Map(vec![(
        rmpv::Value::from("content"),
        rmpv::Value::from(text.as_str()),
    )]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &body).expect("the map encodes");
    fx.vault
        .put_entity(
            &id,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 7, end: 7 },
            9,
            &encoded,
        )
        .expect("a record with a content field");
    let request = ResolveRecordRefRequest {
        reference: id.to_hex(),
        filter: None,
    };
    let snippet = me
        .resolve_record_ref(&request)
        .expect("the ref resolves")
        .value
        .snippet
        .expect("a snippet");
    assert_eq!(snippet.chars().count(), 280);
    assert!(snippet.ends_with('…'));
    set_key(&me, "refs.resolve.snippet_chars", json!(400));
    assert_eq!(
        me.resolve_record_ref(&request)
            .expect("the ref resolves")
            .value
            .snippet
            .as_deref(),
        Some(text.as_str())
    );
    set_key(&me, "refs.resolve.snippet_chars", json!(0));
    assert!(
        me.resolve_record_ref(&request)
            .expect("the ref resolves")
            .value
            .snippet
            .is_none()
    );
}

#[test]
fn lenses_default_ledger_and_dossier_cuts_follow_the_owner_keys() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let mut dossier = vec!["a".repeat(600)];
    dossier.extend((2..=40).map(|line| format!("dossier line {line:02} padding text")));
    let dossier_id = EntityId::now();
    fx.vault
        .put_entity(
            &dossier_id,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 7, end: 7 },
            9,
            dossier.join("\n").as_bytes(),
        )
        .expect("a dossier source");
    let ledger_body = "b".repeat(2000);
    let ledger_id = EntityId::now();
    fx.vault
        .put_entity(
            &ledger_id,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 7, end: 7 },
            9,
            ledger_body.as_bytes(),
        )
        .expect("a ledger source");
    let request = || LensDefaultRequest {
        title: "Cuts".to_owned(),
        ledger: vec![ledger_id.to_hex()],
        dossiers: vec![LensDossierSource {
            entity_ref: dossier_id.to_hex(),
            title: "Dossier".to_owned(),
        }],
        threads: Vec::new(),
        as_of: None,
        surface: None,
    };
    let (ledger, dossier) = ledger_and_dossier_cuts(&me, request());
    assert_eq!(dossier.len(), 32);
    assert_eq!(dossier[0].len(), 512);
    assert_eq!(ledger.len(), 1024);
    set_key(&me, "lenses.default.dossier_lines", json!(40));
    set_key(&me, "lenses.default.dossier_line_bytes", json!(1000));
    set_key(&me, "lenses.default.excerpt_bytes", json!(4096));
    let (ledger, dossier) = ledger_and_dossier_cuts(&me, request());
    assert_eq!(dossier.len(), 40);
    assert_eq!(dossier[0], "a".repeat(600));
    assert_eq!(ledger, ledger_body);
}

#[test]
fn lenses_default_thread_entry_cut_follows_excerpt_bytes() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let content = "c".repeat(2000);
    let message_id = EntityId::now().to_hex();
    me.commit_message(&WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: Some(EntityId::now().to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(message_id.clone()),
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: content.clone(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: fx.vault.now_recorded_at(),
        assertions: WitnessAssertions::default(),
    })
    .expect("a thread MESSAGE source");
    let request = || LensDefaultRequest {
        title: "Thread".to_owned(),
        ledger: Vec::new(),
        dossiers: Vec::new(),
        threads: vec![message_id.clone()],
        as_of: None,
        surface: None,
    };
    assert_eq!(thread_cut(&me, request()).len(), 1024);
    set_key(&me, "lenses.default.excerpt_bytes", json!(4096));
    assert_eq!(thread_cut(&me, request()), content);
}

#[test]
fn page_and_cut_key_values_are_checked_on_set() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    refused(&me, "support_grants.list.page_max", json!(0));
    refused(&me, "lenses.default.excerpt_bytes", json!(16385));
    set_key(&me, "lenses.default.excerpt_bytes", json!(16384));
    refused(&me, "lenses.default.dossier_line_bytes", json!(16385));
}
