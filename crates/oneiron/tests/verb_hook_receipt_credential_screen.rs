//! A verb hook's receipt is screened by its real rows, not its invocation (HOOKS-04, leg B1).
//!
//! Pins the T1 fix: `credential_kept_receipts` judges a Hook receipt by
//! `crate::receipt::referenced_rows` (binding, CODE and the saved run's read
//! rows; a verb hook's invocation trigger names no row), withholding it when
//! the helper answers None (unknown or unkept run). A fact hook's trigger
//! stays a row.
//!
//! Public paths only: `Vault::put_pack` installs the packs, the fake
//! `ContinueRuntime`/`NothingRuntime` run the bodies via
//! `Vault::install_hook_runtime` (verb) and `FactHookRunner::run_pass`
//! (fact), `Vault::pre_verb_hooks`/`post_verb_hooks` record the verb-hook
//! receipts, and `Memory::with_read_proof` plus `Memory::receipts_page`
//! pages kinds `["hook"]` through a credential. No new test door.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_hook_receipt_credential_screen`
//! (the cfg enables no door here; the sandbox feature builds but the fake
//! runtimes run the bodies).
//!
//! - (a) `owner_credential_bound_read_returns_its_verb_hook_receipts`: red on
//!   main (0 of 2: the invocation trigger names no entity, so the lane
//!   withholds both), green on the head (2 of 2: the owner's broad
//!   credential reads binding, CODE and the empty run reads).
//! - (b) `credential_without_binding_or_code_reads_no_verb_hook_receipt`:
//!   green on main (0: the invocation already withholds) and on the head
//!   (0: binding and CODE are unreadable).
//! - (c) `fact_hook_receipt_visibility_still_follows_its_trigger_row`: green
//!   on main and on the head (owner broad keeps 1, stranger keeps 0; the
//!   fact trigger stays a row, plus binding/CODE/run rows on the head).
//! - (d) `a_verb_hook_receipt_reaches_only_the_actor_that_made_the_call`
//!   (review round 1 of #9535): a call made as another PERSON; the owner's
//!   broad credential reads the binding and CODE but did not make the call,
//!   so it gets none of its receipts (a receipt can carry the call's own
//!   words in `note`). Green on main (the invocation withholds), red at
//!   49fff85d (2 of 2), green on the head.
//! - (e) `a_narrower_credential_of_the_caller_reads_no_receipt_whose_input_showed_a_row_it_cannot_read`
//!   (review round 2 of #9535): the owner makes three calls whose post
//!   hooks see a result: one naming no row, one a pack whose item is a row
//!   the narrower credential does not read (the run's input dependency),
//!   one a list with no pack naming that row (a row the call named). The
//!   owner's credential held to the binding and CODE rows keeps the first
//!   call's two receipts and none of the others'; the broad one keeps all
//!   six. Green on main (the invocation withholds every one: 0 for the
//!   first call, so its MISSING assert fails there; red on main), red at
//!   c029867c (2 and 2: LEAK), green on the head.
//! - (f) `a_credential_reads_no_receipt_whose_input_showed_content_naming_no_held_row`
//!   (VERB-HOOK-RECEIPT-UNNAMED-SOURCE-PROVENANCE): five calls whose post
//!   hooks see content no row object names: a count, a list naming its row
//!   only by short ref, a list naming a row this vault does not hold, a pack
//!   whose item ref does not resolve, and (review round 1 of #9643) a bare
//!   list of a held row's id beside a name. Nothing tells which rows a body
//!   could copy from them into its receipt, so no credential-bound reader
//!   keeps their receipts, as for a host verb's free text since #9535; the
//!   owner reading unbound still lists all ten. Red on main (the narrower
//!   credential keeps 2 of each call's 2: LEAK), red at a1dfdba3 for the
//!   last call (2: an id-shaped string named the result), green on the head.
//! - (g) `a_later_hook_reads_no_receipt_of_unknown_provenance_in_its_tail`
//!   (review round 1 of #9643): after a call whose receipts (f) withholds,
//!   the next call's post hooks find those receipts withheld in their
//!   `receipt_tail`, so no body copies their notes into a receipt of its
//!   own; a receipt of a call whose input showed nothing stays. Red on main
//!   and at a1dfdba3 (the tail shows them), green on the head.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::consent::AuthenticatedOwner;
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::{
    FactHookRunner, HookBodyRun, HookBodyRuntime, HookRunContext, InvocationId, VerbCall,
    VerbDomain,
};
use oneiron::skill_hub::HubFile;
use oneiron::skill_hub::pack_catalog::{HookActorClass, PackHookBinding, PackInstallDisposition};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;

/// The verb the post hooks run on, as HOOKS-04's hooks run on `vault.claims.list`.
const VERB: &str = "vault.claims.list";
/// The verb-hook pack the owner puts.
const PACK: &str = "example.hookscreen";
/// The fact-hook pack the owner puts.
const FACT_PACK: &str = "example.factscreen";
/// The fact hook's input predicate.
const FACT_PREDICATE: &str = "example.factscreen.input";
/// The challenge the credential proofs sign, as a transport challenge does.
const CHALLENGE: &[u8] = b"oneiron-request:verb-hook-receipt-screen";
/// A page large enough to hold every Hook receipt the fixture records.
const PAGE_LIMIT: usize = 100;
/// The words only the restricted row's place in a result carries, so the
/// body inputs that showed it are found among every test's.
const RESTRICTED_WORDS: &str = "words drawn from the restricted row";

/// Every input a verb body ran on, as JSON, from every test of this file:
/// a case finds its own by its invocation id.
static HOOK_INPUTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

const PACK_MD: &str = "---
name: example.hookscreen
description: Two vault.claims.list post hooks answering Continue.
version: 1.0.0
kind: capability
hooks: [\"post-first\", \"post-second\"]
---
A pack whose two post hooks run on one call.
";

const POST_FIRST_HOOK_MD: &str = "---
name: post-first
version: 1.0.0
verbs: [\"vault.claims.list\"]
phase: post
priority: 10
budget_ms: 1000
blocking: false
outcomes: [\"continue\"]
---
First post hook: answers Continue.
";

const POST_SECOND_HOOK_MD: &str = "---
name: post-second
version: 1.0.0
verbs: [\"vault.claims.list\"]
phase: post
priority: 0
budget_ms: 1000
blocking: false
outcomes: [\"continue\"]
---
Second post hook: answers Continue.
";

const CONTINUE_BODY_JS: &str = "return { kind: \"continue\" };\n";

const FACT_PACK_MD: &str = "---
name: example.factscreen
description: One fact hook the owner binds.
version: 1.0.0
kind: capability
hooks: [\"fact-note\"]
---
A pack whose one fact hook the owner's put binds.
";

const FACT_HOOK_MD: &str = "---
name: fact-note
version: 1.0.0
verbs: [\"claim.landed:example.factscreen.input\"]
phase: fact
outcomes: [\"nothing\"]
---
Watches example.factscreen.input claims and does nothing.
";

const NOTHING_BODY_JS: &str = "return { kind: \"nothing\" };\n";

/// A hook sandbox that answers every verb body with Continue, reading
/// nothing; it keeps each input in [`HOOK_INPUTS`].
struct ContinueRuntime;

impl HookBodyRuntime for ContinueRuntime {
    fn run_hook(
        &self,
        _body: &str,
        input_json: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        HOOK_INPUTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(input_json.to_owned());
        Ok(HookBodyRun {
            outcome_json: r#"{"kind":"continue"}"#.to_owned(),
            fuel_used: None,
            host_calls: 1,
        })
    }
}

/// A hook sandbox that answers every fact body with Nothing, reading nothing.
struct NothingRuntime;

impl HookBodyRuntime for NothingRuntime {
    fn run_hook(
        &self,
        _body: &str,
        _input_json: &str,
        _context: &mut HookRunContext,
        _read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> oneiron::Result<HookBodyRun> {
        Ok(HookBodyRun {
            outcome_json: r#"{"kind":"nothing"}"#.to_owned(),
            fuel_used: None,
            host_calls: 1,
        })
    }
}

struct Fixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    /// A vault with its install signing, embedded owner, host root and the
    /// fake Continue runtime verb hooks run on, installed before any hook
    /// runs so no sandbox builds first.
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("FIXTURE: vault dir");
        let vault =
            Vault::open(directory.path(), VaultConfig::device()).expect("FIXTURE: open vault");
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        vault
            .install_hook_runtime(Arc::new(ContinueRuntime))
            .expect("FIXTURE: the vault runs verb hooks on the fake Continue runtime");
        vault
            .prepare_install_signing()
            .expect("FIXTURE: load this install's signing keys");
        let owner = vault.ensure_embedded_owner_actor().expect("FIXTURE: owner");
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-verb-hook-receipt-screen")
            .expect("FIXTURE: host issuer");
        vault
            .ensure_host_root_slip(&issuer)
            .expect("FIXTURE: host root slip");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("FIXTURE: owner proof");
        Self {
            vault,
            issuer,
            owner,
            owner_proof,
            _directory: directory,
        }
    }

    /// The owner's put of the two post hooks; answers this pack's live bindings.
    fn put_verb_pack(&self) -> Vec<(EntityId, PackHookBinding)> {
        let files = vec![
            HubFile::new("PACK.md", PACK_MD),
            HubFile::new("hooks/post-first/HOOK.md", POST_FIRST_HOOK_MD),
            HubFile::new("hooks/post-first/body.js", CONTINUE_BODY_JS),
            HubFile::new("hooks/post-second/HOOK.md", POST_SECOND_HOOK_MD),
            HubFile::new("hooks/post-second/body.js", CONTINUE_BODY_JS),
        ];
        match self
            .vault
            .put_pack(&self.owner_proof, files)
            .expect("FIXTURE: the owner's put installs the pack")
        {
            PackInstallDisposition::Installed(receipt) => {
                assert_eq!(
                    receipt.pack_name, PACK,
                    "FIXTURE: the owner's put installs this pack"
                );
            }
            other => {
                panic!("FIXTURE: the owner's put installs the pack and binds its hooks: {other:?}")
            }
        }
        let bindings = self
            .vault
            .pack_hook_bindings()
            .expect("FIXTURE: live bindings read")
            .into_iter()
            .filter(|(_, binding)| binding.pack == PACK)
            .collect::<Vec<_>>();
        assert_eq!(
            bindings.len(),
            2,
            "FIXTURE: the put binds both post hooks live: {bindings:?}"
        );
        bindings
    }

    /// The owner's put of the one fact hook; answers its binding id.
    fn put_fact_pack(&self) -> EntityId {
        let files = vec![
            HubFile::new("PACK.md", FACT_PACK_MD),
            HubFile::new("hooks/fact-note/HOOK.md", FACT_HOOK_MD),
            HubFile::new("hooks/fact-note/body.js", NOTHING_BODY_JS),
        ];
        match self
            .vault
            .put_pack(&self.owner_proof, files)
            .expect("FIXTURE: the owner's put installs the fact pack")
        {
            PackInstallDisposition::Installed(receipt) => {
                assert_eq!(
                    receipt.pack_name, FACT_PACK,
                    "FIXTURE: the owner's put installs the fact pack"
                );
            }
            other => panic!(
                "FIXTURE: the owner's put installs the fact pack and binds its hook: {other:?}"
            ),
        }
        let bindings = self
            .vault
            .pack_hook_bindings()
            .expect("FIXTURE: live bindings read")
            .into_iter()
            .filter(|(_, binding)| binding.pack == FACT_PACK)
            .collect::<Vec<_>>();
        assert_eq!(
            bindings.len(),
            1,
            "FIXTURE: the put binds the fact hook live: {bindings:?}"
        );
        bindings[0].0
    }

    /// One call of `VERB` as the owner, through its pre and post chains; the
    /// post chain records the two Continue receipts. Answers the invocation.
    fn run_verb_call(&self) -> InvocationId {
        self.run_verb_call_as(self.owner)
    }

    /// One call of `VERB` as `actor`, as `run_verb_call`.
    fn run_verb_call_as(&self, actor: EntityId) -> InvocationId {
        self.run_verb_call_with(actor, serde_json::json!({"rows": []}))
    }

    /// One call of `VERB` as `actor` whose post hooks see `result`, as
    /// `run_verb_call`.
    fn run_verb_call_with(&self, actor: EntityId, result: serde_json::Value) -> InvocationId {
        let invocation = InvocationId::mint();
        let call = VerbCall {
            verb: VERB.to_owned(),
            invocation,
            actor,
            class: HookActorClass::Human,
            scope: None,
            board_epoch: None,
            turn: None,
            domain: VerbDomain::Read,
            reader: None,
        };
        let args = serde_json::json!({});
        let check = |_: &serde_json::Value| -> std::result::Result<(), String> { Ok(()) };
        let pre = self
            .vault
            .pre_verb_hooks(call, args, &check)
            .expect("FIXTURE: the pre chain runs")
            .expect("FIXTURE: the pre chain passes with no pre hook");
        self.vault
            .post_verb_hooks(pre, result)
            .expect("FIXTURE: the post chain runs")
            .expect("FIXTURE: the post chain admits both Continues");
        invocation
    }

    /// The Hook receipts whose trigger is `invocation`, newest first.
    fn hook_runs(&self, invocation: InvocationId) -> Vec<ReceiptRecord> {
        let want = invocation.to_hex();
        self.vault
            .receipts(ReceiptQuery::new(1000).with_kind(ReceiptKind::Hook))
            .expect("FIXTURE: hook receipts read")
            .into_iter()
            .filter(|receipt| receipt.trigger_ref.as_deref() == Some(want.as_str()))
            .collect()
    }
}

fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The live `human` credential this host mints `holder`, held to `records`
/// (empty: no records narrowing), verified as a transport verifies it.
fn credential(fixture: &Fixture, holder: EntityId, records: BTreeSet<String>) -> VerifiedSlip {
    let root = fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("FIXTURE: host root slip");
    let mut claims = root.claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.records = records;
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("FIXTURE: mint the credential slip");
    let binding = fixture
        .issuer
        .binding_proof(&slip, CHALLENGE)
        .expect("FIXTURE: sign the credential proof");
    fixture
        .vault
        .verify_capability_slip(&fixture.issuer.public_key(), &slip, CHALLENGE, &binding)
        .expect("FIXTURE: verify the credential as a transport does")
}

/// One landed claim with `FACT_PREDICATE` about a fresh person; answers the claim id.
fn land_fact_claim(vault: &Vault) -> EntityId {
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"hook subject",
        )
        .expect("FIXTURE: put the claim subject");
    let claim_id = EntityId::now();
    let body = ClaimBody::new(
        FACT_PREDICATE,
        ClaimSubject::Entity(subject),
        rmpv::Value::from("fixture input"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: build the claim body");
    vault
        .put_claim(&claim_id, &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("FIXTURE: land the fact claim");
    claim_id
}

#[test]
fn owner_credential_bound_read_returns_its_verb_hook_receipts() {
    let fixture = Fixture::new();
    let bindings = fixture.put_verb_pack();
    assert_eq!(
        bindings.len(),
        2,
        "FIXTURE: both post hooks bind live: {bindings:?}"
    );
    let invocation = fixture.run_verb_call();
    let kept = fixture.hook_runs(invocation);
    assert_eq!(
        kept.len(),
        2,
        "FIXTURE: the post chain records two Hook receipts for the call: {kept:?}"
    );
    for receipt in &kept {
        assert_eq!(
            receipt.fields.get("verb").map(String::as_str),
            Some(VERB),
            "FIXTURE: a verb-hook receipt names its verb: {receipt:?}"
        );
        assert_eq!(
            receipt.fields.get("invocation").map(String::as_str),
            receipt.trigger_ref.as_deref(),
            "FIXTURE: a verb-hook receipt triggers on its invocation: {receipt:?}"
        );
        assert!(
            receipt.fields.contains_key("binding")
                && receipt.fields.contains_key("code")
                && receipt.fields.contains_key("run_key"),
            "FIXTURE: a verb-hook receipt names its binding, CODE and run: {receipt:?}"
        );
    }
    // The owner's broad credential (no records narrowing) reads the binding,
    // CODE and the runs' (empty) read rows.
    let proof = credential(&fixture, fixture.owner, BTreeSet::new());
    let reader = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&proof);
    let page = reader
        .receipts_page(PAGE_LIMIT, &["hook".to_owned()], None)
        .expect("FIXTURE: the credential-bound kinds [hook] page reads");
    let got: Vec<_> = page
        .receipts
        .iter()
        .filter(|receipt| receipt.fields.get("verb").map(String::as_str) == Some(VERB))
        .collect();
    assert_eq!(
        got.len(),
        2,
        "MISSING: the owner's credential-bound kinds [hook] read returns the call's two verb-hook receipts, got {}: {got:?}",
        got.len()
    );
}

#[test]
fn credential_without_binding_or_code_reads_no_verb_hook_receipt() {
    let fixture = Fixture::new();
    fixture.put_verb_pack();
    let invocation = fixture.run_verb_call();
    let kept = fixture.hook_runs(invocation);
    assert_eq!(
        kept.len(),
        2,
        "FIXTURE: the post chain records two Hook receipts for the call: {kept:?}"
    );
    // A person with no grant, held by a records caveat to its own row: it
    // reads neither the hook's binding, its CODE row, nor any run read row.
    let stranger = EntityId::now();
    fixture
        .vault
        .put_entity(
            &stranger,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a person with no grant",
        )
        .expect("FIXTURE: put the stranger person");
    let proof = credential(&fixture, stranger, BTreeSet::from([stranger.to_hex()]));
    let reader = fixture
        .vault
        .memory(stranger, EdgeActorClass::Human)
        .with_read_proof(&proof);
    let page = reader
        .receipts_page(PAGE_LIMIT, &["hook".to_owned()], None)
        .expect("FIXTURE: the credential-bound kinds [hook] page reads");
    let got: Vec<_> = page
        .receipts
        .iter()
        .filter(|receipt| receipt.fields.get("verb").map(String::as_str) == Some(VERB))
        .collect();
    assert!(
        got.is_empty(),
        "LEAK: a credential that cannot read the hook's binding or CODE row gets none of its verb-hook receipts, got {got:?}"
    );
}

#[test]
fn fact_hook_receipt_visibility_still_follows_its_trigger_row() {
    let fixture = Fixture::new();
    let binding = fixture.put_fact_pack();
    let claim_id = land_fact_claim(&fixture.vault);
    let pass = FactHookRunner::new()
        .run_pass(&fixture.vault, &NothingRuntime, 256)
        .expect("FIXTURE: the runner takes the fact");
    assert_eq!(
        pass.runs, 1,
        "FIXTURE: the fact hook runs once on the landed claim: {pass:?}"
    );
    let want = claim_id.to_hex();
    let kept: Vec<_> = fixture
        .vault
        .receipts(ReceiptQuery::new(1000).with_kind(ReceiptKind::Hook))
        .expect("FIXTURE: hook receipts read")
        .into_iter()
        .filter(|receipt| receipt.trigger_ref.as_deref() == Some(want.as_str()))
        .collect();
    assert_eq!(
        kept.len(),
        1,
        "FIXTURE: the fact run records one Hook receipt on its trigger: {kept:?}"
    );
    assert!(
        !kept[0].fields.contains_key("verb"),
        "FIXTURE: a fact-hook receipt carries no verb field: {kept:?}"
    );
    let binding_hex = binding.to_hex();
    assert_eq!(
        kept[0].fields.get("binding").map(String::as_str),
        Some(binding_hex.as_str()),
        "FIXTURE: the fact-hook receipt names its binding: {kept:?}"
    );
    // The owner's broad credential reads the trigger, binding, CODE and the
    // run's (empty) read rows, so it keeps the fact-hook receipt.
    let owner_proof = credential(&fixture, fixture.owner, BTreeSet::new());
    let owner = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&owner_proof);
    let owner_page = owner
        .receipts_page(PAGE_LIMIT, &["hook".to_owned()], None)
        .expect("FIXTURE: the owner's kinds [hook] page reads");
    let owner_got: Vec<_> = owner_page
        .receipts
        .iter()
        .filter(|receipt| {
            receipt.fields.get("hook").map(String::as_str) == Some("example.factscreen/fact-note")
        })
        .collect();
    assert_eq!(
        owner_got.len(),
        1,
        "MISSING: the owner's credential-bound kinds [hook] read keeps the fact-hook receipt it triggers on, got {}: {owner_got:?}",
        owner_got.len()
    );
    // A stranger held to its own row reads no trigger row, so it keeps none.
    let stranger = EntityId::now();
    fixture
        .vault
        .put_entity(
            &stranger,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a person with no grant",
        )
        .expect("FIXTURE: put the stranger person");
    let stranger_proof = credential(&fixture, stranger, BTreeSet::from([stranger.to_hex()]));
    let stranger_reader = fixture
        .vault
        .memory(stranger, EdgeActorClass::Human)
        .with_read_proof(&stranger_proof);
    let stranger_page = stranger_reader
        .receipts_page(PAGE_LIMIT, &["hook".to_owned()], None)
        .expect("FIXTURE: the stranger's kinds [hook] page reads");
    let stranger_got: Vec<_> = stranger_page
        .receipts
        .iter()
        .filter(|receipt| {
            receipt.fields.get("hook").map(String::as_str) == Some("example.factscreen/fact-note")
        })
        .collect();
    assert!(
        stranger_got.is_empty(),
        "LEAK: a credential that cannot read the fact trigger keeps no fact-hook receipt, got {stranger_got:?}"
    );
}

#[test]
fn a_verb_hook_receipt_reaches_only_the_actor_that_made_the_call() {
    let fixture = Fixture::new();
    fixture.put_verb_pack();
    let caller = EntityId::now();
    fixture
        .vault
        .put_entity(
            &caller,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"the person who makes the call",
        )
        .expect("FIXTURE: put the calling person");
    let invocation = fixture.run_verb_call_as(caller);
    let kept = fixture.hook_runs(invocation);
    assert_eq!(
        kept.len(),
        2,
        "FIXTURE: the post chain records two Hook receipts for the call: {kept:?}"
    );
    let caller_hex = caller.to_hex();
    for receipt in &kept {
        assert_eq!(
            receipt.on_behalf_of.as_deref(),
            Some(caller_hex.as_str()),
            "FIXTURE: a verb-hook receipt names the actor that made the call: {receipt:?}"
        );
    }
    // The owner's broad credential reads the binding, CODE and the runs'
    // (empty) read rows, as in case (a), but it did not make this call.
    let proof = credential(&fixture, fixture.owner, BTreeSet::new());
    let reader = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&proof);
    let page = reader
        .receipts_page(PAGE_LIMIT, &["hook".to_owned()], None)
        .expect("FIXTURE: the credential-bound kinds [hook] page reads");
    let want = invocation.to_hex();
    let got: Vec<_> = page
        .receipts
        .iter()
        .filter(|receipt| {
            receipt.fields.get("invocation").map(String::as_str) == Some(want.as_str())
        })
        .collect();
    assert!(
        got.is_empty(),
        "LEAK: a credential that did not make the call reads its verb-hook receipts, got {got:?}"
    );
}

/// The hex of each row `field` names among `receipts`' fields, after any
/// `<kind>:` prefixes.
fn named_hex(receipts: &[ReceiptRecord], field: &str) -> BTreeSet<String> {
    receipts
        .iter()
        .filter_map(|receipt| receipt.fields.get(field))
        .filter_map(|value| value.rsplit(':').next())
        .map(str::to_owned)
        .collect()
}

/// How many of `reader`'s kinds [hook] page receipts each of `calls` has.
fn kept_per_call(reader: &oneiron::Memory<'_>, calls: &[InvocationId]) -> Vec<usize> {
    let page = reader
        .receipts_page(PAGE_LIMIT, &["hook".to_owned()], None)
        .expect("FIXTURE: the credential-bound kinds [hook] page reads");
    calls
        .iter()
        .map(|call| {
            let want = call.to_hex();
            page.receipts
                .iter()
                .filter(|receipt| {
                    receipt.fields.get("invocation").map(String::as_str) == Some(want.as_str())
                })
                .count()
        })
        .collect()
}

#[test]
fn a_narrower_credential_of_the_caller_reads_no_receipt_whose_input_showed_a_row_it_cannot_read() {
    let fixture = Fixture::new();
    fixture.put_verb_pack();
    let restricted = EntityId::now();
    fixture
        .vault
        .put_entity(
            &restricted,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a row the narrower credential does not read",
        )
        .expect("FIXTURE: put the restricted row");
    let plain = fixture.run_verb_call();
    let packed = fixture.run_verb_call_with(
        fixture.owner,
        serde_json::json!({
            "pack_version": "v1",
            "items": [{"short_id": restricted.to_hex(), "text": RESTRICTED_WORDS}],
            "rendered": RESTRICTED_WORDS,
        }),
    );
    let listed = fixture.run_verb_call_with(
        fixture.owner,
        serde_json::json!({
            "rows": [{"claim_ref": restricted.to_hex(), "value": RESTRICTED_WORDS}],
        }),
    );
    let shown: Vec<usize> = {
        let inputs = HOOK_INPUTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        [packed, listed]
            .iter()
            .map(|call| {
                let want = call.to_hex();
                inputs
                    .iter()
                    .filter(|input| input.contains(&want) && input.contains(RESTRICTED_WORDS))
                    .count()
            })
            .collect()
    };
    assert_eq!(
        shown,
        vec![2, 2],
        "FIXTURE: both post hooks of each call saw the restricted row's words (packed, listed)"
    );
    let mut kept = Vec::new();
    for call in [plain, packed, listed] {
        let runs = fixture.hook_runs(call);
        assert_eq!(
            runs.len(),
            2,
            "FIXTURE: the post chain records two Hook receipts for each call: {runs:?}"
        );
        kept.extend(runs);
    }
    let mut records = named_hex(&kept, "binding");
    records.extend(named_hex(&kept, "code"));
    assert!(
        records.len() >= 2 && !records.contains(&restricted.to_hex()),
        "FIXTURE: the narrower credential is held to the binding and CODE rows: {records:?}"
    );
    let calls = [plain, packed, listed];

    let broad = credential(&fixture, fixture.owner, BTreeSet::new());
    let broad_reader = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&broad);
    assert_eq!(
        kept_per_call(&broad_reader, &calls),
        vec![2, 2, 2],
        "MISSING: the owner's broad credential, which reads the restricted row, keeps every call's two receipts (plain, packed, listed)"
    );

    let narrow = credential(&fixture, fixture.owner, records);
    let narrow_reader = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&narrow);
    let got = kept_per_call(&narrow_reader, &calls);
    assert_eq!(
        got[0], 2,
        "MISSING: the owner's credential held to the binding and CODE rows keeps the receipts of a call whose input showed no other row, got {got:?} (plain, packed, listed)"
    );
    assert_eq!(
        &got[1..],
        &[0, 0],
        "LEAK: a narrower credential of the caller reads receipts whose run's input showed a row it cannot read, got {got:?} (plain, packed, listed)"
    );
}

#[test]
fn a_credential_reads_no_receipt_whose_input_showed_content_naming_no_held_row() {
    let fixture = Fixture::new();
    fixture.put_verb_pack();
    let unheld = EntityId::now();
    let counted = fixture.run_verb_call_with(fixture.owner, serde_json::json!({"count": 3}));
    let short_ref = fixture.run_verb_call_with(
        fixture.owner,
        serde_json::json!({"rows": [{"short_id": "ms1:0a", "value": RESTRICTED_WORDS}]}),
    );
    let foreign = fixture.run_verb_call_with(
        fixture.owner,
        serde_json::json!({"rows": [{"claim_ref": unheld.to_hex(), "value": RESTRICTED_WORDS}]}),
    );
    let unresolved = fixture.run_verb_call_with(
        fixture.owner,
        serde_json::json!({
            "pack_version": "v1",
            "items": [{"short_id": "ms1:0a", "text": RESTRICTED_WORDS}],
            "rendered": RESTRICTED_WORDS,
        }),
    );
    let code = named_hex(&fixture.hook_runs(counted), "code")
        .into_iter()
        .next()
        .expect("FIXTURE: a Hook receipt names its CODE row");
    let named_beside = fixture.run_verb_call_with(
        fixture.owner,
        serde_json::json!({"value": [code, "private-name"], "narrowing": {"suppressed_count": 0}}),
    );
    let calls = [counted, short_ref, foreign, unresolved, named_beside];
    let mut kept = Vec::new();
    for call in calls {
        let runs = fixture.hook_runs(call);
        assert_eq!(
            runs.len(),
            2,
            "FIXTURE: the post chain records two Hook receipts for each call, read unbound: {runs:?}"
        );
        kept.extend(runs);
    }
    let mut records = named_hex(&kept, "binding");
    records.extend(named_hex(&kept, "code"));
    assert!(
        records.len() >= 2 && !records.contains(&unheld.to_hex()),
        "FIXTURE: the narrower credential is held to the binding and CODE rows: {records:?}"
    );

    let narrow = credential(&fixture, fixture.owner, records);
    let narrow_reader = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&narrow);
    let got = kept_per_call(&narrow_reader, &calls);
    assert_eq!(
        got,
        vec![0, 0, 0, 0, 0],
        "LEAK: a narrower credential of the caller reads receipts whose run's input showed content no row object names, got {got:?} (count, short ref, unheld id, unresolved pack item, id beside a name)"
    );

    let broad = credential(&fixture, fixture.owner, BTreeSet::new());
    let broad_reader = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&broad);
    let got = kept_per_call(&broad_reader, &calls);
    assert_eq!(
        got,
        vec![0, 0, 0, 0, 0],
        "RULE: no credential-bound reader keeps such a receipt, the broad one included, as for a host verb's free text, got {got:?} (count, short ref, unheld id, unresolved pack item, id beside a name)"
    );
}

/// The `receipt_tail` entries of each body input the call `invocation`'s
/// hooks ran on.
fn tails_of(invocation: InvocationId) -> Vec<Vec<serde_json::Value>> {
    let want = invocation.to_hex();
    HOOK_INPUTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter_map(|input| serde_json::from_str::<serde_json::Value>(input).ok())
        .filter(|input| {
            input.get("invocation").and_then(serde_json::Value::as_str) == Some(want.as_str())
        })
        .map(|input| {
            input
                .get("receipt_tail")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

/// How many of `tail`'s entries are Hook receipts of the call `invocation`.
fn receipts_of_call(tail: &[serde_json::Value], invocation: InvocationId) -> usize {
    let want = invocation.to_hex();
    tail.iter()
        .filter(|receipt| {
            receipt
                .pointer("/fields/invocation")
                .and_then(serde_json::Value::as_str)
                == Some(want.as_str())
        })
        .count()
}

#[test]
fn a_later_hook_reads_no_receipt_of_unknown_provenance_in_its_tail() {
    let fixture = Fixture::new();
    fixture.put_verb_pack();
    // A tail holds the 8 newest receipts, ordered by their second and, within
    // one, Gate before Hook: the calls start a second after the pack's
    // install receipts, so their Hook receipts are the tail's newest.
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let plain = fixture.run_verb_call();
    let counted = fixture.run_verb_call_with(fixture.owner, serde_json::json!({"count": 3}));
    let next = fixture.run_verb_call();
    let tails = tails_of(next);
    assert_eq!(
        tails.len(),
        2,
        "FIXTURE: both post hooks of the next call ran and kept their input"
    );
    for tail in &tails {
        assert_eq!(
            receipts_of_call(tail, plain),
            2,
            "MISSING: a later hook's tail keeps the receipts of a call whose input showed nothing: {tail:?}"
        );
        assert_eq!(
            receipts_of_call(tail, counted),
            0,
            "LEAK: a later hook's tail shows receipts the receipt screen withholds, whose notes it could copy: {tail:?}"
        );
    }
}
