//! self.code doors: what the custody rows answer, keep, and refuse.
//!
//! P1 (canon `oneiron/code-in-oneiron/oneiron-arch-0068-repo-custody-v1.md:80`,
//! amended 2026-08-05): "no upstream secret value exists workspace-side":
//! the checkout holds a slip (a redemption right against the door), never
//! the secret. `self.code.checkout.bind` answers `RepoCheckoutBindOutput`
//! (`crates/oneiron-verb-wire/src/memory/repo_doors/custody.rs:35`), whose
//! `remote_url` is `<endpoint>/lease/<checkout>.<epoch>/<repo>.git`
//! (`crates/oneiron/src/memory/repo_doors/custody.rs:111-126`,
//! `holder.rs:80-92`) and "holds a redemption right only"; the door grammar
//! refuses any endpoint that could carry a credential
//! (`crates/oneiron/src/git_wire/checkout_remote.rs:16-40`), and the
//! lease row the bind stands on (`CheckoutLeaseAct`,
//! `crates/oneiron/src/store/checkout_lease.rs:291`) and the work stamp
//! `self.code.work.open` keeps (`RepoRunStamp`,
//! `crates/oneiron-records/src/memory/repo_doors/types.rs:37`) hold ids,
//! refs, and epochs only. A positive end-to-end bind needs a served store
//! under the vault's serving root, which no public fixture provides, so
//! this file proves every reachable enforcement point instead: the real
//! `work.open` answer, the real lease row, the endpoint grammar, the
//! operator-wins base, and the pinned answer shape.
//!
//! P2 (canon `:63`): "dirty or uncertain checkouts are retained, never
//! assumed disposable": a checkout collects only after a pushed-head
//! receipt. The verb path `vault.code.checkout.teardown` is host-only on an
//! embedded handle, but the shared teardown it fronts is public
//! (`CheckoutLeaseService::teardown`,
//! `crates/oneiron/src/checkout/lease/lifecycle.rs:173`), judging
//! `teardown_reason` (`crates/oneiron/src/checkout/lease/teardown.rs:78`):
//! no receipt is retained, a dirty or uncertain tree is retained, and only
//! a clean tree at the pushed head collects.
//!
//! P3 (canon `:64`): "retries cannot double-promote": a candidate result
//! has deterministic identity plus exactly one select/apply/release/discard
//! receipt. The verb path `vault.code.checkout.settle` is host-only on an
//! embedded handle, but the shared settlement it fronts is public
//! (`CheckoutLeaseService::settle`, `lifecycle.rs:116`): an identical retry
//! returns the first receipt, and any conflicting settle answers
//! `SettlementAlreadyWon`
//! (`crates/oneiron/src/checkout/lease/transactions.rs:135-180`).
//!
//! All 18 `self.code.*` rows state `"context": "run"`, so the generated
//! dispatch refuses each by name before hooks with `BAD_REQUEST` /
//! "unknown SDK agent verb"
//! (`crates/oneiron-sdk-generator/src/generate/emit_core.rs:826`); the two
//! checkout verb paths answer the host-only refusal instead. The table
//! test pins every refusal's code, message, and layer.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test self_code_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

use fixture::{
    LABEL_RS, MAIN, MATH_RS, RepoFixture, TestResult, agent_run, create_enabled_agent, leased_try,
    mint_repo_grant, paired_agent_slip,
};
use oneiron::checkout::lease::{
    CheckoutClaimRequest, CheckoutError, CheckoutFactMutation, CheckoutFactSink, CheckoutId,
    CheckoutLeaseAct, CheckoutLeaseFence, CheckoutLeaseGrant, CheckoutLeaseService,
    CheckoutLeaseState, CheckoutLiveness, CheckoutLivenessPulse, CheckoutRepoOps, CheckoutResult,
    CheckoutRetainReason, CheckoutSettlementDisposition, CheckoutSettlementRequest,
    CheckoutTaskClass, CheckoutTeardownInspection, CheckoutTeardownOutcome, GitOid,
    PushedHeadReceipt, TeardownReceiptMatch,
};
use oneiron::codebase::RepoRef;
use oneiron::git_wire::validate_checkout_door;
use oneiron::memory::repo_doors::{
    RepoCheckoutBindInput, RepoCheckoutBindOutput, RepoWorkOpenInput, with_host_door_base,
};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_MODEL_UNAVAILABLE};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_testkit::{TestVault, door};
use serde_json::{Value, json};

/// The 18 self.code rows, in verb-table order.
const SELF_CODE_ROWS: [&str; 18] = [
    "self.code.checkout.bind",
    "self.code.export",
    "self.code.merge_queue.enqueue",
    "self.code.merge_queue.observe",
    "self.code.proposal_resolve",
    "self.code.proposal_submit",
    "self.code.snapshots.get",
    "self.code.snapshots.ingest",
    "self.code.snapshots.read",
    "self.code.symbols.declare",
    "self.code.symbols.definitions",
    "self.code.symbols.neighbors",
    "self.code.symbols.observe",
    "self.code.symbols.release",
    "self.code.symbols.renew",
    "self.code.views.get",
    "self.code.views.read",
    "self.code.work.open",
];

/// The checkout verb paths behind P2 and P3.
const HOST_ONLY_ROWS: [&str; 2] = ["vault.code.checkout.teardown", "vault.code.checkout.settle"];

/// The pushed head the test checkout sits at (40 hex chars).
const PUSHED_HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// The holder every test lease is claimed for.
const LEASE_HOLDER: &str = "self-code-doors-holder";
/// A test lease's lifetime: long past the test, so no expiry moves a row.
const LEASE_TTL: u64 = 3_600;
/// A checkout id that is never a real ticket (32 hex chars).
const TABLE_CHECKOUT: &str = "07070707070707070707070707070707";

/// Whether `seen` is `len` lowercase hex chars: an id or hash shape.
fn is_lower_hex(seen: &str, len: usize) -> bool {
    seen.len() == len
        && seen
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The test checkout id: byte 7 sixteen times.
fn checkout_id_for_test() -> CheckoutId {
    CheckoutId::from_bytes([7; 16]).expect("the test checkout id")
}

/// A plain vault on a temp dir that the returned handle keeps alive.
#[allow(dead_code)]
struct LeaseVault {
    dir: tempfile::TempDir,
    vault: Vault,
}

impl LeaseVault {
    fn opened() -> Self {
        let dir = tempfile::tempdir().expect("a temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("the vault opens");
        Self { dir, vault }
    }
}

/// The fact sink the lease tests run: every TASK fact applies.
struct AcceptFacts;

impl CheckoutFactSink for AcceptFacts {
    fn apply_checkout_fact(&mut self, _: CheckoutFactMutation) -> CheckoutResult<()> {
        Ok(())
    }
}

/// No liveness pulse is ever seen, so teardown judges the checkout by its
/// receipt and its tree alone.
struct NoLiveness;

impl CheckoutLiveness for NoLiveness {
    fn publish(&mut self, _: CheckoutLivenessPulse) -> CheckoutResult<()> {
        Ok(())
    }

    fn current(&self, _: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>> {
        Ok(None)
    }

    fn clear(&mut self, _: CheckoutId, _: u64) -> CheckoutResult<()> {
        Ok(())
    }
}

type LeaseService<'vault> = CheckoutLeaseService<'vault, AcceptFacts, NoLiveness>;

/// The repo port the teardown tests drive: a tree at the pushed head whose
/// dirt and receipt match the test sets, counting its collections.
struct DrivenRepo {
    dirty: Cell<bool>,
    receipt_match: Cell<TeardownReceiptMatch>,
    collect_calls: Cell<u32>,
}

impl DrivenRepo {
    fn clean_at_pushed_head() -> Self {
        Self {
            dirty: Cell::new(false),
            receipt_match: Cell::new(TeardownReceiptMatch::Match),
            collect_calls: Cell::new(0),
        }
    }
}

impl CheckoutRepoOps for DrivenRepo {
    fn materialize(&self, _: &CheckoutLeaseAct) -> CheckoutResult<()> {
        Ok(())
    }

    fn inspect_teardown(
        &self,
        _: &CheckoutLeaseAct,
        _: &PushedHeadReceipt,
    ) -> CheckoutResult<CheckoutTeardownInspection> {
        Ok(CheckoutTeardownInspection {
            observed_head: Some(GitOid::parse(PUSHED_HEAD).expect("the pushed head parses")),
            dirty: self.dirty.get(),
            receipt_match: self.receipt_match.get(),
            occupant: None,
        })
    }

    fn collect(&self, _: &CheckoutLeaseAct) -> CheckoutResult<()> {
        self.collect_calls.set(self.collect_calls.get() + 1);
        Ok(())
    }
}

/// Claims the test checkout for [`LEASE_HOLDER`] with an hour's lease.
/// Answers the grant and the first second every lease door accepts: the
/// doors compare `now` with the lease's `claimed_at`, which the vault's own
/// clock stamps.
fn claim_test_checkout(service: &mut LeaseService<'_>) -> (CheckoutLeaseGrant, u64) {
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs();
    let grant = service
        .claim(CheckoutClaimRequest {
            checkout_id: checkout_id_for_test(),
            task_ref: EntityId::from_bytes([1; 16]).expect("a task id"),
            repo_ref: RepoRef::parse(&format!("github:owner/repo#{PUSHED_HEAD}"))
                .expect("a repo ref"),
            holder_ref: LEASE_HOLDER.into(),
            task_class: CheckoutTaskClass::Build,
            ttl_secs: Some(LEASE_TTL),
            now: wall,
        })
        .expect("the claim lands");
    let claimed_at = service
        .get(checkout_id_for_test())
        .expect("the lease reads")
        .expect("the claim kept its lease")
        .claimed_at;
    let start = wall.max(claimed_at);
    assert!(
        start + 10 < wall + LEASE_TTL,
        "the vault clock ({claimed_at}) is within the lease of the wall clock ({wall})"
    );
    (grant, start)
}

/// The fence the holder drives its grant's lease with.
fn fence_for_grant(grant: &CheckoutLeaseGrant) -> CheckoutLeaseFence {
    CheckoutLeaseFence {
        checkout_id: checkout_id_for_test(),
        epoch: grant.epoch,
        holder_ref: LEASE_HOLDER.into(),
    }
}

/// The pushed-head receipt for the grant's epoch at [`PUSHED_HEAD`].
fn receipt_for_grant(grant: &CheckoutLeaseGrant) -> PushedHeadReceipt {
    PushedHeadReceipt {
        receipt_ref: "self-code-doors-receipt".to_owned(),
        observed_ref: "self-code-doors-observed".to_owned(),
        pushed_head: PUSHED_HEAD.to_owned(),
        checkout_id: checkout_id_for_test(),
        epoch: grant.epoch,
    }
}

/// The settlement request the holder settles its grant's lease with.
fn settle_request_for_grant(
    grant: &CheckoutLeaseGrant,
    disposition: CheckoutSettlementDisposition,
    observed: &str,
    result: &str,
    now: u64,
) -> CheckoutSettlementRequest {
    CheckoutSettlementRequest {
        fence: fence_for_grant(grant),
        disposition,
        observed_ref: observed.to_owned(),
        result_ref: result.to_owned(),
        now,
    }
}

/// One agent's live run on a fresh repo: its sealed run binding and the
/// work it opened at the queue's green commit.
struct CodeRun {
    repo: RepoFixture,
    binding: oneiron::memory::repo_doors::RepoRunBinding,
    actor: oneiron::WriteActor,
    work: EntityId,
}

impl CodeRun {
    fn opened() -> TestResult<Self> {
        let repo = RepoFixture::new()?;
        let (binding, actor, work) = {
            let vault = &repo.vault;
            let owner_proof = &repo.owner_proof;
            let bounds = repo.bounds(&["*.rs"], &["*.rs"]);
            let agent = create_enabled_agent(vault, owner_proof, "self-code-doors-agent")?;
            let slip = paired_agent_slip(vault, &repo.issuer, owner_proof, agent, 0x61)?;
            let grant = mint_repo_grant(vault, owner_proof, agent, Some(&bounds))?;
            let owner_memory = repo.owner_memory();
            let leased = leased_try(vault, &owner_memory, repo.owner, agent, "self code")?;
            let bound = agent_run(vault, &slip, leased, repo.repo, grant)?;
            (bound.binding, bound.actor, bound.work)
        };
        Ok(Self {
            repo,
            binding,
            actor,
            work,
        })
    }
}

/// P1: the checkout holds a redemption right, never the secret. The real
/// `work.open` answer carries ids, refs, and hashes only; the real lease
/// row a bind stands on carries claim inputs only; the door grammar refuses
/// any endpoint that could carry a credential; the operator's door base
/// wins over the run's; and the bind answer shape holds the ticket only.
/// Proved at the enforcement points; no positive end-to-end bind runs here.
#[test]
fn checkout_answers_and_lease_rows_hold_a_ticket_never_an_upstream_secret() -> TestResult {
    let code_run = CodeRun::opened()?;
    let vault = &code_run.repo.vault;
    let memory = vault.memory(code_run.actor.entity_ref(), code_run.actor.actor_class());

    // The run's own fresh work: every open mints a fresh work id, and two
    // opens at one green share one fork.
    let first = memory
        .repo_work_open_for_run(
            &code_run.binding,
            RepoWorkOpenInput {
                repo: code_run.repo.repo,
                portable_repo: None,
                git_ref: MAIN.to_owned(),
            },
        )?
        .output;
    let second = memory
        .repo_work_open_for_run(
            &code_run.binding,
            RepoWorkOpenInput {
                repo: code_run.repo.repo,
                portable_repo: None,
                git_ref: MAIN.to_owned(),
            },
        )?
        .output;
    assert_eq!(first.repo, code_run.repo.repo, "the work names its anchor");
    assert_eq!(first.git_ref, MAIN, "the work echoes its ref");
    assert_eq!(
        first.base_green, code_run.repo.commit,
        "the work pins the queue's green commit"
    );
    assert!(
        is_lower_hex(&first.base_snapshot, 64),
        "the base snapshot is a hash: {snapshot}",
        snapshot = &first.base_snapshot
    );
    assert!(
        is_lower_hex(&first.fork_hash, 64),
        "the fork hash is a hash: {fork}",
        fork = &first.fork_hash
    );
    assert_ne!(first.work, second.work, "two opens are two works");
    assert_ne!(first.work, code_run.work, "each open mints a fresh work");
    assert_eq!(
        first.fork_hash, second.fork_hash,
        "two opens at one green share one fork"
    );
    let mut seen_paths: Vec<String> = first.files.iter().map(|file| file.path.clone()).collect();
    seen_paths.sort();
    assert_eq!(
        seen_paths,
        ["label.rs", "math.rs"],
        "the work holds the two files"
    );
    for file in &first.files {
        let expected = match file.path.as_str() {
            "math.rs" => MATH_RS,
            "label.rs" => LABEL_RS,
            other => panic!("unexpected work file: {other}"),
        };
        assert_eq!(
            file.content_hash_blake3,
            blake3::hash(expected.as_bytes()).to_hex().to_string(),
            "the work cites {path} as committed",
            path = &file.path
        );
        assert!(
            file.projection.is_none(),
            "an unmarked file rides no projection: {path}",
            path = &file.path
        );
    }

    // The lease row a bind stands on: the claim's own inputs, nothing more.
    let lease_vault = LeaseVault::opened();
    let mut service = LeaseService::new(&lease_vault.vault, AcceptFacts, NoLiveness);
    let (grant, _) = claim_test_checkout(&mut service);
    assert_eq!(grant.epoch, 1, "a fresh checkout id starts at epoch 1");
    let kept = service
        .get(checkout_id_for_test())
        .expect("the lease reads")
        .expect("the claim kept its lease");
    assert_eq!(
        kept.checkout_id,
        checkout_id_for_test(),
        "the lease keeps its id"
    );
    assert_eq!(
        kept.task_ref,
        EntityId::from_bytes([1; 16]).expect("a task id"),
        "the lease keeps its TASK"
    );
    assert_eq!(
        kept.repo_ref,
        RepoRef::parse(&format!("github:owner/repo#{PUSHED_HEAD}")).expect("a repo ref"),
        "the lease keeps its repo ref"
    );
    assert_eq!(kept.holder_ref, LEASE_HOLDER, "the lease keeps its holder");
    assert_eq!(kept.epoch, 1, "the lease keeps its epoch");
    assert_eq!(
        kept.state,
        CheckoutLeaseState::Active,
        "a fresh lease is active"
    );
    assert!(kept.bound_attempt.is_none(), "no dispatch bound this lease");
    assert_eq!(
        kept.checkout_id.to_string(),
        "07".repeat(16),
        "the ticket names the checkout id as 32 hex chars"
    );

    // The door grammar: a credential-bearing endpoint never becomes a
    // checkout remote.
    assert!(
        validate_checkout_door("https://host.example/git").is_ok(),
        "a plain door base validates"
    );
    for refused in [
        "https://user:token@host.example/git",
        "https://user@host.example/git",
        "https://host.example/git?next=1",
        "https://host.example/other",
        "http://host.example/git",
    ] {
        assert!(
            validate_checkout_door(refused).is_err(),
            "the door grammar refuses {refused}"
        );
    }
    assert!(
        validate_checkout_door("http://localhost:8080/git").is_ok(),
        "HTTP stays for loopback only"
    );

    // The operator's door base wins over the run's, so a run cannot point
    // its checkout at another door.
    let bind_input: RepoCheckoutBindInput = serde_json::from_value(json!({
        "repo": code_run.repo.repo.to_hex(),
        "ref": MAIN,
        "checkout": TABLE_CHECKOUT,
        "epoch": 1,
        "endpoint": "https://run.example/git",
    }))?;
    assert_eq!(
        with_host_door_base(bind_input.clone(), Some("https://operator.example/git")).endpoint,
        Some("https://operator.example/git".to_owned()),
        "the operator setting wins"
    );
    assert_eq!(
        with_host_door_base(bind_input, None).endpoint,
        Some("https://run.example/git".to_owned()),
        "with none set the run base stays"
    );

    // The bind answer shape: the ticket and the lease URL, nothing more,
    // and no hidden credential member decodes.
    let bind_output: RepoCheckoutBindOutput = serde_json::from_value(json!({
        "repo": code_run.repo.repo.to_hex(),
        "ref": MAIN,
        "checkout": TABLE_CHECKOUT,
        "epoch": 1,
        "remote_url": format!(
            "https://host.example/git/lease/{TABLE_CHECKOUT}.1/{repo_hex}.git",
            repo_hex = code_run.repo.repo.to_hex()
        ),
    }))?;
    let shape: Value = serde_json::to_value(&bind_output)?;
    let mut shape_keys: Vec<String> = shape
        .as_object()
        .expect("the answer is an object")
        .keys()
        .cloned()
        .collect();
    shape_keys.sort();
    assert_eq!(
        shape_keys,
        ["checkout", "epoch", "ref", "remote_url", "repo"],
        "the bind answer holds the ticket only"
    );
    // An unknown credential-shaped member is dropped, never kept: the
    // answer carries exactly its five members.
    let dropped: RepoCheckoutBindOutput = serde_json::from_value(json!({
        "repo": code_run.repo.repo.to_hex(),
        "ref": MAIN,
        "checkout": TABLE_CHECKOUT,
        "epoch": 1,
        "remote_url": "https://host.example/git/lease/x",
        "token": "upstream-secret-value",
    }))
    .expect("unknown members do not break the bind answer");
    let dropped_shape: Value = serde_json::to_value(&dropped)?;
    assert_eq!(
        dropped_shape
            .as_object()
            .expect("the answer is an object")
            .len(),
        5,
        "an unknown member is dropped, never kept"
    );
    Ok(())
}

/// P2: a checkout collects only after a pushed-head receipt; dirty or
/// uncertain checkouts are retained, never assumed disposable — and a
/// retained checkout re-drives to collection once its holder clears the
/// cause.
#[test]
fn teardown_retains_dirty_and_unpushed_checkouts_until_the_pushed_head() {
    let lease_vault = LeaseVault::opened();
    let mut service = LeaseService::new(&lease_vault.vault, AcceptFacts, NoLiveness);
    let (grant, start) = claim_test_checkout(&mut service);
    let fence = fence_for_grant(&grant);
    let receipt = receipt_for_grant(&grant);

    // No receipt: retained, and nothing collects.
    let unpushed = DrivenRepo::clean_at_pushed_head();
    let outcome = service
        .teardown(fence.clone(), None, &unpushed, start + 1)
        .expect("teardown answers");
    assert_eq!(
        outcome,
        CheckoutTeardownOutcome::Retained {
            checkout_id: checkout_id_for_test(),
            epoch: grant.epoch,
            reason: CheckoutRetainReason::MissingPushedHeadReceipt,
        },
        "an unpushed checkout is retained"
    );
    assert_eq!(unpushed.collect_calls.get(), 0, "a retain collects nothing");

    // A dirty tree at the pushed head: retained, and nothing collects.
    let dirty = DrivenRepo::clean_at_pushed_head();
    dirty.dirty.set(true);
    let outcome = service
        .teardown(fence.clone(), Some(&receipt), &dirty, start + 2)
        .expect("teardown answers");
    assert_eq!(
        outcome,
        CheckoutTeardownOutcome::Retained {
            checkout_id: checkout_id_for_test(),
            epoch: grant.epoch,
            reason: CheckoutRetainReason::DirtyOrUncertain,
        },
        "a dirty checkout is retained"
    );
    assert_eq!(dirty.collect_calls.get(), 0, "a retain collects nothing");

    // An uncertain receipt match: retained, and nothing collects.
    let uncertain = DrivenRepo::clean_at_pushed_head();
    uncertain.receipt_match.set(TeardownReceiptMatch::Uncertain);
    let outcome = service
        .teardown(fence.clone(), Some(&receipt), &uncertain, start + 3)
        .expect("teardown answers");
    assert_eq!(
        outcome,
        CheckoutTeardownOutcome::Retained {
            checkout_id: checkout_id_for_test(),
            epoch: grant.epoch,
            reason: CheckoutRetainReason::DirtyOrUncertain,
        },
        "an uncertain checkout is retained"
    );
    assert_eq!(
        uncertain.collect_calls.get(),
        0,
        "a retain collects nothing"
    );
    assert_eq!(
        service
            .get(checkout_id_for_test())
            .expect("the lease reads")
            .expect("the retained lease stays")
            .state,
        CheckoutLeaseState::Retained,
        "a retain pins the lease retained"
    );

    // The holder clears the cause and drives teardown again: collected.
    let cleared = DrivenRepo::clean_at_pushed_head();
    let outcome = service
        .teardown(fence, Some(&receipt), &cleared, start + 4)
        .expect("teardown answers");
    assert_eq!(
        outcome,
        CheckoutTeardownOutcome::Collected {
            checkout_id: checkout_id_for_test(),
            epoch: grant.epoch,
        },
        "a clean checkout at the pushed head collects"
    );
    assert_eq!(cleared.collect_calls.get(), 1, "collection collects once");
}

/// P3: a candidate result settles exactly once. An identical retry returns
/// the first receipt; any conflicting settle is refused, so retries cannot
/// double-promote.
#[test]
fn settle_consumes_once_and_an_identical_retry_returns_its_receipt() {
    let lease_vault = LeaseVault::opened();
    let mut service = LeaseService::new(&lease_vault.vault, AcceptFacts, NoLiveness);
    let (grant, start) = claim_test_checkout(&mut service);

    let won = service
        .settle(settle_request_for_grant(
            &grant,
            CheckoutSettlementDisposition::Select,
            "self-code-doors-observed",
            "self-code-doors-result",
            start + 1,
        ))
        .expect("the first settle wins");
    assert_eq!(
        won.checkout_id,
        checkout_id_for_test(),
        "the receipt names its checkout"
    );
    assert_eq!(won.epoch, grant.epoch, "the receipt names its epoch");
    assert_eq!(
        won.disposition,
        CheckoutSettlementDisposition::Select,
        "the receipt names its disposition"
    );
    assert_eq!(
        service
            .get(checkout_id_for_test())
            .expect("the lease reads")
            .expect("the settled lease stays")
            .state,
        CheckoutLeaseState::Settled,
        "a settle pins the lease settled"
    );

    // An identical retry returns the first receipt, byte for byte.
    let again = service
        .settle(settle_request_for_grant(
            &grant,
            CheckoutSettlementDisposition::Select,
            "self-code-doors-observed",
            "self-code-doors-result",
            start + 2,
        ))
        .expect("an identical retry returns its receipt");
    assert_eq!(again, won, "a retry returns the one receipt, not a second");

    // A conflicting settle — another disposition, another result — loses.
    for conflict in [
        settle_request_for_grant(
            &grant,
            CheckoutSettlementDisposition::Discard,
            "self-code-doors-observed",
            "self-code-doors-result",
            start + 3,
        ),
        settle_request_for_grant(
            &grant,
            CheckoutSettlementDisposition::Select,
            "self-code-doors-observed",
            "self-code-doors-other-result",
            start + 3,
        ),
    ] {
        assert!(
            matches!(
                service.settle(conflict),
                Err(CheckoutError::SettlementAlreadyWon)
            ),
            "a conflicting settle loses to the won receipt"
        );
    }
}

/// Every row without its context answers its typed refusal: each of the 18
/// run-only self.code rows is refused before hooks with BAD_REQUEST /
/// "unknown SDK agent verb", and each checkout verb path is refused with
/// the host-only MODEL_UNAVAILABLE and its fixed message.
#[test]
fn rows_without_a_run_or_a_host_answer_their_typed_refusal() {
    let test_vault =
        TestVault::seeded("self-code-doors-table", |_, _| Ok(())).expect("seed the vault");
    let vault = test_vault.open_owned().expect("open the vault owned");
    vault
        .ensure_embedded_owner_actor()
        .expect("ensure the embedded owner");
    let owner = door::owner(&vault).expect("the owner caller");
    let stranger = vault.memory(
        vault
            .ensure_agent_principal("self-code-doors-stranger")
            .expect("ensure the agent"),
        EdgeActorClass::Agent,
    );

    for row in SELF_CODE_ROWS {
        for caller in [&owner, &stranger] {
            let refused =
                door::invoke(caller, row, json!({})).expect_err(&format!("{row} is refused"));
            assert_eq!(
                refused.code, MEMORY_CODE_BAD_REQUEST,
                "{row} refusal code (dispatch facade gate)"
            );
            assert_eq!(
                refused.message, "unknown SDK agent verb",
                "{row} refusal message (dispatch facade gate)"
            );
        }
    }

    let candidate = EntityId::now().to_hex();
    for row in HOST_ONLY_ROWS {
        let input = match row {
            "vault.code.checkout.teardown" => json!({
                "checkout": TABLE_CHECKOUT,
                "epoch": 1,
                "pushed_head_receipt": null,
            }),
            _ => json!({
                "checkout": TABLE_CHECKOUT,
                "epoch": 1,
                "observed_ref": "self-code-doors-observed",
                "candidate": candidate.clone(),
                "action": "select",
            }),
        };
        let refused = door::invoke(&owner, row, input).expect_err(&format!("{row} is refused"));
        assert_eq!(
            refused.code, MEMORY_CODE_MODEL_UNAVAILABLE,
            "{row} refusal code (host-only row)"
        );
        assert_eq!(
            refused.message,
            format!(
                "{row} runs on a server's own model seats, decision ladder or hook sandbox; an embedded vault has none"
            ),
            "{row} refusal message (host-only row)"
        );
    }
}
