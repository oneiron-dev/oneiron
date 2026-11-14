//! OPUS-T0-F gate pins, PR 8 (Engine NOTE 13 Nov 02:19): green pins for
//! seven owner gates of OPUS-TRIAGECENSUS's census (census/TRIAGE.md, class
//! GAP-PASSES: real callers pass these gates today, and no running test
//! drove them from a door). Each test drives the owner door the server's
//! facade calls, with that caller's inputs, through the gate, and reads the
//! write or the read back. A pin that goes red is a live refusal of a real
//! caller (GAP-BROKEN).
//!
//! Each test name starts with the census ids it drives, so `-- g224_` runs
//! one gate's pins.
//!
//! - G190 `code_owner` and G153 `code_readable`: the owner declares a TASK's
//!   code symbols (`code_symbols_declare_as`), renews and releases them.
//! - G192 `merge_queue_owner` and G193 `merge_queue_repo`: the owner observes
//!   the repo's merge queue (`merge_queue_observe_as`).
//! - G224 `BuildCache::admit_account_in_txn`: the owner builds in a working
//!   view and the cache answers the build again (`code_view_build_as`,
//!   `code_cache_reuse_as`, `code_cache_get_as`); a reuse on an empty cache
//!   answers a miss.
//! - G226 `weave_lens_answer_plan`: the owner's live weave lens admits a plan
//!   that cites every item once (`weave_lens_prepare`,
//!   `weave_lens_finish_framed`).
//! - G227 `ScopedRead::weave_report_in_txn`, the Owner arm: the owner's weave
//!   report reads an Approved claim about the owner (`weave_report`).
//!
//! G198 `require_admitted_push` needs a served git push; its pin is its own
//! file. Test doors: the run repo fixture's (`label_writers::embedded_owner`)
//! and `code_view_fork::commit_tested_revision`.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test gate_pins_code_merge_queue_weave`.
#![cfg(oneiron_test_support)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use std::collections::BTreeMap;

use fixture::{LABEL_RS, MATH_RS, RepoFixture, TestResult};
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, WeaveItemView,
    WeaveLensPlan, WeaveLensPlanLine, WeaveLensPlanSection, WeaveReportRequest, WeaveSectionInput,
    WeaveSectionKind,
};
use oneiron::code_view::VisibleFilePolicy;
use oneiron::lens::GeneratedUiSurfaceCapabilities;
use oneiron::memory::code_doors::{CodeSymbolsDeclareRequest, CodeSymbolsTaskRequest};
use oneiron::memory::code_view_doors::{
    CodeBuildClass, CodeBuildSpec, CodeCacheReadRequest, CodeCacheState, CodeViewActionRequest,
    CodeViewBuildRequest, CodeViewMaterializeRequest, CodeViewRequest,
};
use oneiron::memory::merge_queue_doors::MergeQueueObserveRequest;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::code_view_fork::commit_tested_revision;
use oneiron::{EntityId, TimeRange};

// ── G190, G153: the owner's symbol declaration ──────────────────────────

#[test]
fn g153_g190_the_owner_declares_renews_and_releases_a_tasks_symbols() -> TestResult {
    let repo = RepoFixture::new()?;
    let memory = repo.owner_memory();
    let task = memory
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some("symbol lease pin".into()),
            Some(repo.owner),
            Some(repo.vault.now_recorded_at()),
        ))?
        .task_ref
        .ok_or("the owner's TASK lands")?;
    let symbol = repo.symbol("math.rs", "add_one")?;

    let declared = memory.code_symbols_declare_as(
        &repo.owner_proof,
        CodeSymbolsDeclareRequest {
            repo: repo.repo,
            task,
            symbols: vec![symbol],
            ttl_seconds: 600,
        },
    )?;
    assert!(declared.declaration.held, "nothing overlaps: it holds");
    assert_eq!(declared.declaration.task, task);
    assert_eq!(declared.declaration.holder, repo.owner);
    assert_eq!(declared.declaration.symbols, vec![symbol]);
    assert!(declared.blockers.is_empty());

    // The renew re-loads the stored declaration.
    let renewed =
        memory.code_symbols_renew_as(&repo.owner_proof, CodeSymbolsTaskRequest { task })?;
    assert_eq!(renewed.symbols, vec![symbol]);
    let released =
        memory.code_symbols_release_as(&repo.owner_proof, CodeSymbolsTaskRequest { task })?;
    assert!(released.released);
    Ok(())
}

// ── G192, G193: the owner's merge queue observation ─────────────────────

#[test]
fn g192_g193_the_owner_observes_the_repos_merge_queue() -> TestResult {
    let repo = RepoFixture::new()?;
    let seen = repo.owner_memory().merge_queue_observe_as(
        &repo.owner_proof,
        MergeQueueObserveRequest {
            repo: repo.repo,
            batches: Vec::new(),
        },
    )?;
    assert_eq!(seen.repo, repo.repo);
    assert_eq!(seen.green_commit, repo.commit, "the fixture's green");
    assert!(seen.batches.is_empty());
    assert!(seen.pending_slow_batch_refs.is_empty());
    Ok(())
}

// ── G224: the owner's build cache ───────────────────────────────────────

/// The repo, its tested revision of both files, and one owner working view
/// of it, as tests/code_view_edit.rs builds them.
struct ViewFixture {
    repo: RepoFixture,
    view: CodeViewRequest,
}

fn open_view() -> TestResult<ViewFixture> {
    let repo = RepoFixture::new()?;
    let tested = commit_tested_revision(
        &repo.vault,
        repo.owner,
        repo.repo,
        &[("math.rs", MATH_RS), ("label.rs", LABEL_RS)],
    )?;
    let view = repo
        .owner_memory()
        .code_view_materialize_as(
            &repo.owner_proof,
            CodeViewMaterializeRequest {
                repo: repo.repo,
                tested,
                account: repo.owner,
                policy: VisibleFilePolicy {
                    version: 1,
                    include_prefixes: vec![String::new()],
                    exclude_prefixes: Vec::new(),
                },
            },
        )?
        .view;
    let view = CodeViewRequest {
        view,
        repo: repo.repo,
        tested,
        account: repo.owner,
    };
    Ok(ViewFixture { repo, view })
}

/// The owner's build request for `/usr/bin/true` in the view, under the
/// action digest the view's action door answers, as a client sends it.
fn build_request(fixture: &ViewFixture) -> TestResult<CodeViewBuildRequest> {
    let spec = CodeBuildSpec {
        argv: vec!["/usr/bin/true".to_owned()],
        env_allowlist: BTreeMap::new(),
        platform: BTreeMap::new(),
        declared_outputs: Vec::new(),
        secret_taint_refs: Vec::new(),
        class: CodeBuildClass::Build,
    };
    let action_digest = fixture
        .repo
        .owner_memory()
        .code_view_action_as(
            &fixture.repo.owner_proof,
            CodeViewActionRequest {
                view: fixture.view.clone(),
                spec: spec.clone(),
            },
        )?
        .action_digest;
    Ok(CodeViewBuildRequest {
        view: fixture.view.clone(),
        spec,
        action_digest,
    })
}

#[test]
fn g224_a_reuse_on_an_empty_cache_answers_a_miss() -> TestResult {
    let fixture = open_view()?;
    let request = build_request(&fixture)?;
    let reused = fixture
        .repo
        .owner_memory()
        .code_cache_reuse_as(&fixture.repo.owner_proof, request)?;
    assert!(matches!(reused.state, CodeCacheState::Miss), "{reused:?}");
    assert!(reused.entry.is_none());
    Ok(())
}

#[test]
fn g224_the_owners_view_build_is_answered_again_from_the_cache() -> TestResult {
    let fixture = open_view()?;
    let request = build_request(&fixture)?;
    let memory = fixture.repo.owner_memory();
    let proof = &fixture.repo.owner_proof;

    let built = memory.code_view_build_as(proof, request.clone())?;
    let entry = built.entry.ok_or("the build answers its entry")?;
    assert_eq!(entry.exit_code, 0);

    let reused = memory.code_cache_reuse_as(proof, request.clone())?;
    assert!(matches!(reused.state, CodeCacheState::Hit), "{reused:?}");
    let again = reused.entry.ok_or("a hit answers its entry")?;
    assert_eq!(again.exit_code, 0);
    assert_eq!(again.receipt, entry.receipt, "the original producer");

    let read = memory.code_cache_get_as(
        proof,
        CodeCacheReadRequest {
            account: fixture.repo.owner,
            action_digest: request.action_digest,
        },
    )?;
    assert!(matches!(read.state, CodeCacheState::Hit), "{read:?}");
    Ok(())
}

// ── G226, G227: the owner's weave report and lens ───────────────────────

/// A predicate the shipped policy manifest names normal (its `profile.`
/// rule). A predicate no rule names takes the criticality floor, and the
/// owner's Approved claim on it pends (`gate.pending.criticality_floor`).
const NOTE_PREDICATE: &str = "profile.note";
const PLAN_TITLE: &str = "Owen's notes";
const PLAN_LINE: &str = "yuki noted one thing";

/// One Approved, Active claim the owner stated about the owner.
fn put_note(repo: &RepoFixture) -> TestResult<EntityId> {
    let at = repo.vault.now_recorded_at();
    let mut body = ClaimBody::new(
        NOTE_PREDICATE,
        ClaimSubject::Entity(repo.owner),
        rmpv::Value::from("yuki"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    let id = EntityId::now();
    repo.vault
        .put_claim(&id, &body, TimeRange { start: at, end: at }, at)?;
    Ok(id)
}

/// One owner section, the claims under the note predicate.
fn note_report() -> WeaveReportRequest {
    WeaveReportRequest {
        sections: vec![WeaveSectionInput {
            kind: WeaveSectionKind::Conflicts,
            predicates: vec![NOTE_PREDICATE.to_owned()],
            edge_kinds: Vec::new(),
        }],
    }
}

#[test]
fn g227_the_owners_weave_report_reads_a_claim_about_the_owner() -> TestResult {
    let repo = RepoFixture::new()?;
    let note = put_note(&repo)?;
    let view = repo
        .owner_memory()
        .weave_report(Some(&repo.owner_proof), &note_report())?;
    assert_eq!(view.sections.len(), 1);
    assert_eq!(view.sections[0].kind, WeaveSectionKind::Conflicts);
    let [WeaveItemView::Claim { claim }] = view.sections[0].items.as_slice() else {
        return Err(format!("the section is not the one note: {:?}", view.sections[0]).into());
    };
    assert_eq!(claim.claim_ref, note.to_hex());
    assert_eq!(claim.predicate, NOTE_PREDICATE);
    Ok(())
}

/// The keys of the live lens's input items, as the generate step reads them.
fn item_keys(input: &str) -> TestResult<Vec<String>> {
    let input: serde_json::Value = serde_json::from_str(input)?;
    let mut keys = Vec::new();
    for section in input["sections"].as_array().ok_or("input sections")? {
        for item in section["items"].as_array().ok_or("section items")? {
            keys.push(item["key"].as_str().ok_or("item key")?.to_owned());
        }
    }
    Ok(keys)
}

#[test]
fn g226_the_owners_weave_lens_admits_a_plan_citing_each_item_once() -> TestResult {
    let repo = RepoFixture::new()?;
    put_note(&repo)?;
    let request = note_report();
    let memory = repo.owner_memory();
    let live = memory
        .weave_lens_prepare(Some(&repo.owner_proof), &request)?
        .ok_or("the weave-report skill loads")?;
    let keys = item_keys(&live.input)?;
    assert_eq!(keys.len(), 1, "the one note: {}", live.input);

    // The model's answer, as the server's weave lens step hands it on.
    let answer = serde_json::to_string(&WeaveLensPlan {
        title: PLAN_TITLE.to_owned(),
        wrong_label: "Not right".to_owned(),
        sections: vec![WeaveLensPlanSection {
            heading: "Notes".to_owned(),
            summary: Vec::new(),
            items: keys
                .into_iter()
                .map(|key| WeaveLensPlanLine {
                    key,
                    line: PLAN_LINE.to_owned(),
                })
                .collect(),
        }],
    })?;
    assert_eq!(live.plan_refusal(&answer), None);
    let lens = memory
        .weave_lens_finish_framed(
            Some(&repo.owner_proof),
            &request,
            live,
            &answer,
            "gate-pins-model",
        )?
        .ok_or("the report moved between the two reads")?;
    let (_frame, card) = lens.lower(&GeneratedUiSurfaceCapabilities::all_atom_kit())?;
    let card = serde_json::to_string(&card)?;
    assert!(card.contains(PLAN_TITLE), "{card}");
    assert!(card.contains(PLAN_LINE), "{card}");
    Ok(())
}
