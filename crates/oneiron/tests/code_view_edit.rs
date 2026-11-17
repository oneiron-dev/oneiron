//! Row 6 WORKING-VIEW-EDIT, ruled CODECUSTODY-VIEW = A and
//! CODECUSTODY-VIEW-BUILD Q1 = A, Q2 = A, Q3 = A: `vault.code.views.edit`
//! edits one owner working view's own fork of a file.
//!
//! - The owner's edit lands on that view alone: the view reads the new text,
//!   its action key moves, and its fork's operation names him; another view
//!   of the same tested revision, the tested state and the shared document
//!   keep their text. A stale revision or file hash refuses, and a copy left
//!   behind its row heals at the next owner read.
//! - An agent edits the view only under a live Grant bound to that view and
//!   account, on its editable globs; every other repo edit seam passes over
//!   that Grant, and a revoke refuses its next edit.
//! - A path the view holds as a masked copy is refused; its other paths edit.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test code_view_edit`.
#![cfg(oneiron_test_support)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use std::collections::{BTreeMap, BTreeSet};

use fixture::{LABEL_RS, MAIN, MATH_RS, RepoFixture, TestResult, create_enabled_agent};
use oneiron::authority::ActSurface;
use oneiron::code_view::VisibleFilePolicy;
use oneiron::codebase::RepoRef;
use oneiron::federation::{RepoAccessBounds, Scope, ScopeAxis, WorkingViewEditBounds};
use oneiron::memory::MemoryResult;
use oneiron::memory::code_view_doors::{
    CodeBuildClass, CodeBuildSpec, CodeViewActionRequest, CodeViewEdit, CodeViewEditProof,
    CodeViewEditRequest, CodeViewMaterializeRequest, CodeViewReadRequest, CodeViewRequest,
};
use oneiron::test_doors::code_view_fork::{
    ViewForkEdit, commit_tested_revision, hold_masked_copy, repo_edit_refusal, view_fork_edits,
};
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;

/// math.rs as the edits leave it.
const MATH_EDITED: &str = "pub fn add_one(value: u32) -> u32 {\n    value.saturating_add(1)\n}\n";
const MATH_AGAIN: &str = "pub fn add_one(value: u32) -> u32 {\n    value.wrapping_add(1)\n}\n";

fn sha256(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The repo, its tested revision of both files, and two owner views of it.
struct Fixture {
    repo: RepoFixture,
    tested: EntityId,
    one: EntityId,
    two: EntityId,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let repo = RepoFixture::new()?;
        let tested = commit_tested_revision(
            &repo.vault,
            repo.owner,
            repo.repo,
            &[("math.rs", MATH_RS), ("label.rs", LABEL_RS)],
        )?;
        let mut fixture = Self {
            repo,
            tested,
            one: EntityId::now(),
            two: EntityId::now(),
        };
        fixture.one = fixture.materialize()?;
        fixture.two = fixture.materialize()?;
        Ok(fixture)
    }

    fn materialize(&self) -> TestResult<EntityId> {
        Ok(self
            .repo
            .owner_memory()
            .code_view_materialize_as(
                &self.repo.owner_proof,
                CodeViewMaterializeRequest {
                    repo: self.repo.repo,
                    tested: self.tested,
                    account: self.repo.owner,
                    policy: VisibleFilePolicy {
                        version: 1,
                        include_prefixes: vec![String::new()],
                        exclude_prefixes: Vec::new(),
                    },
                },
            )?
            .view)
    }

    fn view(&self, view: EntityId) -> CodeViewRequest {
        CodeViewRequest {
            view,
            repo: self.repo.repo,
            tested: self.tested,
            account: self.repo.owner,
        }
    }

    fn read(&self, view: EntityId, path: &str) -> TestResult<String> {
        let file = self.repo.owner_memory().code_view_read_as(
            &self.repo.owner_proof,
            CodeViewReadRequest {
                view: self.view(view),
                path: path.to_owned(),
                why: None,
            },
        )?;
        Ok(String::from_utf8(file.bytes)?)
    }

    fn revision(&self, view: EntityId) -> TestResult<u64> {
        Ok(self
            .repo
            .owner_memory()
            .code_view_get_as(&self.repo.owner_proof, self.view(view))?
            .revision)
    }

    fn action_key(&self, view: EntityId) -> TestResult<String> {
        Ok(self
            .repo
            .owner_memory()
            .code_view_action_as(
                &self.repo.owner_proof,
                CodeViewActionRequest {
                    view: self.view(view),
                    spec: CodeBuildSpec {
                        argv: vec!["/usr/bin/true".to_owned()],
                        env_allowlist: BTreeMap::new(),
                        platform: BTreeMap::new(),
                        declared_outputs: Vec::new(),
                        secret_taint_refs: Vec::new(),
                        class: CodeBuildClass::Build,
                    },
                },
            )?
            .action_digest
            .hash)
    }

    fn edit_request(
        &self,
        view: EntityId,
        path: &str,
        revision: u64,
        before: &str,
        after: &str,
    ) -> CodeViewEditRequest {
        CodeViewEditRequest {
            view: self.view(view),
            path: path.to_owned(),
            expected_revision: revision,
            expected_sha256: sha256(before),
            replacement_text: after.to_owned(),
        }
    }

    fn owner_edit(&self, request: CodeViewEditRequest) -> MemoryResult<CodeViewEdit> {
        self.repo.owner_memory().code_view_edit_as(
            &CodeViewEditProof::Owner(self.repo.owner_proof.clone()),
            request,
        )
    }

    fn agent_edit(
        &self,
        agent: EntityId,
        request: CodeViewEditRequest,
    ) -> MemoryResult<CodeViewEdit> {
        self.repo
            .vault
            .memory(agent, EdgeActorClass::Agent)
            .code_view_edit_as(&CodeViewEditProof::Grant, request)
    }

    /// The tested state's text of `path`, regenerated from its frontier.
    fn tested_text(&self, path: &str) -> TestResult<String> {
        let revision = self
            .repo
            .vault
            .get_code_revision(&self.tested)?
            .ok_or("the tested revision is finalized")?;
        let frontier = revision
            .file_frontiers
            .values()
            .find(|frontier| frontier.path == path)
            .ok_or("the tested revision holds the path")?;
        Ok(self.repo.vault.code_document_at(frontier)?)
    }

    /// The shared live document's text of `path`.
    fn shared_text(&self, path: &str) -> TestResult<String> {
        let body = self
            .repo
            .vault
            .get_code_artifact(&self.repo.repo)?
            .ok_or("the repo is a CODE_ARTIFACT")?;
        let identity = self
            .repo
            .vault
            .resolve_repo_identity(&RepoRef::parse(&body.repo_ref)?)?;
        Ok(self
            .repo
            .vault
            .open_code_document(identity.as_str(), path, "", EntityId::now())?
            .text())
    }

    /// An owner-minted Access Grant for `agent`, read and write, editing
    /// `editable` under repo bounds, bound to `view` when given.
    fn mint(
        &self,
        agent: EntityId,
        editable: &[&str],
        view: Option<WorkingViewEditBounds>,
    ) -> TestResult<EntityId> {
        let mut authority_scope = Scope::top();
        authority_scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        Ok(mint_agent_grant_as(
            &self.repo.vault,
            &self.repo.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: Some(self.bounds(editable)),
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: view,
                check_in_ref: None,
            },
        )?
        .grant
        .grant_ref)
    }

    fn bounds(&self, editable: &[&str]) -> RepoAccessBounds {
        self.repo.bounds(&["*.rs"], editable)
    }

    fn bound(&self, view: EntityId) -> WorkingViewEditBounds {
        WorkingViewEditBounds {
            view,
            account: self.repo.owner,
        }
    }
}

/// The refusal code of an edit that must be refused.
fn refused<T: std::fmt::Debug>(answer: MemoryResult<T>, what: &str) -> String {
    answer.expect_err(what).code
}

#[test]
fn an_owner_edit_lands_on_its_view_alone() -> TestResult {
    let fixture = Fixture::new()?;
    let (one, two) = (fixture.one, fixture.two);
    assert_eq!(fixture.read(one, "math.rs")?, MATH_RS);
    let key_one = fixture.action_key(one)?;
    let key_two = fixture.action_key(two)?;
    assert_eq!(key_one, key_two, "two views of one tested tree share a key");

    let edit = fixture.owner_edit(fixture.edit_request(one, "math.rs", 0, MATH_RS, MATH_EDITED))?;
    assert_eq!(edit.revision, 1);
    assert_eq!(edit.before_sha256, sha256(MATH_RS));
    assert_eq!(edit.after_sha256, sha256(MATH_EDITED));

    assert_eq!(
        fixture.read(one, "math.rs")?,
        MATH_EDITED,
        "the view reads its edit"
    );
    assert_eq!(fixture.read(one, "label.rs")?, LABEL_RS);
    assert_eq!(
        fixture.read(two, "math.rs")?,
        MATH_RS,
        "another view keeps its text"
    );
    assert_eq!(
        fixture.tested_text("math.rs")?,
        MATH_RS,
        "the tested state keeps its text"
    );
    assert_eq!(
        fixture.shared_text("math.rs")?,
        MATH_RS,
        "the shared document keeps its text"
    );
    assert_eq!(
        view_fork_edits(&fixture.repo.vault, one, "math.rs")?,
        vec![ViewForkEdit {
            operation: edit.operation,
            actor: Some(fixture.repo.owner),
            revision: 1,
        }],
        "the view's fork names the owner's operation"
    );
    assert!(view_fork_edits(&fixture.repo.vault, two, "math.rs")?.is_empty());
    assert_eq!(fixture.revision(one)?, 1);
    assert_eq!(fixture.revision(two)?, 0);
    let got = fixture
        .repo
        .owner_memory()
        .code_view_get_as(&fixture.repo.owner_proof, fixture.view(one))?;
    assert_eq!(got.forks.len(), 1);
    assert_eq!(got.forks[0].path, "math.rs");
    assert_eq!(got.forks[0].text_sha256, sha256(MATH_EDITED));
    assert_ne!(
        fixture.action_key(one)?,
        key_one,
        "the edited view's key moves"
    );
    assert_eq!(
        fixture.action_key(two)?,
        key_two,
        "the other view's key stays"
    );

    // A stale revision or file hash refuses, and changes nothing.
    assert_eq!(
        refused(
            fixture.owner_edit(fixture.edit_request(one, "math.rs", 0, MATH_EDITED, MATH_AGAIN)),
            "a stale revision"
        ),
        "INVALID_STATE"
    );
    assert_eq!(
        refused(
            fixture.owner_edit(fixture.edit_request(one, "math.rs", 1, MATH_RS, MATH_AGAIN)),
            "a stale file hash"
        ),
        "INVALID_STATE"
    );
    assert_eq!(fixture.read(one, "math.rs")?, MATH_EDITED);
    let again =
        fixture.owner_edit(fixture.edit_request(one, "math.rs", 1, MATH_EDITED, MATH_AGAIN))?;
    assert_eq!(again.revision, 2);

    // A copy behind its row (an edit that committed before its copy landed)
    // heals at the next owner read.
    let host = fixture
        .repo
        .owner_memory()
        .code_view_get_as(&fixture.repo.owner_proof, fixture.view(one))?
        .host_path;
    let copy = std::path::Path::new(&host).join("math.rs");
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o644))?;
    std::fs::write(&copy, MATH_RS)?;
    assert_eq!(
        fixture.read(one, "math.rs")?,
        MATH_AGAIN,
        "the read repairs the copy"
    );
    Ok(())
}

#[test]
fn a_view_bound_grant_edits_that_view_alone() -> TestResult {
    let fixture = Fixture::new()?;
    let (one, two) = (fixture.one, fixture.two);
    let vault = &fixture.repo.vault;
    let owner_proof = &fixture.repo.owner_proof;
    let editor = create_enabled_agent(vault, owner_proof, "view-editor")?;
    let grant = fixture.mint(editor, &["math.rs"], Some(fixture.bound(one)))?;

    let edit = fixture.agent_edit(
        editor,
        fixture.edit_request(one, "math.rs", 0, MATH_RS, MATH_EDITED),
    )?;
    assert_eq!(edit.revision, 1);
    assert_eq!(fixture.read(one, "math.rs")?, MATH_EDITED);
    assert_eq!(
        view_fork_edits(vault, one, "math.rs")?,
        vec![ViewForkEdit {
            operation: edit.operation,
            actor: Some(editor),
            revision: 1,
        }],
        "the operation names the agent"
    );
    assert_eq!(fixture.read(two, "math.rs")?, MATH_RS);

    // Another view, a path outside the editable globs, and a request naming
    // another account are not this Grant's.
    assert_eq!(
        refused(
            fixture.agent_edit(
                editor,
                fixture.edit_request(two, "math.rs", 0, MATH_RS, MATH_EDITED)
            ),
            "another view"
        ),
        "repo_no_membership"
    );
    assert_eq!(
        refused(
            fixture.agent_edit(
                editor,
                fixture.edit_request(one, "label.rs", 1, LABEL_RS, MATH_EDITED)
            ),
            "a path outside the editable globs"
        ),
        "repo_path_outside_scope"
    );
    let mut elsewhere = fixture.edit_request(one, "math.rs", 1, MATH_EDITED, MATH_AGAIN);
    elsewhere.view.account = editor;
    assert_eq!(
        refused(fixture.agent_edit(editor, elsewhere), "another account"),
        "repo_no_membership"
    );

    // Every ordinary repo edit seam passes over the view-bound Grant; an
    // ordinary repo Grant of the same bounds passes there and edits no view.
    assert_eq!(
        repo_edit_refusal(
            vault,
            editor,
            EdgeActorClass::Agent,
            fixture.repo.repo,
            MAIN,
            "math.rs"
        )?,
        Some("repo_no_membership"),
        "a view-bound Grant is refused by a generic repo edit"
    );
    let plain = create_enabled_agent(vault, owner_proof, "repo-editor")?;
    fixture.mint(plain, &["math.rs"], None)?;
    assert_eq!(
        repo_edit_refusal(
            vault,
            plain,
            EdgeActorClass::Agent,
            fixture.repo.repo,
            MAIN,
            "math.rs"
        )?,
        None
    );
    assert_eq!(
        refused(
            fixture.agent_edit(
                plain,
                fixture.edit_request(one, "math.rs", 1, MATH_EDITED, MATH_AGAIN)
            ),
            "a Grant bound to no view"
        ),
        "repo_no_membership"
    );

    // After a revoke the same agent's next edit refuses.
    revoke_agent_grant_as(
        vault,
        owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: grant,
            seen: None,
        },
    )?;
    assert_eq!(
        refused(
            fixture.agent_edit(
                editor,
                fixture.edit_request(one, "math.rs", 1, MATH_EDITED, MATH_AGAIN)
            ),
            "a revoked Grant"
        ),
        "repo_no_membership"
    );
    assert_eq!(fixture.read(one, "math.rs")?, MATH_EDITED);
    Ok(())
}

#[test]
fn a_view_bound_grant_mints_only_on_an_owner_view_with_repo_bounds() -> TestResult {
    let fixture = Fixture::new()?;
    let vault = &fixture.repo.vault;
    let editor = create_enabled_agent(vault, &fixture.repo.owner_proof, "view-editor")?;
    let mut authority_scope = Scope::top();
    authority_scope.verbs =
        ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let without_bounds = mint_agent_grant_as(
        vault,
        &fixture.repo.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: editor,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: Some(fixture.bound(fixture.one)),
            check_in_ref: None,
        },
    );
    assert!(without_bounds.is_err(), "a view bound needs repo bounds");
    let unknown = fixture.mint(editor, &["math.rs"], Some(fixture.bound(EntityId::now())));
    assert!(unknown.is_err(), "a view bound names a live owner view");
    let other_account = fixture.mint(
        editor,
        &["math.rs"],
        Some(WorkingViewEditBounds {
            view: fixture.one,
            account: editor,
        }),
    );
    assert!(
        other_account.is_err(),
        "a view bound names the minting owner's account"
    );
    Ok(())
}

#[test]
fn a_masked_copy_is_refused_and_the_other_paths_edit() -> TestResult {
    let fixture = Fixture::new()?;
    let one = fixture.one;
    hold_masked_copy(&fixture.repo.vault, one, "math.rs")?;
    let error = fixture
        .owner_edit(fixture.edit_request(one, "math.rs", 0, MATH_RS, MATH_EDITED))
        .expect_err("a masked copy's edit refuses");
    assert_eq!(error.code, "BAD_REQUEST");
    assert!(
        error.message.contains("masked copy"),
        "the refusal names the masked copy: {}",
        error.message
    );
    assert_eq!(fixture.read(one, "math.rs")?, MATH_RS);
    let label = "pub fn label() -> &'static str {\n    \"edited\"\n}\n";
    let edit = fixture.owner_edit(fixture.edit_request(one, "label.rs", 0, LABEL_RS, label))?;
    assert_eq!(edit.revision, 1);
    assert_eq!(fixture.read(one, "label.rs")?, label);
    Ok(())
}
