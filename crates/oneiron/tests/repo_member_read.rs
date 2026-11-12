//! NO-DOOR REPO-MEMBER-SNAPSHOT-SYMBOL-READ (tests/e2e/code-custody.test.ts
//! CODE-CUSTODY-01), ruled CODECUSTODY-READ = A: a repository member reads
//! a snapshot, its files and its symbols through the run repo doors
//! (`self.code.snapshots.get` and `.read`, `self.code.symbols.definitions`
//! and `.neighbors`), on the paths its Grant reads and no others.
//!
//! Membership is an owner-minted Access Grant with repo bounds, checked at
//! each call. An agent whose live Grant names no bounds for the repo is
//! refused `repo_no_membership`, and so is a member on its next call after
//! the owner revokes its Grant.
//!
//! Each agent run is real: an enabled AGENT_DEF paired to the owner, on a
//! TASK the owner assigned it, a claimed attempt the host sealed with an
//! executor run. The repo is a committed snapshot the owner ingested.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test repo_member_read`.
#![cfg(oneiron_test_support)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use std::collections::BTreeSet;

use fixture::{
    LABEL_RS, MAIN, MATH_RS, RepoFixture, RunBinding, TestResult, bind_run, create_enabled_agent,
    leased_try, mint_repo_grant, paired_agent_slip,
};
use oneiron::authority::ActSurface;
use oneiron::memory::MemoryResult;
use oneiron::memory::repo_doors::{
    RepoSnapshotsGetInput, RepoSnapshotsReadInput, RepoSymbolsDefinitionsInput,
    RepoSymbolsNeighborsInput,
};
use oneiron::verbs::{AgentGrantRevokeRequest, revoke_agent_grant_as};
use oneiron::{EntityId, Vault};
use sha2::{Digest, Sha256};

/// The repo, and three runs on it: a member that reads every Rust file, a
/// member that reads `math.rs` alone, and an agent with no membership.
struct Fixture {
    repo: RepoFixture,
    /// `add_one` in math.rs, by its current CODE_SYMBOL id.
    add_one: EntityId,
    member: RunBinding,
    member_grant: EntityId,
    narrow: RunBinding,
    outsider: RunBinding,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let repo = RepoFixture::new()?;
        let add_one = repo.symbol("math.rs", "add_one")?;
        let (member, member_grant, narrow, outsider) = {
            let vault = &repo.vault;
            let owner_proof = &repo.owner_proof;
            let member = create_enabled_agent(vault, owner_proof, "repo-read-member")?;
            let narrow = create_enabled_agent(vault, owner_proof, "repo-read-narrow")?;
            let outsider = create_enabled_agent(vault, owner_proof, "repo-read-outsider")?;
            let member_slip = paired_agent_slip(vault, &repo.issuer, owner_proof, member, 0x61)?;
            let narrow_slip = paired_agent_slip(vault, &repo.issuer, owner_proof, narrow, 0x62)?;
            let outsider_slip =
                paired_agent_slip(vault, &repo.issuer, owner_proof, outsider, 0x63)?;
            let member_grant = mint_repo_grant(
                vault,
                owner_proof,
                member,
                Some(&repo.bounds(&["*.rs"], &["*.rs"])),
            )?;
            mint_repo_grant(
                vault,
                owner_proof,
                narrow,
                Some(&repo.bounds(&["math.rs"], &["math.rs"])),
            )?;
            // A live Grant, read and write, that names no repo bounds.
            mint_repo_grant(vault, owner_proof, outsider, None)?;

            let owner_memory = repo.owner_memory();
            let member_try = leased_try(vault, &owner_memory, repo.owner, member, "read all")?;
            let narrow_try = leased_try(vault, &owner_memory, repo.owner, narrow, "read math")?;
            let outsider_try = leased_try(vault, &owner_memory, repo.owner, outsider, "read none")?;
            (
                bind_run(vault, &member_slip, member_try)?,
                member_grant,
                bind_run(vault, &narrow_slip, narrow_try)?,
                bind_run(vault, &outsider_slip, outsider_try)?,
            )
        };
        Ok(Self {
            repo,
            add_one,
            member,
            member_grant,
            narrow,
            outsider,
        })
    }

    fn vault(&self) -> &Vault {
        &self.repo.vault
    }

    /// `self.code.snapshots.get` for `run`: the paths it lists.
    fn list(&self, run: &RunBinding) -> MemoryResult<BTreeSet<String>> {
        let answer = run.memory(self.vault()).repo_snapshots_get_for_run(
            &run.binding,
            RepoSnapshotsGetInput {
                repo: self.repo.repo,
                portable_repo: None,
                git_ref: MAIN.to_owned(),
                snapshot: self.repo.snapshot.clone(),
            },
        )?;
        let view = answer.output;
        assert_eq!(
            (view.repo, view.commit.as_str(), view.snapshot.as_str()),
            (
                self.repo.repo,
                self.repo.commit.as_str(),
                self.repo.snapshot.as_str()
            ),
            "the snapshot of the commit main names now"
        );
        Ok(view.files.into_iter().map(|file| file.path).collect())
    }

    /// `self.code.snapshots.read` for `run`: the text of `path`.
    fn read(&self, run: &RunBinding, path: &str) -> MemoryResult<String> {
        let answer = run.memory(self.vault()).repo_snapshots_read_for_run(
            &run.binding,
            RepoSnapshotsReadInput {
                repo: self.repo.repo,
                portable_repo: None,
                git_ref: MAIN.to_owned(),
                snapshot: self.repo.snapshot.clone(),
                path: path.to_owned(),
                why: None,
            },
        )?;
        let read = answer.output;
        assert_eq!(read.file.path, path);
        assert_eq!(
            read.text_sha256,
            format!("{:x}", Sha256::digest(read.content.as_bytes())),
            "the text hash is the returned text's"
        );
        Ok(read.content)
    }

    /// `self.code.symbols.definitions` for `run`: each definition of `name`,
    /// as (symbol, path).
    fn definitions(&self, run: &RunBinding, name: &str) -> MemoryResult<Vec<(EntityId, String)>> {
        let answer = run.memory(self.vault()).repo_symbols_definitions_for_run(
            &run.binding,
            RepoSymbolsDefinitionsInput {
                repo: self.repo.repo,
                portable_repo: None,
                git_ref: MAIN.to_owned(),
                snapshot: self.repo.snapshot.clone(),
                name: name.to_owned(),
            },
        )?;
        Ok(answer
            .output
            .definitions
            .into_iter()
            .map(|definition| (definition.symbol, definition.path))
            .collect())
    }

    /// `self.code.symbols.neighbors` for `run`, seeded at `add_one`: the
    /// seed's symbol and the paths of every relation endpoint it shows.
    fn neighbors(&self, run: &RunBinding) -> MemoryResult<(EntityId, BTreeSet<String>)> {
        let answer = run.memory(self.vault()).repo_symbols_neighbors_for_run(
            &run.binding,
            RepoSymbolsNeighborsInput {
                repo: self.repo.repo,
                git_ref: MAIN.to_owned(),
                snapshot: self.repo.snapshot.clone(),
                symbol: self.add_one,
                path: "math.rs".to_owned(),
                kinds: None,
                direction: None,
            },
        )?;
        let view = answer.output;
        assert_eq!(view.seed.definition.name, "add_one");
        assert_eq!(view.seed.definition.path, "math.rs");
        assert_eq!(
            view.seed.content_hash_blake3,
            blake3::hash(MATH_RS.as_bytes()).to_hex().to_string(),
            "the seed cites math.rs as committed"
        );
        let paths = view
            .neighbors
            .into_iter()
            .flat_map(|neighbor| {
                [
                    neighbor.source.definition.path,
                    neighbor.target.definition.path,
                ]
            })
            .collect();
        Ok((view.seed.definition.symbol, paths))
    }
}

/// The refusal code of a read that must be refused.
fn refused<T: std::fmt::Debug>(read: MemoryResult<T>, what: &str) -> String {
    read.expect_err(what).code
}

#[test]
fn a_granted_member_reads_the_snapshot_its_files_and_its_symbols() -> TestResult {
    let fixture = Fixture::new()?;
    let member = &fixture.member;

    assert_eq!(
        fixture.list(member)?,
        BTreeSet::from(["label.rs".to_owned(), "math.rs".to_owned()]),
    );
    assert_eq!(fixture.read(member, "math.rs")?, MATH_RS);
    assert_eq!(fixture.read(member, "label.rs")?, LABEL_RS);
    assert_eq!(
        fixture.definitions(member, "add_one")?,
        vec![(fixture.add_one, "math.rs".to_owned())],
    );
    let (seed, endpoints) = fixture.neighbors(member)?;
    assert_eq!(seed, fixture.add_one);
    assert!(
        endpoints
            .iter()
            .all(|path| path == "math.rs" || path == "label.rs"),
        "{endpoints:?}"
    );
    Ok(())
}

#[test]
fn a_member_reads_only_the_paths_its_grant_reads() -> TestResult {
    let fixture = Fixture::new()?;
    let narrow = &fixture.narrow;

    assert_eq!(
        fixture.list(narrow)?,
        BTreeSet::from(["math.rs".to_owned()]),
        "label.rs is not listed"
    );
    assert_eq!(fixture.read(narrow, "math.rs")?, MATH_RS);
    assert_eq!(
        refused(
            fixture.read(narrow, "label.rs"),
            "label.rs is outside the Grant"
        ),
        "repo_path_outside_scope"
    );
    assert_eq!(
        fixture.definitions(narrow, "label")?,
        Vec::new(),
        "a definition on an unread path is absent"
    );
    assert_eq!(
        fixture.definitions(narrow, "add_one")?,
        vec![(fixture.add_one, "math.rs".to_owned())],
    );
    let (seed, endpoints) = fixture.neighbors(narrow)?;
    assert_eq!(seed, fixture.add_one);
    assert!(
        endpoints.iter().all(|path| path == "math.rs"),
        "{endpoints:?}"
    );
    Ok(())
}

#[test]
fn an_agent_without_membership_is_refused_every_read() -> TestResult {
    let fixture = Fixture::new()?;
    let outsider = &fixture.outsider;

    assert_eq!(
        refused(fixture.list(outsider), "no membership lists nothing"),
        "repo_no_membership"
    );
    assert_eq!(
        refused(
            fixture.read(outsider, "math.rs"),
            "no membership reads no file"
        ),
        "repo_no_membership"
    );
    assert_eq!(
        refused(
            fixture.definitions(outsider, "add_one"),
            "no membership reads no definition"
        ),
        "repo_no_membership"
    );
    assert_eq!(
        refused(
            fixture.neighbors(outsider),
            "no membership reads no relation"
        ),
        "repo_no_membership"
    );
    Ok(())
}

#[test]
fn a_revoked_grant_is_refused_on_the_next_read() -> TestResult {
    let fixture = Fixture::new()?;
    let member = &fixture.member;
    assert_eq!(fixture.read(member, "math.rs")?, MATH_RS);

    revoke_agent_grant_as(
        fixture.vault(),
        &fixture.repo.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: fixture.member_grant,
            seen: None,
        },
    )?;
    assert_eq!(
        refused(
            fixture.read(member, "math.rs"),
            "a revoked Grant reads no file"
        ),
        "repo_no_membership"
    );
    assert_eq!(
        refused(fixture.list(member), "a revoked Grant lists nothing"),
        "repo_no_membership"
    );
    assert_eq!(
        refused(
            fixture.definitions(member, "add_one"),
            "a revoked Grant reads no definition"
        ),
        "repo_no_membership"
    );
    assert_eq!(
        refused(
            fixture.neighbors(member),
            "a revoked Grant reads no relation"
        ),
        "repo_no_membership"
    );
    Ok(())
}
