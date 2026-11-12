//! NO-DOOR SYMBOL-LEASE-OBSERVATION (tests/e2e/code-custody.test.ts
//! CODE-CUSTODY-03): a leased run reads its own symbol declaration, held or
//! waiting, and the TASKs it waits behind now, through
//! `self.code.symbols.observe` (`Memory::repo_symbols_observe_for_run`),
//! without renewing, releasing or changing it. A renewal moves the expiry,
//! so it is not a read.
//!
//! Two agent runs are real: each agent is an enabled AGENT_DEF paired to the
//! owner, holds an owner-minted Access Grant with repo bounds, and runs a
//! TASK the owner assigned it, on a claimed attempt the host sealed with an
//! executor run. The repo is a committed snapshot the owner ingested, a
//! member of the root PROJECT, with its merge queue initialized at that
//! commit. A revoked Grant is refused on the next observation.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test symbol_lease_observe`.
#![cfg(oneiron_test_support)]

#[path = "repo_run/fixture.rs"]
mod fixture;

use fixture::{
    AgentRun, RepoFixture, TestResult, agent_run, create_enabled_agent, leased_try,
    mint_repo_grant, paired_agent_slip,
};
use oneiron::authority::ActSurface;
use oneiron::claim::PointRead;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::repo_doors::{
    RepoSymbolDeclarationView, RepoSymbolsDeclareInput, RepoSymbolsObserveInput,
    RepoSymbolsReleaseInput,
};
use oneiron::verbs::{AgentGrantRevokeRequest, revoke_agent_grant_as};
use oneiron::{EntityId, Vault};

/// A declaration's lifetime here: long past the test, so no expiry moves a
/// row while it runs.
const TTL_SECONDS: u64 = 3_600;

struct Fixture {
    repo: RepoFixture,
    symbol: EntityId,
    a: AgentRun,
    b: AgentRun,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let repo = RepoFixture::new()?;
        // The one symbol both runs declare: `add_one` in math.rs, by its
        // current CODE_SYMBOL id.
        let symbol = repo.symbol("math.rs", "add_one")?;
        let (a, b) = {
            let vault = &repo.vault;
            let owner_proof = &repo.owner_proof;
            let bounds = repo.bounds(&["*.rs"], &["*.rs"]);
            let agent_a = create_enabled_agent(vault, owner_proof, "symbol-observe-agent-a")?;
            let agent_b = create_enabled_agent(vault, owner_proof, "symbol-observe-agent-b")?;
            let slip_a = paired_agent_slip(vault, &repo.issuer, owner_proof, agent_a, 0x51)?;
            let slip_b = paired_agent_slip(vault, &repo.issuer, owner_proof, agent_b, 0x52)?;
            let grant_a = mint_repo_grant(vault, owner_proof, agent_a, Some(&bounds))?;
            let grant_b = mint_repo_grant(vault, owner_proof, agent_b, Some(&bounds))?;

            // Both TASKs are created and both tries claimed before any
            // symbol is declared.
            let owner_memory = repo.owner_memory();
            let leased_a = leased_try(vault, &owner_memory, repo.owner, agent_a, "observe A")?;
            let leased_b = leased_try(vault, &owner_memory, repo.owner, agent_b, "observe B")?;
            (
                agent_run(vault, &slip_a, leased_a, repo.repo, grant_a)?,
                agent_run(vault, &slip_b, leased_b, repo.repo, grant_b)?,
            )
        };
        Ok(Self { repo, symbol, a, b })
    }

    fn vault(&self) -> &Vault {
        &self.repo.vault
    }

    fn owner_proof(&self) -> &AuthenticatedOwner {
        &self.repo.owner_proof
    }

    fn observe(&self, run: &AgentRun) -> oneiron::memory::MemoryResult<RepoSymbolDeclarationView> {
        Ok(self
            .vault()
            .memory(run.actor.entity_ref(), run.actor.actor_class())
            .repo_symbols_observe_for_run(&run.binding, RepoSymbolsObserveInput { work: run.work })?
            .output)
    }

    fn declare(&self, run: &AgentRun) -> TestResult<RepoSymbolDeclarationView> {
        Ok(self
            .vault()
            .memory(run.actor.entity_ref(), run.actor.actor_class())
            .repo_symbols_declare_for_run(
                &run.binding,
                RepoSymbolsDeclareInput {
                    work: run.work,
                    symbols: vec![self.symbol],
                    ttl_seconds: TTL_SECONDS,
                },
            )?
            .output)
    }
}

#[test]
fn a_run_observes_its_held_or_waiting_declaration_without_changing_it() -> TestResult {
    let fixture = Fixture::new()?;
    let (a, b) = (&fixture.a, &fixture.b);

    // No declaration yet: there is nothing current to read.
    let none = fixture
        .observe(a)
        .expect_err("a run with no declaration observes none");
    assert_eq!(none.code, "repo_stale_lease", "{none:?}");

    let held = fixture.declare(a)?;
    assert!(held.held, "A declares first and holds");
    let waiting = fixture.declare(b)?;
    assert!(!waiting.held, "B overlaps A's live declaration and waits");

    // B's lane reads A's TASK, so A shows among B's blockers.
    let lane = fixture
        .vault()
        .scoped_read(b.reader.clone())
        .read(&[PointRead::id(a.task)], None)?;
    assert!(
        lane.value[0].as_ref().is_some_and(|row| row.body.is_some()),
        "B's lane reads A's TASK"
    );
    assert_eq!(waiting.blockers, vec![a.task]);

    // A observes its held declaration as declared; B its waiting one, with
    // A as its blocker. Each read twice: the id and expiry do not move.
    for _ in 0..2 {
        let seen = fixture.observe(a)?;
        assert_eq!(
            (
                seen.declaration,
                seen.task,
                seen.work,
                seen.expires_at,
                seen.held
            ),
            (held.declaration, a.task, a.work, held.expires_at, true),
        );
        assert_eq!(seen.symbols, vec![fixture.symbol]);
        assert!(
            seen.blockers.is_empty(),
            "a held declaration waits behind none"
        );

        let seen = fixture.observe(b)?;
        assert_eq!(
            (
                seen.declaration,
                seen.task,
                seen.work,
                seen.expires_at,
                seen.held
            ),
            (
                waiting.declaration,
                b.task,
                b.work,
                waiting.expires_at,
                false
            ),
        );
        assert_eq!(seen.symbols, vec![fixture.symbol]);
        assert_eq!(seen.blockers, vec![a.task]);
    }

    // A releases. B's declaration stays waiting as stored, with no blocker
    // left; observing it neither promotes nor renews it.
    fixture
        .vault()
        .memory(a.actor.entity_ref(), a.actor.actor_class())
        .repo_symbols_release_for_run(
            &a.binding,
            RepoSymbolsReleaseInput {
                work: a.work,
                declaration: held.declaration,
            },
        )?;
    let released = fixture
        .observe(a)
        .expect_err("A's released declaration is no longer current");
    assert_eq!(released.code, "repo_stale_lease", "{released:?}");
    let seen = fixture.observe(b)?;
    assert_eq!(
        (seen.declaration, seen.expires_at, seen.held),
        (waiting.declaration, waiting.expires_at, false),
    );
    assert!(seen.blockers.is_empty(), "A's release leaves B no blocker");

    // The owner revokes B's Grant: B's next observation is refused.
    revoke_agent_grant_as(
        fixture.vault(),
        fixture.owner_proof(),
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: b.grant,
            seen: None,
        },
    )?;
    let revoked = fixture
        .observe(b)
        .expect_err("a revoked Grant admits no observation");
    assert_eq!(revoked.code, "repo_no_membership", "{revoked:?}");
    Ok(())
}
