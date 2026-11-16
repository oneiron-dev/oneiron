//! The loop's shipped skills (ARCH-0053:273 #r4b-hubs: they "version with" the
//! engine, and restore defaults re-imports a deleted or changed one) reach
//! the loop: a restored default, once admitted, is the skill the loop loads,
//! and a loop skill a later engine ships reaches a vault seeded before it
//! (FIX BOOTSTRAP-SEED-ADDED-SKILL-MISSES-SEEDED-VAULTS; BOOTSTRAP-SEED-ON-UPGRADE
//! = A, Engine 00:07 17 Nov).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test bootstrap_loop_skills`.
#![cfg(oneiron_test_support)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::skill::SkillLifecycle;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::bootstrap_skills::{
    admit_restored_default, agent_health_reviewer_revision, bootstrap_skill_id, judge_rubric_skill,
    seed_bootstrap_skills_adding,
};
use oneiron::test_doors::skill_hub_restore::restore_bootstrap_skills;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const JUDGE: &str = "judge";
const AGENT_HEALTH_REVIEW: &str = "agent-health-review";
/// A loop skill a later engine ships, which this engine's seed set lacks.
const LATER_NAME: &str = "later-loop-skill";
const LATER_SKILL: &str = "---\nname: later-loop-skill\ndescription: A loop skill a later engine ships.\n---\n\nAnswer the loop's later step.\n";

fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A seeded vault, opened as most hosts open one.
    fn open() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::default()).map_err(at("open"))?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(at("embedded owner"))?;
        Ok(Self {
            vault,
            owner,
            _dir: dir,
        })
    }

    fn owner_proof(&self) -> TestResult<AuthenticatedOwner> {
        Ok(self
            .vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .map_err(at("owner proof"))?)
    }

    /// The owner deletes the shipped skill `name`, then restores the shipped
    /// defaults (the restore's shipped-default step, as the owner route runs
    /// it after the library fetch). Returns the fresh Candidate of `name`.
    fn delete_and_restore(&self, name: &str) -> TestResult<EntityId> {
        let seed = bootstrap_skill_id(name).map_err(at("seed id"))?;
        assert!(
            self.vault
                .delete_entity(&seed)
                .map_err(at("delete the shipped skill"))?,
            "the shipped {name} is deleted"
        );
        let now = self.vault.now_recorded_at();
        let restored = restore_bootstrap_skills(
            &self.vault,
            &self.owner_proof()?,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .map_err(at("the owner's restore"))?;
        let mut of_name = Vec::new();
        for id in restored {
            let record = self
                .vault
                .get_skill_record(&id)
                .map_err(at("restored read"))?
                .ok_or("a restored id has no record")?;
            if record.skill_id == name {
                assert_eq!(record.lifecycle_status, SkillLifecycle::Candidate);
                of_name.push(id);
            }
        }
        assert_eq!(of_name.len(), 1, "one fresh {name}: {of_name:?}");
        Ok(of_name[0])
    }
}

/// Red on main: the judge walk starts at the deleted bootstrap id and finds
/// no successor (labels/rubric.rs), so the admitted restored judge is never
/// the rubric the judge loads.
#[test]
fn a_restored_judge_default_is_the_judge_the_rubric_loads() -> TestResult {
    let fixture = Fixture::open()?;
    let seed = bootstrap_skill_id(JUDGE)?;
    assert_eq!(
        judge_rubric_skill(&fixture.vault).map_err(at("fresh judge"))?,
        Some(seed),
        "a fresh vault's judge is the shipped one"
    );
    let restored = fixture.delete_and_restore(JUDGE)?;
    admit_restored_default(&fixture.vault, &restored, fixture.vault.now_recorded_at())
        .map_err(at("admit the restored judge"))?;
    assert_eq!(
        judge_rubric_skill(&fixture.vault).map_err(at("restored judge"))?,
        Some(restored),
        "the admitted restored judge is the rubric the judge loads"
    );
    Ok(())
}

/// Red on main: the reviewer policy walk starts at the deleted bootstrap id
/// (agent_health/policy.rs), so the pass stays on its compiled seeds.
#[test]
fn a_restored_agent_health_review_is_the_policy_the_reviewer_loads() -> TestResult {
    let fixture = Fixture::open()?;
    let seed = bootstrap_skill_id(AGENT_HEALTH_REVIEW)?;
    assert_eq!(
        agent_health_reviewer_revision(&fixture.vault).map_err(at("fresh reviewer"))?,
        Some(seed),
        "a fresh vault's reviewer is the shipped one"
    );
    let restored = fixture.delete_and_restore(AGENT_HEALTH_REVIEW)?;
    admit_restored_default(&fixture.vault, &restored, fixture.vault.now_recorded_at())
        .map_err(at("admit the restored reviewer"))?;
    assert_eq!(
        agent_health_reviewer_revision(&fixture.vault).map_err(at("restored reviewer"))?,
        Some(restored),
        "the admitted restored reviewer is the revision the pass loads"
    );
    Ok(())
}

/// Guard: a restored default stays a Candidate until it is admitted, and no
/// loop pass loads a Candidate.
#[test]
fn a_restored_candidate_is_not_loaded_before_activation() -> TestResult {
    let fixture = Fixture::open()?;
    fixture.delete_and_restore(JUDGE)?;
    fixture.delete_and_restore(AGENT_HEALTH_REVIEW)?;
    assert_eq!(
        judge_rubric_skill(&fixture.vault).map_err(at("judge"))?,
        None,
        "no judge rubric while the restored judge is a Candidate"
    );
    assert_eq!(
        agent_health_reviewer_revision(&fixture.vault).map_err(at("reviewer"))?,
        None,
        "no reviewer revision while the restored reviewer is a Candidate"
    );
    Ok(())
}

/// Red on main: the seed pass returns at the one SEEDED marker
/// (skill_hub/bootstrap.rs), so a loop skill a later engine ships never
/// reaches a vault seeded before it.
#[test]
fn a_loop_skill_added_later_reaches_a_seeded_vault() -> TestResult {
    let fixture = Fixture::open()?;
    let later = bootstrap_skill_id(LATER_NAME)?;
    assert!(
        fixture.vault.get_skill_record(&later)?.is_none(),
        "this engine does not ship the later skill"
    );
    seed_bootstrap_skills_adding(&fixture.vault, &[(LATER_NAME, LATER_SKILL)])
        .map_err(at("the later engine's open"))?;
    let record = fixture
        .vault
        .get_skill_record(&later)
        .map_err(at("later read"))?
        .ok_or("the later loop skill was not seeded at its bootstrap id")?;
    assert_eq!(record.skill_id, LATER_NAME);
    assert_eq!(
        record.lifecycle_status,
        SkillLifecycle::Active,
        "seeded with the bootstrap proof, as at first open"
    );
    Ok(())
}

/// Guard: a later engine's seed pass never brings back a shipped skill the
/// owner deleted.
#[test]
fn a_deleted_loop_skill_stays_deleted_when_a_later_one_is_seeded() -> TestResult {
    let fixture = Fixture::open()?;
    let judge = bootstrap_skill_id(JUDGE)?;
    assert!(fixture.vault.delete_entity(&judge).map_err(at("delete"))?);
    seed_bootstrap_skills_adding(&fixture.vault, &[(LATER_NAME, LATER_SKILL)])
        .map_err(at("the later engine's open"))?;
    assert!(
        fixture.vault.get_skill_record(&judge)?.is_none(),
        "the deleted shipped judge stays deleted"
    );
    Ok(())
}
