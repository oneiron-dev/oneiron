//! NO-DOOR REPO-LFS-PATH-POLICY (tests/e2e/code-custody.test.ts
//! CODE-CUSTODY-06; Engine CODECUSTODY-LFS Q1 = A): the owner reads and
//! replaces one served origin's ordered LFS path rules through
//! `vault.code.origin.lfs_path_policy.get` and `.set`. A fresh origin is at
//! revision 0 with no rules; a set names the revision it read, and a stale one
//! is refused with nothing written. Rules are exact paths or directory
//! prefixes, first match wins, and an unmatched path is repository-large. A
//! path that is not normalized is refused, a caller that is not the owner is
//! refused, and the policy survives a reopen.
//!
//! `cargo test --locked -p oneiron --all-features --test origin_lfs_path_policy`.

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::origin_doors::{
    OriginLfsPathPolicySetRequest, OriginRegisterRequest, OriginRepoRequest,
};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE};
use oneiron::origin::lfs::{LfsAssetClass, LfsPathPolicy, OriginLfsPathMatch, OriginLfsPathRule};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REPO: &str = "assets";

fn owner(vault: &Vault) -> TestResult<(EntityId, AuthenticatedOwner)> {
    let id = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(id, "principal:owner", true, GateDecisionId::now())?;
    Ok((id, proof))
}

fn rule(path_match: OriginLfsPathMatch, class: LfsAssetClass) -> OriginLfsPathRule {
    OriginLfsPathRule { path_match, class }
}

fn set(expected_revision: u64, rules: Vec<OriginLfsPathRule>) -> OriginLfsPathPolicySetRequest {
    OriginLfsPathPolicySetRequest {
        repo: REPO.to_owned(),
        expected_revision,
        rules,
    }
}

fn get() -> OriginRepoRequest {
    OriginRepoRequest {
        repo: REPO.to_owned(),
    }
}

#[test]
fn the_owner_sets_and_reads_an_origins_lfs_path_policy() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let (owner_id, proof) = owner(&vault)?;
    let memory = vault.memory(owner_id, EdgeActorClass::Human);
    memory.origin_register_as(
        &proof,
        OriginRegisterRequest {
            repo: REPO.to_owned(),
            default_branch: "main".to_owned(),
        },
    )?;

    let fresh = memory.origin_lfs_path_policy_get_as(&proof, get())?;
    assert_eq!(
        (fresh.revision, fresh.rules.is_empty(), fresh.default_class),
        (0, true, LfsAssetClass::RepositoryLarge)
    );

    // An exact override before the broader prefix wins: first match.
    let rules = vec![
        rule(
            OriginLfsPathMatch::Exact("vendor/keep-large.bin".to_owned()),
            LfsAssetClass::RepositoryLarge,
        ),
        rule(
            OriginLfsPathMatch::Prefix("vendor".to_owned()),
            LfsAssetClass::BuildRequired,
        ),
        rule(
            OriginLfsPathMatch::Exact("assets/logo.bin".to_owned()),
            LfsAssetClass::BuildRequired,
        ),
    ];
    let first = memory.origin_lfs_path_policy_set_as(&proof, set(0, rules.clone()))?;
    assert_eq!((first.revision, &first.rules), (1, &rules));
    assert_eq!(first.repo_id, fresh.repo_id);
    assert_eq!(
        memory.origin_lfs_path_policy_get_as(&proof, get())?.rules,
        rules
    );

    // A set at a revision the policy moved past is refused; nothing changes.
    let stale = memory
        .origin_lfs_path_policy_set_as(&proof, set(0, Vec::new()))
        .expect_err("a stale revision is refused");
    assert_eq!(stale.code, MEMORY_CODE_INVALID_STATE, "{stale:?}");
    // A path that is not a normalized repository-relative path is refused.
    for bad in ["/abs.bin", "a/../b.bin", "dir/", ""] {
        let refused = memory
            .origin_lfs_path_policy_set_as(
                &proof,
                set(
                    1,
                    vec![rule(
                        OriginLfsPathMatch::Exact(bad.to_owned()),
                        LfsAssetClass::BuildRequired,
                    )],
                ),
            )
            .expect_err("an unnormalized path is refused");
        assert_eq!(
            refused.code, MEMORY_CODE_BAD_REQUEST,
            "{bad:?}: {refused:?}"
        );
    }
    // Another caller cannot borrow the owner's proof.
    let forbidden = vault
        .memory(EntityId::now(), EdgeActorClass::Human)
        .origin_lfs_path_policy_set_as(&proof, set(1, Vec::new()))
        .expect_err("a caller that is not the owner is refused");
    assert_eq!(forbidden.code, MEMORY_CODE_FORBIDDEN, "{forbidden:?}");

    // The stored policy classifies: exact, prefix at a `/` boundary, first
    // match, and repository-large for every other path.
    let (repo_id, stored) = vault.served_origin_lfs_path_policy(REPO)?;
    assert_eq!((repo_id, stored.revision), (fresh.repo_id, 1));
    for (path, class) in [
        ("assets/logo.bin", LfsAssetClass::BuildRequired),
        ("vendor/lib/model.bin", LfsAssetClass::BuildRequired),
        ("vendor/keep-large.bin", LfsAssetClass::RepositoryLarge),
        ("vendor-other/lib.bin", LfsAssetClass::RepositoryLarge),
        ("vendor", LfsAssetClass::RepositoryLarge),
        ("docs/manual.pdf", LfsAssetClass::RepositoryLarge),
    ] {
        assert_eq!(stored.classify(repo_id, path.as_bytes())?, class, "{path}");
    }

    // The policy survives a reopen; an empty set restores the default and
    // still advances the revision.
    drop(memory);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let (owner_id, proof) = owner(&vault)?;
    let memory = vault.memory(owner_id, EdgeActorClass::Human);
    let reopened = memory.origin_lfs_path_policy_get_as(&proof, get())?;
    assert_eq!((reopened.revision, reopened.rules), (1, rules));
    let cleared = memory.origin_lfs_path_policy_set_as(&proof, set(1, Vec::new()))?;
    assert_eq!((cleared.revision, cleared.rules.is_empty()), (2, true));
    Ok(())
}
