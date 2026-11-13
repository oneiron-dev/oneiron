//! Engine CODECUSTODY-LFS Q2 = A (NO-DOOR REPO-LFS-PATH-POLICY,
//! tests/e2e/code-custody.test.ts CODE-CUSTODY-06): a pushed LFS pointer to
//! a build-required path keeps its object, required and attached, as a
//! repository-large one does. A build needs the bytes wherever the
//! repository builds, a mirror clone included (ARCH-0068:201). Before, a
//! build-required pointer was admitted as KeepInGit, and landing left its
//! staged object unreferenced and collectible.
//!
//! `cargo test --locked -p oneiron --all-features --test
//! lfs_build_required_pointer`.

use oneiron::origin::lfs::{LfsAdmission, LfsAssetClass, LfsOid, LfsPathPolicy, LfsPointerIntent};
use oneiron::{EntityId, Vault, VaultConfig};

/// Every path under `prefix` is build-required; every other is
/// repository-large.
struct BuildRequiredUnder(&'static [u8]);

impl LfsPathPolicy for BuildRequiredUnder {
    fn classify(&self, _repo_id: EntityId, path: &[u8]) -> oneiron::Result<LfsAssetClass> {
        Ok(if path.starts_with(self.0) {
            LfsAssetClass::BuildRequired
        } else {
            LfsAssetClass::RepositoryLarge
        })
    }
}

#[test]
fn a_build_required_pointer_keeps_its_object() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let repo_id = EntityId::now();
    let oid = LfsOid::parse_hex(&"ab".repeat(32))?;
    let intent = |path: &str| LfsPointerIntent {
        repo_id,
        path: path.as_bytes().to_vec(),
        oid,
        size_bytes: 3,
    };
    let policy = BuildRequiredUnder(b"assets/");
    assert_eq!(
        policy.classify(repo_id, b"assets/model.bin")?,
        LfsAssetClass::BuildRequired
    );
    assert_eq!(
        vault.admit_lfs_pointer(&policy, &intent("assets/model.bin"))?,
        LfsAdmission::StoreInLfs,
        "a build-required pointer requires and keeps its object"
    );
    assert_eq!(
        vault.admit_lfs_pointer(&policy, &intent("docs/manual.pdf"))?,
        LfsAdmission::StoreInLfs,
        "a repository-large pointer still does"
    );
    Ok(())
}
