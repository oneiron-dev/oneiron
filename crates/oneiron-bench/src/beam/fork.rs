//! One base vault per corpus, one byte-copy fork per question.
//!
//! A shared corpus is ingested once into a base vault, which is then closed.
//! Every question runs against its own copy of that closed vault, so nothing
//! a question's retrieval writes (telemetry, traces, access counts) can reach
//! another question. The engine has no vault-clone verb: the checkpoint path
//! rebuilds indexes and re-embeds, so the fork copies the LMDB root instead
//! (`std::fs::copy`, which clones on APFS and uses `copy_file_range` on
//! Linux). Each fork is keyed by the corpus identity and the question, the
//! same keying the RetrievalTrace fork hash uses for replay (OF-260).
use super::{BeamResult, util::beam_vault_config};
use oneiron::Vault;
use sha2::{Digest, Sha256};
use std::path::Path;

/// A closed, fully ingested vault that forks copy from.
pub(super) struct BaseVault {
    dir: tempfile::TempDir,
    /// What the base holds: a shared corpus sha256 or an inline corpus digest.
    corpus_identity: String,
}

/// One question's private copy of a base vault. `vault` drops before `_dir`.
pub(super) struct VaultFork {
    pub(super) vault: Vault,
    pub(super) fork_key: String,
    _dir: tempfile::TempDir,
}

impl BaseVault {
    /// Opens a fresh vault, runs `ingest` on it, then closes it.
    pub(super) fn build<T>(
        corpus_identity: String,
        ingest: impl FnOnce(&Vault) -> BeamResult<T>,
    ) -> BeamResult<(Self, T)> {
        let dir = tempfile::tempdir()?;
        let output = {
            let vault = Vault::open(dir.path(), beam_vault_config())?;
            ingest(&vault)?
        };
        Ok((
            Self {
                dir,
                corpus_identity,
            },
            output,
        ))
    }

    #[cfg(test)]
    pub(super) fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Copies the closed base root and opens the copy.
    pub(super) fn fork(&self, question_id: &str) -> BeamResult<VaultFork> {
        let dir = tempfile::tempdir()?;
        copy_tree(self.dir.path(), dir.path())?;
        let vault = Vault::open(dir.path(), beam_vault_config())?;
        Ok(VaultFork {
            vault,
            fork_key: fork_key(&self.corpus_identity, question_id),
            _dir: dir,
        })
    }
}

/// `sha256:` over the base corpus identity and the question id.
pub(super) fn fork_key(corpus_identity: &str, question_id: &str) -> String {
    let mut hasher = Sha256::new();
    super::util::hash_str(&mut hasher, "oneiron-bench.vault-fork.v1");
    super::util::hash_str(&mut hasher, corpus_identity);
    super::util::hash_str(&mut hasher, question_id);
    format!("sha256:{}", super::util::hex_lower(&hasher.finalize()))
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            std::fs::create_dir_all(&target)?;
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target)?;
        } else {
            return Err(std::io::Error::other(format!(
                "vault root entry {} is neither a file nor a directory",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::{EntityId, TimeRange};

    fn put(vault: &Vault, byte: u8, text: &str) -> EntityId {
        let id = EntityId::from_bytes([byte; 16]).unwrap();
        let payload = rmp_serde::to_vec_named(&serde_json::json!({"txt": text})).unwrap();
        vault
            .batch()
            .put(
                &id,
                oneiron::registry::ENTITY_TYPE_TURN,
                TimeRange { start: 10, end: 10 },
                10,
                &payload,
            )
            .text(&id, &[("txt", text)])
            .commit()
            .unwrap();
        id
    }

    #[test]
    fn forks_share_the_base_and_never_see_each_others_writes() {
        let (base, base_id) =
            BaseVault::build("corpus-a".into(), |vault| Ok(put(vault, 1, "base turn"))).unwrap();
        let a = base.fork("q-a").unwrap();
        let b = base.fork("q-b").unwrap();
        assert!(
            a.vault.get_learned_at(&base_id).is_ok(),
            "fork a sees the base"
        );
        assert!(
            b.vault.get_learned_at(&base_id).is_ok(),
            "fork b sees the base"
        );
        let only_a = put(&a.vault, 2, "written in fork a");
        assert!(a.vault.get_learned_at(&only_a).is_ok());
        assert!(
            b.vault.get_learned_at(&only_a).is_err(),
            "a write in one fork never reaches another"
        );
        let c = base.fork("q-c").unwrap();
        assert!(
            c.vault.get_learned_at(&only_a).is_err(),
            "the base stays closed"
        );
        assert_ne!(a.fork_key, b.fork_key);
        assert_eq!(a.fork_key, fork_key("corpus-a", "q-a"));
        assert!(base.path().join("data.mdb").exists());
    }
}
