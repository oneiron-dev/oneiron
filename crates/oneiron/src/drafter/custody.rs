//! A drafter version's sealed artifact (FIX 12569, after the inference
//! snapshot's publication and retirement, without its eviction: every
//! version that is not erased keeps its artifact).
//!
//! The host that returns a trained version asks for a [`DrafterSealing`]:
//! the writer checks that the version is still training at the generation
//! the job was dispatched at and mints the version's erasable key there,
//! journaled before it commits. The host seals each file of the load set
//! chunk by chunk under that key ([`DrafterSealing::seal_chunk`]), writes
//! the sealed files, and publishes the artifact's reference: the publishing
//! writer checks the version and its generation again, so a completion that
//! an erase or another dispatch overtook never publishes, and its key
//! retires in that writer. The version's record names the key by its random
//! ref only, never by its bytes.

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal_with_aad,
};
use zeroize::Zeroizing;

use super::{
    DrafterArtifact, DrafterArtifactFile, DrafterVersion, DrafterVersionState, VERSIONS, hash_json,
    invalid,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::drafter_custody::{
    DrafterArtifactKey, drafter_artifact_key_in_txn, mint_drafter_artifact_key_in_txn,
    retire_drafter_artifact_key_in_txn,
};

/// The AEAD every drafter artifact chunk seals under.
const CHUNK_AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
/// The envelope epoch every drafter artifact chunk seals at, the erasable
/// key envelopes' epoch.
const CHUNK_EPOCH: u64 = 1;
/// The recipient a drafter artifact chunk binds, apart from every other
/// erasable key envelope.
const CHUNK_RECIPIENT: &[u8] = b"oneiron/erasable-key/drafter-artifact/v1";
/// The label a chunk's extra associated data opens with.
const CHUNK_AAD_LABEL: &[u8] = b"oneiron/drafter-artifact/chunk/v1\0";

/// One version's artifact key, open in this process for the host that seals
/// or loads its files. It never goes to a record, a log or another process.
pub struct DrafterSealing {
    version: EntityId,
    generation: u64,
    artifact: [u8; 16],
    key: DrafterArtifactKey,
}

impl DrafterSealing {
    /// The sealing of one side of version `version`'s corpus (FIX 14973):
    /// `file` is that side's random id, and `key` its erasable key, minted
    /// under the version as the load set's is, so an erase of the version
    /// retires it too. A corpus sealing is never published as a load set.
    pub(super) fn for_corpus(version: EntityId, file: [u8; 16], key: DrafterArtifactKey) -> Self {
        Self {
            version,
            generation: 0,
            artifact: file,
            key,
        }
    }

    /// The sealing of one training example's body (FIX 15128): `seal` is
    /// the body's random id, and `key` its erasable key, minted under the
    /// example as a version's are under the version, so an erase that drops
    /// the example retires it. An example sealing is never published.
    pub(super) fn for_example(example: EntityId, seal: [u8; 16], key: DrafterArtifactKey) -> Self {
        Self {
            version: example,
            generation: 0,
            artifact: seal,
            key,
        }
    }

    /// The version the artifact belongs to.
    #[must_use]
    pub fn version(&self) -> EntityId {
        self.version
    }

    /// The artifact's random id: the sealed load set's name.
    #[must_use]
    pub fn artifact(&self) -> [u8; 16] {
        self.artifact
    }

    /// A chunk's extra associated data: the label, then the version (16),
    /// the artifact (16), the BLAKE3 of the file's name (32), the chunk's
    /// index (8) and whether it is the last (1), all fixed-width.
    fn chunk_aad(&self, file: &str, index: u64, last: bool) -> Vec<u8> {
        let mut aad = Vec::with_capacity(CHUNK_AAD_LABEL.len() + 16 + 16 + 32 + 8 + 1);
        aad.extend_from_slice(CHUNK_AAD_LABEL);
        aad.extend_from_slice(self.version.as_bytes());
        aad.extend_from_slice(&self.artifact);
        aad.extend_from_slice(blake3::hash(file.as_bytes()).as_bytes());
        aad.extend_from_slice(&index.to_be_bytes());
        aad.push(u8::from(last));
        aad
    }

    /// Seals chunk `index` of file `file` under the artifact's key: a chunk
    /// moved to another file, index, artifact or version, or one claimed
    /// last that was not, does not open.
    ///
    /// # Errors
    /// The envelope refused the chunk, or the random source failed.
    pub fn seal_chunk(&self, file: &str, index: u64, last: bool, plain: &[u8]) -> Result<Vec<u8>> {
        let params = SealParams {
            suite: CHUNK_AEAD,
            purpose: Purpose::ErasableKey,
            epoch: CHUNK_EPOCH,
            key_id: &self.key.key_ref,
            recipient: CHUNK_RECIPIENT,
            vault_id: &self.key.key_ref,
        };
        let kek = Kek::from_bytes_ref(&self.key.secret);
        seal_with_aad(
            &params,
            SealKey::SymmetricKek(&kek),
            plain,
            &self.chunk_aad(file, index, last),
            &mut SysRng,
        )
        .map(|envelope| envelope.to_bytes())
        .map_err(|_| Error::InvalidConfig("sealing a drafter artifact chunk failed".into()))
    }

    /// Opens what [`Self::seal_chunk`] sealed as chunk `index` of `file`,
    /// authenticated before a byte of it is returned.
    ///
    /// # Errors
    /// Any failure: another key, place or artifact, or damage.
    pub fn open_chunk(
        &self,
        file: &str,
        index: u64,
        last: bool,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let policy = OpenPolicy {
            purpose: Purpose::ErasableKey,
            vault_id: &self.key.key_ref,
            recipient: CHUNK_RECIPIENT,
            key_id: &self.key.key_ref,
            wraps: &[WrapType::SymmetricKek],
            aead_suites: &[CHUNK_AEAD],
            kem_suites: &[],
            min_epoch: CHUNK_EPOCH,
            argon2_max: Argon2Cost::RFC9106_SECOND,
        };
        let kek = Kek::from_bytes_ref(&self.key.secret);
        Envelope::parse(sealed)
            .map_err(|_| Error::CorruptedIndex("drafter artifact chunk"))?
            .open_with_aad(
                OpenKey::SymmetricKek(&kek),
                &policy,
                &self.chunk_aad(file, index, last),
            )
            .map_err(|_| Error::CorruptedIndex("drafter artifact chunk"))
    }
}

/// Refuses a version that is not training at `generation`: an erase,
/// another dispatch or a later state overtook the job.
fn check_training(version: &DrafterVersion, generation: u64) -> Result<()> {
    if version.state != DrafterVersionState::Training || version.generation != generation {
        return Err(invalid(
            "the drafter version is no longer training at the generation its job was dispatched at",
        ));
    }
    Ok(())
}

impl Vault {
    /// The host's door to seal a trained artifact of drafter version
    /// `version`: in one write, the version must still be training at
    /// `expected_generation`, and its erasable key for a fresh artifact id
    /// is minted and journaled before the write commits.
    ///
    /// # Errors
    /// An unknown version, one no longer training at that generation, an
    /// archived vault, and custody and storage faults.
    pub fn begin_drafter_artifact(
        &self,
        version: &EntityId,
        expected_generation: u64,
    ) -> Result<DrafterSealing> {
        let mut artifact = [0u8; 16];
        crate::key_material::os_fill(&mut artifact)?;
        self.with_write_txn_grouped(|txn| {
            let row = VERSIONS
                .get(&self.store, txn, version)?
                .ok_or(Error::EntityNotFound)?;
            check_training(&row, expected_generation)?;
            let key = mint_drafter_artifact_key_in_txn(&self.store, txn, version, &artifact)?;
            Ok(DrafterSealing {
                version: *version,
                generation: expected_generation,
                artifact,
                key,
            })
        })
    }

    /// The host's door to publish the sealed artifact `sealing` began, its
    /// files already sealed and written: in one write, the version must
    /// still be training at the generation the sealing began at. Then the
    /// version is `Returned` with the artifact's reference and its
    /// generation bumps. A late completion an erase or another dispatch
    /// overtook is refused, and its key's retirement is staged in the same
    /// write, so weights derived from erased data are never published or
    /// opened; the caller removes the sealed files.
    ///
    /// # Errors
    /// An unknown version, a refused late completion, and custody and
    /// storage faults.
    pub fn publish_drafter_artifact(
        &self,
        sealing: &DrafterSealing,
        files: Vec<DrafterArtifactFile>,
    ) -> Result<DrafterVersion> {
        let load_set_blake3 = hash_json(&files)?;
        self.with_write_txn_grouped(|txn| {
            let store = &self.store;
            let mut row = VERSIONS
                .get(store, txn, &sealing.version)?
                .ok_or(Error::EntityNotFound)?;
            if let Err(refused) = check_training(&row, sealing.generation) {
                retire_drafter_artifact_key_in_txn(store, txn, &sealing.key.key_ref)?;
                return Ok(Err(refused));
            }
            row.artifact = Some(DrafterArtifact {
                id: sealing.artifact,
                key_ref: sealing.key.key_ref,
                files,
                load_set_blake3,
            });
            row.state = DrafterVersionState::Returned;
            row.generation += 1;
            row.updated_at = self.now_recorded_at();
            VERSIONS.put(store, txn, &sealing.version, &row)?;
            Ok(Ok(row))
        })?
    }

    /// The live key of the artifact drafter version `version` keeps, open in
    /// this process for the host that loads it; `None` when the version is
    /// unknown, keeps no artifact, or its key is retired or retiring.
    ///
    /// # Errors
    /// A damaged key, and custody and storage faults.
    pub fn drafter_artifact_sealing(&self, version: &EntityId) -> Result<Option<DrafterSealing>> {
        let txn = self.store.env.read_txn()?;
        let Some(row) = VERSIONS.get(&self.store, &txn, version)? else {
            return Ok(None);
        };
        let Some(artifact) = row.artifact.as_ref() else {
            return Ok(None);
        };
        let Some(key) = drafter_artifact_key_in_txn(&self.store, &txn, version, &artifact.key_ref)?
        else {
            return Ok(None);
        };
        Ok(Some(DrafterSealing {
            version: *version,
            generation: row.generation,
            artifact: artifact.id,
            key,
        }))
    }
}
