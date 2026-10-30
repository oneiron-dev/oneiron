//! FIX 6870 phase 1 (G5, ARCH-0068 RA2): a repo's portable identity and
//! its manifest.
//!
//! Every repo id this vault held was its own: a path's hash, a derived
//! anchor, a random CODE id. Two replicas of one vault, or two federated
//! vaults, named one repo two ways. A [`RepoPortableId`] is 32 random bytes,
//! minted once where a served repo's CODE anchor is first bound here (the
//! owner's import) and never derived from a path, a URL or a commit. Its
//! [`RepoManifest`] names that CODE entity and rides the window that carries
//! the CODE row, under the same grant (`sync::repo_manifests`). A vault that
//! receives it names the repo by the same id, and resolves the id to its own
//! CODE anchor.
//!
//! - One manifest stands for each CODE entity. Where two ids name one (two
//!   machines minted before either saw the other's), the earliest
//!   `minted_at` stands, ties to the lower id; the other stays under its own
//!   id as an alias of the same entity, so nothing that named it is lost.
//! - Two copies of one id merge by the higher epoch, then the later
//!   `updated_at`, then the lower encoded bytes.
//! - Refs are single-writer: only the host holding the origin authority, or
//!   the machine that minted the id while none is held, refreshes
//!   `visible_refs` and `lfs_pointers` (`refresh`). Every other vault keeps
//!   what it received.

mod refresh;

use std::cmp::Ordering;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Vault;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName};
use crate::origin::lfs::LfsOid;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The manifest version this build writes and reads.
pub const REPO_MANIFEST_VERSION: u16 = 1;

/// Every manifest held here, an alias's too. Key: the portable id's bytes.
const MANIFESTS: SideTable<[u8; 32], RepoManifest, Named> =
    SideTable::new(&side_table::REPO_MANIFEST);

/// The portable id that stands for one CODE entity. Key: the entity's id.
const BY_CODE: SideTable<EntityId, [u8; 32], Raw> =
    SideTable::new(&side_table::REPO_MANIFEST_BY_CODE);

/// The portable ids this machine minted. Key: the portable id's bytes.
const MINTED: SideTable<[u8; 32], (), Raw> = SideTable::new(&side_table::REPO_MANIFEST_MINTED);

/// A repo's portable identity: 32 random bytes, minted once (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepoPortableId([u8; 32]);

impl RepoPortableId {
    /// Wraps an id's bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The id's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The id's one spelling: 64 lowercase hex digits.
    #[must_use]
    pub fn to_hex(&self) -> String {
        bytes_to_hex_lower(&self.0)
    }

    /// The id `text` spells; `None` for anything but its one spelling.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 64 || !text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        let mut bytes = [0; 32];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// A fresh id from the OS RNG: never derived from anything (F1).
    fn mint() -> Self {
        let mut bytes = [0; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
        Self(bytes)
    }
}

impl Serialize for RepoPortableId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for RepoPortableId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::from_hex(&text).ok_or_else(|| serde::de::Error::custom("not a portable repo id"))
    }
}

/// One repo's manifest, as every vault that holds it names the repo. Phases
/// 2 and 3 add their fields under a version bump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoManifest {
    /// The repo's portable id.
    pub portable: RepoPortableId,
    /// [`REPO_MANIFEST_VERSION`].
    pub version: u16,
    /// The CODE entity the repo is anchored to.
    pub code: EntityId,
    /// When the id was minted, on the minting vault's clock.
    pub minted_at: u64,
    /// The served name, where the minting vault serves the repo.
    pub origin_name: Option<String>,
    /// Each ref the origin advertises, by ascending name, with its commit:
    /// its Published `ORIGIN_VISIBLE_REF` rows.
    pub visible_refs: Vec<(String, String)>,
    /// The LFS objects those refs carry, ascending: pointers, never bytes.
    #[serde(with = "lfs_oids")]
    pub lfs_pointers: Vec<LfsOid>,
    /// The epoch of the origin authority the refs writer holds, else 0.
    pub epoch: u64,
    /// When the refs writer last changed the manifest.
    pub updated_at: u64,
}

/// An LFS object id list as hex text.
mod lfs_oids {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::origin::lfs::LfsOid;

    pub(super) fn serialize<S: Serializer>(oids: &[LfsOid], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(oids.iter().map(|oid| oid.to_hex()))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<LfsOid>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|hex| LfsOid::parse_hex(hex).map_err(serde::de::Error::custom))
            .collect()
    }
}

impl RepoManifest {
    /// The bytes a window carries the manifest as, which rule 7's last tie
    /// compares.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvalidConfig("a repo manifest does not encode".to_owned()))
    }

    /// The manifest `bytes` carry in its one spelling, of this build's
    /// version: refs by strictly ascending name, each a full ref name and a
    /// commit id, and pointers strictly ascending. `None` for other bytes.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let manifest: Self = rmp_serde::from_slice(bytes).ok()?;
        let refs = &manifest.visible_refs;
        let well_formed = manifest.version == REPO_MANIFEST_VERSION
            && refs.windows(2).all(|pair| pair[0].0 < pair[1].0)
            && refs.iter().all(|(name, oid)| {
                GitRefName::parse_full(name.as_str()).is_ok() && GitOid::parse_hex(oid.as_str()).is_ok()
            })
            && manifest.lfs_pointers.windows(2).all(|pair| pair[0] < pair[1]);
        (well_formed && manifest.encode().ok()?.as_slice() == bytes).then_some(manifest)
    }

    /// Rule 7: whether this copy replaces `held`, a copy of the same id.
    pub(crate) fn replaces(&self, held: &Self) -> Result<bool> {
        Ok(
            match (self.epoch, self.updated_at).cmp(&(held.epoch, held.updated_at)) {
                Ordering::Greater => true,
                Ordering::Less => false,
                Ordering::Equal => self.encode()? < held.encode()?,
            },
        )
    }

    /// Rule 3: whether this manifest stands for its CODE entity over `other`.
    fn mints_before(&self, other: &Self) -> bool {
        (self.minted_at, self.portable) < (other.minted_at, other.portable)
    }
}

/// What merging one carried manifest did here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepoManifestMerge {
    /// The carried copy is the one held here now.
    Adopted,
    /// The copy held here stands.
    Held,
    /// No live CODE entity it names is held here: it waits in the window.
    Waiting,
    /// It names another CODE entity or mint than the copy held under its id,
    /// which stands; it stays aside in the window.
    Conflict,
}

/// Whether `code` is a live CODE entity in `txn`.
fn code_anchor_live(vault: &Vault, txn: &heed::RoTxn<'_>, code: &EntityId) -> Result<bool> {
    Ok(matches!(
        live_entity_row_in_txn(&vault.store, txn, code)?,
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CODE_ARTIFACT,
            ..
        }
    ))
}

impl Vault {
    /// The manifest portable id `id` names here (FIX 6870). An alias
    /// answers the manifest that stands for its CODE entity.
    ///
    /// # Errors
    /// A store failure.
    pub fn repo_manifest_for_portable(&self, id: &RepoPortableId) -> Result<Option<RepoManifest>> {
        let txn = self.store.env.read_txn()?;
        let Some(manifest) = MANIFESTS.get(&self.store, &txn, &id.0)? else {
            return Ok(None);
        };
        match BY_CODE.get(&self.store, &txn, &manifest.code)? {
            Some(standing) if standing != id.0 => Ok(MANIFESTS
                .get(&self.store, &txn, &standing)?
                .or(Some(manifest))),
            _ => Ok(Some(manifest)),
        }
    }

    /// The portable id that stands for CODE entity `code` here (FIX 6870).
    ///
    /// # Errors
    /// A store failure.
    pub fn repo_portable_id_for_code(&self, code: EntityId) -> Result<Option<RepoPortableId>> {
        let txn = self.store.env.read_txn()?;
        Ok(BY_CODE.get(&self.store, &txn, &code)?.map(RepoPortableId))
    }

    /// The local CODE anchor portable id `id` names, while it stands live
    /// in `txn`; an alias names the same anchor.
    pub(crate) fn resolve_repo_anchor_by_portable_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &RepoPortableId,
    ) -> Result<Option<EntityId>> {
        let Some(manifest) = MANIFESTS.get(&self.store, txn, &id.0)? else {
            return Ok(None);
        };
        Ok(code_anchor_live(self, txn, &manifest.code)?.then_some(manifest.code))
    }

    /// The manifest that stands for each CODE entity `keep` takes: what
    /// the window mirror writes beside those CODE rows.
    pub(crate) fn standing_repo_manifests(
        &self,
        keep: impl Fn(&EntityId) -> bool,
    ) -> Result<Vec<RepoManifest>> {
        let txn = self.store.env.read_txn()?;
        let mut standing = Vec::new();
        for row in BY_CODE.iter_from(&self.store, &txn, &[])? {
            let (code, portable) = row?;
            if keep(&code)
                && let Some(manifest) = MANIFESTS.get(&self.store, &txn, &portable)?
            {
                standing.push(manifest);
            }
        }
        Ok(standing)
    }

    /// Mints the manifest of the served repo `origin_name`, anchored at
    /// CODE entity `code`, unless one already stands for it (a vault that
    /// adopted a carried one mints nothing), then refreshes it. It never
    /// fails its caller: a fault is logged, and the next mirror pass
    /// refreshes what stands.
    pub(crate) fn ensure_repo_manifest(&self, code: EntityId, origin_name: &str) {
        let ensured = self.with_write_txn_grouped(|txn| {
            if let Some(portable) = BY_CODE.get(&self.store, txn, &code)? {
                return Ok((RepoPortableId(portable), false));
            }
            let portable = RepoPortableId::mint();
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let manifest = RepoManifest {
                portable,
                version: REPO_MANIFEST_VERSION,
                code,
                minted_at: now,
                origin_name: Some(origin_name.to_owned()),
                visible_refs: Vec::new(),
                lfs_pointers: Vec::new(),
                epoch: 0,
                updated_at: now,
            };
            MANIFESTS.put(&self.store, txn, &portable.0, &manifest)?;
            BY_CODE.put(&self.store, txn, &code, &portable.0)?;
            MINTED.put(&self.store, txn, &portable.0, &())?;
            Ok((portable, true))
        });
        let refreshed = ensured.and_then(|(portable, minted)| {
            if minted {
                self.note_repo_manifest_written(code);
            }
            self.refresh_repo_manifest(code, portable)
        });
        if let Err(error) = refreshed {
            tracing::warn!(code = %code.to_hex(), kind = ?error.kind(), "repo manifest not ensured");
        }
    }

    /// Merges `carried`, a manifest a window brought, here: rule 7 against
    /// the copy held under its id, then rule 3 against the manifest that
    /// stands for its CODE entity. A copy already held is found by a read.
    pub(crate) fn merge_carried_repo_manifest(
        &self,
        carried: &RepoManifest,
    ) -> Result<RepoManifestMerge> {
        {
            let txn = self.store.env.read_txn()?;
            if MANIFESTS.get(&self.store, &txn, &carried.portable.0)?.as_ref() == Some(carried) {
                return Ok(RepoManifestMerge::Held);
            }
        }
        self.with_write_txn_grouped(|txn| {
            if !code_anchor_live(self, txn, &carried.code)? {
                return Ok(RepoManifestMerge::Waiting);
            }
            let key = carried.portable.0;
            if let Some(held) = MANIFESTS.get(&self.store, txn, &key)? {
                if held.code != carried.code || held.minted_at != carried.minted_at {
                    return Ok(RepoManifestMerge::Conflict);
                }
                if !carried.replaces(&held)? {
                    return Ok(RepoManifestMerge::Held);
                }
            }
            MANIFESTS.put(&self.store, txn, &key, carried)?;
            let stands = match BY_CODE.get(&self.store, txn, &carried.code)? {
                Some(standing) if standing == key => false,
                Some(standing) => MANIFESTS
                    .get(&self.store, txn, &standing)?
                    .is_none_or(|other| carried.mints_before(&other)),
                None => true,
            };
            if stands {
                BY_CODE.put(&self.store, txn, &carried.code, &key)?;
            }
            Ok(RepoManifestMerge::Adopted)
        })
    }

    /// Hands CODE entity `code` to the live mirror as an import's row, so
    /// each loaded window that carries it takes its manifest now.
    fn note_repo_manifest_written(&self, code: EntityId) {
        #[cfg(feature = "sync")]
        {
            let _import = crate::sync::manager::import_scope();
            self.note_committed_rows(std::collections::BTreeSet::from([code]));
        }
        #[cfg(not(feature = "sync"))]
        let _ = code;
    }
}
