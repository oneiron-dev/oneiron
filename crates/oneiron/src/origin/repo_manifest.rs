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

#[cfg(feature = "sync")]
use std::cmp::Ordering;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Vault;
#[cfg(feature = "sync")]
use crate::authority::OriginCutStanding;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
#[cfg(feature = "sync")]
use crate::git_wire::{GitOid, GitRefName};
use crate::origin::lfs::LfsOid;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::side_table::{self, Named, Raw, SideKey, SideTable};
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The manifest version this build writes and reads: 2 adds the refs
/// writer's signature (FIX 12765).
pub const REPO_MANIFEST_VERSION: u16 = 2;

/// The domain a manifest's writer signature is made in.
const WRITER_SIGNATURE_DOMAIN: &[u8] = b"oneiron/repo-manifest/writer/v2\0";

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
        if text.len() != 64
            || !text
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
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
    /// Each ref the origin's checked advertisement exposes, by ascending
    /// name, with its commit.
    pub visible_refs: Vec<(String, String)>,
    /// The LFS objects those refs carry, ascending: pointers, never bytes.
    #[serde(with = "lfs_oids")]
    pub lfs_pointers: Vec<LfsOid>,
    /// The epoch of the owner's origin cut in force that names the refs
    /// writer (FIX 15740), else 0.
    pub epoch: u64,
    /// When the refs writer last changed the manifest.
    pub updated_at: u64,
    /// The refs writer's signature over every other field, where the
    /// machine that wrote the manifest held a signer; `None` otherwise. A
    /// carried copy replaces the one held under its id only from a writer
    /// proven here (FIX 12765).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer: Option<RepoManifestWriter>,
}

/// The refs writer's signature on a manifest (FIX 12765): the machine that
/// wrote it, and its Ed25519 signature over
/// [`RepoManifest::writer_signing_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoManifestWriter {
    /// The machine whose key signed.
    pub machine: EntityId,
    /// The 64-byte signature.
    pub signature: Vec<u8>,
}

/// An LFS object id list as hex text.
mod lfs_oids {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::origin::lfs::LfsOid;

    pub(super) fn serialize<S: Serializer>(
        oids: &[LfsOid],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
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
    /// What the refs writer signs: every field but its signature, in the
    /// manifest's one spelling, in the signature's own domain.
    fn writer_signing_bytes(&self) -> Result<Vec<u8>> {
        let unsigned = Self {
            writer: None,
            ..self.clone()
        };
        let body = rmp_serde::to_vec_named(&unsigned)
            .map_err(|_| Error::InvalidConfig("a repo manifest does not encode".to_owned()))?;
        Ok([WRITER_SIGNATURE_DOMAIN, body.as_slice()].concat())
    }

    /// The bytes a window carries the manifest as, which rule 7's last tie
    /// compares.
    #[cfg(feature = "sync")]
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvalidConfig("a repo manifest does not encode".to_owned()))
    }

    /// The manifest `bytes` carry in its one spelling, of this build's
    /// version: refs by strictly ascending name, each a full ref name and a
    /// commit id, and pointers strictly ascending. `None` for other bytes.
    #[cfg(feature = "sync")]
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let manifest: Self = rmp_serde::from_slice(bytes).ok()?;
        let refs = &manifest.visible_refs;
        let well_formed = manifest.version == REPO_MANIFEST_VERSION
            && refs.windows(2).all(|pair| pair[0].0 < pair[1].0)
            && refs.iter().all(|(name, oid)| {
                GitRefName::parse_full(name.as_str()).is_ok()
                    && GitOid::parse_hex(oid.as_str()).is_ok()
            })
            && manifest
                .lfs_pointers
                .windows(2)
                .all(|pair| pair[0] < pair[1]);
        (well_formed && manifest.encode().ok()?.as_slice() == bytes).then_some(manifest)
    }

    /// Rule 7: whether this copy replaces `held`, a copy of the same id.
    #[cfg(feature = "sync")]
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
#[cfg(feature = "sync")]
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
    /// It would replace the copy held under its id, but its writer is not
    /// proven here (FIX 12765): the held copy stands and it waits in the
    /// window.
    Unproven,
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

/// The portable id that stands for the repository at `repo` in `txn`
/// (FIX 12761): the one standing id among the live CODE entities whose
/// stored locator names the same repository (`RepoRef::same_repository`,
/// commit ignored). `None` when none stands for it, or when two distinct
/// standing ids do (two PROJECT anchors of one location): no first row is
/// picked. A CODE row that is not live or whose locator does not parse
/// names nothing. It reads only; it never mints or repairs.
///
/// # Errors
/// A store failure.
pub(crate) fn standing_portable_id_for_location_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    repo: &crate::codebase::RepoRef,
) -> Result<Option<RepoPortableId>> {
    let mut found: Option<[u8; 32]> = None;
    for row in BY_CODE.iter_from(&vault.store, txn, &[])? {
        let (code, portable) = row?;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CODE_ARTIFACT,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &code)?
        else {
            continue;
        };
        let Some(located) = crate::code_artifact::decode_code_artifact_body(&body)
            .ok()
            .and_then(|artifact| crate::codebase::RepoRef::parse(&artifact.repo_ref).ok())
        else {
            continue;
        };
        if !located.same_repository(repo) {
            continue;
        }
        match found {
            None => found = Some(portable),
            Some(seen) if seen == portable => {}
            Some(_) => return Ok(None),
        }
    }
    Ok(found.map(RepoPortableId))
}

/// Removes every repo manifest anchored at erased CODE entity `id`: the
/// standing manifest, every alias of it, and their minted markers, with the
/// CODE index row (FIX 6870). Registered in `deletion/derived_rows.rs`, so it
/// runs in the erase's own transaction at both delete doors, before the
/// record's body and edges go; without it the origin name, refs and LFS
/// pointers stay stored and readable after the anchor's erase. A row that
/// does not decode stays as it is (FIX 5736).
pub(crate) fn erase_repo_manifests_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    BY_CODE.delete(store, txn, id)?;
    let mut gone = Vec::new();
    for row in MANIFESTS.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        let Ok(manifest) = MANIFESTS.decode_value(&bytes) else {
            continue;
        };
        if manifest.code == *id {
            gone.push(key);
        }
    }
    for key in gone {
        let Some(portable) = <[u8; 32] as SideKey>::decode_key(&key) else {
            continue;
        };
        MANIFESTS.delete(store, txn, &portable)?;
        MINTED.delete(store, txn, &portable)?;
    }
    Ok(())
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
    /// in `txn`; an alias names the same anchor. Its callers are the phase
    /// 1b hooks (federation repo access, git push, code symbols).
    #[allow(dead_code)]
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
                && manifest.code == code
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
            if !code_anchor_live(self, txn, &code)? {
                return Ok(None);
            }
            if let Some(portable) = BY_CODE.get(&self.store, txn, &code)? {
                return Ok(Some((RepoPortableId(portable), false)));
            }
            // Restore a missing index from the oldest held id before minting another.
            let mut held: Option<RepoManifest> = None;
            for row in MANIFESTS.iter_raw_from(&self.store, txn, &[])? {
                let (key, bytes) = row?;
                let Ok(manifest) = MANIFESTS.decode_value(&bytes) else {
                    continue;
                };
                if manifest.code != code
                    || <[u8; 32] as SideKey>::decode_key(&key) != Some(manifest.portable.0)
                {
                    continue;
                }
                if held
                    .as_ref()
                    .is_none_or(|other| manifest.mints_before(other))
                {
                    held = Some(manifest);
                }
            }
            if let Some(manifest) = held {
                BY_CODE.put(&self.store, txn, &code, &manifest.portable.0)?;
                return Ok(Some((manifest.portable, true)));
            }
            let portable = RepoPortableId::mint();
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let mut manifest = RepoManifest {
                portable,
                version: REPO_MANIFEST_VERSION,
                code,
                minted_at: now,
                origin_name: Some(origin_name.to_owned()),
                visible_refs: Vec::new(),
                lfs_pointers: Vec::new(),
                epoch: 0,
                updated_at: now,
                writer: None,
            };
            self.sign_repo_manifest_in_txn(txn, &mut manifest)?;
            MANIFESTS.put(&self.store, txn, &portable.0, &manifest)?;
            BY_CODE.put(&self.store, txn, &code, &portable.0)?;
            MINTED.put(&self.store, txn, &portable.0, &())?;
            Ok(Some((portable, true)))
        });
        let refreshed = ensured.and_then(|ensured| {
            let Some((portable, written)) = ensured else {
                return Ok(());
            };
            if written {
                self.note_repo_manifest_written(code);
            }
            self.refresh_repo_manifest(code, portable)
        });
        if let Err(error) = refreshed {
            tracing::warn!(code = %code.to_hex(), kind = ?error.kind(), "repo manifest not ensured");
        }
    }

    /// Prepares one carried manifest's held origin context outside any
    /// writer: the held copy's served-name/CODE pair the writer rechecks,
    /// plus the served repo id whose authority row the writer judges. Where
    /// `skip_held` is set, `None` is the read byte-equal shortcut (the copy
    /// held here already): no filesystem read runs. Where it is not, the
    /// real context is always resolved, even for a byte-equal copy, so the
    /// stage writer judges the current copy itself. The read transaction is
    /// dropped before the object-store resolution. Shared by the live
    /// wrapper (`skip_held`, the no-FS shortcut kept) and the bootstrap
    /// batch (always resolve, same-writer freshness) so the one resolution
    /// lives once.
    #[cfg(feature = "sync")]
    pub(crate) fn repo_manifest_prepare_context(
        &self,
        carried: &RepoManifest,
        skip_held: bool,
    ) -> Result<Option<(Option<(Option<String>, EntityId)>, Option<EntityId>)>> {
        let held = {
            let txn = self.store.env.read_txn()?;
            MANIFESTS.get(&self.store, &txn, &carried.portable.0)?
        };
        if skip_held && held.as_ref() == Some(carried) {
            return Ok(None);
        }
        // Which repo this host serves for the copy held here (never what the
        // carried one says) is resolved outside the writer: it reads the
        // object store. Its origin authority row is read inside the writer,
        // so an owner cutover is never judged from a stale row.
        let resolved_for = held
            .as_ref()
            .map(|held| (held.origin_name.clone(), held.code));
        let served = match &held {
            Some(held) => self.served_origin_repo_id(held)?,
            None => None,
        };
        Ok(Some((resolved_for, served)))
    }

    /// Merges `carried`, a manifest a window brought, here: rule 7 against
    /// the copy held under its id, then rule 3 against the manifest that
    /// stands for its CODE entity. A copy already held is found by a read.
    /// A copy that would replace the one held under its id must come from a
    /// proven writer (FIX 12765, [`Self::repo_manifest_writer_proven_in_txn`]),
    /// else it waits in the window.
    #[cfg(feature = "sync")]
    pub(crate) fn merge_carried_repo_manifest(
        &self,
        carried: &RepoManifest,
    ) -> Result<RepoManifestMerge> {
        let Some((resolved_for, served)) = self.repo_manifest_prepare_context(carried, true)?
        else {
            return Ok(RepoManifestMerge::Held);
        };
        self.with_write_txn_grouped(|txn| {
            self.merge_carried_repo_manifest_in_txn(txn, carried, &resolved_for, served)
        })
    }

    /// Merges a carried manifest in the caller's writer, with the held repo's
    /// origin identity resolved before that writer opened.
    #[cfg(feature = "sync")]
    pub(crate) fn merge_carried_repo_manifest_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        carried: &RepoManifest,
        resolved_for: &Option<(Option<String>, EntityId)>,
        served: Option<EntityId>,
    ) -> Result<RepoManifestMerge> {
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
            // The held copy moved since the repo was resolved: wait for
            // the next pass to resolve it again.
            if resolved_for.as_ref() != Some(&(held.origin_name.clone(), held.code)) {
                return Ok(RepoManifestMerge::Unproven);
            }
            // Where this host serves the repo, a copy keeps the served
            // name, so refresh and later merges still judge it here.
            if served.is_some() && carried.origin_name != held.origin_name {
                return Ok(RepoManifestMerge::Unproven);
            }
            let origin = match served {
                Some(repo_id) => self.origin_authority_in_txn(txn, repo_id)?,
                None => None,
            };
            if !self.repo_manifest_writer_proven_in_txn(txn, carried, origin.as_ref())? {
                return Ok(RepoManifestMerge::Unproven);
            }
        } else if self
            .authority_view_readonly_in_txn(txn)?
            .origin_cut_standing(carried.portable.as_bytes())?
            != OriginCutStanding::NoCut
            && !self.repo_manifest_writer_proven_in_txn(txn, carried, None)?
        {
            // Once the owner cut the repo, a first copy is proven as a
            // replacement is (FIX 15740); before any cut it is adopted.
            return Ok(RepoManifestMerge::Unproven);
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
    }

    /// Signs `manifest` as this machine, the refs writer that writes it, in
    /// the writer's transaction (FIX 12765). A machine with no signer loaded
    /// leaves it unsigned, warned: no copy of it replaces another.
    pub(super) fn sign_repo_manifest_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        manifest: &mut RepoManifest,
    ) -> Result<()> {
        manifest.writer = None;
        let (machine, key) = match crate::store::install_identity::machine_signer_in_txn(self, txn)
        {
            Ok(signer) => signer,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "repo manifest written unsigned: no signer here");
                return Ok(());
            }
        };
        let signature = ed25519_dalek::Signer::sign(&key, &manifest.writer_signing_bytes()?);
        manifest.writer = Some(RepoManifestWriter {
            machine,
            signature: signature.to_bytes().to_vec(),
        });
        Ok(())
    }

    /// Whether `manifest`'s writer is proven here (FIX 12765, Engine 02:54
    /// A3; FIX 15740, A2): its signature verifies under the key of a machine
    /// this vault's own authority fold trusts now, and that machine writes
    /// the repo at exactly the manifest's epoch. Where the owner's cut of the
    /// repo is in force, on every device, it names the machine and the epoch.
    /// Where his cuts conflict or the newest does not count here, no writer
    /// is proven. Before any cut only the bootstrap epoch 0 is proven, which
    /// refresh then writes; where this host serves the repo (`origin`, its
    /// authority row in `txn`), the row must also name the machine. A foreign
    /// or unsigned writer is not proven, and its copy waits.
    #[cfg(feature = "sync")]
    fn repo_manifest_writer_proven_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        manifest: &RepoManifest,
        origin: Option<&crate::origin::residence::OriginAuthority>,
    ) -> Result<bool> {
        let Some(writer) = &manifest.writer else {
            return Ok(false);
        };
        let Ok(signature) = <[u8; 64]>::try_from(writer.signature.as_slice()) else {
            return Ok(false);
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let Some(machine_key) = fold
            .trusted_machine(writer.machine)
            .map(|trusted| trusted.profile.machine_key)
        else {
            return Ok(false);
        };
        if fold.machine_proof_key(writer.machine) != Some(machine_key) {
            return Ok(false);
        }
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&machine_key) else {
            return Ok(false);
        };
        let signed = manifest.writer_signing_bytes()?;
        if key
            .verify_strict(&signed, &ed25519_dalek::Signature::from_bytes(&signature))
            .is_err()
        {
            return Ok(false);
        }
        Ok(
            match fold.origin_cut_standing(manifest.portable.as_bytes())? {
                OriginCutStanding::InForce(cut) => {
                    cut.writer == writer.machine && cut.epoch == manifest.epoch
                }
                OriginCutStanding::Unresolved => false,
                OriginCutStanding::NoCut => {
                    manifest.epoch == 0
                        && origin.is_none_or(|row| row.writer == writer.machine.to_hex())
                }
            },
        )
    }

    /// The raw manifest held under `portable` when it actually conflicts with
    /// `carried` in `txn` (FIX 12763): both name `portable`, both CODE anchors
    /// are live and their CODE or `minted_at` differs. `None` for a missing,
    /// unbound or non-conflicting row; store faults propagate. Reads the raw
    /// id row, never the alias redirect, so the window door reviews exactly
    /// what the merge would judge as `Conflict` while both anchors are live.
    #[cfg(feature = "sync")]
    pub(crate) fn repo_manifest_conflict_held_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        portable: &RepoPortableId,
        carried: &RepoManifest,
    ) -> Result<Option<RepoManifest>> {
        if carried.portable != *portable {
            return Ok(None);
        }
        let Some(held) = MANIFESTS.get(&self.store, txn, &portable.0)? else {
            return Ok(None);
        };
        if held.portable != *portable {
            return Ok(None);
        }
        if !code_anchor_live(self, txn, &held.code)? {
            return Ok(None);
        }
        if !code_anchor_live(self, txn, &carried.code)? {
            return Ok(None);
        }
        if held.code == carried.code && held.minted_at == carried.minted_at {
            return Ok(None);
        }
        Ok(Some(held))
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
