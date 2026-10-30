//! Pack lenses (OF-250): a pack ships its lens with its skills, the face half
//! beside the engine half (ARCH-0010). A PACK.md `lenses:` key names folders
//! under `lenses/`; each holds a `LENS.json` facet that binds one of the
//! pack's `skills/` folders as the lens's slot. A lens folder may carry its
//! frozen compiled tree (`tree.json`, the generated-lens envelope) with the
//! authored prompt it was compiled from (`intent.md`), and a compiled
//! Component Model build (`lens.wasm`). The build is not pack source: like an
//! organ build it travels as a blob asset held by the source, pinned by
//! BLAKE3 in the facet, so the source hash pins the binary. A lens that
//! carries neither is a host code lens: the host renders it, bound to the
//! pack's skill ([`LensMount::Pack`]).
//!
//! Install carries the folder with its source. `vault.lenses.propose` takes
//! the tree from the installed pack ([`Memory::lenses_propose_from_pack`]),
//! and a host builds a lens runtime from the held build
//! ([`Vault::pack_lens_component`]). A lens adds no power to the permission
//! card and holds no install as code does: its build runs only in the
//! read-only lens sandbox, where it reads what the rendering reader's own
//! scoped read admits and emits atoms, never effects.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::admission::{PACK_INSTALL, PackCommit, pack_permissions};
use super::builtin::{ENGINE_PUBLISHER, engine_hub_id};
use super::{
    PackFitVerdict, PackInstallReceipt, PackInstallStatus, PackManifest, PackSource, PackTree,
    invalid,
};
use crate::consent::AuthenticatedOwner;
use crate::lens::{
    GeneratedLens, LensIntentRecord, LensMount, LensProposeRequest, LensScope, LensSlot,
};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::provenance::made_by::MadeByTrigger;
use crate::receipt::LensProposalReceipt;
use crate::skill_hub::{HubFile, HubPin, HubRef};
use crate::{EntityId, TimeRange, Vault, error::Result};

const LENS_DIR: &str = "lenses/";
const LENS_MANIFEST: &str = "LENS.json";
const LENS_TREE: &str = "tree.json";
const LENS_INTENT: &str = "intent.md";
const LENS_COMPONENT: &str = "lens.wasm";

/// The first-party weave lens pack: "The weave report is a lens over the
/// vault. It lives in the lens pack." (ARCH-0063 §6).
pub const WEAVE_LENS_PACK_NAME: &str = "oneiron.weave";
/// The weave pack's lens, and the `skills/` folder of the skill whose
/// SKILL.md is the weave render's instruction.
pub const WEAVE_REPORT_LENS: &str = "weave-report";

/// The engine hub ref the weave lens pack installs under.
const WEAVE_LENS_PACK_HUB_REF: &str = "built-in:weave";

/// The weave lens pack's exact folder: the `weave-report` skill and the lens
/// that binds it. The engine renders the lens in code, so the folder carries
/// no tree and no build. Vault open installs it Active
/// ([`seed_weave_lens_pack_in_txn`]); `vault.packs.put` replaces it like any
/// owner folder.
#[must_use]
pub fn weave_lens_pack_files() -> Vec<HubFile> {
    vec![
        HubFile::new(
            "PACK.md",
            include_str!("../../../../../packs/weave/PACK.md").as_bytes(),
        ),
        HubFile::new(
            "skills/weave-report/SKILL.md",
            include_str!("../../../../../packs/weave/skills/weave-report/SKILL.md").as_bytes(),
        ),
        HubFile::new(
            "lenses/weave-report/LENS.json",
            include_str!("../../../../../packs/weave/lenses/weave-report/LENS.json").as_bytes(),
        ),
    ]
}

/// Vault open installs the weave lens pack Active from the engine's own
/// folder, with the built-in packs and once per engine version: an
/// engine-seeded install follows the engine's folder. An owner's install
/// under its name, or a source of the folder's hash the vault already holds
/// or erased, is left as it is.
pub(super) fn seed_weave_lens_pack_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    let source = PackSource::from_files(weave_lens_pack_files())?;
    let prior = PACK_INSTALL.get(&vault.store, &*txn, &source.manifest.name)?;
    if prior.as_ref().is_some_and(|installed| {
        installed.publisher != ENGINE_PUBLISHER
            || installed.content_hash == source.content_hash().to_hex()
    }) {
        return Ok(());
    }
    let source_id = source.entity_id()?;
    let deletion =
        crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &*txn, &source_id)?;
    if crate::ports::EntityStoreRead::port_entity_present(&vault.store, &*txn, &source_id)?
        || deletion.deleted
        || deletion.stale
    {
        return Ok(());
    }
    vault.stage_pack_source_in_txn(txn, &source, TimeRange { start: 0, end: 0 }, 0)?;
    let hub = HubRef::new(
        engine_hub_id()?,
        WEAVE_LENS_PACK_HUB_REF,
        HubPin::ContentHash(source.content_hash().to_hex()),
    )?;
    let permissions = pack_permissions(&source, prior.as_ref())?;
    vault.commit_pack_install_in_txn(
        txn,
        &source,
        &PackCommit {
            source_id,
            hub: &hub,
            publisher: ENGINE_PUBLISHER,
            foreign: None,
            verdict: PackFitVerdict {
                fits: true,
                rules_hit: false,
                code_auto_install: false,
            },
            permissions: &permissions,
            qualification: None,
            world: None,
            owner_activated: &[],
        },
    )?;
    Ok(())
}

/// One lens a pack carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackLens {
    /// Its folder under `lenses/`.
    pub name: String,
    /// The `skills/` folder whose skill backs it: its slot.
    pub skill: String,
    /// The frozen compiled tree, validated as the renderer reads it.
    pub tree: Option<serde_json::Value>,
    /// The authored prompt the tree was compiled from.
    pub intent: Option<String>,
    /// Its compiled component, pinned by content.
    pub component: Option<PackLensComponent>,
}

/// A lens's compiled Component Model build, pinned by content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackLensComponent {
    /// The build's BLAKE3, 64 lowercase hex.
    pub blake3: String,
    /// The build's length.
    pub bytes: u64,
}

/// What a `LENS.json` declares.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LensFacet {
    skill: String,
    #[serde(default)]
    component: Option<PackLensComponent>,
}

impl PackLens {
    fn from_folder(name: &str, folder: &BTreeMap<&str, &[u8]>, files: &[HubFile]) -> Result<Self> {
        let facet: LensFacet = serde_json::from_slice(
            folder
                .get(LENS_MANIFEST)
                .ok_or_else(|| invalid("a lens requires LENS.json"))?,
        )
        .map_err(|_| invalid("LENS.json must be a typed JSON object"))?;
        let skill_folder = format!("skills/{}/", facet.skill);
        if facet.skill.is_empty()
            || facet.skill.contains('/')
            || !files
                .iter()
                .any(|file| file.path.starts_with(&skill_folder))
        {
            return Err(invalid("a lens names a skill folder its pack carries"));
        }
        if let Some(component) = &facet.component {
            component.hash()?;
            if component.bytes == 0 {
                return Err(invalid("a lens component is empty"));
            }
        }
        let intent = folder
            .get(LENS_INTENT)
            .map(|bytes| std::str::from_utf8(bytes).map(|text| text.trim().to_owned()))
            .transpose()
            .map_err(|_| invalid("lens intent.md is not UTF-8"))?
            .filter(|text| !text.is_empty());
        if let Some(intent) = &intent {
            LensIntentRecord::new(intent.as_str())
                .map_err(|_| invalid("lens intent.md exceeds the lens intent bound"))?;
        }
        let tree = folder
            .get(LENS_TREE)
            .map(|bytes| {
                let lens: GeneratedLens = serde_json::from_slice(bytes)
                    .map_err(|_| invalid("lens tree.json is not a frozen lens tree"))?;
                serde_json::to_value(&lens).map_err(|_| invalid("lens tree did not encode"))
            })
            .transpose()?;
        if tree.is_some() && intent.is_none() {
            return Err(invalid(
                "a lens tree requires the intent.md it was compiled from",
            ));
        }
        Ok(Self {
            name: name.to_owned(),
            skill: facet.skill,
            tree,
            intent,
            component: facet.component,
        })
    }
}

impl PackLensComponent {
    /// The pinned BLAKE3.
    pub fn hash(&self) -> Result<[u8; 32]> {
        if self.blake3.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(invalid("lens component hash must be 64 lowercase hex"));
        }
        blake3::Hash::from_hex(&self.blake3)
            .map(|hash| *hash.as_bytes())
            .map_err(|_| invalid("lens component hash must be 64 lowercase hex"))
    }

    pub(super) fn verify(&self, bytes: &[u8]) -> Result<[u8; 32]> {
        let hash = self.hash()?;
        if bytes.len() as u64 != self.bytes || *blake3::hash(bytes).as_bytes() != hash {
            return Err(invalid("lens component bytes disagree with their pin"));
        }
        Ok(hash)
    }
}

pub(super) fn validate_lens_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name.as_bytes()[0].is_ascii_lowercase()
        || !name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
        })
    {
        return Err(invalid("lens names are short lowercase folder names"));
    }
    Ok(())
}

/// The lens folder a `lenses/<name>/lens.wasm` path names: a build, not
/// source.
pub(super) fn lens_component_folder(path: &str) -> Option<&str> {
    path.strip_prefix(LENS_DIR)?
        .split_once('/')
        .filter(|(folder, file)| !folder.is_empty() && *file == LENS_COMPONENT)
        .map(|(folder, _)| folder)
}

/// The lenses a source's `lenses:` key names, each read from its folder. A
/// folder the key does not name, an unknown file, or a build inside the
/// source is refused.
pub(super) fn parse_source_lenses(
    manifest: &PackManifest,
    files: &[HubFile],
) -> Result<Vec<PackLens>> {
    let mut folders = BTreeMap::<&str, BTreeMap<&str, &[u8]>>::new();
    for file in files {
        let Some(relative) = file.path.strip_prefix(LENS_DIR) else {
            continue;
        };
        let (folder, name) = relative
            .split_once('/')
            .ok_or_else(|| invalid("a lens must have a folder"))?;
        if name == LENS_COMPONENT {
            return Err(invalid(
                "lens components travel as blob assets, not pack source",
            ));
        }
        if !matches!(name, LENS_MANIFEST | LENS_TREE | LENS_INTENT) {
            return Err(invalid(
                "a lens folder holds LENS.json, tree.json, intent.md and lens.wasm only",
            ));
        }
        if !manifest.lenses.contains(folder) {
            return Err(invalid("lens folder is not named under lenses:"));
        }
        folders
            .entry(folder)
            .or_default()
            .insert(name, file.content.as_slice());
    }
    manifest
        .lenses
        .iter()
        .map(|name| {
            let folder = folders
                .get(name.as_str())
                .ok_or_else(|| invalid("declared lens folder is absent"))?;
            PackLens::from_folder(name, folder, files)
        })
        .collect()
}

/// The installed SKILL a lens's slot names. A pack's skills install one per
/// `skills/` folder, in folder order, so the receipt lists them that way.
fn lens_skill(
    receipt: &PackInstallReceipt,
    source: &PackSource,
    lens: &PackLens,
) -> Result<EntityId> {
    let folders: BTreeSet<&str> = source
        .files
        .iter()
        .filter_map(|file| file.path.strip_prefix("skills/")?.split_once('/'))
        .map(|(folder, _)| folder)
        .collect();
    if folders.len() != receipt.skills.len() {
        return Err(invalid("installed pack skills disagree with its source"));
    }
    let index = folders
        .iter()
        .position(|folder| *folder == lens.skill)
        .ok_or_else(|| invalid("a lens names a skill folder its pack carries"))?;
    EntityId::from_hex(&receipt.skills[index])
}

/// One lens of an Active installation, bound to its slot.
#[derive(Debug, Clone, Serialize)]
pub struct PackLensEntry {
    pub pack_name: String,
    pub source_id: String,
    /// The installed source's content hash: the pack content a proposal of
    /// the lens's tree is compiled against.
    pub content_hash: String,
    /// The SKILL backing the lens, 32 hex: the slot it mounts in.
    pub skill_id: String,
    pub lens: PackLens,
    /// Whether this vault holds the lens's component build.
    pub component_held: bool,
}

impl PackLensEntry {
    /// The host binding for this lens. It mounts while the pack stays
    /// installed and its skill still loads ([`Vault::mounted_lenses`]).
    pub fn mount(&self) -> Result<LensMount> {
        Ok(LensMount::Pack {
            pack_name: self.pack_name.clone(),
            skill_id: EntityId::from_hex(&self.skill_id)?,
        })
    }
}

impl Vault {
    /// Holds a tree's lens components as blob assets of its staged source.
    pub(super) fn hold_lens_components_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        source_id: &EntityId,
        tree: &PackTree,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        for bytes in &tree.lens_components {
            crate::ports::BlobStore::port_blob_put(
                self, txn, source_id, bytes, occurred, learned_at,
            )?;
        }
        Ok(())
    }

    /// Owner door: hold one lens component for a staged pack source, checked
    /// against the source's pin. Holding grants nothing; only an Active
    /// installation hands a component out.
    pub fn put_pack_lens_component(
        &self,
        owner: &AuthenticatedOwner,
        source_id: EntityId,
        lens: &str,
        bytes: &[u8],
    ) -> Result<PackLensComponent> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let source = self
                .pack_source_in_txn(txn, &source_id)?
                .ok_or_else(|| invalid("pack source missing"))?;
            let component = source
                .lens(lens)
                .and_then(|declared| declared.component.clone())
                .ok_or_else(|| invalid("the source pins no such lens component"))?;
            component.verify(bytes)?;
            let at = crate::unix_seconds_now();
            crate::ports::BlobStore::port_blob_put(
                self,
                txn,
                &source_id,
                bytes,
                TimeRange { start: at, end: at },
                at,
            )?;
            Ok(component)
        })
    }

    /// Every lens of every Active installation, each bound to the skill its
    /// slot names: the inventory a host mounts pack lenses from.
    pub fn pack_lenses(&self) -> Result<Vec<PackLensEntry>> {
        let installed = self.installed_packs()?;
        let txn = self.store.env.read_txn()?;
        let mut entries = Vec::new();
        for receipt in installed {
            let source_id = EntityId::from_hex(&receipt.source_id)?;
            let Some(source) = self.pack_source_in_txn(&txn, &source_id)? else {
                continue;
            };
            for lens in source.lenses() {
                entries.push(self.pack_lens_entry_in(&txn, &receipt, &source, lens)?);
            }
        }
        Ok(entries)
    }

    /// The lens `lens` of the Active pack `pack_name`, bound to its slot.
    pub fn pack_lens(&self, pack_name: &str, lens: &str) -> Result<PackLensEntry> {
        let txn = self.store.env.read_txn()?;
        let (receipt, source) = self.active_pack_source_in(&txn, pack_name)?;
        let declared = source
            .lens(lens)
            .ok_or_else(|| invalid("the pack carries no such lens"))?;
        self.pack_lens_entry_in(&txn, &receipt, &source, declared)
    }

    /// [`Self::pack_lens`], or `None` while no Active pack `pack_name`
    /// carries `lens`: how an engine render reads its own lens pack.
    pub fn pack_lens_if_active(
        &self,
        pack_name: &str,
        lens: &str,
    ) -> Result<Option<PackLensEntry>> {
        let txn = self.store.env.read_txn()?;
        let Some((receipt, source)) = self.active_pack_in(&txn, pack_name)? else {
            return Ok(None);
        };
        source
            .lens(lens)
            .map(|declared| self.pack_lens_entry_in(&txn, &receipt, &source, declared))
            .transpose()
    }

    /// An Active pack lens's component build, its bytes verified against
    /// the pin: what a host builds the lens's runtime from
    /// ([`crate::lens::LensExecutionRuntime::from_component`]). A Candidate
    /// pack has no lens to run.
    pub fn pack_lens_component(&self, pack_name: &str, lens: &str) -> Result<Vec<u8>> {
        let txn = self.store.env.read_txn()?;
        let (_, source) = self.active_pack_source_in(&txn, pack_name)?;
        let component = source
            .lens(lens)
            .ok_or_else(|| invalid("the pack carries no such lens"))?
            .component
            .as_ref()
            .ok_or_else(|| invalid("the lens ships no component"))?;
        let bytes = crate::ports::BlobStore::port_blob_get(self, &txn, &component.hash()?)?
            .ok_or_else(|| invalid("this vault holds no copy of the lens component"))?;
        component.verify(&bytes)?;
        Ok(bytes)
    }

    fn active_pack_source_in(
        &self,
        txn: &heed::RoTxn<'_>,
        pack_name: &str,
    ) -> Result<(PackInstallReceipt, PackSource)> {
        self.active_pack_in(txn, pack_name)?
            .ok_or_else(|| invalid("no Active pack is installed under that name"))
    }

    /// The Active installation under `pack_name` with its source, or `None`
    /// when no pack of that name is installed Active.
    fn active_pack_in(
        &self,
        txn: &heed::RoTxn<'_>,
        pack_name: &str,
    ) -> Result<Option<(PackInstallReceipt, PackSource)>> {
        let Some(receipt) = self
            .mounted_pack_in_txn(txn, pack_name)?
            .filter(|receipt| receipt.status == PackInstallStatus::Active)
        else {
            return Ok(None);
        };
        let source = self
            .pack_source_in_txn(txn, &EntityId::from_hex(&receipt.source_id)?)?
            .ok_or_else(|| invalid("installed pack source missing"))?;
        Ok(Some((receipt, source)))
    }

    fn pack_lens_entry_in(
        &self,
        txn: &heed::RoTxn<'_>,
        receipt: &PackInstallReceipt,
        source: &PackSource,
        lens: &PackLens,
    ) -> Result<PackLensEntry> {
        let component_held = match &lens.component {
            Some(component) => {
                crate::ports::BlobStore::port_blob_get(self, txn, &component.hash()?)?.is_some()
            }
            None => false,
        };
        Ok(PackLensEntry {
            pack_name: receipt.pack_name.clone(),
            source_id: receipt.source_id.clone(),
            content_hash: receipt.content_hash.clone(),
            skill_id: lens_skill(receipt, source, lens)?.to_hex(),
            lens: lens.clone(),
            component_held,
        })
    }
}

/// `vault.lenses.propose` for a lens an installed pack carries: the pack and
/// its lens folder name the tree. The tree, its intent, the slot and the
/// pack content it was compiled against are read from the Active
/// installation, never taken from the caller.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackLensProposeRequest {
    pub pack_name: String,
    /// The lens's folder under the pack's `lenses/`.
    pub lens: String,
    /// What caused this proposal, as `vault.lenses.propose` takes it.
    #[serde(default)]
    pub trigger: Option<MadeByTrigger>,
    /// Where the lens's tree is read, as `vault.lenses.propose` takes it.
    #[serde(default)]
    pub scope: Option<LensScope>,
}

impl Memory<'_> {
    /// Proposes the compiled tree an installed pack carries for one of its
    /// lenses, through `vault.lenses.propose`: it lands `proposed` and
    /// mounts only once the owner selects it. The propose door checks again,
    /// in the writer that stores the lens, that the pack is installed Active
    /// at the content the tree was read from, with the lens's skill loading.
    pub fn lenses_propose_from_pack(
        &self,
        input: PackLensProposeRequest,
    ) -> MemoryResult<LensProposalReceipt> {
        let entry = self.vault().pack_lens(&input.pack_name, &input.lens)?;
        let PackLens {
            tree: Some(compiled),
            intent: Some(intent_prompt),
            ..
        } = entry.lens
        else {
            return Err(MemoryError::bad_request(
                "the pack lens carries no compiled tree; its host renders it",
            ));
        };
        self.lenses_propose(LensProposeRequest {
            slot: LensSlot {
                pack_name: entry.pack_name,
                skill_id: entry.skill_id,
            },
            pack_content_hash: entry.content_hash,
            compiled,
            intent_prompt,
            trigger: input.trigger,
            scope: input.scope,
        })
    }
}
