//! The owner registers a secret (ARCH-0069 S1–S3): the production door that
//! puts a value into custody.
//!
//! The owner names the secret, its class, its rung on the custody ladder, its
//! bindings and the value. When the request names a repository, that
//! repository's manifest must declare the name, and it may only narrow (S2):
//! its entry is copied onto the record, and an ask wider than the entry is
//! refused. The floor stays the vault's. It is resolved in the transaction
//! that stores the value, and the owner proof is rechecked there too, so a
//! request queued behind a revoked slip or a removed owner stores nothing.
//!
//! A portable secret is registered as a custody register request (WILL L04
//! row 04): its holder, this install unless the owner names another, stores
//! it and signs its transition to the recipients he permits, in this commit
//! when this install is the holder. A record that stays on its device, or an
//! install that carries no owner act, registers here alone, and the receipt
//! says so. Any other holder gets the manifest text this door read beside the
//! record, and checks the record against it again (CALLS
//! CUSTODY_MANIFEST_RECHECK).

use std::fmt;

use zeroize::Zeroize;

use super::control::{ActiveChange, CustodyKeptHere, CustodyPlan, Material, SecretCustodyWork};
use super::doors::{
    refuse_bindings_wider_than_live_floor, register_generation_in_txn, register_secret_in_txn,
};
use super::transition::custody_portable;
use super::types::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus,
};
use crate::Vault;
use crate::authority::{ActSurface, CustodyChange, OwnerWorkRefusal};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::origin::secret_manifest::OriginSecretManifest;
use crate::secret_manifest::{
    SecretManifestEntry, parse_secret_manifest, validate_secret_manifest,
};
use crate::store::Store;

/// What a holder that is not the recorder checks a register against (CALLS
/// CUSTODY_MANIFEST_RECHECK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyManifestRecheck {
    /// The register's protected input carries, beside the record, the text
    /// of the manifest its recorder read and the owner approved. A register
    /// the owner's surface sealed itself carries, beside its envelope and
    /// under the digest the request names, the manifest the recorder
    /// resolved for the `manifest_ref` the surface stated; a ref that does
    /// not resolve there is refused at the door, by name. The holder takes a
    /// snapshot only for the record's own `manifest_ref`, parses it again
    /// and, in its committing transaction, checks that it still fits the
    /// live floor, declares the record's name, holds its class and every
    /// binding, and declares exactly its paths. That claims consistency with
    /// the owner-approved snapshot only: never that the ref still names it,
    /// nor anything the holder cannot read. No digest is taken of
    /// `manifest_ref` or of the ciphertext. A sealed register whose surface
    /// stated no manifest carries the vault's one current approved manifest,
    /// checked when the record names it, or an explicit "no manifest" mark
    /// (CALLS CUSTODY_MANIFEST_UNSTATED). A register that carries no
    /// snapshot is not checked against one, as before, and nothing asks
    /// where the holder runs.
    OwnerApprovedSnapshot,
}

const CUSTODY_MANIFEST_RECHECK: CustodyManifestRecheck =
    CustodyManifestRecheck::OwnerApprovedSnapshot;

/// Where a registration reads its manifest: a repository the vault serves as
/// origin, at a ref the vault published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestSource {
    /// The served repository's name.
    pub repo: String,
    /// The full ref name, such as `refs/heads/main`.
    pub git_ref: String,
}

/// One binding the owner asks for. Its tier defaults to the secret's rung and
/// may sit at or below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedBinding {
    /// The effector that may use the secret.
    pub effector: String,
    /// The binding's ceiling; `None` is the secret's rung.
    pub tier_ceiling: Option<CustodyTier>,
    /// What the binding grants, such as `read`.
    pub scopes: Vec<String>,
}

/// What the owner asks the vault to hold. It borrows the value: the door copies
/// it once, into the record it stores, and wipes that copy on every path.
pub struct OwnerSecretRegistration<'a> {
    /// The secret's custody name, unique among live records.
    pub name: &'a str,
    /// Its custody class (S1).
    pub class: CustodyClass,
    /// The portable record's "this device only" dial.
    pub device_only: bool,
    /// The rung this credential is used at (S3). Each binding names its rung,
    /// and none sits above this one.
    pub rung: CustodyTier,
    /// The bindings asked for. Empty with a manifest takes the manifest's,
    /// each at most at the rung.
    pub bindings: Vec<RequestedBinding>,
    /// The repository whose manifest declares the name, if any.
    pub manifest: Option<ManifestSource>,
    /// The value.
    pub value: &'a [u8],
}

impl fmt::Debug for OwnerSecretRegistration<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerSecretRegistration")
            .field("name", &self.name)
            .field("class", &self.class)
            .field("device_only", &self.device_only)
            .field("rung", &self.rung)
            .field("bindings", &self.bindings)
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

/// What landed: the record's metadata and its manifest copy, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRegistered {
    /// The custody record's id.
    pub secret_id: EntityId,
    /// The secret's name.
    pub name: String,
    /// Its custody class.
    pub class: CustodyClass,
    /// The "this device only" dial.
    pub device_only: bool,
    /// Zero, or one above a revoked record's when the name is reclaimed.
    pub rotation_generation: u32,
    /// When it was registered.
    pub registered_at: u64,
    /// The bindings stored.
    pub bindings: Vec<SecretBinding>,
    /// The manifest it was registered from; empty without one.
    pub manifest_ref: String,
    /// The paths the manifest entry declares.
    pub declared_paths: Vec<String>,
    /// The custody register request recorded for the owner's machines, or
    /// why the record stays on this install. Until its holder enacts it,
    /// the record is the holder's to store, not this install's.
    pub custody: SecretCustodyWork,
}

impl Vault {
    /// Registers a secret on the vault owner's behalf, rechecking the owner
    /// proof in the transaction that stores the value: this install the
    /// holder, and the recipient a portable record is sealed to
    /// ([`Vault::register_secret_with_custody`] with the default plan).
    ///
    /// # Errors
    /// Those of [`Vault::register_secret_with_custody`].
    pub fn register_secret_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        request: &OwnerSecretRegistration<'_>,
        at: u64,
    ) -> Result<SecretRegistered> {
        self.register_secret_with_custody(
            owner,
            ActSurface::ThisInstall,
            request,
            &CustodyPlan::default(),
            at,
        )
    }

    /// Registers a secret on the vault owner's behalf, rechecking the owner
    /// proof in the transaction that stores the value. A portable one is a
    /// custody register request: the holder `plan` names, this install by
    /// default, stores it and seals it to the recipients `plan` permits,
    /// itself alone by default. When this install is the holder it does so
    /// in this commit; any other holder gets the record sealed to its key
    /// as the request's protected input. `surface` is audit only. The
    /// install key loads before the writer, and a load that fails refuses.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof belongs to
    /// another vault, its slip or person is no longer live, or the actor no
    /// longer owns this vault. [`SecretError::SecretWiderThanManifest`] when
    /// the ask reaches past the manifest entry, or the manifest does not declare
    /// the name. [`SecretError::ManifestWidensFloor`] when the rung, a binding
    /// or the manifest reaches past the live floor.
    /// [`SecretError::SecretNameInUse`] for a live name.
    /// [`SecretError::InvalidSecretCustodyBody`] for an empty name or value, a
    /// binding above the rung, or one effector bound twice. The manifest read's
    /// own errors, from [`Vault::origin_secret_manifest`]. For a portable
    /// record, a holder or recipient that is no live linked install with an
    /// importable key, and a refusal of this install as holder.
    pub fn register_secret_with_custody(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        request: &OwnerSecretRegistration<'_>,
        plan: &CustodyPlan,
        at: u64,
    ) -> Result<SecretRegistered> {
        if request.value.is_empty() {
            return Err(invalid("a registered secret needs a value"));
        }
        // Read before the writer is taken: the manifest comes out of git.
        let manifest = request
            .manifest
            .as_ref()
            .map(|source| self.origin_secret_manifest(&source.repo, &source.git_ref))
            .transpose()?;
        let entry = manifest
            .as_ref()
            .map(|manifest| declared_entry(manifest, request.name))
            .transpose()?;
        let bindings = bindings_at_rung(request, entry)?;
        if let Some(entry) = entry {
            refuse_wider_than_entry(entry, request.class, &bindings)?;
        }

        let id = self.store.clock.entity_id()?;
        // The install key signs a portable record's request and transition
        // in the writer below; a key that fails to load refuses here.
        self.load_install_signing_if_minted()?;
        let mut wtxn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &wtxn)?;
        if !crate::policy_model::is_live_vault_owner_in_txn(self, &wtxn, &actor)? {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "only the vault owner registers a secret",
            )));
        }
        let floor = SecretCustodyFloor::resolve(&self.store, &wtxn)?;
        if let Some(manifest) = &manifest {
            validate_secret_manifest(&manifest.manifest, &floor)?;
        }
        let floor_max = floor.band_for(request.class).max;
        if request.rung > floor_max {
            return Err(Error::Secret(SecretError::ManifestWidensFloor {
                secret_ref: request.name.to_owned(),
                class: request.class,
                requested: request.rung,
                floor_max,
            }));
        }
        let mut rec = Held(SecretCustodyRecord {
            schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
            name: request.name.to_owned(),
            class: request.class,
            device_only: request.device_only,
            value_bytes: request.value.to_vec(),
            status: SecretCustodyStatus::Active,
            registered_at: at,
            rotated_at: None,
            rotation_generation: 0,
            bindings,
            manifest_ref: manifest
                .as_ref()
                .map(|manifest| manifest.manifest_ref.clone())
                .unwrap_or_default(),
            declared_paths: entry
                .map(|entry| entry.declared_paths.clone())
                .unwrap_or_default(),
            policy_floor_snapshot: floor,
        });
        let custody = if custody_portable(&rec.0) {
            rec.0.rotation_generation =
                register_generation_in_txn(&self.store, &wtxn, request.name)?;
            refuse_bindings_wider_than_live_floor(&self.store, &wtxn, &rec.0)?;
            let recorded = self.record_custody_change_in_txn(
                &mut wtxn,
                actor,
                surface,
                ActiveChange {
                    change: CustodyChange::Register,
                    id,
                    generation: rec.0.rotation_generation,
                    plan,
                    material: Material::Record(
                        &rec.0,
                        manifest.as_ref().map(|manifest| manifest.text.as_str()),
                    ),
                    sealed: None,
                    seen: None,
                    permits: None,
                },
                at,
            )?;
            // An install that carries no owner act keeps the record here,
            // and the receipt says so.
            if recorded.custody.kept_here.is_some() {
                register_secret_in_txn(self, &mut wtxn, &id, &mut rec.0)?;
            }
            recorded.custody
        } else {
            register_secret_in_txn(self, &mut wtxn, &id, &mut rec.0)?;
            SecretCustodyWork::kept(CustodyKeptHere::DeviceLocal)
        };
        wtxn.commit()?;
        self.mirror_custody_change(&custody);
        let rec = &rec.0;
        Ok(SecretRegistered {
            secret_id: id,
            name: rec.name.clone(),
            class: rec.class,
            device_only: rec.device_only,
            rotation_generation: rec.rotation_generation,
            registered_at: rec.registered_at,
            bindings: rec.bindings.clone(),
            manifest_ref: rec.manifest_ref.clone(),
            declared_paths: rec.declared_paths.clone(),
            custody,
        })
    }
}

/// The record a registration stores. Its value is wiped when the door is done
/// with it, on every path.
struct Held(SecretCustodyRecord);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.value_bytes.zeroize();
    }
}

fn invalid(reason: &'static str) -> Error {
    Error::Secret(SecretError::InvalidSecretCustodyBody(reason))
}

fn wider(name: &str, reason: &'static str) -> Error {
    Error::Secret(SecretError::SecretWiderThanManifest {
        secret_ref: name.to_owned(),
        reason,
    })
}

/// Why a holder refuses `record`, a register opened from its protected
/// input, against `snapshot`, the manifest text the input carries for the
/// record's `manifest_ref`, in its committing transaction `txn` (CALLS
/// CUSTODY_MANIFEST_RECHECK); `None` when they agree, or when there is no
/// snapshot to check. A manifest wider than the live floor is
/// [`OwnerWorkRefusal::WiderThanFloor`], any other disagreement
/// [`OwnerWorkRefusal::InvalidInput`].
pub(super) fn recheck_manifest_snapshot_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &SecretCustodyRecord,
    snapshot: Option<&str>,
) -> Result<Option<OwnerWorkRefusal>> {
    match CUSTODY_MANIFEST_RECHECK {
        CustodyManifestRecheck::OwnerApprovedSnapshot => {}
    }
    let Some(text) = snapshot else {
        return Ok(None);
    };
    let Ok(manifest) = parse_secret_manifest(text) else {
        return Ok(Some(OwnerWorkRefusal::InvalidInput));
    };
    match validate_secret_manifest(&manifest, &SecretCustodyFloor::resolve(store, txn)?) {
        Ok(()) => {}
        Err(Error::Secret(SecretError::ManifestWidensFloor { .. })) => {
            return Ok(Some(OwnerWorkRefusal::WiderThanFloor));
        }
        Err(_) => return Ok(Some(OwnerWorkRefusal::InvalidInput)),
    }
    let agrees = !record.manifest_ref.is_empty()
        && manifest.secrets.iter().any(|entry| {
            entry.name == record.name
                && entry.declared_paths == record.declared_paths
                && refuse_wider_than_entry(entry, record.class, &record.bindings).is_ok()
        });
    Ok((!agrees).then_some(OwnerWorkRefusal::InvalidInput))
}

/// The manifest's entry for `name`. Naming a repository whose manifest does
/// not declare the name asks for more than that manifest gives.
fn declared_entry<'m>(
    manifest: &'m OriginSecretManifest,
    name: &str,
) -> Result<&'m SecretManifestEntry> {
    manifest
        .manifest
        .secrets
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| wider(name, "the manifest does not declare this name"))
}

/// The bindings to store, each naming its rung. With none asked for, a
/// manifest's are taken, each lowered to the rung if it sits above it.
fn bindings_at_rung(
    request: &OwnerSecretRegistration<'_>,
    entry: Option<&SecretManifestEntry>,
) -> Result<Vec<SecretBinding>> {
    if request.bindings.is_empty()
        && let Some(entry) = entry
    {
        return Ok(entry
            .bindings
            .iter()
            .map(|declared| SecretBinding {
                effector: declared.effector.clone(),
                tier_ceiling: declared.tier_ceiling.min(request.rung),
                scopes: declared.scopes.clone(),
            })
            .collect());
    }
    let mut bindings: Vec<SecretBinding> = Vec::with_capacity(request.bindings.len());
    for asked in &request.bindings {
        if asked.effector.is_empty() {
            return Err(invalid("a binding names its effector"));
        }
        if bindings.iter().any(|b| b.effector == asked.effector) {
            return Err(invalid("an effector is bound once"));
        }
        let tier_ceiling = asked.tier_ceiling.unwrap_or(request.rung);
        if tier_ceiling > request.rung {
            return Err(invalid("a binding sits above the secret's rung"));
        }
        bindings.push(SecretBinding {
            effector: asked.effector.clone(),
            tier_ceiling,
            scopes: asked.scopes.clone(),
        });
    }
    Ok(bindings)
}

/// How far a class lets the value travel: a cross-vault value never
/// replicates, a device-bound one stays on its device, a portable one may
/// leave it.
const fn reach(class: CustodyClass) -> u8 {
    match class {
        CustodyClass::CrossVault => 0,
        CustodyClass::CustodyDeviceBound => 1,
        CustodyClass::CustodyPortable => 2,
    }
}

/// S2: the manifest may only narrow. The class, and each binding's effector,
/// tier and scopes, must sit inside what the entry declares.
fn refuse_wider_than_entry(
    entry: &SecretManifestEntry,
    class: CustodyClass,
    bindings: &[SecretBinding],
) -> Result<()> {
    if reach(class) > reach(entry.class) {
        return Err(wider(
            &entry.name,
            "the class lets the value travel further than the manifest's",
        ));
    }
    for binding in bindings {
        let Some(declared) = entry
            .bindings
            .iter()
            .find(|declared| declared.effector == binding.effector)
        else {
            return Err(wider(
                &entry.name,
                "a binding names an effector the manifest does not declare",
            ));
        };
        if binding.tier_ceiling > declared.tier_ceiling {
            return Err(wider(
                &entry.name,
                "a binding's tier sits above the manifest's",
            ));
        }
        if !binding
            .scopes
            .iter()
            .all(|scope| declared.scopes.contains(scope))
        {
            return Err(wider(
                &entry.name,
                "a binding carries a scope the manifest does not declare",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
