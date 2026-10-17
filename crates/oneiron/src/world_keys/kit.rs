//! The world kit ceremony (OF-173): issue, confirm by re-entering pieces,
//! restore, and the public inventory of every kit this vault issued.
//!
//! Issue draws a root and splits its seed into the fixed 2-of-3 kit. It
//! publishes nothing and stores only a pending row. Confirm takes two pieces
//! back, or one and the passphrase, rebuilds the seed, checks it grows into
//! the root the row names, and activates that root. The root, the pin, the
//! re-wraps, the row and the vault key's `world-kit` escrow wrap commit in one
//! transaction. No seed, piece, point or passphrase is ever stored.
//!
//! The escrow wrap runs one way: the kit's root opens the vault key, so a kit
//! restore on a new host opens a sealed backup. Nothing wraps the root under
//! the vault key or a passkey, and a passkey never opens a world key.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::doors::world_recovery_state_in;
use super::root_doors::this_machine_only;
use super::{
    ActivatedRoot, KitConfirmation, RecoveryRoot, RecoveryRootId, RecoveryRootSeed, RootRestore,
    VaultKeyStatus, VaultKeyWrapInfo, WorldRecoveryState, refused,
};
use crate::authority::EditOrigin;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::recovery::{
    CodeKeeping, KitCoverage, KitError, KitId, KitIssue, KitMachine, KitManifest, KitPassphrase,
    KitPiece, KitSecretKind, PieceHome, issue_recovery_root_kit, restore_kit,
};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// The label of the vault key's escrow wrap to the current world kit's root.
pub const WORLD_KIT_ESCROW: &str = "world-kit";

const KITS: SideTable<String, StoredKit, Named> = SideTable::new(&side_table::RECOVERY_KIT);

/// The passphrase piece's Argon2id cost, as the inventory keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCost {
    pub memory_mib: u32,
    pub passes: u8,
}

/// One kit this vault issued, public facts only: never a piece, point, tag,
/// passphrase, seed or export.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredKit {
    pub kit_id: KitId,
    pub kind: KitSecretKind,
    /// The owner's pick per point: `homes[i]` holds x = i + 1.
    pub homes: [PieceHome; 3],
    pub cost: Option<StoredCost>,
    /// What losing one machine leaves, judged from the homes at issue.
    pub coverage: KitCoverage,
    /// The id of the root the kit's seed grows into.
    pub root: [u8; 32],
    /// The vault clock, in seconds, at issue.
    pub created_at: u64,
    /// When the owner re-entered pieces and the root went live; `None` while
    /// pending. A pending kit never counts as coverage.
    pub confirmed_at: Option<u64>,
    /// The kit confirmed after this one. Its pieces still rebuild its own
    /// seed: a replaced kit is not a revoked one.
    pub replaced_by: Option<KitId>,
}

impl StoredKit {
    /// Confirmed, and no later kit replaced it.
    #[must_use]
    pub fn current(&self) -> bool {
        self.confirmed_at.is_some() && self.replaced_by.is_none()
    }
}

/// A world kit just issued: its pieces for the owner to place, and its public
/// facts. Nothing is published until [`Vault::confirm_world_kit`].
#[derive(Debug)]
pub struct IssuedWorldKit {
    /// The vault id the kit is bound to. A restore on a new host names it.
    pub vault_id: [u8; 32],
    /// The fingerprint of the root the kit carries.
    pub root: RecoveryRootId,
    pub manifest: KitManifest,
    /// The stored pieces in x order. A passphrase home has none.
    pub pieces: Vec<KitPiece>,
}

/// A world kit confirmed: its root is live on this install.
#[derive(Debug)]
pub struct ConfirmedWorldKit {
    pub kit: KitId,
    pub activated: ActivatedRoot,
    /// The kits this one replaced.
    pub replaced: Vec<KitId>,
    /// The vault key's `world-kit` escrow wrap, sealed to this kit's root;
    /// `None` when the vault has no data key yet.
    pub escrow: Option<VaultKeyWrapInfo>,
}

/// What a world kit restore did.
#[derive(Debug)]
pub struct WorldKitRestore {
    pub kit: KitId,
    pub root: RecoveryRootId,
    pub keys: RootRestore,
    /// The kit's passphrase cost is below today's default: offer a reissue.
    pub reissue_advised: bool,
}

/// The kits this vault issued and what they cover on this install.
#[derive(Debug)]
pub struct WorldKitStatus {
    /// The vault id kits are bound to; `None` before the authority genesis.
    pub vault_id: Option<[u8; 32]>,
    /// This install's pinned root.
    pub pinned: Option<RecoveryRootId>,
    /// The current kit whose root is the pin.
    pub current: Option<KitId>,
    /// Every kit, pending ones too.
    pub kits: Vec<StoredKit>,
    /// Each private world's no-kit state. `Covered` means only that its
    /// current key has a wrap to the pin; saved pieces and placement are the
    /// kits' own facts.
    pub worlds: Vec<(EntityId, WorldRecoveryState)>,
}

fn kit_key(id: KitId) -> String {
    id.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A kit refusal as the engine's: the kit's fixed reason, never piece bytes.
fn kit_refused(error: KitError) -> Error {
    refused(match error {
        KitError::PrivacyModeRequired => "privacy backup requires owner-held keys",
        KitError::EntropyUnavailable => "backup entropy unavailable",
        KitError::SameMachineTwice => "two kit pieces would live on one machine",
        KitError::PassphraseTwice => "a kit holds at most one passphrase piece",
        KitError::PassphraseMissing => "the passphrase piece needs a passphrase",
        KitError::PassphraseUnused => "this kit has no passphrase piece",
        KitError::PassphraseLength => "passphrase length out of range",
        KitError::PassphraseCost => "passphrase cost outside the kit's bounds",
        KitError::PassphraseStretch => "passphrase stretch failed",
        KitError::InvalidSecret => "invalid vault id or secret",
        KitError::InvalidPiece => "not a v2 kit piece",
        KitError::CodeChecksum => "recovery code check failed",
        KitError::WrongKind => "piece belongs to another kind of kit",
        KitError::MixedKits => "pieces come from different kits",
        KitError::NeedTwoPieces => "two distinct kit pieces are required",
        KitError::NoMatch => "the pieces do not open this kit",
    })
}

/// The homes with this machine's own id read as this machine, before the
/// kit judges placement and coverage: a code file on `me` is a file here,
/// and another machine's home never names `me`. Otherwise one machine under
/// two names would pass for two machines.
fn resolve_homes(homes: &[PieceHome; 3], me: Option<EntityId>) -> Result<[PieceHome; 3]> {
    let mut resolved = homes.clone();
    for home in &mut resolved {
        match *home {
            PieceHome::OtherMachine(id) if Some(id) == me => {
                return Err(refused("an other-machine home names this machine"));
            }
            PieceHome::RecoveryCode(CodeKeeping::FileOn(KitMachine::Other(id)))
                if Some(id) == me =>
            {
                *home = PieceHome::RecoveryCode(CodeKeeping::FileOn(KitMachine::ThisMachine));
            }
            _ => {}
        }
    }
    Ok(resolved)
}

/// The row a confirm finishes: this vault's, still pending, and naming the
/// root the pieces rebuild.
fn pending_row(row: Option<StoredKit>, root: &RecoveryRoot) -> Result<StoredKit> {
    let row = row.ok_or_else(|| refused("this vault issued no kit with these pieces' id"))?;
    if row.kind != KitSecretKind::RecoveryRoot || row.root != root.id.0 {
        return Err(refused(
            "the pieces do not rebuild the root this kit was issued with",
        ));
    }
    if row.confirmed_at.is_some() {
        return Err(refused("this kit is already confirmed"));
    }
    Ok(row)
}

impl Vault {
    /// The id kits are bound to: the vault's authority id, which its roots
    /// bind too, so a replica restores the same kit.
    fn kit_vault_id(&self) -> Result<[u8; 32]> {
        let txn = self.store.env.read_txn()?;
        self.authority_view_readonly_in_txn(&txn)?
            .vault_id
            .ok_or_else(|| refused("the vault has no authority genesis yet"))
    }

    /// Issues a world kit: a fresh root's seed, split 2-of-3 over the homes
    /// the owner picked. `only_machine` is decided here from the machine
    /// roster, never taken from the caller, and a home naming this machine's
    /// own id is read as this machine. Nothing is published; the inventory
    /// keeps a pending row until [`Self::confirm_world_kit`].
    pub fn issue_world_kit(
        &self,
        owner: &AuthenticatedOwner,
        issue: &KitIssue<'_>,
    ) -> Result<IssuedWorldKit> {
        let prepared = self.prepare_owner_root(owner)?;
        let (vault_id, only_machine, me) = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let me = crate::identity::read_machine_id_in_txn(self, &txn)?;
            let vault_id = fold
                .vault_id
                .ok_or_else(|| refused("the vault has no authority genesis yet"))?;
            let others = fold
                .machines
                .keys()
                .any(|machine| Some(*machine) != me && fold.trusted_machine(*machine).is_some());
            (vault_id, !others, me)
        };
        if issue.vault_id != vault_id {
            return Err(refused("the kit names another vault"));
        }
        let homes = resolve_homes(&issue.homes, me)?;
        let root = prepared.seed().public(&vault_id)?.id;
        let kit = issue_recovery_root_kit(
            &KitIssue {
                vault_id,
                homes,
                passphrase: issue.passphrase,
                cost: issue.cost,
                only_machine,
            },
            &prepared.seed().kit_bytes(),
        )
        .map_err(kit_refused)?;
        drop(prepared);
        let manifest = kit.manifest().clone();
        self.with_write_txn(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let key = kit_key(manifest.kit_id);
            if KITS.get(&self.store, txn, &key)?.is_some() {
                return Err(refused("a kit with this id is already listed"));
            }
            let row = StoredKit {
                kit_id: manifest.kit_id,
                kind: manifest.kind,
                homes: manifest.homes.clone(),
                cost: manifest.cost.map(|cost| StoredCost {
                    memory_mib: cost.memory_mib(),
                    passes: cost.passes(),
                }),
                coverage: manifest.coverage,
                root: root.0,
                created_at: self.instant_in_txn(txn)?.secs(),
                confirmed_at: None,
                replaced_by: None,
            };
            KITS.put(&self.store, txn, &key, &row)
        })?;
        Ok(IssuedWorldKit {
            vault_id,
            root,
            manifest,
            pieces: kit.into_pieces(),
        })
    }

    /// Confirms a world kit from its pieces as the owner saved them: two, or
    /// one and the passphrase. They must rebuild the seed of the root its
    /// pending row names. That root then goes live as
    /// [`Self::activate_owner_root`] makes it, with `carry` and every refusal
    /// there. The row, the kits it replaces and the vault key's `world-kit`
    /// escrow wrap commit in the activation's transaction. A vault with a
    /// data key needs it held on this handle: the new wrap replaces the old
    /// kit's, so a locked key refuses the confirm before anything is written.
    pub fn confirm_world_kit(
        &self,
        owner: &AuthenticatedOwner,
        origin: EditOrigin,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
        carry: &BTreeSet<EntityId>,
    ) -> Result<ConfirmedWorldKit> {
        this_machine_only(origin)?;
        let kit = pieces
            .first()
            .map(|piece| piece.kit_id())
            .ok_or_else(|| kit_refused(KitError::NeedTwoPieces))?;
        let key = kit_key(kit);
        let vault_id = self.kit_vault_id()?;
        let secret = restore_kit(vault_id, KitSecretKind::RecoveryRoot, pieces, passphrase)
            .map_err(kit_refused)?;
        let seed = RecoveryRootSeed::from_restored_kit(secret)?;
        let root = seed.public(&vault_id)?;
        {
            let txn = self.store.env.read_txn()?;
            pending_row(KITS.get(&self.store, &txn, &key)?, &root)?;
        }
        // The escrow wrap's transaction checks the key again.
        if self.vault_key_status()? == VaultKeyStatus::Locked {
            return Err(refused("unlock the vault key first"));
        }
        let prepared = self.prepare_owner_root_from_seed(owner, seed)?;
        // The `world-kit` wrap is a wrap change: a sealed vault's page-seal
        // mirror is staged in the activation's transaction and rewritten
        // after it commits (OF-570).
        let transition = self.begin_wrap_transition()?;
        let (activated, (replaced, escrow)) =
            self.activate_owner_root_with(owner, origin, prepared, carry, |txn| {
                let mut row = pending_row(KITS.get(&self.store, txn, &key)?, &root)?;
                let mut replaced = Vec::new();
                for (other_key, mut other) in KITS.scan(&self.store, txn)? {
                    if other.kit_id != kit && other.current() {
                        other.replaced_by = Some(kit);
                        replaced.push(other.kit_id);
                        KITS.put(&self.store, txn, &other_key, &other)?;
                    }
                }
                row.confirmed_at = Some(self.instant_in_txn(txn)?.secs());
                KITS.put(&self.store, txn, &key, &row)?;
                let escrow = self.put_vault_key_escrow_in_txn(
                    txn,
                    &transition,
                    WORLD_KIT_ESCROW,
                    &root.recovery_key,
                )?;
                Ok((replaced, escrow))
            })?;
        transition.finish()?;
        Ok(ConfirmedWorldKit {
            kit,
            activated,
            replaced,
            escrow,
        })
    }

    /// Restores this vault's world keys from the kit: the pieces rebuild the
    /// seed, then [`Self::restore_world_keys`] runs with `confirm` and every
    /// rule there. A seed it cannot authenticate is refused as
    /// `UnverifiedKitRestore`, unchanged, and no setting is edited. The
    /// inventory is never written. The root door reads it only to refuse a
    /// kit it lists as pending, which [`Self::confirm_world_kit`] finishes
    /// instead; a fresh host with no row for the kit restores without it.
    pub fn restore_world_kit(
        &self,
        owner: &AuthenticatedOwner,
        origin: EditOrigin,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
        confirm: Option<KitConfirmation>,
    ) -> Result<WorldKitRestore> {
        this_machine_only(origin)?;
        let kit = pieces
            .first()
            .map(|piece| piece.kit_id())
            .ok_or_else(|| kit_refused(KitError::NeedTwoPieces))?;
        let vault_id = self.kit_vault_id()?;
        let secret = restore_kit(vault_id, KitSecretKind::RecoveryRoot, pieces, passphrase)
            .map_err(kit_refused)?;
        let reissue_advised = secret.reissue_advised();
        let seed = RecoveryRootSeed::from_restored_kit(secret)?;
        let root = seed.public(&vault_id)?.id;
        let keys = self.restore_world_keys(owner, origin, &seed, confirm)?;
        Ok(WorldKitRestore {
            kit,
            root,
            keys,
            reissue_advised,
        })
    }

    /// Whether a kit this vault issued for `root` still waits for its
    /// confirm, read in `txn`. Only that confirm publishes the root: a seed
    /// door refuses it, so a pending kit never becomes coverage.
    pub(super) fn kit_root_pending_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        root: RecoveryRootId,
    ) -> Result<bool> {
        Ok(KITS
            .scan(&self.store, txn)?
            .into_iter()
            .any(|(_, kit)| kit.root == root.0 && kit.confirmed_at.is_none()))
    }

    /// Every kit this vault issued, the current one, and each private world's
    /// no-kit state on this install, from one snapshot.
    pub fn world_kit_status(&self) -> Result<WorldKitStatus> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let kits: Vec<StoredKit> = KITS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, kit)| kit)
            .collect();
        let pinned = fold.pinned_root.map(|pin| pin.id);
        let current = kits
            .iter()
            .find(|kit| kit.current() && Some(RecoveryRootId(kit.root)) == pinned)
            .map(|kit| kit.kit_id);
        let worlds: BTreeSet<EntityId> = fold
            .worlds
            .keys()
            .copied()
            .chain(fold.all_world_keys().map(|key| key.id.world))
            .collect();
        let worlds = worlds
            .into_iter()
            .map(|world| (world, world_recovery_state_in(&fold, world)))
            .filter(|(_, state)| *state != WorldRecoveryState::NotPrivate)
            .collect();
        Ok(WorldKitStatus {
            vault_id: fold.vault_id,
            pinned,
            current,
            kits,
            worlds,
        })
    }
}
