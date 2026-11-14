//! The data-key kit (FIX 4532): the owner's 2-of-3 copy of the vault data key
//! this handle holds, issued on his proof, and the door that takes its pieces
//! back (FIX 5614).
//!
//! The key is split by [`issue_vault_key_kit`] over the homes the owner names,
//! at the passphrase cost he asks, on any custody: his will to keep a copy
//! counts wherever the vault runs, a hosted vault's included, and the kit is
//! a copy, never a claim of host-blindness. No key is minted, rotated or
//! wrapped, no raw key leaves this handle except split into the pieces, and
//! the world kit and its `world-kit` escrow wrap stay as they are. The kit's
//! public facts go into the kit inventory with no root
//! ([`StoredKit`](crate::world_keys::StoredKit)): it is issued and stays so,
//! never pending, current or replaced.
//!
//! Its pieces come back as
//! [`VaultKeyUnlock::Kit`](super::VaultKeyUnlock::Kit): two, or one and the
//! kit passphrase, rebuild the key bound to the vault id the owner names. It
//! opens only when that id is the vault's and the key is the one the vault's
//! commitment names, so a restore on a new host, `vault-key add-device` and
//! a sealed vault's pages open on it with no wrap carried. The commitment is
//! what authenticates a key one piece and the passphrase rebuilt. No
//! inventory row is read for it: a fresh host lists nothing.
//!
//! A `ThisMachine` home's piece stays in this install's key slots, replacing
//! the piece an earlier data-key kit kept there, and the unlock here reads it
//! back as one of the pieces (FIX 2063). A sealed vault's pages unlock before
//! its machine id can be read, so there the pieces the host's keystore keeps
//! for each install a carried device wrap names join the pieces given (FIX
//! 11976), and so does the piece of the install the vault id alone names as
//! keeping one, with no device wrap carried for it (FIX 12054).
//!
//! A `Passkey` home's piece is handed to no one: it is sealed under the
//! owner's passkey into a `kit_point` wrap in the issuing write, and an
//! unlock that names the passkey joins it to the pieces given (census L10-18,
//! [`kit_passkey`](super::kit_passkey)).

use std::path::Path;
use std::sync::Arc;

use oneiron_keystore::DeviceKeystore;

use super::super::page_seal::{WrapTransition, read_mirror_carried};
use super::kit_passkey::{kit_point_kind, passkey_pieces, seal_kit_point};
use super::{
    CarriedVaultKey, KitPasskey, STATE, StoredWrap, VaultDataKey, VaultKeyUnlock, VaultKeyWrapInfo,
    VaultKeyWrapKind, WRAPS, check_name,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::world_keys::kit::{kit_refused, resolve_homes};
use crate::world_keys::kit_piece::keep_this_machine_piece;
use crate::world_keys::{HybridSecretKey, RecoveryRootSeed};
use crate::world_keys::{keystore_error, refused};
use crate::{
    recovery::KitPieceStore,
    recovery::{
        issue_vault_key_kit, join_kept_piece, recovery_root_pending_piece_install,
        recovery_root_piece_install, restore_kit, vault_key_piece_install,
    },
    store::recovery_kit::{
        KitError, KitId, KitIssue, KitManifest, KitPassphrase, KitPiece, KitPiecePair,
        KitSecretKind, PieceHome, RestoredKitSecret,
    },
};

/// A data-key kit just issued: its pieces for the owner to place, and its
/// public facts. Nothing secret is stored or published.
#[derive(Debug)]
pub struct IssuedVaultKeyKit {
    /// The vault id the data key, its wraps and the kit are bound to
    /// ([`Vault::vault_key_vault_id`]): a restore names it.
    pub vault_id: [u8; 32],
    pub manifest: KitManifest,
    /// The pieces to hand out, in x order. A passphrase home has none, a
    /// `ThisMachine` home's piece is in this install's key slots (FIX 2063),
    /// and a `Passkey` home's is in the vault key's `kit_point` wrap.
    pub pieces: Vec<KitPiece>,
    /// Whether the kit's public facts went into the kit inventory. The
    /// pieces open the key either way; a vault that took no write keeps no
    /// row of it.
    pub listed: bool,
}

/// A data-key kit drawn and not yet handed over: its public facts, the
/// pieces for the owner to place (a `ThisMachine` home's still among them),
/// and a `Passkey` home's piece sealed as the `kit_point` wrap the issuing
/// write stores, its kind and envelope. Nothing of it is written yet.
pub(super) struct DrawnVaultKeyKit {
    vault_id: [u8; 32],
    pub(super) commitment: [u8; 32],
    pub(super) manifest: KitManifest,
    pieces: Vec<KitPiece>,
    pub(super) point: Option<(VaultKeyWrapKind, Vec<u8>)>,
    store: Option<KitPieceStore>,
}

impl DrawnVaultKeyKit {
    /// Runs `keep` on the pieces [`Self::hand_over`] hands to the owner,
    /// before it replaces the piece an earlier data-key kit kept in this
    /// install's key slots: a failed keep leaves those slots as they were
    /// (review of #7781). A `ThisMachine` home's piece moves to the end of
    /// the list and is not offered; the other pieces keep their order.
    pub(super) fn keep_owner_pieces(
        &mut self,
        keep: impl FnOnce(&[KitPiece]) -> Result<()>,
    ) -> Result<()> {
        // As `keep_this_machine_piece` decides: with no store the kit has
        // no `ThisMachine` home, and every piece is the owner's.
        let has_store = self.store.is_some();
        let local =
            move |piece: &KitPiece| has_store && piece.home() == Some(&PieceHome::ThisMachine);
        self.pieces.sort_by_key(local);
        let owned = self.pieces.iter().filter(|piece| !local(piece)).count();
        keep(&self.pieces[..owned])
    }

    /// Issue's last step, once its write went through: a `ThisMachine`
    /// home's piece to this install's key slots, replacing the piece an
    /// earlier data-key kit kept there (FIX 2063), and the other pieces
    /// handed over.
    pub(super) fn hand_over(self, listed: bool) -> Result<IssuedVaultKeyKit> {
        let pair = KitPiecePair::Current(KitSecretKind::VaultKey);
        let pieces = keep_this_machine_piece(self.store.as_ref(), pair, self.pieces)?;
        Ok(IssuedVaultKeyKit {
            vault_id: self.vault_id,
            manifest: self.manifest,
            pieces,
            listed,
        })
    }
}

/// The vault data key the data-key kit's pieces in `unlock` rebuild for the
/// vault `vault_id`, checked against the commitment `carried` names. The id
/// the owner names the kit by must be `vault_id`: another vault's is refused
/// before any passphrase work. With the keystore `unlock` names, this
/// machine's own piece of the kit joins the pieces given (FIX 11976), as
/// [`Vault::restore_kit_here`] joins it on an open vault; with the passkey it
/// names, the piece a carried `kit_point` wrap seals under it joins them too.
/// Every kit refusal names its fixed reason, never piece bytes.
pub(super) fn open_kit(
    vault_id: &[u8; 32],
    carried: &CarriedVaultKey,
    unlock: &VaultKeyUnlock<'_>,
) -> Result<VaultDataKey> {
    let VaultKeyUnlock::Kit {
        vault_id: named,
        pieces,
        passphrase,
        passkey,
        keystore,
    } = unlock
    else {
        return Err(refused("the unlock carries no data-key kit pieces"));
    };
    if named != vault_id {
        return Err(refused("the kit names another vault"));
    }
    let mut given: Vec<&KitPiece> = pieces.iter().collect();
    let sealed = match passkey {
        Some(passkey) => passkey_pieces(
            vault_id,
            carried.commitment(),
            &carried.0.wraps,
            *passkey,
            &given,
        )?,
        None => Vec::new(),
    };
    given.extend(&sealed);
    let (kept, unreadable) = match keystore {
        Some(keystore) => kept_pieces(keystore, vault_id, carried, KitSecretKind::VaultKey, None),
        None => (Vec::new(), false),
    };
    let secret = restore_joined(
        *vault_id,
        KitSecretKind::VaultKey,
        &given,
        &kept,
        unreadable,
        *passphrase,
    )
    .map_err(kit_refused)?;
    committed_key(vault_id, carried.commitment(), secret)
}

/// The recovery secret the world kit's pieces in `unlock` rebuild, bound to
/// its authority-genesis `WorldKit.vault_id`. The mirror's independent store
/// id names the kept slots here and the escrow wrap the caller opens; the two
/// ids are never compared. With the keystore `unlock` names, this machine's
/// own recovery-root piece of the kit joins the pieces given before the pages
/// open (FIX 11974): the kept piece of each install a carried device wrap
/// names, of the install the store id alone names (FIX 12055), current or
/// still pending. The caller opens the `world-kit` escrow wrap with the
/// secret, as a world kit rebuilt in plain does. Every kit refusal names
/// its fixed reason, never piece bytes.
pub(super) fn open_world_kit(
    store_vault_id: &[u8; 32],
    carried: &CarriedVaultKey,
    unlock: &VaultKeyUnlock<'_>,
) -> Result<HybridSecretKey> {
    let VaultKeyUnlock::WorldKit {
        vault_id: world_vault_id,
        kit,
        pieces,
        passphrase,
        keystore,
    } = unlock
    else {
        return Err(refused("the unlock carries no world kit pieces"));
    };
    let given: Vec<&KitPiece> = pieces.iter().collect();
    let pending = Some(*kit);
    let (kept, unreadable) = match keystore {
        Some(keystore) => kept_pieces(
            keystore,
            store_vault_id,
            carried,
            KitSecretKind::RecoveryRoot,
            pending,
        ),
        None => (Vec::new(), false),
    };
    let kept = kept
        .into_iter()
        .filter(|piece| piece.kit_id() == *kit)
        .collect::<Vec<_>>();
    let secret = restore_joined(
        *world_vault_id,
        KitSecretKind::RecoveryRoot,
        &given,
        &kept,
        unreadable,
        *passphrase,
    )
    .map_err(kit_refused)?;
    RecoveryRootSeed::from_restored_kit(secret)?.recovery_secret()
}

/// Whether `keystore` keeps a piece of the exact kit `kit` of `kind` for the
/// sealed vault at `vault_path`, readable before its pages open (FIX
/// 12055): the piece of each install a device wrap the mirror carries
/// names, of the install the vault id alone names for this kind, current
/// or, for a recovery-root kit, its pending piece. A host asking for a kit
/// passphrase counts it first, so one given piece and the kept piece ask
/// for none. A kept name or piece that does not read counts as kept: the
/// open then says so ([`KitError::KeptPieceUnreadable`]) instead of the
/// count and the open disagreeing. Another kit's piece never counts, so a
/// stale kit's kept piece cannot take the prompt away from an open that
/// would still need the passphrase.
///
/// # Errors
///
/// The mirror's own refusals (no mirror, a malformed or other-version one),
/// as [`page_seal_vault_id`](crate::world_keys::page_seal_vault_id) raises
/// them. Keystore reads never fail the count: they count as kept, above.
pub fn sealed_keeps_kit_piece(
    vault_path: &Path,
    keystore: &Arc<dyn DeviceKeystore>,
    kind: KitSecretKind,
    kit: KitId,
) -> Result<bool> {
    let (vault_id, carried) = read_mirror_carried(vault_path)?;
    let pending = (kind == KitSecretKind::RecoveryRoot).then_some(kit);
    let (kept, unreadable) = kept_pieces(keystore, &vault_id, &carried, kind, pending);
    Ok(unreadable
        || kept
            .iter()
            .any(|piece| piece.kind() == kind && piece.kit_id() == kit))
}

/// The pieces of kits of `kind` `keystore` keeps for the vault `vault_id`
/// (FIX 11976, FIX 12055): a sealed vault's machine id is read only once its
/// pages open, so the slots read are those of each install a device wrap in
/// `carried` names, then of the install the vault id alone names as keeping
/// a current piece of this kind, when no carried wrap names it (FIX 12054,
/// FIX 12055). For a recovery-root kit `pending` names, its per-kit pending
/// install name joins that discovery too, so a crash-left pending pair is
/// found even with no wrap or current name. Each install's current pair and
/// that pending pair are read: a data-key kit has no pending pair (FIX
/// 12046). And whether a slot held a piece or a name that did not read: it
/// is logged and left out.
fn kept_pieces(
    keystore: &Arc<dyn DeviceKeystore>,
    vault_id: &[u8; 32],
    carried: &CarriedVaultKey,
    kind: KitSecretKind,
    pending: Option<KitId>,
) -> (Vec<KitPiece>, bool) {
    let mut installs: Vec<[u8; 16]> = carried
        .wrap_infos()
        .into_iter()
        .filter_map(|info| match &info.kind {
            VaultKeyWrapKind::Device { install } => crate::EntityId::from_hex(install).ok(),
            _ => None,
        })
        .map(|install| *install.as_bytes())
        .collect();
    let mut kept = Vec::new();
    let mut unreadable = false;
    let named = match kind {
        KitSecretKind::VaultKey => vault_key_piece_install(&**keystore, vault_id),
        KitSecretKind::RecoveryRoot => recovery_root_piece_install(&**keystore, vault_id),
    };
    match named {
        Ok(Some(install)) if !installs.contains(&install) => installs.push(install),
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(
                kind = ?keystore_error(error).kind(),
                kit_kind = ?kind,
                "the vault id's name of the install keeping this machine's kit \
                 piece did not read; unlocking with the pieces the device wraps find"
            );
            unreadable = true;
        }
    }
    if kind == KitSecretKind::RecoveryRoot
        && let Some(kit) = pending
    {
        match recovery_root_pending_piece_install(&**keystore, vault_id, kit) {
            Ok(Some(install)) if !installs.contains(&install) => installs.push(install),
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    kind = ?keystore_error(error).kind(),
                    kit_kind = ?kind,
                    "the vault id's name of the install keeping this kit's pending piece did \
                     not read; unlocking with the pieces the device wraps find"
                );
                unreadable = true;
            }
        }
    }
    let mut pairs = vec![KitPiecePair::Current(kind)];
    if kind == KitSecretKind::RecoveryRoot {
        pairs.extend(pending.map(KitPiecePair::Pending));
    }
    for install in &installs {
        let store = KitPieceStore::new(Arc::clone(keystore), *vault_id, *install);
        for pair in &pairs {
            match store.get(*pair) {
                Ok(Some(piece)) => kept.push(piece),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        kind = ?keystore_error(error).kind(),
                        kit_kind = ?kind,
                        "this machine's kit piece did not read; unlocking with the \
                         pieces given"
                    );
                    unreadable = true;
                }
            }
        }
    }
    (kept, unreadable)
}

/// [`restore_kit`] over `given` joined by each piece of `kept` of their kit in
/// turn, one piece per kit, then over `given` alone, until one finishes: a kit
/// whose given pieces reach its threshold opens as it does with none kept. A
/// refusal is the first attempt's, except that when the unjoined attempt falls
/// short and a piece did not read (`unreadable`), it says so
/// ([`KitError::KeptPieceUnreadable`]) before any older refusal, as
/// [`Vault::restore_kit_here`] does.
fn restore_joined(
    vault_id: [u8; 32],
    kind: KitSecretKind,
    given: &[&KitPiece],
    kept: &[KitPiece],
    unreadable: bool,
    passphrase: Option<&KitPassphrase>,
) -> std::result::Result<RestoredKitSecret, KitError> {
    let mut kits = Vec::new();
    let mut refusal = None;
    for piece in kept {
        let pieces = join_kept_piece(Some(piece), given);
        if pieces.len() == given.len() || kits.contains(&piece.kit_id()) {
            continue;
        }
        kits.push(piece.kit_id());
        match restore_kit(vault_id, kind, &pieces, passphrase) {
            Ok(secret) => return Ok(secret),
            Err(error) => {
                refusal.get_or_insert(error);
            }
        }
    }
    let alone = restore_kit(vault_id, kind, given, passphrase);
    match (alone, refusal) {
        (Ok(secret), _) => Ok(secret),
        (Err(KitError::NeedTwoPieces), _) if unreadable => Err(KitError::KeptPieceUnreadable),
        (Err(_), Some(first)) => Err(first),
        (Err(error), None) => Err(error),
    }
}

/// The data key a kit rebuilt for the vault `vault_id`, held only when it is
/// the key `commitment` names.
fn committed_key(
    vault_id: &[u8; 32],
    commitment: &[u8; 32],
    secret: RestoredKitSecret,
) -> Result<VaultDataKey> {
    let key = VaultDataKey::from_guarded(secret.into_bytes());
    if key.commitment(vault_id) != *commitment {
        return Err(refused(
            "the kit opens to another key than the one this vault's commitment names",
        ));
    }
    Ok(key)
}

impl Vault {
    /// Issues a kit of the vault data key this handle holds, on `owner`'s
    /// request. The owner proof, the key's commitment and the machine roster
    /// are read in one snapshot: the proof must still hold, and the
    /// commitment must name the held key. The vault id `issue` names must be
    /// the one the key is bound to. `only_machine` comes from the roster,
    /// never the caller, and a home naming this machine's own id is read as
    /// this machine, as a world kit's homes are. The homes and the cost are
    /// the owner's as `issue` names them. A `ThisMachine` home's piece goes
    /// to this install's key slots before the listing, and the other homes'
    /// pieces are returned (FIX 2063). The kit's public facts are then
    /// listed in the inventory, the owner rechecked in that write; a write
    /// that does not go through leaves the kit issued and unlisted.
    ///
    /// # Errors
    ///
    /// A key this handle does not hold (unlock it first) or the vault does
    /// not have; an owner proof that no longer holds; another vault's id; a
    /// held key the commitment does not name; and every kit refusal by its
    /// fixed reason, never piece bytes.
    pub fn issue_vault_key_recovery_kit_as(
        &self,
        owner: &AuthenticatedOwner,
        issue: &KitIssue<'_>,
    ) -> Result<IssuedVaultKeyKit> {
        self.issue_vault_key_recovery_kit_with_passkey_as(owner, issue, None)
    }

    /// [`Self::issue_vault_key_recovery_kit_as`], with the owner's synced
    /// passkey keeping one piece (census L10-18): a `Passkey` home's piece is
    /// sealed under `passkey`'s PRF output into a `kit_point` wrap, stored in
    /// the write that lists the kit, and handed to no one. That write must go
    /// through, or nothing is issued. A kit holds at most one passkey piece,
    /// and only with its passkey. Under every recovery preset: the wrap opens
    /// a piece, never the key.
    ///
    /// # Errors
    ///
    /// Those of [`Self::issue_vault_key_recovery_kit_as`]; a `Passkey` home
    /// with no passkey, a passkey with no such home, or two passkey homes;
    /// and the listing's own refusal.
    pub fn issue_vault_key_recovery_kit_with_passkey_as(
        &self,
        owner: &AuthenticatedOwner,
        issue: &KitIssue<'_>,
        passkey: Option<KitPasskey<'_>>,
    ) -> Result<IssuedVaultKeyKit> {
        let mut drawn = self.draw_vault_key_kit(owner, issue, passkey)?;
        if let Some(point) = drawn.point.take() {
            let transition = self.begin_wrap_transition()?;
            self.with_write_txn(|txn| {
                self.list_vault_key_kit_in_txn(txn, owner, &drawn.manifest)?;
                self.put_kit_point_in_txn(txn, &transition, &drawn.commitment, point)
            })?;
            transition.finish()?;
            return drawn.hand_over(true);
        }
        let pair = KitPiecePair::Current(KitSecretKind::VaultKey);
        let pieces = keep_this_machine_piece(drawn.store.as_ref(), pair, drawn.pieces)?;
        // The pieces never depend on the row: a write refused here (a vault
        // that takes none, a proof gone since the snapshot) is said, and the
        // kit is handed over all the same.
        let listed = match self
            .with_write_txn(|txn| self.list_vault_key_kit_in_txn(txn, owner, &drawn.manifest))
        {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "the data-key kit was issued and not listed in the kit inventory"
                );
                false
            }
        };
        Ok(IssuedVaultKeyKit {
            vault_id: drawn.vault_id,
            manifest: drawn.manifest,
            pieces,
            listed,
        })
    }

    /// Draws a data-key kit of the held key over `issue`'s homes, as
    /// [`Self::issue_vault_key_recovery_kit_as`] reads them: the owner proof,
    /// the key's commitment and the machine roster in one snapshot. A
    /// `Passkey` home's piece is sealed under `passkey` as its `kit_point`
    /// wrap's envelope, and taken out of the pieces. Nothing is written or
    /// kept yet.
    pub(super) fn draw_vault_key_kit(
        &self,
        owner: &AuthenticatedOwner,
        issue: &KitIssue<'_>,
        passkey: Option<KitPasskey<'_>>,
    ) -> Result<DrawnVaultKeyKit> {
        let passkey_homes = issue
            .homes
            .iter()
            .filter(|home| **home == PieceHome::Passkey)
            .count();
        match (passkey_homes, passkey) {
            (0, None) | (1, Some(_)) => {}
            (0, Some(_)) => return Err(refused("the kit has no passkey home for this passkey")),
            (1, None) => return Err(refused("a passkey home needs the passkey's PRF output")),
            _ => return Err(refused("a kit holds at most one passkey piece")),
        }
        if let Some(passkey) = passkey {
            check_name(passkey.credential)?;
        }
        let key = self
            .held_vault_key()
            .ok_or_else(|| refused("the vault key is not held on this handle: unlock it first"))?;
        let vault_id = self.vault_key_vault_id();
        let commitment = key.commitment(&vault_id);
        let store = self.this_machine_piece_store(&issue.homes)?;
        let (only_machine, me) = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            let state = STATE
                .get(&self.store, &txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?;
            if commitment != state.commitment {
                return Err(refused(
                    "the held key is not the one this vault's commitment names",
                ));
            }
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let me = crate::identity::read_machine_id_in_txn(self, &txn)?;
            let others = fold
                .machines
                .keys()
                .any(|machine| Some(*machine) != me && fold.trusted_machine(*machine).is_some());
            (!others, me)
        };
        if issue.vault_id != vault_id {
            return Err(refused("the kit names another vault"));
        }
        let homes = resolve_homes(&issue.homes, me)?;
        let kit = issue_vault_key_kit(
            &self.config.privacy,
            &KitIssue {
                vault_id,
                homes,
                passphrase: issue.passphrase,
                cost: issue.cost,
                only_machine,
            },
            key.guarded_bytes(),
        )
        .map_err(kit_refused)?;
        let manifest = kit.manifest().clone();
        let mut pieces = kit.into_pieces();
        let point = match passkey {
            Some(passkey) => {
                let at = pieces
                    .iter()
                    .position(|piece| piece.home() == Some(&PieceHome::Passkey))
                    .ok_or_else(|| refused("the kit drew no passkey piece"))?;
                let piece = pieces.remove(at);
                let kind = kit_point_kind(manifest.kit_id, passkey.credential);
                let envelope = seal_kit_point(&vault_id, &commitment, &kind, passkey, &piece)?;
                Some((kind, envelope))
            }
            None => None,
        };
        Ok(DrawnVaultKeyKit {
            vault_id,
            commitment,
            manifest,
            pieces,
            point,
            store,
        })
    }

    /// Stores a passkey piece's `kit_point` wrap, its kind and envelope
    /// `point`, in the caller's write, replacing one of its id: under any
    /// recovery preset, as it opens a piece and never the key. The key it
    /// was sealed beside, by `commitment`, must still be the vault's. A
    /// sealed vault's mirror is staged first ([`WrapTransition`]).
    pub(super) fn put_kit_point_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        transition: &WrapTransition<'_>,
        commitment: &[u8; 32],
        point: (VaultKeyWrapKind, Vec<u8>),
    ) -> Result<()> {
        let state = STATE
            .get(&self.store, txn, &())?
            .ok_or_else(|| refused("the vault has no data key"))?;
        if state.commitment != *commitment {
            return Err(refused("this handle holds another vault key"));
        }
        let (kind, envelope) = point;
        let stored = StoredWrap {
            info: VaultKeyWrapInfo {
                id: kind.id(),
                kind,
                created_at: self.instant_in_txn(txn)?.secs(),
            },
            envelope,
        };
        transition.stage(|| self.staged_wraps_in_txn(txn, Some(&stored)))?;
        WRAPS.put(&self.store, txn, &stored.info.id, &stored)?;
        Ok(())
    }

    /// Unlocks the vault data key with the data-key kit's pieces: two, or one
    /// and the kit passphrase, bound to `vault_id`, the id the owner names.
    /// The key they rebuild is held only when `vault_id` is this vault's and
    /// the key is the one the vault's commitment names. No wrap opens and
    /// none is needed: a vault restored from an artifact opens on the kit as
    /// on a wrap it carries. This machine's own piece of the kit, when it
    /// keeps one, joins `pieces` (FIX 2063).
    ///
    /// # Errors
    ///
    /// A vault with no data key; another vault's id; every kit refusal by its
    /// fixed reason, never piece bytes; and a key the commitment does not
    /// name.
    pub fn unlock_vault_key_with_kit(
        &self,
        vault_id: &[u8; 32],
        pieces: &[KitPiece],
        passphrase: Option<&KitPassphrase>,
    ) -> Result<()> {
        self.unlock_vault_key_with_kit_pieces(vault_id, pieces, passphrase, None)
    }

    /// [`Self::unlock_vault_key_with_kit`], with the owner's synced passkey
    /// as one piece (census L10-18): the piece the vault's `kit_point` wrap
    /// of its name seals joins `pieces`, of the kit they name, or with none,
    /// of the newest such wrap. The passkey alone never opens the key: a
    /// second piece or the kit passphrase must join it.
    ///
    /// # Errors
    ///
    /// Those of [`Self::unlock_vault_key_with_kit`], and a passkey that
    /// opens no kit piece wrap of this vault.
    pub fn unlock_vault_key_with_kit_and_passkey(
        &self,
        vault_id: &[u8; 32],
        pieces: &[KitPiece],
        passphrase: Option<&KitPassphrase>,
        passkey: KitPasskey<'_>,
    ) -> Result<()> {
        self.unlock_vault_key_with_kit_pieces(vault_id, pieces, passphrase, Some(passkey))
    }

    fn unlock_vault_key_with_kit_pieces(
        &self,
        vault_id: &[u8; 32],
        pieces: &[KitPiece],
        passphrase: Option<&KitPassphrase>,
        passkey: Option<KitPasskey<'_>>,
    ) -> Result<()> {
        let (commitment, wraps) = {
            let txn = self.store.env.read_txn()?;
            let commitment = STATE
                .get(&self.store, &txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?
                .commitment;
            let wraps: Vec<StoredWrap> = match passkey {
                Some(_) => WRAPS
                    .scan(&self.store, &txn)?
                    .into_iter()
                    .map(|(_, stored)| stored)
                    .collect(),
                None => Vec::new(),
            };
            (commitment, wraps)
        };
        let own = self.vault_key_vault_id();
        if *vault_id != own {
            return Err(refused("the kit names another vault"));
        }
        let mut given: Vec<&KitPiece> = pieces.iter().collect();
        let sealed = match passkey {
            Some(passkey) => passkey_pieces(&own, &commitment, &wraps, passkey, &given)?,
            None => Vec::new(),
        };
        given.extend(&sealed);
        let secret = self
            .restore_kit_here(own, KitSecretKind::VaultKey, &given, passphrase)
            .map_err(kit_refused)?;
        let key = committed_key(&own, &commitment, secret)?;
        self.hold_vault_key(key);
        Ok(())
    }
}
