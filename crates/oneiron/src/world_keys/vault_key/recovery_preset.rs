//! The owner's recovery preset and the printed recovery sheet it issues
//! (CROSS-ARCH-0019 #vault-20-unlock, PQC-KIT A; census L10-18).
//!
//! `Standard` is the default: each day Face ID, a passkey or the device
//! keychain opens the vault, and every wrap kind may be added. "Nobody but
//! me" sits under More, for strict kit-only vaults and relay mode: there the
//! printed sheet alone restores the vault (L10-18-SWITCH-OFF = B). Entering
//! it, in one write, issues the sheet, removes the password and passkey
//! wraps, and retires every escrow recipient but the world kit's. While it
//! holds, every door that adds a wrap refuses those kinds in its own
//! transaction, a presented escrow capsule opens nothing on the live vault,
//! and no delivered key is admitted. A device wrap stays: it opens only on
//! its own install. The data-key kit and the world kit need two pieces, so
//! they stay too.
//!
//! The switch "any 2 pieces" (`NobodyButMeAnyTwo`; L10-18 PIECES = A,
//! FLIP = A, OLD-DEVICE = A): "one switch requires any 2 pieces: the
//! passkey, the sheet, a trusted person or an old device". Turning it on
//! issues a data-key kit over the owner's three homes in the same write and
//! removes the sheet's wrap too, so no single secret opens the key: two of
//! the kit's pieces do (the paper piece is the new sheet, a passkey's piece
//! rides in a `kit_point` wrap, an old device keeps an `OtherMachine` piece),
//! or one and the kit passphrase. Turning it off prints a fresh sheet; the
//! kit stays usable.
//!
//! A sealed artifact's key header carries the wraps a fresh device can open
//! and names the preset in force when it was sealed, bound to the artifact
//! by its manifest. Under "Nobody but me" the header carries no password,
//! passkey or escrow wrap, and a presented escrow capsule opens nothing, as
//! the data key does not rotate: a capsule kept from before the change would
//! otherwise open what was sealed after it. A sheet, piece or capsule handed
//! out before a change still opens the artifacts sealed before it.
//!
//! The sheet, or the kit's pieces, reach the owner before the write that
//! removes the old wraps ([`Vault::set_recovery_preset_as`],
//! [`Vault::set_recovery_preset_any_two_as`]), so a failed hand-over leaves
//! the old ways in place, and a mirror rewrite that fails after the commit
//! is answered as pending, never as an error that drops the secret.

use super::kit::IssuedVaultKeyKit;
use super::*;
use crate::config::VaultDataKeyCustody;
use crate::store::recovery_kit::{KitIssue, KitPassphrase, KitPiece};
use crate::world_keys::{WORLD_KIT_ESCROW, derive_guarded, os_fill};

const SHEET_KEK_CONTEXT: &str = "oneiron/vault-key-sheet/v1";
const SHEET_CHECK_CONTEXT: &str = "oneiron/vault-key-sheet/v1/check";
const SHEET_SECRET_LEN: usize = 32;
const SHEET_CHECK_LEN: usize = 3;
const SHEET_CODE_BYTES: usize = SHEET_SECRET_LEN + SHEET_CHECK_LEN;
const SHEET_SYMBOLS: usize = SHEET_CODE_BYTES * 8 / 5;
const SHEET_GROUP: usize = 4;
/// The kit code's Crockford alphabet (`oneiron_store::recovery_kit`).
const SHEET_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const PRESET_PASSWORD: &str = "recovery preset \"Nobody but me\" refuses a vault password: the printed sheet restores the vault";
const PRESET_PASSKEY: &str = "recovery preset \"Nobody but me\" refuses a passkey wrap: the printed sheet restores the vault";
const PRESET_ESCROW: &str =
    "recovery preset \"Nobody but me\" refuses an escrow wrap: nobody but the owner holds a piece";
const PRESET_CAPSULE: &str = "recovery preset \"Nobody but me\" refuses a presented escrow capsule: nobody but the owner holds a piece";
const ANY_TWO_PASSWORD: &str = "recovery preset \"Nobody but me\" with \"any 2 pieces\" refuses a vault password: two kit pieces restore the vault";
const ANY_TWO_PASSKEY: &str = "recovery preset \"Nobody but me\" with \"any 2 pieces\" refuses a passkey wrap: the passkey is one kit piece";
const ANY_TWO_NEEDS_KIT: &str =
    "turning on \"any 2 pieces\" issues the kit its pieces come from: name the kit's three homes";
const KIT_POINT_ADDED: &str =
    "a passkey's kit piece wrap is written by issuing its kit, not added as a wrap";
const PRESET_DELIVERED: &str = "recovery preset \"Nobody but me\" refuses a delivered data key: nobody but the owner holds the key";
const PRESET_ESCROW_OPENED: &str = "recovery preset \"Nobody but me\" refuses a key an escrow recipient opened from an earlier backup: nobody but the owner holds a piece";
const PRESET_ANSWER_DEVICE: &str = "recovery preset \"Nobody but me\" is entered over the owner API only while this install's device wrap stays, as the answer alone carries the sheet: add it, or set the preset with the CLI, which keeps the sheet in a file first";
const PRESET_CUSTODY: &str = "recovery preset \"Nobody but me\" needs an owner-held data key, not a \
     host-managed or supervisor-delivered one";
const SHEET_ADDED: &str = "the printed sheet is issued by the recovery preset, not added as a wrap";
const WORLD_KIT_LABEL: &str = "the world kit's escrow wrap is written by confirming a kit";
const SHEET_MALFORMED: &str = "a recovery sheet's code is 56 letters and digits";
const SHEET_TYPO: &str = "the recovery sheet's code has a typo: its check does not match";
const PRESET_RACED: &str = "the recovery preset changed while the sheet was drawn: set it again";
const KIT_ONLY_NEEDS_KIT: &str = "switching to Nobody but me needs your recovery kit, so the key the \
                                  recovery box could release is replaced; bring the kit; nothing was \
                                  written";
const KIT_NOT_THIS_VAULTS: &str = "this recovery kit does not hold this vault's live way back; nothing \
                                   was written";
const PRESET_OWNER_ONLY: &str =
    "setting the recovery preset is the owner's to do; no Grant action names it";

/// Who writes an escrow wrap, typed by the writing path and never read from
/// its label: the world kit's confirm, or any other recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::world_keys) enum EscrowOrigin {
    WorldKit,
    Recipient,
}

/// Refuses a wrap of `kind` from `origin` that `preset` rules out. The world
/// kit's label is its confirm's alone in every preset, so the label a wrap
/// carries can be trusted when the preset is entered; a sheet is issued
/// only by entering the preset.
pub(super) fn admit_wrap(
    preset: RecoveryPreset,
    kind: &VaultKeyWrapKind,
    origin: EscrowOrigin,
) -> Result<()> {
    let any_two = preset == RecoveryPreset::NobodyButMeAnyTwo;
    match (kind, origin) {
        (VaultKeyWrapKind::Sheet, _) => Err(refused(SHEET_ADDED)),
        (VaultKeyWrapKind::KitPoint { .. }, _) => Err(refused(KIT_POINT_ADDED)),
        (VaultKeyWrapKind::Escrow { label }, EscrowOrigin::Recipient)
            if label == WORLD_KIT_ESCROW =>
        {
            Err(refused(WORLD_KIT_LABEL))
        }
        _ if preset == RecoveryPreset::Standard => Ok(()),
        (VaultKeyWrapKind::Device { .. }, _)
        | (VaultKeyWrapKind::Escrow { .. }, EscrowOrigin::WorldKit) => Ok(()),
        (VaultKeyWrapKind::Password, _) if any_two => Err(refused(ANY_TWO_PASSWORD)),
        (VaultKeyWrapKind::Password, _) => Err(refused(PRESET_PASSWORD)),
        (VaultKeyWrapKind::Passkey { .. }, _) if any_two => Err(refused(ANY_TWO_PASSKEY)),
        (VaultKeyWrapKind::Passkey { .. }, _) => Err(refused(PRESET_PASSKEY)),
        (VaultKeyWrapKind::Escrow { .. }, EscrowOrigin::Recipient) => Err(refused(PRESET_ESCROW)),
    }
}

/// Refuses a presented escrow capsule under "Nobody but me".
pub(super) fn admit_presented_capsule(preset: RecoveryPreset) -> Result<()> {
    if preset.is_nobody_but_me() {
        return Err(refused(PRESET_CAPSULE));
    }
    Ok(())
}

/// Refuses, under "Nobody but me", a key an escrow recipient opened (a
/// carried escrow wrap but the world kit's, or a presented capsule) from an
/// earlier artifact: the preset retired every such recipient, and the data
/// key does not rotate (review of #7766, round 2).
pub(super) fn admit_escrow_opened_key(preset: RecoveryPreset) -> Result<()> {
    if preset.is_nobody_but_me() {
        return Err(refused(PRESET_ESCROW_OPENED));
    }
    Ok(())
}

impl VaultKeyUnlock<'_> {
    /// Whether this unlock reaches the key through an escrow recipient that
    /// "Nobody but me" retires: an escrow wrap but the world kit's, or a
    /// presented capsule.
    pub(crate) fn is_escrow_recipient_unlock(&self) -> bool {
        match self {
            Self::EscrowCapsule { .. } => true,
            Self::Escrow { label, .. } => *label != WORLD_KIT_ESCROW,
            _ => false,
        }
    }
}

/// Refuses a delivered data key under "Nobody but me".
pub(super) fn admit_delivered_key(preset: RecoveryPreset) -> Result<()> {
    if preset.is_nobody_but_me() {
        return Err(refused(PRESET_DELIVERED));
    }
    Ok(())
}

/// The printed recovery sheet's secret: 32 random bytes. It is typed back as
/// a 56-symbol code ([`Self::code`]), whose last 3 bytes are a check. The
/// wrap's KEK is `BLAKE3-derive_key("oneiron/vault-key-sheet/v1", secret ‖
/// vault id)`, with no Argon2: the secret is random, not a password. Debug
/// never prints it; drop wipes it.
pub struct RecoverySheet(Zeroizing<[u8; SHEET_SECRET_LEN]>);

impl std::fmt::Debug for RecoverySheet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoverySheet(<redacted>)")
    }
}

impl RecoverySheet {
    fn generate() -> Result<Self> {
        let mut secret = Zeroizing::new([0u8; SHEET_SECRET_LEN]);
        os_fill(&mut secret[..])?;
        Ok(Self(secret))
    }

    /// The code to print: Crockford base32 of the secret and its check, 56
    /// symbols in groups of 4. Explicit, for showing or printing it on the
    /// owner's device.
    pub fn code(&self) -> Zeroizing<String> {
        let mut bytes = Zeroizing::new([0u8; SHEET_CODE_BYTES]);
        bytes[..SHEET_SECRET_LEN].copy_from_slice(&self.0[..]);
        bytes[SHEET_SECRET_LEN..].copy_from_slice(&sheet_check(&self.0));
        let mut text = Zeroizing::new(String::with_capacity(
            SHEET_SYMBOLS + SHEET_SYMBOLS / SHEET_GROUP,
        ));
        let (mut acc, mut bits, mut symbols) = (0u16, 0u32, 0usize);
        for byte in bytes.as_slice() {
            acc = (acc << 8) | u16::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                if symbols > 0 && symbols % SHEET_GROUP == 0 {
                    text.push('-');
                }
                text.push(char::from(SHEET_ALPHABET[usize::from((acc >> bits) & 31)]));
                symbols += 1;
            }
            acc &= (1 << bits) - 1;
        }
        text
    }

    /// Reads a typed sheet code back: case, `-` and whitespace are ignored,
    /// `O` reads as `0`, and `I` and `L` read as `1`. A failed check is a
    /// typo.
    pub fn from_code(text: &str) -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; SHEET_CODE_BYTES]);
        let (mut acc, mut bits, mut symbols, mut at) = (0u16, 0u32, 0usize, 0usize);
        for c in text.chars() {
            let value = match c.to_ascii_uppercase() {
                c if c == '-' || c.is_whitespace() => continue,
                'O' => 0,
                'I' | 'L' => 1,
                c => SHEET_ALPHABET
                    .iter()
                    .position(|symbol| char::from(*symbol) == c)
                    .ok_or_else(|| refused(SHEET_MALFORMED))? as u16,
            };
            symbols += 1;
            if symbols > SHEET_SYMBOLS {
                return Err(refused(SHEET_MALFORMED));
            }
            acc = (acc << 5) | value;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                bytes[at] = (acc >> bits) as u8;
                at += 1;
                acc &= (1 << bits) - 1;
            }
        }
        if symbols != SHEET_SYMBOLS {
            return Err(refused(SHEET_MALFORMED));
        }
        let mut secret = Zeroizing::new([0u8; SHEET_SECRET_LEN]);
        secret.copy_from_slice(&bytes[..SHEET_SECRET_LEN]);
        if sheet_check(&secret)[..] != bytes[SHEET_SECRET_LEN..] {
            return Err(refused(SHEET_TYPO));
        }
        Ok(Self(secret))
    }

    /// The sheet wrap's KEK for the vault `vault_id`.
    pub(super) fn kek(&self, vault_id: &[u8; 32]) -> Kek {
        Kek::from_zeroizing(derive_guarded(SHEET_KEK_CONTEXT, &[&self.0[..], vault_id]))
    }
}

/// A sheet code's check: the first 3 bytes of `BLAKE3-derive_key` of the
/// secret. It catches a typo; it is no secret.
fn sheet_check(secret: &[u8; SHEET_SECRET_LEN]) -> [u8; SHEET_CHECK_LEN] {
    let mut check = [0; SHEET_CHECK_LEN];
    check.copy_from_slice(&blake3::derive_key(SHEET_CHECK_CONTEXT, secret)[..SHEET_CHECK_LEN]);
    check
}

/// Step 3 of a preset change's [`WrapTransition`], for an answer that hands
/// over a secret: a mirror rewrite that fails after the commit is logged and
/// answered as pending, since an error would drop the committed change and
/// its secret. The next sealed open repairs the mirror.
fn finish_or_pending(transition: WrapTransition<'_>) -> bool {
    match transition.finish() {
        Ok(()) => false,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a recovery preset change committed; its page-seal mirror is pending"
            );
            true
        }
    }
}

/// How the printed sheet reaches the owner when a preset change draws one.
enum SheetHandover {
    /// `keep_sheet` kept it durably before the write (the CLI's file).
    Kept,
    /// Only the answer carries it: entering "Nobody but me" needs this
    /// install's device wrap, `device_wrap`, to stay; `None` when this
    /// install's keystore holds no slot for one.
    Answer { device_wrap: Option<String> },
}

/// A kit door's prepared authority rotation: the kit's restored seed and the
/// live generation it held on the pre-write read snapshot, if any. The write
/// finds the live generation again in its txn and rotates from it; no seed
/// is handed out by the switch.
struct PreparedRotation {
    seed: crate::world_keys::RecoveryRootSeed,
    live_pre: Option<u32>,
}

/// What setting the recovery preset did.
#[derive(Debug)]
pub struct RecoveryPresetChange {
    /// The preset before the change.
    pub previous: RecoveryPreset,
    /// The preset in force now.
    pub preset: RecoveryPreset,
    /// The printed sheet, when the change entered "Nobody but me" with its
    /// switch off. Shown once; the vault keeps only its wrap.
    pub sheet: Option<RecoverySheet>,
    /// The wraps the change removed: the password, each passkey's and each
    /// escrow wrap but the world kit's, and with "any 2 pieces" the sheet's.
    pub removed: Vec<VaultKeyWrapInfo>,
    /// The receipt of each escrow recipient the change retired.
    pub retired: Vec<EscrowRetirement>,
    /// The change committed but the sealed vault's page-seal mirror rewrite
    /// failed after it: the change stands, and the next sealed open repairs
    /// the mirror.
    pub mirror_pending: bool,
    /// The change committed to `Standard` but the recovery box's release did
    /// not go through: the preset stands, and the box still holds kit-only.
    /// Never an error; only the switch back sets it. The marker
    /// [`RecoveryBoxHoldPending`] stays set, and a managed boot resends the hold.
    pub box_release_pending: bool,
}

/// What turning on "any 2 pieces" did: the preset's change, and the kit its
/// pieces come from, handed over once.
#[derive(Debug)]
pub struct RecoveryPresetAnyTwoChange {
    pub change: RecoveryPresetChange,
    pub kit: IssuedVaultKeyKit,
}

/// The recovery box's hold for kit-only (BOX-KIT-ONLY-HOLD = A): the engine
/// calls it through this trait, and OPUS-WAYBACK-BOX builds the HTTP
/// implementation on the server. Target kit-only calls `hold_kit_only(true)`
/// after the no-write checks pass and before the write txn opens; its error
/// refuses the switch with nothing written. Target `Standard` calls
/// `hold_kit_only(false)` after the commit; its failure answers
/// [`RecoveryPresetChange::box_release_pending`], never an error. A switch
/// refused before the hold makes no hold call; one that fails after it sends
/// `hold_kit_only(false)` once, best-effort, while the vault still reads
/// `Standard`, and answers the first error. The marker [`RecoveryBoxHoldPending`]
/// stays set, and a managed boot resends the hold.
pub trait RecoveryBoxHold {
    /// Holds kit-only (`true`) or releases it (`false`) on the recovery box.
    fn hold_kit_only(&self, kit_only: bool) -> Result<()>;
}

/// No recovery box: every hold answers `Ok`. The preset doors' callers pass
/// it until OPUS-WAYBACK-BOX wires the HTTP hold.
pub struct NoRecoveryBox;

impl RecoveryBoxHold for NoRecoveryBox {
    fn hold_kit_only(&self, _kit_only: bool) -> Result<()> {
        Ok(())
    }
}

/// Whether the recovery box's kit-only hold may not match the recovery preset: set before a
/// switch into 'Nobody but me' asks the box to hold, and by a switch out of it; cleared once
/// the box answered. A managed boot resends the hold that matches the preset when it is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryBoxHoldPending {
    /// The hold the switch asked for.
    pub target_kit_only: bool,
    /// A fresh random id per switch, compared by the clear.
    pub attempt: u64,
}

/// A fresh random attempt id for one switch's box-hold-pending marker, from
/// the OS CSPRNG. Never "stored + 1": after a delete a counter restarts and
/// could repeat an attempt a heal still holds.
fn fresh_box_hold_attempt() -> Result<u64> {
    let mut bytes = [0u8; 8];
    os_fill(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

impl Vault {
    /// The owner's recovery preset: `Standard` while the vault has no data
    /// key.
    pub fn recovery_preset(&self) -> Result<RecoveryPreset> {
        let txn = self.store.env.read_txn()?;
        self.recovery_preset_in_txn(&txn)
    }

    /// [`Self::recovery_preset`] in the caller's transaction (a read or a
    /// write): `Standard` while the vault has no data key. The root door
    /// refuses the box's released key under kit-only in its writer through
    /// it, so the check counts.
    pub(crate) fn recovery_preset_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<RecoveryPreset> {
        Ok(STATE
            .get(&self.store, txn, &())?
            .map_or(RecoveryPreset::Standard, |state| state.recovery))
    }

    /// The box-hold-pending marker, if set: the hold a switch asked for and its attempt. A
    /// managed boot resends the hold that matches the preset when it is set.
    pub fn recovery_box_hold_pending(&self) -> Result<Option<RecoveryBoxHoldPending>> {
        let txn = self.store.env.read_txn()?;
        BOX_HOLD_PENDING.get(&self.store, &txn, &())
    }

    /// Clears the box-hold-pending marker only when its stored attempt equals `attempt`; true
    /// when it deleted. A heal never clears the marker of a switch that started while it ran.
    pub fn clear_recovery_box_hold_pending(&self, attempt: u64) -> Result<bool> {
        self.with_write_txn(|txn| self.clear_recovery_box_hold_pending_in_txn(txn, attempt))
    }

    /// [`Self::recovery_box_hold_pending`]'s write, in the caller's write txn.
    pub(crate) fn put_recovery_box_hold_pending_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        pending: &RecoveryBoxHoldPending,
    ) -> Result<()> {
        BOX_HOLD_PENDING.put(&self.store, txn, &(), pending)
    }

    /// [`Self::clear_recovery_box_hold_pending`] in the caller's write txn.
    pub(crate) fn clear_recovery_box_hold_pending_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: u64,
    ) -> Result<bool> {
        match BOX_HOLD_PENDING.get(&self.store, txn, &())? {
            Some(stored) if stored.attempt == attempt => {
                BOX_HOLD_PENDING.delete(&self.store, txn, &())
            }
            _ => Ok(false),
        }
    }

    /// Sets the owner's recovery preset, rechecked in the transaction that
    /// stores it. Entering "Nobody but me" needs the held key and an
    /// owner-held key custody: a host-managed or supervisor-delivered key is
    /// the host's to recover, which the preset rules out. It draws the
    /// printed sheet and hands it to `keep_sheet` before any write: the
    /// caller keeps it durably (a synced file), and a failed keep changes
    /// nothing; a caller whose answer alone carries the sheet uses
    /// [`Vault::set_recovery_preset_answered_as`]. Then, in one write, it
    /// adds the sheet's wrap, removes the password and passkey wraps, and
    /// retires every escrow recipient but the world kit's, each with its
    /// receipt; the answer carries the sheet too. Coming from "any 2 pieces",
    /// the kit stays usable beside the fresh sheet (FLIP = A). Leaving it
    /// changes no wrap; any other wrap is added through the ordinary doors
    /// after. The preset already in force changes nothing and draws no sheet.
    /// A mirror rewrite that fails after the commit is answered as
    /// `mirror_pending`. "Any 2 pieces" is turned on with its kit:
    /// [`Self::set_recovery_preset_any_two_as`].
    pub fn set_recovery_preset_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        preset: RecoveryPreset,
        keep_sheet: impl FnOnce(&RecoverySheet) -> Result<()>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<RecoveryPresetChange> {
        // No rotation without the kit: the surface never reaches an enrol.
        let authority = crate::authority::ActAuthority::Owner(
            owner.clone(),
            crate::authority::ActSurface::ThisInstall,
        );
        self.set_recovery_preset_handed_over(
            &authority,
            preset,
            keep_sheet,
            SheetHandover::Kept,
            None,
            box_hold,
        )
    }

    /// [`Vault::set_recovery_preset_as`] for a caller whose answer is the
    /// sheet's only hand-over, as the owner API's is: nothing is kept before
    /// the write. Entering "Nobody but me" then needs this install's device
    /// wrap, its keystore slot held, and the preset's own write refuses the
    /// change when the wrap is gone. After a lost answer and a restart the
    /// device reopens the key, and leaving and entering the preset again
    /// issues a new sheet (review of #7766, round 2).
    pub fn set_recovery_preset_answered_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        preset: RecoveryPreset,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<RecoveryPresetChange> {
        let device_wrap = self.device_wrap_held_here()?;
        let authority = crate::authority::ActAuthority::Owner(
            owner.clone(),
            crate::authority::ActSurface::ThisInstall,
        );
        self.set_recovery_preset_handed_over(
            &authority,
            preset,
            |_| Ok(()),
            SheetHandover::Answer { device_wrap },
            None,
            box_hold,
        )
    }

    /// [`Vault::set_recovery_preset_as`] with the recovery kit: `pieces` and
    /// `passphrase` read as [`Vault::confirm_world_kit`] reads them. Entering
    /// "Nobody but me" from `Standard` while a generation is live enrols the
    /// next generation and revokes the live one in the same write as the
    /// preset change; the kit's generation must be the live one, else
    /// `KIT_NOT_THIS_VAULTS`. Kit-only to kit-only, re-entering the same
    /// preset and the switch back change no roster. No seed is handed out.
    pub fn set_recovery_preset_with_kit_as(
        &self,
        authority: &crate::authority::ActAuthority,
        preset: RecoveryPreset,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
        keep_sheet: impl FnOnce(&RecoverySheet) -> Result<()>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<RecoveryPresetChange> {
        if matches!(authority, crate::authority::ActAuthority::Agent(_)) {
            return Err(crate::authority::authority_refused(PRESET_OWNER_ONLY));
        }
        let (rotation, any_live) = self.prepare_kit_rotation(pieces, passphrase)?;
        if self.recovery_preset()? == RecoveryPreset::Standard
            && preset.is_nobody_but_me()
            && rotation.live_pre.is_none()
            && any_live
        {
            return Err(crate::authority::authority_refused(KIT_NOT_THIS_VAULTS));
        }
        self.set_recovery_preset_handed_over(
            authority,
            preset,
            keep_sheet,
            SheetHandover::Kept,
            Some(rotation),
            box_hold,
        )
    }

    /// [`Vault::set_recovery_preset_with_kit_as`] for a caller whose answer is
    /// the sheet's only hand-over, as the owner API's is: entering needs this
    /// install's device wrap to stay, as
    /// [`Vault::set_recovery_preset_answered_as`] needs it.
    pub fn set_recovery_preset_answered_with_kit_as(
        &self,
        authority: &crate::authority::ActAuthority,
        preset: RecoveryPreset,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<RecoveryPresetChange> {
        if matches!(authority, crate::authority::ActAuthority::Agent(_)) {
            return Err(crate::authority::authority_refused(PRESET_OWNER_ONLY));
        }
        let device_wrap = self.device_wrap_held_here()?;
        let (rotation, any_live) = self.prepare_kit_rotation(pieces, passphrase)?;
        if self.recovery_preset()? == RecoveryPreset::Standard
            && preset.is_nobody_but_me()
            && rotation.live_pre.is_none()
            && any_live
        {
            return Err(crate::authority::authority_refused(KIT_NOT_THIS_VAULTS));
        }
        self.set_recovery_preset_handed_over(
            authority,
            preset,
            |_| Ok(()),
            SheetHandover::Answer { device_wrap },
            Some(rotation),
            box_hold,
        )
    }

    /// The id of this install's device wrap when this install's keystore
    /// holds its slot, read without creating one; `None` with no keystore.
    fn device_wrap_held_here(&self) -> Result<Option<String>> {
        let Ok(keystore) = self.device_keystore() else {
            return Ok(None);
        };
        let install = self.prepare_install_signing()?;
        let held = keystore
            .get(&self.vault_key_slot(install))
            .map_err(crate::world_keys::machine::keystore_error)?
            .is_some();
        Ok(held.then(|| {
            VaultKeyWrapKind::Device {
                install: install.to_hex(),
            }
            .id()
        }))
    }

    fn set_recovery_preset_handed_over(
        &self,
        authority: &crate::authority::ActAuthority,
        preset: RecoveryPreset,
        keep_sheet: impl FnOnce(&RecoverySheet) -> Result<()>,
        handover: SheetHandover,
        rotation: Option<PreparedRotation>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<RecoveryPresetChange> {
        let owner = match authority {
            crate::authority::ActAuthority::Owner(owner, _) => owner,
            crate::authority::ActAuthority::Agent(_) => {
                return Err(crate::authority::authority_refused(PRESET_OWNER_ONLY));
            }
        };
        let current = self.recovery_preset()?;
        // Entering kit-only without the kit while a generation is live is
        // refused before anything is drawn or kept. The write checks again.
        if rotation.is_none() && current == RecoveryPreset::Standard && preset.is_nobody_but_me() {
            let txn = self.store.env.read_txn()?;
            if self.any_live_recovery_authority_in_txn(&txn)? {
                return Err(crate::authority::authority_refused(KIT_ONLY_NEEDS_KIT));
            }
        }
        let issue = match preset {
            RecoveryPreset::NobodyButMeAnyTwo => return Err(refused(ANY_TWO_NEEDS_KIT)),
            RecoveryPreset::NobodyButMe if current != preset => {
                // Custody first, then the held key, as the draw checked them
                // before it took the key as an argument.
                if !matches!(self.data_key_custody(), VaultDataKeyCustody::OwnerHeldLocal) {
                    return Err(refused(PRESET_CUSTODY));
                }
                let held = self
                    .held_vault_key()
                    .ok_or_else(|| refused("unlock the vault key first"))?;
                Some(self.draw_recovery_sheet(&held, keep_sheet)?)
            }
            RecoveryPreset::NobodyButMe | RecoveryPreset::Standard => None,
        };
        // Target kit-only writes the box-hold-pending marker in its own write
        // before it holds the box, after the no-write checks pass; the switch's
        // own write clears it, and a failure after the hold releases the box
        // again on a vault still on `Standard`. A hold error refuses with the
        // marker set for a managed boot to heal.
        let held_box = preset.is_nobody_but_me();
        let hold_attempt = if held_box {
            let attempt = fresh_box_hold_attempt()?;
            let pending = RecoveryBoxHoldPending {
                target_kit_only: true,
                attempt,
            };
            self.with_write_txn(|txn| self.put_recovery_box_hold_pending_in_txn(txn, &pending))?;
            box_hold.hold_kit_only(true)?;
            Some(attempt)
        } else {
            None
        };
        // Leaving kit-only draws its attempt before the write; the write puts
        // the marker when it actually leaves, in the same txn as the preset.
        let leave_attempt = if preset == RecoveryPreset::Standard {
            Some(fresh_box_hold_attempt()?)
        } else {
            None
        };
        let transition = self.release_box_hold_on_failure(
            self.begin_wrap_transition(),
            held_box,
            hold_attempt,
            box_hold,
        )?;
        let written = self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            if let Some(attempt) = hold_attempt {
                self.clear_recovery_box_hold_pending_in_txn(txn, attempt)?;
            }
            let mut state = STATE
                .get(&self.store, txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?;
            let mut change = RecoveryPresetChange {
                previous: state.recovery,
                preset,
                sheet: None,
                removed: Vec::new(),
                retired: Vec::new(),
                mirror_pending: false,
                box_release_pending: false,
            };
            if state.recovery == preset {
                return Ok((change, None));
            }
            // Rotation happens iff Standard goes to kit-only and a generation
            // is live. Kit-only to kit-only and the switch back change no
            // roster.
            if state.recovery == RecoveryPreset::Standard && preset.is_nobody_but_me() {
                self.maybe_rotate_recovery_authority_in_txn(txn, authority, &rotation)?;
            }
            if preset == RecoveryPreset::NobodyButMe {
                let Some((_, commitment, envelope)) = &issue else {
                    return Err(refused(PRESET_RACED));
                };
                if state.commitment != *commitment {
                    return Err(refused("this handle holds another vault key"));
                }
                if let SheetHandover::Answer { device_wrap } = &handover {
                    let stays = match device_wrap {
                        Some(id) => WRAPS.get(&self.store, txn, id)?.is_some(),
                        None => false,
                    };
                    if !stays {
                        return Err(refused(PRESET_ANSWER_DEVICE));
                    }
                }
                (change.removed, change.retired) = self.enter_nobody_but_me_in_txn(
                    txn,
                    &transition,
                    preset,
                    Some((VaultKeyWrapKind::Sheet, envelope.clone())),
                )?;
            }
            // Leaving kit-only sets the marker in the same txn, before the STATE
            // put; staying on Standard writes no marker.
            let mut leave_marker: Option<u64> = None;
            if preset == RecoveryPreset::Standard && state.recovery.is_nobody_but_me() {
                if let Some(attempt) = leave_attempt {
                    self.put_recovery_box_hold_pending_in_txn(
                        txn,
                        &RecoveryBoxHoldPending {
                            target_kit_only: false,
                            attempt,
                        },
                    )?;
                    leave_marker = Some(attempt);
                }
            }
            state.recovery = preset;
            // [VAULT-DATA-KEY-ROTATION]: its `start_data_key_generation_in_txn`
            // will run last in this write, after the STATE put.
            STATE.put(&self.store, txn, &(), &state)?;
            Ok((change, leave_marker))
        });
        let (mut change, leave_marker) =
            self.release_box_hold_on_failure(written, held_box, hold_attempt, box_hold)?;
        change.mirror_pending = finish_or_pending(transition);
        // Target Standard releases the box after the commit; a failure is
        // answered as pending, never an error. An `Ok` release clears the
        // leaving marker (a failure there is logged only); an `Err` keeps it.
        if preset == RecoveryPreset::Standard {
            match box_hold.hold_kit_only(false) {
                Ok(()) => {
                    if let Some(attempt) = leave_marker {
                        if let Err(error) = self.clear_recovery_box_hold_pending(attempt) {
                            tracing::warn!(
                                kind = ?error.kind(),
                                "a recovery preset change committed to Standard and released the box; clearing its marker did not go through"
                            );
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "a recovery preset change committed to Standard; the recovery box release is pending"
                    );
                    change.box_release_pending = true;
                }
            }
        }
        if change.previous != change.preset {
            change.sheet = issue.map(|(sheet, _, _)| sheet);
        }
        Ok(change)
    }

    /// Draws a printed sheet for `key`, its wrap sealed, and hands it to
    /// `keep_sheet` before any write. The sheet, the commitment of the key it
    /// opens and its wrap's envelope. The caller checks an owner-held key
    /// custody and passes the held key; the commitment checks keep comparing
    /// the held key's commitment.
    fn draw_recovery_sheet(
        &self,
        key: &VaultDataKey,
        keep_sheet: impl FnOnce(&RecoverySheet) -> Result<()>,
    ) -> Result<(RecoverySheet, [u8; 32], Vec<u8>)> {
        let vault_id = *self.vault_id().as_bytes();
        let commitment = key.commitment(&vault_id);
        let sheet = RecoverySheet::generate()?;
        let envelope = seal_wrap(
            &vault_id,
            &commitment,
            &VaultKeyWrapKind::Sheet,
            &WrapSecret::Kek(sheet.kek(&vault_id)),
            key,
        )?;
        keep_sheet(&sheet)?;
        Ok((sheet, commitment, envelope))
    }

    /// Restores the kit's seed from `pieces` and `passphrase` (as
    /// [`Vault::confirm_world_kit`] reads them: two pieces, or one and the
    /// passphrase) and finds the live generation it held on a read snapshot,
    /// deriving the next generation pre-write. No store or keystore write.
    /// Returns the prepared rotation with whether any generation is live at
    /// all (for the wrong-kit check). The write finds the live generation
    /// again in its txn.
    fn prepare_kit_rotation(
        &self,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
    ) -> Result<(PreparedRotation, bool)> {
        let seed = self.kit_seed(pieces, passphrase)?.seed;
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold
            .vault_id
            .ok_or_else(crate::authority::invalid_authority)?;
        let live_pre = self
            .recovery_authority_generations_in_txn(&txn, &seed, &vault_id)?
            .live
            .map(|(generation, _)| generation);
        if let Some(generation) = live_pre {
            let next = generation
                .checked_add(1)
                .ok_or_else(crate::authority::invalid_authority)?;
            let _ = crate::world_keys::RecoveryAuthoritySigner::from_seed(&seed, &vault_id, next)?;
        }
        let any_live = self.any_live_recovery_authority_in_txn(&txn)?;
        Ok((PreparedRotation { seed, live_pre }, any_live))
    }

    /// Rotates the recovery authority key in the preset's write `txn`, which
    /// enters kit-only from `Standard`: with `rotation` (a kit door), the
    /// kit's generation must be the live one, else `KIT_NOT_THIS_VAULTS`,
    /// then the rotation step; without it (a kitless door), a live
    /// generation refuses `KIT_ONLY_NEEDS_KIT`. No live generation writes no
    /// roster row. Returns the new live generation, if it rotated.
    fn maybe_rotate_recovery_authority_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        authority: &crate::authority::ActAuthority,
        rotation: &Option<PreparedRotation>,
    ) -> Result<Option<u32>> {
        let Some(prepared) = rotation else {
            if self.any_live_recovery_authority_in_txn(txn)? {
                return Err(crate::authority::authority_refused(KIT_ONLY_NEEDS_KIT));
            }
            return Ok(None);
        };
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let vault_id = fold
            .vault_id
            .ok_or_else(crate::authority::invalid_authority)?;
        let found = self.recovery_authority_generations_in_txn(txn, &prepared.seed, &vault_id)?;
        match found.live {
            Some((live, _)) => {
                if prepared.live_pre.is_some_and(|before| before != live) {
                    return Err(crate::authority::authority_refused(KIT_NOT_THIS_VAULTS));
                }
                let (next, _, _) = self.rotate_recovery_authority_key_in_txn(
                    txn,
                    authority,
                    &prepared.seed,
                    live,
                )?;
                Ok(Some(next))
            }
            None => {
                if self.any_live_recovery_authority_in_txn(txn)? {
                    return Err(crate::authority::authority_refused(KIT_NOT_THIS_VAULTS));
                }
                Ok(None)
            }
        }
    }

    /// Turns on "Nobody but me" with its switch "any 2 pieces", rechecked in
    /// the transaction that stores it. Needs the held key and an owner-held
    /// key custody, as entering "Nobody but me" does. It draws the data-key
    /// kit over `issue`'s homes, keeps a `ThisMachine` home's piece here
    /// (FIX 2063) and hands the other pieces to `keep_pieces` before any
    /// write: the caller keeps them durably, and a failed keep leaves every
    /// wrap and the preset as they were. Then, in one write, it lists the
    /// kit and stores its passkey piece's `kit_point` wrap (a `Passkey`
    /// home, with `passkey`), removes the sheet, password and passkey wraps,
    /// and retires every escrow recipient but the world kit's, each with its
    /// receipt. From then on two of the pieces restore the vault, or one and
    /// the kit passphrase; an old device's piece is one of the two
    /// (OLD-DEVICE = A). The old sheet opens nothing sealed after the change
    /// (FLIP = A); what was sealed before still opens with what opened it
    /// then. With the switch already on, the new kit is issued and no other
    /// wrap changes. A mirror rewrite that fails after the commit is
    /// answered as `mirror_pending`. Entering from `Standard` while a
    /// generation is live needs the kit:
    /// [`Self::set_recovery_preset_any_two_with_kit_as`].
    ///
    /// # Errors
    ///
    /// A host-managed or supervisor-delivered key; a key this handle does
    /// not hold; a failed keep; an owner proof that no longer holds; and
    /// every refusal of [`Self::issue_vault_key_recovery_kit_with_passkey_as`].
    pub fn set_recovery_preset_any_two_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        issue: &KitIssue<'_>,
        passkey: Option<KitPasskey<'_>>,
        keep_pieces: impl FnOnce(&[KitPiece]) -> Result<()>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<RecoveryPresetAnyTwoChange> {
        // No rotation without the kit: the surface never reaches an enrol.
        let authority = crate::authority::ActAuthority::Owner(
            owner.clone(),
            crate::authority::ActSurface::ThisInstall,
        );
        self.set_recovery_preset_any_two_handed_over(
            &authority,
            issue,
            passkey,
            keep_pieces,
            None,
            box_hold,
        )
    }

    /// [`Vault::set_recovery_preset_any_two_as`] with the recovery kit:
    /// `pieces` and `passphrase` read as [`Vault::confirm_world_kit`] reads
    /// them. Entering from `Standard` while a generation is live enrols the
    /// next generation and revokes the live one in the same write; the kit's
    /// generation must be the live one, else `KIT_NOT_THIS_VAULTS`. With the
    /// switch already on, the new kit is issued and no roster changes. No
    /// seed is handed out.
    pub fn set_recovery_preset_any_two_with_kit_as(
        &self,
        authority: &crate::authority::ActAuthority,
        issue: &KitIssue<'_>,
        passkey: Option<KitPasskey<'_>>,
        pieces: &[&KitPiece],
        passphrase: Option<&KitPassphrase>,
        keep_pieces: impl FnOnce(&[KitPiece]) -> Result<()>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<RecoveryPresetAnyTwoChange> {
        if matches!(authority, crate::authority::ActAuthority::Agent(_)) {
            return Err(crate::authority::authority_refused(PRESET_OWNER_ONLY));
        }
        let (rotation, any_live) = self.prepare_kit_rotation(pieces, passphrase)?;
        if self.recovery_preset()? == RecoveryPreset::Standard
            && rotation.live_pre.is_none()
            && any_live
        {
            return Err(crate::authority::authority_refused(KIT_NOT_THIS_VAULTS));
        }
        self.set_recovery_preset_any_two_handed_over(
            authority,
            issue,
            passkey,
            keep_pieces,
            Some(rotation),
            box_hold,
        )
    }

    fn set_recovery_preset_any_two_handed_over(
        &self,
        authority: &crate::authority::ActAuthority,
        issue: &KitIssue<'_>,
        passkey: Option<KitPasskey<'_>>,
        keep_pieces: impl FnOnce(&[KitPiece]) -> Result<()>,
        rotation: Option<PreparedRotation>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<RecoveryPresetAnyTwoChange> {
        let owner = match authority {
            crate::authority::ActAuthority::Owner(owner, _) => owner,
            crate::authority::ActAuthority::Agent(_) => {
                return Err(crate::authority::authority_refused(PRESET_OWNER_ONLY));
            }
        };
        if !matches!(self.data_key_custody(), VaultDataKeyCustody::OwnerHeldLocal) {
            return Err(refused(PRESET_CUSTODY));
        }
        // Entering from Standard without the kit while a generation is live
        // is refused before anything is drawn or kept. The write checks
        // again. The target is always kit-only here.
        if rotation.is_none() && self.recovery_preset()? == RecoveryPreset::Standard {
            let txn = self.store.env.read_txn()?;
            if self.any_live_recovery_authority_in_txn(&txn)? {
                return Err(crate::authority::authority_refused(KIT_ONLY_NEEDS_KIT));
            }
        }
        let held = self
            .held_vault_key()
            .ok_or_else(|| refused("the vault key is not held on this handle: unlock it first"))?;
        let mut drawn = self.draw_vault_key_kit(&held, owner, issue, passkey)?;
        let point = drawn.point.take();
        let commitment = drawn.commitment;
        // The owner's pieces are kept before this install's slot is
        // replaced, so a failed keep leaves the earlier kit's local piece.
        drawn.keep_owner_pieces(keep_pieces)?;
        let kit = drawn.hand_over(true)?;
        let preset = RecoveryPreset::NobodyButMeAnyTwo;
        // The target is always kit-only: write the box-hold-pending marker in
        // its own write before holding the box, after the no-write checks pass;
        // the switch's own write clears it. A failure after the hold releases
        // the box again on a vault still on `Standard`.
        let attempt = fresh_box_hold_attempt()?;
        self.with_write_txn(|txn| {
            self.put_recovery_box_hold_pending_in_txn(
                txn,
                &RecoveryBoxHoldPending {
                    target_kit_only: true,
                    attempt,
                },
            )
        })?;
        box_hold.hold_kit_only(true)?;
        let transition = self.release_box_hold_on_failure(
            self.begin_wrap_transition(),
            true,
            Some(attempt),
            box_hold,
        )?;
        let written = self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            self.clear_recovery_box_hold_pending_in_txn(txn, attempt)?;
            let mut state = STATE
                .get(&self.store, txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?;
            if state.commitment != commitment {
                return Err(refused("this handle holds another vault key"));
            }
            // Rotation happens iff Standard goes to kit-only and a generation
            // is live. With the switch already on, the new kit is issued and
            // no roster changes.
            if state.recovery == RecoveryPreset::Standard {
                self.maybe_rotate_recovery_authority_in_txn(txn, authority, &rotation)?;
            }
            self.list_vault_key_kit_in_txn(txn, owner, &kit.manifest)?;
            let (removed, retired) =
                self.enter_nobody_but_me_in_txn(txn, &transition, preset, point)?;
            let change = RecoveryPresetChange {
                previous: state.recovery,
                preset,
                sheet: None,
                removed,
                retired,
                mirror_pending: false,
                box_release_pending: false,
            };
            state.recovery = preset;
            // [VAULT-DATA-KEY-ROTATION]: its `start_data_key_generation_in_txn`
            // will run last in this write, after the STATE put.
            STATE.put(&self.store, txn, &(), &state)?;
            Ok(change)
        });
        let mut change =
            self.release_box_hold_on_failure(written, true, Some(attempt), box_hold)?;
        change.mirror_pending = finish_or_pending(transition);
        Ok(RecoveryPresetAnyTwoChange { change, kit })
    }

    /// `result`, with the recovery box released first when it is an error
    /// and the door held the box for kit-only ([RECOVERY-BOX-HOLD-ORPHAN]).
    /// After `hold_kit_only(true)` answered, a failed switch (a refusal in
    /// the write, a failed commit) leaves the box holding kit-only while the
    /// vault stays as it was. So the box follows the stored preset again: a
    /// vault still on `Standard` sends `hold_kit_only(false)` once,
    /// best-effort. A vault already on kit-only (re-entering it, or turning
    /// "any 2 pieces" on) keeps the hold, and a preset that cannot be read
    /// sends nothing. After an `Ok` release the marker of `attempt` is cleared
    /// (a failure there is logged and never changes the answer); after an `Err`
    /// the marker stays, and a managed boot resends the hold. The answer stays
    /// the first error. `attempt` is `None` when no marker was written.
    fn release_box_hold_on_failure<T>(
        &self,
        result: Result<T>,
        held_box: bool,
        attempt: Option<u64>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<T> {
        if result.is_err() && held_box {
            match self.recovery_preset() {
                Ok(RecoveryPreset::Standard) => match box_hold.hold_kit_only(false) {
                    Ok(()) => {
                        if let Some(attempt) = attempt {
                            if let Err(error) = self.clear_recovery_box_hold_pending(attempt) {
                                tracing::warn!(
                                    kind = ?error.kind(),
                                    "a recovery preset switch failed after the recovery box held kit-only; the box is released but clearing its marker did not go through"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            kind = ?error.kind(),
                            "a recovery preset switch failed after the recovery box held kit-only; its release did not go through"
                        );
                    }
                },
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    "a recovery preset switch failed after the recovery box held kit-only; the preset is unreadable, so the hold stays"
                ),
            }
        }
        result
    }

    /// Unlocks the vault data key with the printed recovery sheet.
    pub fn unlock_vault_key_with_sheet(&self, sheet: &RecoverySheet) -> Result<()> {
        let kek = sheet.kek(self.vault_id().as_bytes());
        self.unlock_vault_key_with(&VaultKeyWrapKind::Sheet.id(), &UnlockSecret::Kek(kek))
    }

    /// Entering `preset`, one of "Nobody but me", in the preset's write: the
    /// wrap `adding` (its kind and sealed envelope) added, replacing one of
    /// its id; the password and passkey wraps removed, and with "any 2
    /// pieces" the sheet's; and every escrow wrap but the world kit's
    /// removed with its label retired (an earlier receipt for the label
    /// stands). A device wrap, the world kit's escrow and each kit piece's
    /// wrap stay. A sealed vault's mirror is staged first with every wrap
    /// and the one added. The removed wraps and the receipts.
    fn enter_nobody_but_me_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        transition: &WrapTransition<'_>,
        preset: RecoveryPreset,
        adding: Option<(VaultKeyWrapKind, Vec<u8>)>,
    ) -> Result<(Vec<VaultKeyWrapInfo>, Vec<EscrowRetirement>)> {
        let now = self.instant_in_txn(txn)?.secs();
        let adding = adding.map(|(kind, envelope)| StoredWrap {
            info: VaultKeyWrapInfo {
                id: kind.id(),
                kind,
                created_at: now,
            },
            envelope,
        });
        transition.stage(|| self.staged_wraps_in_txn(txn, adding.as_ref()))?;
        let mut removed = Vec::new();
        let mut retired = Vec::new();
        for (id, stored) in WRAPS.scan(&self.store, txn)? {
            let retiring = match &stored.info.kind {
                VaultKeyWrapKind::Password | VaultKeyWrapKind::Passkey { .. } => None,
                VaultKeyWrapKind::Sheet if preset == RecoveryPreset::NobodyButMeAnyTwo => None,
                VaultKeyWrapKind::Escrow { label } if label != WORLD_KIT_ESCROW => {
                    Some(label.clone())
                }
                _ => continue,
            };
            WRAPS.delete(&self.store, txn, &id)?;
            if let Some(label) = retiring {
                ESCROW_SPOOLED.delete(&self.store, txn, &id)?;
                let receipt = match ESCROW_RETIRED.get(&self.store, txn, &label)? {
                    Some(earlier) => earlier,
                    None => {
                        let receipt = EscrowRetirement {
                            receipt_id: self.store.clock.entity_id()?.to_hex(),
                            label: label.clone(),
                            removed_wrap: true,
                            retired_at: now,
                        };
                        ESCROW_RETIRED.put(&self.store, txn, &label, &receipt)?;
                        receipt
                    }
                };
                retired.push(receipt);
            }
            removed.push(stored.info);
        }
        if let Some(adding) = &adding {
            WRAPS.put(&self.store, txn, &adding.info.id, adding)?;
        }
        Ok((removed, retired))
    }
}
