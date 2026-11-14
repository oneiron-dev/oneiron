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
//! A sealed artifact's key header carries the wraps a fresh device can open
//! and names the preset in force when it was sealed, bound to the artifact
//! by its manifest. Under "Nobody but me" the header carries no password,
//! passkey or escrow wrap, and a presented escrow capsule opens nothing, as
//! the data key does not rotate: a capsule kept from before the change would
//! otherwise open what was sealed after it. A sheet, piece or capsule handed
//! out before a change still opens the artifacts sealed before it.
//!
//! The sheet reaches the owner before the write that removes the old wraps
//! ([`Vault::set_recovery_preset_as`]), so a failed hand-over leaves the old
//! ways in place, and a mirror rewrite that fails after the commit is
//! answered as pending, never as an error that drops the sheet.

use super::*;
use crate::config::VaultDataKeyCustody;
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
    match (kind, origin) {
        (VaultKeyWrapKind::Sheet, _) => Err(refused(SHEET_ADDED)),
        (VaultKeyWrapKind::Escrow { label }, EscrowOrigin::Recipient)
            if label == WORLD_KIT_ESCROW =>
        {
            Err(refused(WORLD_KIT_LABEL))
        }
        _ if preset == RecoveryPreset::Standard => Ok(()),
        (VaultKeyWrapKind::Device { .. }, _)
        | (VaultKeyWrapKind::Escrow { .. }, EscrowOrigin::WorldKit) => Ok(()),
        (VaultKeyWrapKind::Password, _) => Err(refused(PRESET_PASSWORD)),
        (VaultKeyWrapKind::Passkey { .. }, _) => Err(refused(PRESET_PASSKEY)),
        (VaultKeyWrapKind::Escrow { .. }, EscrowOrigin::Recipient) => Err(refused(PRESET_ESCROW)),
    }
}

/// Refuses a presented escrow capsule under "Nobody but me".
pub(super) fn admit_presented_capsule(preset: RecoveryPreset) -> Result<()> {
    match preset {
        RecoveryPreset::Standard => Ok(()),
        RecoveryPreset::NobodyButMe => Err(refused(PRESET_CAPSULE)),
    }
}

/// Refuses, under "Nobody but me", a key an escrow recipient opened (a
/// carried escrow wrap but the world kit's, or a presented capsule) from an
/// earlier artifact: the preset retired every such recipient, and the data
/// key does not rotate (review of #7766, round 2).
pub(super) fn admit_escrow_opened_key(preset: RecoveryPreset) -> Result<()> {
    match preset {
        RecoveryPreset::Standard => Ok(()),
        RecoveryPreset::NobodyButMe => Err(refused(PRESET_ESCROW_OPENED)),
    }
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
    match preset {
        RecoveryPreset::Standard => Ok(()),
        RecoveryPreset::NobodyButMe => Err(refused(PRESET_DELIVERED)),
    }
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

/// What setting the recovery preset did.
#[derive(Debug)]
pub struct RecoveryPresetChange {
    /// The preset before the change.
    pub previous: RecoveryPreset,
    /// The preset in force now.
    pub preset: RecoveryPreset,
    /// The printed sheet, when the change entered "Nobody but me". Shown
    /// once; the vault keeps only its wrap.
    pub sheet: Option<RecoverySheet>,
    /// The wraps the change removed: the password, each passkey's and each
    /// escrow wrap but the world kit's.
    pub removed: Vec<VaultKeyWrapInfo>,
    /// The receipt of each escrow recipient the change retired.
    pub retired: Vec<EscrowRetirement>,
    /// The change committed but the sealed vault's page-seal mirror rewrite
    /// failed after it: the change stands, and the next sealed open repairs
    /// the mirror.
    pub mirror_pending: bool,
}

impl Vault {
    /// The owner's recovery preset: `Standard` while the vault has no data
    /// key.
    pub fn recovery_preset(&self) -> Result<RecoveryPreset> {
        let txn = self.store.env.read_txn()?;
        Ok(STATE
            .get(&self.store, &txn, &())?
            .map_or(RecoveryPreset::Standard, |state| state.recovery))
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
    /// receipt; the answer carries the sheet too. Leaving it changes no
    /// wrap; any other wrap is added through the ordinary doors after. The
    /// preset already in force changes nothing and draws no sheet. A mirror
    /// rewrite that fails after the commit is answered as `mirror_pending`.
    pub fn set_recovery_preset_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        preset: RecoveryPreset,
        keep_sheet: impl FnOnce(&RecoverySheet) -> Result<()>,
    ) -> Result<RecoveryPresetChange> {
        self.set_recovery_preset_handed_over(owner, preset, keep_sheet, SheetHandover::Kept)
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
    ) -> Result<RecoveryPresetChange> {
        let device_wrap = self.device_wrap_held_here()?;
        self.set_recovery_preset_handed_over(
            owner,
            preset,
            |_| Ok(()),
            SheetHandover::Answer { device_wrap },
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
        owner: &crate::consent::AuthenticatedOwner,
        preset: RecoveryPreset,
        keep_sheet: impl FnOnce(&RecoverySheet) -> Result<()>,
        handover: SheetHandover,
    ) -> Result<RecoveryPresetChange> {
        let issue = match preset {
            RecoveryPreset::NobodyButMe if self.recovery_preset()? != preset => {
                Some(self.draw_recovery_sheet(keep_sheet)?)
            }
            RecoveryPreset::NobodyButMe | RecoveryPreset::Standard => None,
        };
        let transition = self.begin_wrap_transition()?;
        let mut change = self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
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
            };
            if state.recovery == preset {
                return Ok(change);
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
                (change.removed, change.retired) =
                    self.enter_nobody_but_me_in_txn(txn, &transition, envelope.clone())?;
            }
            state.recovery = preset;
            STATE.put(&self.store, txn, &(), &state)?;
            Ok(change)
        })?;
        change.mirror_pending = finish_or_pending(transition);
        if change.previous != change.preset {
            change.sheet = issue.map(|(sheet, _, _)| sheet);
        }
        Ok(change)
    }

    /// Draws a printed sheet for the held key, its wrap sealed, and hands it
    /// to `keep_sheet` before any write. The sheet, the commitment of the key
    /// it opens and its wrap's envelope.
    fn draw_recovery_sheet(
        &self,
        keep_sheet: impl FnOnce(&RecoverySheet) -> Result<()>,
    ) -> Result<(RecoverySheet, [u8; 32], Vec<u8>)> {
        if !matches!(self.data_key_custody(), VaultDataKeyCustody::OwnerHeldLocal) {
            return Err(refused(PRESET_CUSTODY));
        }
        let key = self
            .held_vault_key()
            .ok_or_else(|| refused("unlock the vault key first"))?;
        let vault_id = *self.vault_id().as_bytes();
        let commitment = key.commitment(&vault_id);
        let sheet = RecoverySheet::generate()?;
        let envelope = seal_wrap(
            &vault_id,
            &commitment,
            &VaultKeyWrapKind::Sheet,
            &WrapSecret::Kek(sheet.kek(&vault_id)),
            &key,
        )?;
        keep_sheet(&sheet)?;
        Ok((sheet, commitment, envelope))
    }

    /// Unlocks the vault data key with the printed recovery sheet.
    pub fn unlock_vault_key_with_sheet(&self, sheet: &RecoverySheet) -> Result<()> {
        let kek = sheet.kek(self.vault_id().as_bytes());
        self.unlock_vault_key_with(&VaultKeyWrapKind::Sheet.id(), &UnlockSecret::Kek(kek))
    }

    /// Entering "Nobody but me", in the preset's write: the sheet wrap
    /// sealed as `envelope` added (replacing an earlier sheet), the password
    /// and passkey wraps removed, and every escrow wrap but the world kit's
    /// removed with its label retired (an earlier receipt for the label
    /// stands). A sealed vault's mirror is staged first with every wrap and
    /// the sheet's. The removed wraps and the receipts.
    fn enter_nobody_but_me_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        transition: &WrapTransition<'_>,
        envelope: Vec<u8>,
    ) -> Result<(Vec<VaultKeyWrapInfo>, Vec<EscrowRetirement>)> {
        let now = self.instant_in_txn(txn)?.secs();
        let kind = VaultKeyWrapKind::Sheet;
        let sheet = StoredWrap {
            info: VaultKeyWrapInfo {
                id: kind.id(),
                kind,
                created_at: now,
            },
            envelope,
        };
        transition.stage(|| self.staged_wraps_in_txn(txn, Some(&sheet)))?;
        let mut removed = Vec::new();
        let mut retired = Vec::new();
        for (id, stored) in WRAPS.scan(&self.store, txn)? {
            let retiring = match &stored.info.kind {
                VaultKeyWrapKind::Password | VaultKeyWrapKind::Passkey { .. } => None,
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
        WRAPS.put(&self.store, txn, &sheet.info.id, &sheet)?;
        Ok((removed, retired))
    }
}
