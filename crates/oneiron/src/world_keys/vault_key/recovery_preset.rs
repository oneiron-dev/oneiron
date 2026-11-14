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
use crate::store::recovery_kit::{KitIssue, KitPiece};
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
}

/// What turning on "any 2 pieces" did: the preset's change, and the kit its
/// pieces come from, handed over once.
#[derive(Debug)]
pub struct RecoveryPresetAnyTwoChange {
    pub change: RecoveryPresetChange,
    pub kit: IssuedVaultKeyKit,
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
    /// caller keeps it durably (a synced file, an answer), and a failed keep
    /// changes nothing. Then, in one write, it adds the sheet's wrap, removes
    /// the password and passkey wraps, and retires every escrow recipient but
    /// the world kit's, each with its receipt; the answer carries the sheet
    /// too. Coming from "any 2 pieces", the kit stays usable beside the fresh
    /// sheet (FLIP = A). Leaving it changes no wrap; any other wrap is added
    /// through the ordinary doors after. The preset already in force changes
    /// nothing and draws no sheet. A mirror rewrite that fails after the
    /// commit is answered as `mirror_pending`. "Any 2 pieces" is turned on
    /// with its kit: [`Self::set_recovery_preset_any_two_as`].
    pub fn set_recovery_preset_as(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        preset: RecoveryPreset,
        keep_sheet: impl FnOnce(&RecoverySheet) -> Result<()>,
    ) -> Result<RecoveryPresetChange> {
        let issue = match preset {
            RecoveryPreset::NobodyButMeAnyTwo => return Err(refused(ANY_TWO_NEEDS_KIT)),
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
                (change.removed, change.retired) = self.enter_nobody_but_me_in_txn(
                    txn,
                    &transition,
                    preset,
                    Some((VaultKeyWrapKind::Sheet, envelope.clone())),
                )?;
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
    /// answered as `mirror_pending`.
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
    ) -> Result<RecoveryPresetAnyTwoChange> {
        if !matches!(self.data_key_custody(), VaultDataKeyCustody::OwnerHeldLocal) {
            return Err(refused(PRESET_CUSTODY));
        }
        let mut drawn = self.draw_vault_key_kit(owner, issue, passkey)?;
        let point = drawn.point.take();
        let commitment = drawn.commitment;
        // The owner's pieces are kept before this install's slot is
        // replaced, so a failed keep leaves the earlier kit's local piece.
        drawn.keep_owner_pieces(keep_pieces)?;
        let kit = drawn.hand_over(true)?;
        let preset = RecoveryPreset::NobodyButMeAnyTwo;
        let transition = self.begin_wrap_transition()?;
        let mut change = self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let mut state = STATE
                .get(&self.store, txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?;
            if state.commitment != commitment {
                return Err(refused("this handle holds another vault key"));
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
            };
            state.recovery = preset;
            STATE.put(&self.store, txn, &(), &state)?;
            Ok(change)
        })?;
        change.mirror_pending = finish_or_pending(transition);
        Ok(RecoveryPresetAnyTwoChange { change, kit })
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
