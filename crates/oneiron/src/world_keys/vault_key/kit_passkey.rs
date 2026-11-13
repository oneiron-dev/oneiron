//! The synced passkey as one data-key kit piece (census L10-18;
//! CROSS-ARCH-0019 #vault-20-unlock: "One switch requires any 2 pieces: the
//! passkey, the sheet, a trusted person or an old device").
//!
//! A kit home [`PieceHome::Passkey`] hands out no piece. Its piece is sealed
//! under the passkey's PRF output, at the input a passkey wrap of that name
//! uses ([`passkey_prf_input`]), into a `kit_point` wrap the data key
//! carries, so a new device with a sealed artifact or the vault and the
//! synced passkey opens the piece. The wrap holds the piece's export, never
//! the key: a second piece, or the kit passphrase, must join it, so the
//! passkey alone restores nothing. No other unlock opens the wrap:
//! [`open_wrap`] has no arm for its kind.

use std::cmp::Reverse;

use super::*;
use crate::store::recovery_kit::{KitId, KitPiece, KitSecretKind, PieceHome};
use crate::world_keys::kit::{kit_key, kit_refused};

const KIT_POINT_LABEL: &[u8] = b"oneiron/vault-key-kit-point/v1\0";

/// The `kit_point` wrap of kit `kit`'s piece sealed under the passkey
/// `credential`.
pub(super) fn kit_point_kind(kit: KitId, credential: &str) -> VaultKeyWrapKind {
    VaultKeyWrapKind::KitPoint {
        kit: kit_key(kit),
        credential: credential.to_owned(),
    }
}

/// Seals `piece`'s export under `passkey`'s PRF output as the wrap `kind`,
/// bound to the vault id, the wrap id and the key's commitment.
pub(super) fn seal_kit_point(
    vault_id: &[u8; 32],
    commitment: &[u8; 32],
    kind: &VaultKeyWrapKind,
    passkey: KitPasskey<'_>,
    piece: &KitPiece,
) -> Result<Vec<u8>> {
    let id = kind.id();
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::VaultDek,
        epoch: VAULT_KEY_EPOCH,
        key_id: commitment,
        recipient: id.as_bytes(),
        vault_id,
    };
    let export = piece.export();
    let mut payload = Zeroizing::new(Vec::with_capacity(
        KIT_POINT_LABEL.len() + export.as_bytes().len(),
    ));
    payload.extend_from_slice(KIT_POINT_LABEL);
    payload.extend_from_slice(export.as_bytes());
    let kek = passkey_kek(passkey.prf);
    let envelope = seal(&params, SealKey::Passkey(&kek), &payload, &mut SysRng)
        .map_err(|_| refused("sealing the passkey's kit piece failed"))?;
    Ok(envelope.to_bytes())
}

/// The kit piece the `kit_point` wrap `stored` of kit `kit` seals, opened
/// with `passkey`'s PRF output: a data-key kit's passkey piece of that kit.
fn open_kit_point(
    vault_id: &[u8; 32],
    commitment: &[u8; 32],
    stored: &StoredWrap,
    kit: &str,
    passkey: KitPasskey<'_>,
) -> Result<KitPiece> {
    let id = stored.info.kind.id();
    if id != stored.info.id {
        return Err(refused("a vault key wrap is filed under another id"));
    }
    let policy = OpenPolicy {
        purpose: Purpose::VaultDek,
        vault_id,
        recipient: id.as_bytes(),
        key_id: commitment,
        wraps: &[stored.info.kind.wrap_type()],
        aead_suites: &[AEAD],
        kem_suites: &[KEM],
        min_epoch: VAULT_KEY_EPOCH,
        argon2_max: ARGON2_MAX,
    };
    let kek = passkey_kek(passkey.prf);
    let envelope = Envelope::parse(&stored.envelope)
        .map_err(|_| refused("a passkey's kit piece wrap is malformed"))?;
    let payload = envelope
        .open(OpenKey::Passkey(&kek), &policy)
        .map_err(|_| refused("the passkey's kit piece wrap does not open with this passkey"))?;
    let export = payload
        .strip_prefix(KIT_POINT_LABEL)
        .ok_or_else(|| refused("the passkey's kit piece wrap's payload is malformed"))?;
    let piece = KitPiece::import(export).map_err(kit_refused)?;
    if piece.kind() != KitSecretKind::VaultKey
        || piece.home() != Some(&PieceHome::Passkey)
        || kit_key(piece.kit_id()) != kit
    {
        return Err(refused(
            "the passkey's kit piece wrap holds a piece of another kit",
        ));
    }
    Ok(piece)
}

/// The kit pieces `passkey` opens among `wraps`: of each `kit_point` wrap
/// of its credential, of the kit the first of `given` names, or with none
/// given, of the newest such wrap alone. A wrap that does not open is left
/// out; when none opens, the refusal says why, so a wrong passkey is told.
pub(super) fn passkey_pieces(
    vault_id: &[u8; 32],
    commitment: &[u8; 32],
    wraps: &[StoredWrap],
    passkey: KitPasskey<'_>,
    given: &[&KitPiece],
) -> Result<Vec<KitPiece>> {
    check_name(passkey.credential)?;
    let named = given.first().map(|piece| kit_key(piece.kit_id()));
    let mut opened = Vec::new();
    let mut refusal = None;
    for stored in wraps {
        let VaultKeyWrapKind::KitPoint { kit, credential } = &stored.info.kind else {
            continue;
        };
        if credential != passkey.credential || named.as_ref().is_some_and(|named| named != kit) {
            continue;
        }
        match open_kit_point(vault_id, commitment, stored, kit, passkey) {
            Ok(piece) => opened.push((stored.info.created_at, piece)),
            Err(error) => {
                refusal.get_or_insert(error);
            }
        }
    }
    if opened.is_empty() {
        return Err(refusal.unwrap_or_else(|| {
            refused("the vault key carries no kit piece sealed under this passkey")
        }));
    }
    if named.is_none() {
        opened.sort_by_key(|(created_at, _)| Reverse(*created_at));
        opened.truncate(1);
    }
    Ok(opened.into_iter().map(|(_, piece)| piece).collect())
}
