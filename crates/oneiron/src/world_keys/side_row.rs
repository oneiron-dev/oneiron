//! Private-world side-table content, bound to the caller's exact row identity.

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Purpose, SealKey, SealParams, SuiteId,
    WrapType, seal_with_aad,
};
use zeroize::Zeroizing;

use super::doors::require_mine_reader;
use super::pads::{require_pad_in_txn, world_keys_destroyed_in_txn};
use super::{
    MachineSecret, WORLD_KEY_EPOCH, WorldKey, WorldKeyId, WrapRecipient, open_counted, refused,
};
use crate::Vault;
use crate::error::Result;

const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;

/// Expectations from the caller's admitted row, never copied from an untrusted
/// envelope. `row` is the caller's canonical associated data, including every
/// identity and revision that must not be substituted within `family`.
#[derive(Clone, Copy)]
pub(crate) struct WorldSideRowBinding<'a> {
    pub vault_id: [u8; 32],
    pub key: WorldKeyId,
    pub family: &'a [u8],
    pub row: &'a [u8],
}

/// Seals content under an already obtained private-world key. This grants no
/// permission to read or write the row; the caller retains its native admission.
pub(crate) fn seal_side_row(
    binding: &WorldSideRowBinding<'_>,
    key: &WorldKey,
    plaintext: &[u8],
) -> Result<Envelope> {
    require_binding(binding, key)?;
    let key_id = binding.key.envelope_key_id();
    let kek = Kek::from_bytes_ref(key.expose());
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::WorldSideRow,
        epoch: WORLD_KEY_EPOCH,
        key_id: &key_id,
        recipient: binding.family,
        vault_id: &binding.vault_id,
    };
    seal_with_aad(
        &params,
        SealKey::SymmetricKek(&kek),
        plaintext,
        binding.row,
        &mut SysRng,
    )
    .map_err(|_| refused("sealing world side-table content failed"))
}

/// Opens exactly the expected row under exactly its retained key id, not the
/// world's current key. Admission is separate from possession of this key.
pub(crate) fn open_side_row(
    binding: &WorldSideRowBinding<'_>,
    key: &WorldKey,
    envelope: &Envelope,
) -> Result<Zeroizing<Vec<u8>>> {
    require_binding(binding, key)?;
    let key_id = binding.key.envelope_key_id();
    let kek = Kek::from_bytes_ref(key.expose());
    let policy = OpenPolicy {
        purpose: Purpose::WorldSideRow,
        vault_id: &binding.vault_id,
        recipient: binding.family,
        key_id: &key_id,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: WORLD_KEY_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    envelope
        .open_with_aad(OpenKey::SymmetricKek(&kek), &policy, binding.row)
        .map_err(|_| refused("the world side-table content does not open for this row binding"))
}

fn require_binding(binding: &WorldSideRowBinding<'_>, key: &WorldKey) -> Result<()> {
    if binding.key != *key.id() {
        return Err(refused("the side-table binding names another world key"));
    }
    Ok(())
}

impl Vault {
    /// Opens an exact counted key in the caller's snapshot, including a retained
    /// non-current id. Load `secret` before entering the transaction. This checks
    /// this machine's identity and current world-read setting; it does not replace
    /// the caller's row, consent, purpose or deletion admission.
    ///
    /// No ring entry is used: the same snapshot must still hold the key's pad.
    /// Base reality has no world key and uses the consumer's native base case.
    pub(crate) fn world_content_key_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        secret: &MachineSecret,
        id: &WorldKeyId,
    ) -> Result<WorldKey> {
        let signing = self.door_signing_key_in_txn(txn, secret.machine)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        require_mine_reader(&fold, id.world, secret.machine, &signing)?;
        if world_keys_destroyed_in_txn(&self.store, txn, id.world)? {
            return Err(refused("the world's keys were destroyed with the world"));
        }
        let counted = fold
            .world_key(id)
            .ok_or_else(|| refused("the world key is not in this history"))?;
        if counted.conflicted {
            return Err(refused("the world key has conflicting counted records"));
        }
        let pad = require_pad_in_txn(&self.store, txn, id)?;
        open_counted(
            &fold,
            counted,
            WrapRecipient::Machine(secret.machine),
            &secret.secret,
            &pad,
        )
        .ok_or_else(|| refused("this machine holds no opening wrap of the world key"))
    }
}
