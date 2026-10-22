//! Erase's rewrite of the kept pad objects for one key alone (FIX 7192,
//! 7294): a hard erase of one world key pad row takes that key's pad, by its
//! exact full id, out of every pad object the home keeps, as a world's erase
//! takes every pad of the world out ([`OpenedKeyPads::without_world`]). The
//! generation, the capsules, the outer key and the length stay, every other
//! pad stays, and no sibling key is retired.
//!
//! The erase stages the obligation in its own transaction, before the row is
//! torn and whatever custody holds ([`stage_retained_pad_key_erase_in_txn`]);
//! the home's sweep (`sync::client`) owes it until its proof covers every
//! kept object. The obligation and the proofs share the sweep's family, one
//! row per [`PadEraseSubject`]. The erase itself never waits on the sweep.

use heed::RwTxn;

#[cfg(feature = "sync")]
use super::{
    OpenedKeyPads, PADS, RecoveryRootSeed, SealedKeyPads, SealedObject, SealedPadAdmissionGrant,
    WorldKeyId, encode_pads_body, seal_outer,
};
#[cfg(feature = "sync")]
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

/// The sweep's family: one row per erase subject, empty while it is only
/// owed, else the sweep's proof (`sync::client`'s bundle sweep).
const SWEPT: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_SWEPT);

/// What one erase takes out of every kept pad object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PadEraseSubject {
    /// Every pad of a world whose keys were destroyed here.
    World(EntityId),
    /// One key's pad, by its full id: world (16) | generation (8,
    /// big-endian) | mint (16).
    Key([u8; 40]),
}

impl PadEraseSubject {
    /// Its row's key in the sweep's family (CALLS: rbe subject key codec):
    /// `w:` and the world in hex (32), or `k:` and the key's full id in hex
    /// (80).
    pub(crate) fn table_key(&self) -> String {
        match self {
            Self::World(world) => format!("w:{}", world.to_hex()),
            Self::Key(item) => {
                let hex: String = item.iter().map(|byte| format!("{byte:02x}")).collect();
                format!("k:{hex}")
            }
        }
    }

    /// Parses [`Self::table_key`]; `None` for any other key.
    #[cfg(feature = "sync")]
    pub(crate) fn from_table_key(key: &[u8]) -> Option<Self> {
        let key = std::str::from_utf8(key).ok()?;
        if let Some(world) = key.strip_prefix("w:") {
            if world.len() != 32 {
                return None;
            }
            return EntityId::from_hex(world).ok().map(Self::World);
        }
        let text = key.strip_prefix("k:").filter(|text| text.len() == 80)?;
        let mut item = [0u8; 40];
        for (byte, pair) in item.iter_mut().zip(text.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(Self::Key(item))
    }

    /// Whether `key`'s pad is one it takes out.
    #[cfg(feature = "sync")]
    pub(crate) fn takes(&self, key: &WorldKeyId) -> bool {
        match self {
            Self::World(world) => key.world == *world,
            Self::Key(item) => key.envelope_key_id() == *item,
        }
    }
}

/// Stages, in a hard erase's own transaction and before its row is torn, the
/// sweep of the key whose full id is `item` from every pad object the home
/// keeps (FIX 7192, 7294), whatever custody holds for it. A row the sweep
/// holds for it already stays. A fault is warned by the row `row`, never a
/// refusal: the erase stands as before.
pub(crate) fn stage_retained_pad_key_erase_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    row: &EntityId,
    item: &[u8; 40],
) {
    if let Err(error) = stage_in(store, wtxn, item) {
        tracing::warn!(
            row = %row.to_hex(),
            kind = ?error.kind(),
            "a hard-erased pad row's key was not staged for the kept pad objects' sweep"
        );
    }
}

fn stage_in(store: &Store, wtxn: &mut RwTxn<'_>, item: &[u8; 40]) -> Result<()> {
    let key = PadEraseSubject::Key(*item).table_key();
    if SWEPT.contains(store, wtxn, &key)? {
        return Ok(());
    }
    SWEPT.put(store, wtxn, &key, &Vec::new())
}

#[cfg(feature = "sync")]
impl OpenedKeyPads {
    /// Erase's rewrite of one object for one key: the same generation,
    /// capsules, outer key and length, sealed afresh without the pad of the
    /// key whose full id is `item`, in its pads and its section index alike.
    /// It replaces the old object, which the holder deletes.
    pub(crate) fn without_key(&self, item: &[u8; 40]) -> Result<SealedKeyPads> {
        let entries: Vec<_> = self
            .entries
            .iter()
            .filter(|(key, _, _)| key.envelope_key_id() != *item)
            .cloned()
            .collect();
        let index: Vec<_> = self
            .index
            .iter()
            .filter(|(key, _)| key.envelope_key_id() != *item)
            .copied()
            .collect();
        let body = encode_pads_body(&self.vault_id, self.generation, &entries, &index, None)?;
        let bytes = seal_outer(
            PADS,
            &self.vault_id,
            self.generation,
            &self.outer,
            &self.slots,
            body,
            Some(self.total),
        )?;
        Ok(SealedKeyPads(SealedObject {
            generation: self.generation,
            bytes,
        }))
    }
}

#[cfg(feature = "sync")]
impl Vault {
    /// Erase's rewrite for one key, in one call: every one of `kept`, each
    /// without the pad of the key whose full id is `item`, opened as
    /// [`Vault::drop_world_from_key_pads`] opens them. Every other pad stays.
    /// Refused when one object opens with no key, before anything is
    /// rewritten.
    pub(crate) fn drop_key_from_key_pads(
        &self,
        item: &[u8; 40],
        kept: &[SealedKeyPads],
        kit: Option<&RecoveryRootSeed>,
        grants: &[SealedPadAdmissionGrant],
    ) -> Result<Vec<SealedKeyPads>> {
        let keys = self.erase_keys(kit, grants)?;
        let opened = kept
            .iter()
            .map(|pads| keys.open(pads))
            .collect::<Result<Vec<_>>>()?;
        opened.iter().map(|pads| pads.without_key(item)).collect()
    }
}
