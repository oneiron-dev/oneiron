//! A data-key generation's delivery, received.
//!
//! After an authority ingest, this replica adopts every current-eligible
//! generation above its stored one, in order, with no owner unlock: the
//! capsule and the link give it both keys. For each generation it opens its
//! capsule with the machine secret, checks the commitment and that the link
//! reaches its own stored key, seals its own device wrap, and in one write
//! stores the wrap, the link row and the new state. It stops at the first
//! generation with no capsule for this machine, a conflicted one, or a link
//! that does not reach this replica's key. A host-managed or
//! supervisor-delivered vault adopts nothing, and a page-sealed replica
//! waits for a later change.

use std::sync::Arc;

use super::*;
use super::generation_capsule::{DataKeyGenerationBinding, open_data_key_capsule};
use crate::config::VaultDataKeyCustody;

/// What receiving the folded generations did.
pub struct DataKeyGenerationAdoption {
    /// The generations adopted, ascending.
    pub adopted: Vec<u32>,
}

impl Vault {
    /// Adopts the folded data-key generations above this replica's stored
    /// one, in order, with no owner unlock. Stops at the first generation
    /// with no capsule for this machine, a conflicted one, or a link that
    /// does not reach this replica's key. A page-sealed replica and a
    /// host-managed or supervisor-delivered vault adopt nothing. Runs
    /// outside every transaction; each generation commits in its own write.
    /// After a generation commits, a handle that held the key it replaces
    /// holds the new one, so its ring refills from the links; a handle that
    /// held nothing holds nothing.
    pub fn adopt_data_key_generations(&self) -> Result<DataKeyGenerationAdoption> {
        let mut adopted = Vec::new();
        if !matches!(
            self.data_key_custody(),
            VaultDataKeyCustody::OwnerHeldLocal
        ) {
            return Ok(DataKeyGenerationAdoption { adopted });
        }
        if self.vault_pages_sealed() {
            tracing::warn!(
                "a page-sealed replica adopts a new data-key generation in a later change"
            );
            return Ok(DataKeyGenerationAdoption { adopted });
        }
        let data_vault_id = *self.vault_id().as_bytes();
        loop {
            let state = {
                let txn = self.store.env.read_txn()?;
                STATE.get(&self.store, &txn, &())?
            };
            let Some(state) = state else {
                break;
            };
            let Some(next) = state.generation.checked_add(1) else {
                break;
            };
            let fold = self.authority_fold()?;
            let Some(folded) = fold.data_key_generation(next) else {
                break;
            };
            if folded.conflicted {
                break;
            }
            let Some(authority_vault) = fold.vault_id else {
                break;
            };
            let install = {
                let txn = self.store.env.read_txn()?;
                crate::identity::read_machine_id_in_txn(self, &txn)?
            };
            let Some(install) = install else {
                break;
            };
            let Some((_, capsule)) =
                folded.capsules.iter().find(|(to, _)| *to == install)
            else {
                break;
            };
            let Ok(envelope) = Envelope::parse(capsule) else {
                break;
            };
            let secret = self.machine_secret_outside_txn()?;
            let binding = DataKeyGenerationBinding {
                vault_id: authority_vault,
                data_vault_id,
                generation: next,
                commitment: folded.commitment,
            };
            let opened = open_data_key_capsule(&binding, install, &secret.secret, &envelope)?;
            let next_commitment = opened.commitment(&data_vault_id);
            let link = KeyHeaderLink {
                generation: next,
                previous: folded.previous,
                envelope: folded.link.clone(),
            };
            let Ok(older) = open_link(&data_vault_id, &opened, &link) else {
                break;
            };
            if older.commitment(&data_vault_id) != state.commitment {
                break;
            }
            let (device_kek, device_kind) = self.device_kek()?;
            let device_envelope = seal_wrap(
                &data_vault_id,
                &next_commitment,
                &device_kind,
                &WrapSecret::Kek(device_kek),
                &opened,
            )?;
            let device_id = device_kind.id();
            let held_matches = self
                .held_vault_key()
                .is_some_and(|held| held.commitment(&data_vault_id) == state.commitment);
            let link_bytes = folded.link.clone();
            self.with_write_txn(|txn| {
                let current = STATE
                    .get(&self.store, txn, &())?
                    .ok_or_else(|| refused("the vault has no data key"))?;
                if current.commitment != state.commitment || current.generation != state.generation
                {
                    return Err(refused(
                        "the vault's data key moved while its new generation was received; it will be received again",
                    ));
                }
                let fold = self.authority_view_readonly_in_txn(txn)?;
                let counts = fold.data_key_generation(next).is_some_and(|folded_now| {
                    !folded_now.conflicted
                        && folded_now.commitment == folded.commitment
                        && folded_now.previous == folded.previous
                });
                if !counts {
                    return Err(refused(
                        "the new generation's delivery does not count here; it will be received again",
                    ));
                }
                admit_generation_capsule(current.recovery, true, true, true)?;
                let created_at = self.instant_in_txn(txn)?.secs();
                WRAPS.put(
                    &self.store,
                    txn,
                    &device_id,
                    &StoredWrap {
                        info: VaultKeyWrapInfo {
                            id: device_id.clone(),
                            kind: device_kind,
                            created_at,
                        },
                        envelope: device_envelope,
                    },
                )?;
                LINKS.put(
                    &self.store,
                    txn,
                    &format!("{next:010}"),
                    &KeyHeaderLink {
                        generation: next,
                        previous: current.commitment,
                        envelope: link_bytes,
                    },
                )?;
                STATE.put(
                    &self.store,
                    txn,
                    &(),
                    &VaultKeyState {
                        commitment: next_commitment,
                        generation: next,
                        created_at: current.created_at,
                        recovery: current.recovery,
                    },
                )?;
                Ok(())
            })?;
            if held_matches {
                if let Err(error) = self.install_vault_key(Arc::new(opened)) {
                    tracing::warn!(
                        %error,
                        "the received data key was not held; the vault key locked"
                    );
                    self.drop_held_vault_key();
                }
            }
            adopted.push(next);
        }
        Ok(DataKeyGenerationAdoption { adopted })
    }
}
