//! A data-key generation's delivery, received.
//!
//! After an authority ingest, this replica adopts every current-eligible
//! generation above its stored one, in order, with no owner unlock: the
//! capsule and the link give it both keys. For each generation it tries each
//! counted record's capsule for this machine: it opens the capsule with the
//! machine secret, checks the commitment and that the link reaches its own
//! stored key, seals its own device wrap, and in one write stores the wrap,
//! the link row and the new state. It stops at the first generation with no
//! capsule for this machine, a conflicted one, or no record whose capsule
//! opens here and whose link reaches this replica's key. A host-managed or
//! supervisor-delivered vault adopts nothing, and a page-sealed replica
//! waits for a later change.

use super::generation_capsule::{DataKeyGenerationBinding, open_data_key_capsule};
use super::state::open_link;
use super::*;
use crate::authority::FoldedDataKeyGeneration;
use crate::config::VaultDataKeyCustody;
use crate::entity_id::EntityId;

/// What receiving the folded generations did.
pub struct DataKeyGenerationAdoption {
    /// The generations adopted, ascending.
    pub adopted: Vec<u32>,
}

/// The generation just above this replica's stored one, as one snapshot read
/// it: eligible, and carrying a capsule for this machine.
struct PendingGeneration {
    state: VaultKeyState,
    generation: u32,
    folded: FoldedDataKeyGeneration,
    authority_vault: [u8; 32],
    install: EntityId,
}

impl Vault {
    /// Adopts the folded data-key generations above this replica's stored
    /// one, in order, with no owner unlock. Stops at the first generation
    /// with no capsule for this machine, a conflicted one, or no counted
    /// record whose capsule opens here and whose link reaches this
    /// replica's key. A page-sealed replica and a
    /// host-managed or supervisor-delivered vault adopt nothing. Runs
    /// outside every transaction; each generation commits in its own write,
    /// with snapshot admission paused from before the write until the new
    /// key is held, as the act pauses it. After a generation commits, a
    /// handle that held the key it replaces holds the new one, so its ring
    /// refills from the links; a handle that held nothing holds nothing.
    pub fn adopt_data_key_generations(&self) -> Result<DataKeyGenerationAdoption> {
        let mut adopted = Vec::new();
        if !matches!(self.data_key_custody(), VaultDataKeyCustody::OwnerHeldLocal) {
            return Ok(DataKeyGenerationAdoption { adopted });
        }
        let data_vault_id = *self.vault_id().as_bytes();
        while let Some(pending) = self.pending_data_key_generation()? {
            let PendingGeneration {
                state,
                generation,
                folded,
                authority_vault,
                install,
            } = pending;
            if self.vault_pages_sealed() {
                tracing::warn!(
                    generation,
                    "a page-sealed replica adopts a new data-key generation in a later change"
                );
                break;
            }
            let secret = self.machine_secret_outside_txn()?;
            if secret.machine != install {
                break;
            }
            let binding = DataKeyGenerationBinding {
                vault_id: authority_vault,
                data_vault_id,
                generation,
                commitment: folded.commitment,
            };
            // Every counted record of an eligible generation names one key;
            // the first whose capsule opens here and whose link reaches the
            // stored key delivers it.
            let Some((delivery, opened)) = folded.deliveries.iter().find_map(|delivery| {
                let (_, capsule) = delivery.capsules.iter().find(|(to, _)| *to == install)?;
                let envelope = Envelope::parse(capsule).ok()?;
                let opened =
                    open_data_key_capsule(&binding, install, &secret.secret, &envelope).ok()?;
                let link = KeyHeaderLink {
                    generation,
                    previous: folded.previous,
                    envelope: delivery.link.clone(),
                };
                let older = open_link(&data_vault_id, &opened, &link).ok()?;
                (older.commitment(&data_vault_id) == state.commitment).then_some((delivery, opened))
            }) else {
                tracing::warn!(
                    generation,
                    "no delivery of the new data-key generation opens on this machine and reaches its stored key"
                );
                break;
            };
            let next_commitment = opened.commitment(&data_vault_id);
            let (entry, signer) = (delivery.entry, delivery.machine);
            let (device_kek, device_kind) = self.device_kek()?;
            let device_envelope = seal_wrap(
                &data_vault_id,
                &next_commitment,
                &device_kind,
                &WrapSecret::Kek(device_kek),
                &opened,
            )?;
            let device_id = device_kind.id();
            // No snapshot admitted under the replaced key commits after the
            // write; the pause ends once the new key is held.
            let snapshot_pause = self.store.inference_snapshots.pause_for_key_handoff();
            let held_matches = self
                .held_vault_key()
                .is_some_and(|held| held.commitment(&data_vault_id) == state.commitment);
            let link_bytes = delivery.link.clone();
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
                let counts = fold.data_key_generation(generation).is_some_and(|folded_now| {
                    !folded_now.conflicted
                        && folded_now.commitment == folded.commitment
                        && folded_now.previous == folded.previous
                });
                if !counts {
                    return Err(refused(
                        "the new generation's delivery does not count here; it will be received again",
                    ));
                }
                // Checked above: the capsule is this machine's, the entry
                // counts, and the link reaches the stored key.
                admit_generation_capsule(current.recovery, true, counts, true)?;
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
                    &format!("{generation:010}"),
                    &KeyHeaderLink {
                        generation,
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
                        generation,
                        created_at: current.created_at,
                        recovery: current.recovery,
                    },
                )?;
                Ok(())
            })?;
            if held_matches {
                if let Err(error) = self.hold_vault_key(opened) {
                    // The replaced key is never left held: the vault key
                    // locks, and the next unlock opens the new one.
                    tracing::warn!(
                        %error,
                        "the received data key was not held; the vault key locked"
                    );
                    self.drop_held_vault_key();
                }
            }
            drop(snapshot_pause);
            tracing::info!(
                generation,
                entry = %oneiron_hex::encode(&entry),
                signer = %signer.to_hex(),
                "this device received a new data-key generation"
            );
            adopted.push(generation);
        }
        Ok(DataKeyGenerationAdoption { adopted })
    }

    /// The folded generation just above this replica's stored one, when it
    /// is eligible and carries a capsule for this machine. One read
    /// snapshot, no write: every authority ingest asks it.
    fn pending_data_key_generation(&self) -> Result<Option<PendingGeneration>> {
        let txn = self.store.env.read_txn()?;
        let Some(state) = STATE.get(&self.store, &txn, &())? else {
            return Ok(None);
        };
        let Some(generation) = state.generation.checked_add(1) else {
            return Ok(None);
        };
        let view = self.authority_view_readonly_in_txn(&txn)?;
        let Some(folded) = view
            .data_key_generation(generation)
            .filter(|folded| !folded.conflicted)
        else {
            return Ok(None);
        };
        let Some(authority_vault) = view.vault_id else {
            return Ok(None);
        };
        let Some(install) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
            return Ok(None);
        };
        if !folded
            .deliveries
            .iter()
            .any(|delivery| delivery.capsules.iter().any(|(to, _)| *to == install))
        {
            return Ok(None);
        }
        Ok(Some(PendingGeneration {
            state,
            generation,
            folded: folded.clone(),
            authority_vault,
            install,
        }))
    }
}
