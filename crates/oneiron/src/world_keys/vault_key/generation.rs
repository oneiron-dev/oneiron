//! A new data-key generation: the owner replaces the vault's data key
//! (KIT-ONLY-DATA-KEY = D, Apple ADP behaviour).
//!
//! Everything written after the act is sealed under the new key; old items
//! stay readable under their own key through the link chain. Generation
//! numbers order the keys; a key is named by its commitment. Only the owner
//! starts a generation; an agent may propose it (DATAKEY-GEN-WHO = C). Each
//! presented way gets a wrap of the new key; every other wrap of the old key
//! is removed only when the owner confirmed its removal by id
//! (DATAKEY-GEN-WAYS = A).

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::authority::ActAuthority;
use crate::config::VaultDataKeyCustody;

/// Why the owner starts a new data-key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataKeyGenerationCause {
    /// The owner asked for a new generation.
    OwnerRequest,
    /// The kit-only switch moves to a new key (PR 4).
    KitOnlySwitch,
}

/// The secret ways the owner presents during the act (ruling DATAKEY-GEN-WAYS = A): each presented
/// way gets a wrap of the new key; every other wrap of the old key is removed only when the owner
/// confirmed its removal by id.
pub struct DataKeyGenerationWays<'a> {
    /// The vault password, when the owner keeps it.
    pub password: Option<&'a [u8]>,
    /// The passkeys the owner keeps: each credential and its PRF output.
    pub passkeys: Vec<(&'a str, &'a Zeroizing<[u8; 32]>)>,
    /// The escrows the owner keeps: each label and the recipient to seal to.
    pub escrows: Vec<(&'a str, &'a HybridPublicKey)>,
    /// The wrap ids the owner confirmed for removal.
    pub confirmed_removals: BTreeSet<String>,
}

/// What the act did: the screen names `removed` before (preview) and after.
pub struct DataKeyGenerationOutcome {
    /// The new generation number.
    pub generation: u32,
    /// The commitment naming the new key.
    pub commitment: [u8; 32],
    /// The wraps of the old key the act removed.
    pub removed: Vec<VaultKeyWrapInfo>,
    /// The wraps the act sealed of the new key.
    pub rewrapped: Vec<VaultKeyWrapInfo>,
    /// The page-seal mirror rewrite pends: the act stands, and the next
    /// sealed open repairs the mirror. Always false from the in-txn door,
    /// whose caller finishes the transition.
    pub mirror_pending: bool,
    /// This vault's pages are sealed and keep the key of their incarnation:
    /// the screen tells the owner [`DATA_KEY_GENERATION_PAGE_SEAL_NOTICE`]
    /// (DATAKEY-GEN-PAGE-SEAL = A, until the re-key).
    pub pages_keep_earlier_key: bool,
}

/// What the owner is told after a new data-key generation on a page-sealed
/// vault, until a re-key moves its pages to the new key.
pub const DATA_KEY_GENERATION_PAGE_SEAL_NOTICE: &str =
    "this device's stored copy keeps its old key until it is re-keyed";

/// Everything the act needs from outside a txn (keystore, Argon2): minted before the write.
/// From its minting to the act's finish, inference-snapshot admission stays
/// shut, so no snapshot sealed under the old key commits after the act.
pub struct DataKeyGenerationDraft<'v> {
    /// The next data key.
    next: VaultDataKey,
    /// The commitment of the key the act replaces.
    from_commitment: [u8; 32],
    /// This install's device wrap kind.
    device_kind: VaultKeyWrapKind,
    /// The new key's wraps, sealed before the write, by wrap id: this
    /// install's device wrap and every presented way.
    envelopes: BTreeMap<String, (VaultKeyWrapKind, Vec<u8>)>,
    /// Each presented escrow's recipient fingerprint, by wrap id: the act
    /// rewraps an escrow only to the recipient it was sealed to.
    escrow_fingerprints: BTreeMap<String, [u8; 32]>,
    /// The digest of each password and passkey wrap the presented secret
    /// opened, by wrap id: the act rewraps such a way only for the holder of
    /// its secret, and only the wrap it opened.
    verified_ways: BTreeMap<String, WrapDigest>,
    /// Snapshot admission shut until the new key is held (or the act is
    /// dropped unfinished).
    snapshot_pause: crate::store::snapshot_lifecycle::SnapshotAdmissionPause<'v>,
}

impl DataKeyGenerationDraft<'_> {
    /// The next data key.
    pub fn next_key(&self) -> &VaultDataKey {
        &self.next
    }
}

impl Vault {
    /// The wraps of the current key the act would remove: what no presented
    /// way covers and what is not this install's device wrap. The screen
    /// names them before the act; the act removes them only when confirmed.
    pub fn data_key_generation_preview(
        &self,
        ways: &DataKeyGenerationWays<'_>,
    ) -> Result<Vec<VaultKeyWrapInfo>> {
        let install = self.prepare_install_signing()?;
        let device_id = VaultKeyWrapKind::Device {
            install: install.to_hex(),
        }
        .id();
        let mut covered = BTreeSet::new();
        covered.insert(device_id);
        if ways.password.is_some() {
            covered.insert(VaultKeyWrapKind::Password.id());
        }
        for (credential, _) in &ways.passkeys {
            covered.insert(
                VaultKeyWrapKind::Passkey {
                    credential: (*credential).to_owned(),
                }
                .id(),
            );
        }
        for (label, _) in &ways.escrows {
            covered.insert(
                VaultKeyWrapKind::Escrow {
                    label: (*label).to_owned(),
                }
                .id(),
            );
        }
        let txn = self.store.env.read_txn()?;
        let mut uncovered = Vec::new();
        for (_, stored) in WRAPS.scan(&self.store, &txn)? {
            if matches!(stored.info.kind, VaultKeyWrapKind::KitPoint { .. }) {
                continue;
            }
            if !covered.contains(&stored.info.id) {
                uncovered.push(stored.info);
            }
        }
        Ok(uncovered)
    }

    /// Mints the act's draft outside any txn: the next key, this install's
    /// device wrap, and a sealed wrap of the next key for every presented
    /// way. The password's Argon2 runs here, never in the write. Unlocks with
    /// this device's wrap first, as [`Self::checkpoint_key`] does.
    pub fn prepare_data_key_generation(
        &self,
        ways: &DataKeyGenerationWays<'_>,
    ) -> Result<DataKeyGenerationDraft<'_>> {
        self.unlock_vault_key()?;
        let held = self
            .held_vault_key()
            .ok_or_else(|| refused("unlock the vault key first"))?;
        let vault_id = *self.vault_id().as_bytes();
        let from_commitment = held.commitment(&vault_id);
        // A presented password or passkey must open the wrap of it the
        // vault carries, so the act never seals the new key to other bytes
        // under that way's id. The write checks the wrap is still the one
        // that opened.
        let mut verified_ways = BTreeMap::new();
        if let Some(password) = ways.password {
            let passphrase =
                Passphrase::new(password).map_err(|_| refused("the password is not accepted"))?;
            let id = VaultKeyWrapKind::Password.id();
            if let Some(digest) =
                self.open_presented_way(&id, &UnlockSecret::Passphrase(&passphrase))?
            {
                verified_ways.insert(id, digest);
            }
        }
        for (credential, prf) in &ways.passkeys {
            check_name(credential)?;
            let id = VaultKeyWrapKind::Passkey {
                credential: (*credential).to_owned(),
            }
            .id();
            if let Some(digest) =
                self.open_presented_way(&id, &UnlockSecret::Kek(passkey_kek(prf)))?
            {
                verified_ways.insert(id, digest);
            }
        }
        let next = VaultDataKey::generate()?;
        let next_commitment = next.commitment(&vault_id);
        let mut envelopes = BTreeMap::new();
        let mut escrow_fingerprints = BTreeMap::new();
        let (device_kek, device_kind) = self.device_kek()?;
        let envelope = seal_wrap(
            &vault_id,
            &next_commitment,
            &device_kind,
            &WrapSecret::Kek(device_kek),
            &next,
        )?;
        envelopes.insert(device_kind.id(), (device_kind.clone(), envelope));
        if let Some(password) = ways.password {
            let passphrase =
                Passphrase::new(password).map_err(|_| refused("the password is not accepted"))?;
            let kind = VaultKeyWrapKind::Password;
            let envelope = seal_wrap(
                &vault_id,
                &next_commitment,
                &kind,
                &WrapSecret::Passphrase(&passphrase, Argon2Cost::RFC9106_SECOND),
                &next,
            )?;
            envelopes.insert(kind.id(), (kind, envelope));
        }
        for (credential, prf) in &ways.passkeys {
            check_name(credential)?;
            let kind = VaultKeyWrapKind::Passkey {
                credential: (*credential).to_owned(),
            };
            let envelope = seal_wrap(
                &vault_id,
                &next_commitment,
                &kind,
                &WrapSecret::Kek(passkey_kek(prf)),
                &next,
            )?;
            envelopes.insert(kind.id(), (kind, envelope));
        }
        for (label, recipient) in &ways.escrows {
            check_name(label)?;
            let kind = VaultKeyWrapKind::Escrow {
                label: (*label).to_owned(),
            };
            let envelope = seal_wrap(
                &vault_id,
                &next_commitment,
                &kind,
                &WrapSecret::Hybrid(recipient),
                &next,
            )?;
            escrow_fingerprints.insert(kind.id(), recipient_fingerprint(recipient));
            envelopes.insert(kind.id(), (kind, envelope));
        }
        Ok(DataKeyGenerationDraft {
            next,
            from_commitment,
            device_kind,
            envelopes,
            escrow_fingerprints,
            verified_ways,
            snapshot_pause: self.store.inference_snapshots.pause_for_key_handoff(),
        })
    }

    /// The digest of the stored wrap `id` when `secret` opens it to the key
    /// the vault stores; `None` when the vault carries no such wrap (the
    /// write refuses that way). Refused when it does not open.
    fn open_presented_way(
        &self,
        id: &str,
        secret: &UnlockSecret<'_>,
    ) -> Result<Option<WrapDigest>> {
        let vault_id = *self.vault_id().as_bytes();
        let (state, stored) = {
            let txn = self.store.env.read_txn()?;
            let state = STATE
                .get(&self.store, &txn, &())?
                .ok_or_else(|| refused("the vault has no data key"))?;
            (state, WRAPS.get(&self.store, &txn, &id.to_owned())?)
        };
        let Some(stored) = stored else {
            return Ok(None);
        };
        let opened = open_wrap(&vault_id, &state.commitment, &stored, secret)
            .map_err(|_| refused("a presented way does not open its wrap on this vault"))?;
        if opened.commitment(&vault_id) != state.commitment {
            return Err(refused(
                "a presented way does not open its wrap on this vault",
            ));
        }
        Ok(Some(wrap_digest(&stored)))
    }

    /// Starts a new data-key generation in the caller's write: the wraps of
    /// the presented ways are replaced with wraps of the next key, this
    /// install's device wrap is written (so the new key always keeps a wrap
    /// here), the confirmed wraps are removed, the link is stored, and the
    /// state moves to the next generation. An agent is refused
    /// (DATAKEY-GEN-WHO = C); a host-managed or supervisor-delivered key and
    /// a presented way the vault does not carry are refused too. A presented
    /// escrow must name the recipient it was sealed
    /// to, so the act never moves an escrow (the world kit's included) to
    /// another key; a presented password or passkey must be one whose wrap
    /// opened in [`Self::prepare_data_key_generation`]. No custody head is
    /// sealed under the replaced key after the act whatever the caller holds:
    /// a seal checks its recipients' key against the stored state after its
    /// census. A caller that holds the custody publication policy lock
    /// (`Store::custody_policy_guard`) from before the prepare until after
    /// [`Self::finish_data_key_generation`] also spares a pass that would
    /// stay pending for it.
    pub(crate) fn start_data_key_generation_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        authority: &ActAuthority,
        cause: DataKeyGenerationCause,
        draft: &DataKeyGenerationDraft<'_>,
        ways: &DataKeyGenerationWays<'_>,
        transition: &WrapTransition<'_>,
    ) -> Result<DataKeyGenerationOutcome> {
        let ActAuthority::Owner(owner, _) = authority else {
            return Err(refused(
                "only the owner starts a new data-key generation; an agent may propose it",
            ));
        };
        owner.revalidate_in_txn(self, txn)?;
        if !matches!(self.data_key_custody(), VaultDataKeyCustody::OwnerHeldLocal) {
            return Err(refused(
                "a host-managed or supervisor-delivered data key gets a new generation from its supervisor",
            ));
        }
        let held = self
            .held_vault_key()
            .ok_or_else(|| refused("unlock the vault key first"))?;
        let vault_id = *self.vault_id().as_bytes();
        let state = STATE
            .get(&self.store, txn, &())?
            .ok_or_else(|| refused("the vault has no data key"))?;
        if state.commitment != draft.from_commitment
            || draft.from_commitment != held.commitment(&vault_id)
        {
            return Err(refused("this handle holds another vault key"));
        }
        let next_commitment = draft.next_key().commitment(&vault_id);
        let committed = if transition.sealed() {
            Some(self.staged_wraps_in_txn(txn, None)?)
        } else {
            None
        };
        // Every row is decided before one is written, so an unconfirmed way
        // refuses with nothing written.
        struct Rewrap {
            id: String,
            kind: VaultKeyWrapKind,
            envelope: Vec<u8>,
        }
        let mut rewraps: Vec<Rewrap> = Vec::new();
        let mut removed: Vec<VaultKeyWrapInfo> = Vec::new();
        // The presented ways no stored wrap matched yet.
        let mut unmatched: BTreeSet<&str> = draft.envelopes.keys().map(String::as_str).collect();
        for (id, stored) in WRAPS.scan(&self.store, txn)? {
            // A kit piece's wrap is not a wrap of the data key: it stays, and
            // the kit re-issue is PR 4.
            if matches!(stored.info.kind, VaultKeyWrapKind::KitPoint { .. }) {
                continue;
            }
            unmatched.remove(id.as_str());
            // A wrap already of the new key stays: the kit-only switch
            // stores sheet and kit-point wraps of it before this step.
            let is_new_key_wrap = Envelope::parse(&stored.envelope)
                .is_ok_and(|envelope| envelope.header().key_id == next_commitment);
            if is_new_key_wrap {
                continue;
            }
            if let Some((kind, envelope)) = draft.envelopes.get(&id) {
                match kind {
                    VaultKeyWrapKind::Escrow { label } => {
                        let presented = draft.escrow_fingerprints.get(&id).copied();
                        let sealed = ESCROW_RECIPIENT.get(&self.store, txn, label)?;
                        if presented.is_none() || sealed != presented {
                            return Err(refused(
                                "a presented escrow names another recipient than the one it was sealed to",
                            ));
                        }
                    }
                    VaultKeyWrapKind::Password | VaultKeyWrapKind::Passkey { .. } => {
                        if draft.verified_ways.get(&id) != Some(&wrap_digest(&stored)) {
                            return Err(refused(
                                "a presented way does not open its wrap on this vault",
                            ));
                        }
                    }
                    _ => {}
                }
                rewraps.push(Rewrap {
                    id: id.clone(),
                    kind: kind.clone(),
                    envelope: envelope.clone(),
                });
            } else if ways.confirmed_removals.contains(&id) {
                removed.push(stored.info);
            } else {
                return Err(crate::Error::Secret(
                    crate::error::SecretError::DataKeyGenerationWayUnconfirmed { id },
                ));
            }
        }
        // This install's device wrap is written even when it was missing, so
        // the new key keeps a wrap here; any other presented way must already
        // be on the vault (adding a way is its own act).
        let device_id = draft.device_kind.id();
        for id in unmatched {
            if id != device_id {
                return Err(refused(
                    "a presented way is not on this vault: add it after the act",
                ));
            }
            let (kind, envelope) = &draft.envelopes[id];
            rewraps.push(Rewrap {
                id: id.to_owned(),
                kind: kind.clone(),
                envelope: envelope.clone(),
            });
        }
        let created_at = self.instant_in_txn(txn)?.secs();
        let mut rewrapped = Vec::with_capacity(rewraps.len());
        for rewrap in rewraps {
            let info = VaultKeyWrapInfo {
                id: rewrap.id.clone(),
                kind: rewrap.kind,
                created_at,
            };
            let stored = StoredWrap {
                info: info.clone(),
                envelope: rewrap.envelope,
            };
            WRAPS.put(&self.store, txn, &rewrap.id, &stored)?;
            rewrapped.push(info);
        }
        for info in &removed {
            WRAPS.delete(&self.store, txn, &info.id)?;
        }
        // An escrow that gets a new wrap keeps its recipient row; a removed
        // one follows a plain wrap removal, which touches no escrow table.
        let generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| refused("the vault's data-key generations are exhausted"))?;
        let link = seal_link(&vault_id, draft.next_key(), &held, generation)?;
        LINKS.put(&self.store, txn, &format!("{generation:010}"), &link)?;
        STATE.put(
            &self.store,
            txn,
            &(),
            &VaultKeyState {
                commitment: next_commitment,
                generation,
                created_at: state.created_at,
                recovery: state.recovery,
            },
        )?;
        transition.stage_generation(committed, || self.staged_wraps_in_txn(txn, None))?;
        // No inference snapshot admitted under the old key commits after
        // this write: the draft's pause ended every earlier admission and
        // grants none until the new key is held.
        tracing::info!(
            ?cause,
            generation,
            "the vault data key moved to a new generation"
        );
        Ok(DataKeyGenerationOutcome {
            generation,
            commitment: next_commitment,
            removed,
            rewrapped,
            mirror_pending: false,
            pages_keep_earlier_key: self.vault_pages_sealed(),
        })
    }

    /// Holds the new key after the act's commit, so the ring refills from the
    /// stored links, and finishes the page-seal transition. True when the
    /// mirror rewrite pends.
    pub(crate) fn finish_data_key_generation(
        &self,
        draft: DataKeyGenerationDraft<'_>,
        transition: WrapTransition<'_>,
    ) -> bool {
        let DataKeyGenerationDraft {
            next,
            snapshot_pause,
            ..
        } = draft;
        if let Err(error) = self.hold_vault_key(next) {
            // The act committed, so the replaced key is never left held:
            // the vault key locks, and the next unlock opens the new one.
            tracing::warn!(%error, "the new data key was not held after the act; the vault key locked");
            self.drop_held_vault_key();
        }
        // Admission opens again only now, so the next one reads the new key.
        drop(snapshot_pause);
        // The body seal stays under the key admitted at open until the next open (off-record overlays live only in a session).
        super::recovery_preset::finish_or_pending(transition)
    }

    /// Starts a new data-key generation on the owner's request: an agent may
    /// propose it but never start it (DATAKEY-GEN-WHO = C). Under any
    /// recovery preset but Standard the act runs from the recovery settings
    /// switch (PR 4 adds those).
    pub fn start_data_key_generation_as(
        &self,
        authority: &ActAuthority,
        cause: DataKeyGenerationCause,
        ways: &DataKeyGenerationWays<'_>,
    ) -> Result<DataKeyGenerationOutcome> {
        if matches!(authority, ActAuthority::Agent(_)) {
            return Err(refused(
                "only the owner starts a new data-key generation; an agent may propose it",
            ));
        }
        if self.recovery_preset()? != RecoveryPreset::Standard {
            return Err(refused(
                "under this recovery preset the act runs from the recovery settings switch",
            ));
        }
        // No custody publication pass runs from here until the new key is
        // held, so none reads the old key's subkey and then stays pending at
        // its seal's check of the stored key. Released at the finish, before
        // the door's later work, which may publish.
        let custody_policy = self.store.custody_policy_guard();
        let draft = self.prepare_data_key_generation(ways)?;
        let transition = self.begin_wrap_transition()?;
        // The door can answer an error after its commit is durable (an owed
        // federation sweep, a claim VAD it pays). The act finishes at the
        // commit, before that work: the new key is held before snapshot
        // admission opens again, whatever the door answers after.
        self.write_txn_door_after_commit(
            crate::store::Callback::Opaque,
            move |txn| {
                let outcome = self.start_data_key_generation_in_txn(
                    txn,
                    authority,
                    cause,
                    &draft,
                    ways,
                    &transition,
                )?;
                Ok((outcome, draft, transition))
            },
            |(mut outcome, draft, transition)| {
                outcome.mirror_pending = self.finish_data_key_generation(draft, transition);
                drop(custody_policy);
                Ok(outcome)
            },
        )
    }
}
