//! One slot's take of the newest generation and its upload.

use super::*;

impl SlotRelay<'_> {
    /// Takes the newest generation in when it is newer than the last taken,
    /// then publishes the slot's generation when the slot has none, this
    /// machine publishes and it holds the publisher turn. A publisher asks for
    /// the turn even once the slot is won, so it waits its turn for the next
    /// one. A take that fails here uploads nothing this slot: the upload would
    /// carry less than the home holds. The slot is finished once its upload is
    /// in, another machine's is, the take or the assembly failed here, or the
    /// home refused the upload on an unchanged parent past
    /// [`SEALED_BUNDLE_NONSTALE_REFUSAL_RETRIES_PER_SLOT`]; a machine waiting
    /// for the turn, or whose upload did not reach the home, tries again next
    /// tick. A take no capsule here opens fails, after a publisher gives up its
    /// turn ([`SEALED_BUNDLE_NO_CAPSULE_ACTION`]).
    pub(super) async fn run(
        &self,
        rpc: &mut ResidenceRpc,
        mut cursor: Cursor,
        relay: &mut SealedBundleRelay,
    ) -> Result<(), TransportError> {
        let vault = self.manager.vault();
        let holder = holder_destination(vault, rpc.home);
        let address = rpc.address;
        // The home for the work this slot may begin: the proven machine, or
        // unknown. An unknown home publishes under its explicit unknown-home
        // address exactly as a proven one does (FIX 9254): the absence of a
        // local proof never holds an eligible publisher back.
        let home: Option<EntityId> = match vault.peer_machine_stands(rpc.home) {
            PeerMachine::Proven { machine, .. } => Some(machine),
            PeerMachine::Unknown => None,
        };
        // The newest generation's objects, once fetched: an upload carries
        // what this machine cannot read from them.
        let mut held: Option<(SealedVaultBundle, SealedKeyPads)> = None;
        let mut retries = 0;
        let mut refusals = 0;
        loop {
            let listed = list_generations(rpc).await?;
            let latest = listed.first().copied();
            if let Some(newest) = latest.filter(|newest| {
                cursor
                    .taken
                    .is_none_or(|taken| entries::newer_than_taken(newest, taken, &listed))
            }) {
                let (bundle, pads) = fetch_generation(&mut PartSource::Machine(rpc), Some(newest))
                    .await?
                    .ok_or_else(refused)?;
                let manager = Arc::clone(self.manager);
                let opened = self.mode == SyncResidenceMode::Opened;
                let (took, bundle, pads) = tokio::task::spawn_blocking(move || {
                    let took = manager.take_sealed_bundle(&bundle, &pads, holder, opened);
                    (took, bundle, pads)
                })
                .await
                .map_err(|error| TransportError::Storage(error.to_string()))?;
                match took {
                    Ok((take, awaiting)) => {
                        cursor.taken = Some(newest);
                        relay.taken = Some((newest, take));
                        relay.awaiting_reader = awaiting;
                    }
                    // Not taken: the next slot takes it again before any
                    // upload (FIX 3358).
                    Err(error) => {
                        cursor.slot = self.slot;
                        store_cursor(vault, cursor).map_err(storage)?;
                        if !matches!(error, Error::Secret(SecretError::SealedBundleNoCapsule)) {
                            return Err(storage(error));
                        }
                        match SEALED_BUNDLE_NO_CAPSULE_ACTION {
                            // The next machine waiting need not wait out the lease.
                            NoCapsuleAction::DeferSlot => {
                                if self.publisher {
                                    let _ = turn::ask_turn(rpc, true).await;
                                }
                                return Err(storage(error));
                            }
                        }
                    }
                }
                store_cursor(vault, cursor).map_err(storage)?;
                held = Some((bundle, pads));
            }
            if !self.publisher || latest.is_some_and(|newest| newest.slot >= self.slot) {
                if self.publisher {
                    turn::ask_turn(rpc, false).await?;
                }
                break;
            }
            // Another machine holds the turn: its generation comes in on a
            // later tick, or its turn lapses.
            if !turn::ask_turn(rpc, false).await? {
                return Ok(());
            }
            if let Some(newest) = latest
                && held
                    .as_ref()
                    .is_none_or(|(bundle, _)| bundle.generation() != newest)
            {
                held = Some(
                    fetch_generation(&mut PartSource::Machine(rpc), Some(newest))
                        .await?
                        .ok_or_else(refused)?,
                );
                // A long fetch renews the turn once it ends.
                if !turn::ask_turn(rpc, false).await? {
                    return Ok(());
                }
            }
            // Without an executor identity no begin addresses: the next
            // machine waiting need not wait out the lease.
            let Some(executor) = work::executor_id(vault).map_err(storage)? else {
                let _ = turn::ask_turn(rpc, true).await;
                return Ok(());
            };
            let manager = Arc::clone(self.manager);
            let slot = self.slot;
            // A full machine lands what the assembly merges (FIX 4788).
            let materialize = self.mode == SyncResidenceMode::All;
            let (upload, awaiting, back) = turn::renewing_turn(rpc, move || {
                let upload = manager.assemble_sealed_bundle(
                    slot,
                    holder,
                    held.as_ref().map(|(bundle, pads)| (bundle, pads)),
                    None,
                    materialize,
                );
                let awaiting = upload.as_ref().map_or_else(
                    |_| Vec::new(),
                    |upload| {
                        report::published_awaiting_reader(manager.vault(), &upload.bundle, holder)
                    },
                );
                (upload, awaiting, held)
            })
            .await?;
            held = back;
            let upload = match upload {
                Ok(upload) => upload,
                Err(error) => {
                    cursor.slot = self.slot;
                    store_cursor(vault, cursor).map_err(storage)?;
                    // The next machine waiting need not wait out the lease.
                    let _ = turn::ask_turn(rpc, true).await;
                    return Err(storage(error));
                }
            };
            let generation = upload.bundle.generation();
            // The owner sees each readable section this upload carries
            // unmerged (FIX 19525) once it is assembled, before its commit.
            relay_observation::observe_upload(vault, home, generation, &upload.unmerged_sections);
            let staged = put_object(
                rpc,
                &generation,
                SealedBundleObject::Bundle,
                upload.bundle.as_bytes(),
            )
            .await?
                && put_object(
                    rpc,
                    &generation,
                    SealedBundleObject::Pads,
                    upload.pads.as_bytes(),
                )
                .await?;
            // A terminal begin says itself whether the parent went stale, so
            // the moved recheck below runs only when a part did not stage.
            let terminal: Option<bool> = if !staged {
                None
            } else {
                let mut attempt = attempt::BundleAttempt {
                    home,
                    executor,
                    generation,
                    bundle_digest: upload.bundle.digest(),
                    parent: latest,
                    root: upload.kit_root,
                    request: None,
                    bundle_total: upload.bundle.as_bytes().len() as u64,
                    pads_total: upload.pads.as_bytes().len() as u64,
                    pads_digest: upload.pads.digest(),
                    incomplete_authority: upload.incomplete_authority.clone(),
                    awaiting_reader: awaiting.clone(),
                    unmerged_sections: upload.unmerged_sections.clone(),
                    assembled_at: Some(vault.store.clock.peek_recorded_at()),
                };
                // The exact attempt persists before the first commit send, so
                // an ack lost on the way resumes, never reuploads.
                attempt::persist(vault, attempt::AttemptKey::Auto(address), &mut attempt)
                    .map_err(storage)?;
                match work::begin_work(rpc, &attempt).await? {
                    work::WorkOutcome::Accepted(status) => match status.state {
                        work::WorkState::Pending => return Ok(()),
                        work::WorkState::Committed => {
                            let entry = status.entry.ok_or_else(refused)?;
                            if entry.generation != generation
                                || entry.bundle_digest != upload.bundle.digest()
                                || entry.pads_digest != upload.pads.digest()
                            {
                                return Err(refused());
                            }
                            attempt::settle_one(
                                vault,
                                attempt::AttemptKey::Auto(address),
                                &attempt,
                            )
                            .map_err(storage)?;
                            cursor.taken = Some(generation);
                            relay.published = Some(generation);
                            relay.incomplete_authority = upload.incomplete_authority;
                            relay.awaiting_reader = awaiting;
                            break;
                        }
                        work::WorkState::NeedsRebase => {
                            attempt::settle_one(
                                vault,
                                attempt::AttemptKey::Auto(address),
                                &attempt,
                            )
                            .map_err(storage)?;
                            Some(true)
                        }
                        work::WorkState::Refused => {
                            attempt::settle_one(
                                vault,
                                attempt::AttemptKey::Auto(address),
                                &attempt,
                            )
                            .map_err(storage)?;
                            Some(false)
                        }
                    },
                    work::WorkOutcome::Refused => {
                        attempt::settle_one(vault, attempt::AttemptKey::Auto(address), &attempt)
                            .map_err(storage)?;
                        Some(false)
                    }
                }
            };
            // A refused upload: when the newest generation moved meanwhile,
            // the parent went stale.
            let moved = match terminal {
                Some(moved) => moved,
                None => list_generations(rpc).await?.first().copied() != latest,
            };
            if moved {
                if retries == STALE_PARENT_RETRIES {
                    return Err(upload_refused());
                }
                retries += 1;
            } else {
                if refusals == SEALED_BUNDLE_NONSTALE_REFUSAL_RETRIES_PER_SLOT {
                    cursor.slot = self.slot;
                    store_cursor(vault, cursor).map_err(storage)?;
                    let _ = turn::ask_turn(rpc, true).await;
                    return Err(upload_refused());
                }
                refusals += 1;
            }
        }
        cursor.slot = self.slot;
        store_cursor(vault, cursor).map_err(storage)
    }
}
