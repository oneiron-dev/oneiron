//! A sealed window payload's isolated check before its capsule installs, and
//! the updates that wait for the pads they need (FIX 10474).

use super::*;

impl SyncClient {
    /// What answers an envelope of `key` under `sub_tag` whose pads did not
    /// install here: nothing of it imports. The home is told, sends this
    /// window as the carrier from now on, and is asked for it again.
    pub(super) fn not_ready_answer(
        &self,
        key: &WindowKey,
        sub_tag: u8,
        receipt: &WindowPadReceipt,
    ) -> Result<Vec<Vec<u8>>, TransportError> {
        match WINDOW_PAD_PART_REPAIR {
            WindowPadPartRepair::FreshCapsuleRebind => self.schedule_world_pad_repair(key),
        }
        let ask = if sub_tag == window_sub_tags::REPLACEMENT {
            transport::encode_window_sync(key.as_str(), window_sub_tags::REPLACEMENT_REQUEST, &[])
        } else {
            let window = self.ensure_window(key.as_str())?;
            transport::encode_window_sync(
                key.as_str(),
                window_sub_tags::VV_REQUEST,
                &doc_version_vector(&window.doc),
            )
        };
        Ok(vec![
            transport::encode_window_sync(
                key.as_str(),
                window_sub_tags::WINDOW_PAD_RECEIPT,
                &receipt.encode(),
            )
            .into_result()?,
            ask.into_result()?,
        ])
    }

    /// The isolated check a sealed envelope's `payload` of `key` under
    /// `sub_tag` passes before its capsule installs: the one its import door
    /// runs, on the bytes that door reads ([`Self::payload_as_admitted`]),
    /// without the cutoffs they carry staged (FIX 10474). An own-device update
    /// is read over its window with the world updates still staged for it, a
    /// replacement over a fresh window. A federation lane's frames take the
    /// federation admission at their door, and the other kinds the checks
    /// their callers run.
    pub(super) fn sealed_payload_check(
        &self,
        key: &WindowKey,
        sub_tag: u8,
        payload: &[u8],
    ) -> Result<SealedCheck, TransportError> {
        if self.config.federation_peer.is_some() {
            return Ok(SealedCheck::Admitted);
        }
        match sub_tag {
            window_sub_tags::UPDATE => {
                let window = self.ensure_window(key.as_str())?;
                let Some(admitted) = self.payload_as_admitted(payload, Some(&window.doc)) else {
                    return Ok(SealedCheck::Admitted);
                };
                let payload: &[u8] = &admitted;
                // A base window's import reads no staged world row.
                let world = key.world().is_some();
                let evidence = if world {
                    self.staged_entity_evidence()?
                } else {
                    HashMap::new()
                };
                let staged = world
                    .then(|| self.staged_pad_context(key, &window.doc))
                    .flatten();
                let doc = staged.as_ref().unwrap_or(&window.doc);
                match check_window_update_with_staged_worlds(
                    &self.vault,
                    doc,
                    payload,
                    key,
                    &evidence,
                ) {
                    Ok(()) => Ok(SealedCheck::Admitted),
                    Err(crate::Error::InvalidConfig(reason))
                        if world && reason == EDGE_ENDPOINT_UNRESOLVED =>
                    {
                        Ok(SealedCheck::Waits)
                    }
                    // Built on history this window's own shallow root cut
                    // away: the server's replacement brings it level.
                    Err(_)
                        if crate::sync::window::update_reaches_below_root(&window.doc, payload) =>
                    {
                        Ok(SealedCheck::Answered(vec![
                            transport::encode_window_sync(
                                key.as_str(),
                                window_sub_tags::REPLACEMENT_REQUEST,
                                &[],
                            )
                            .into_result()?,
                        ]))
                    }
                    Err(error) => Err(TransportError::from_window_admission(
                        &error,
                        UPDATE_REFUSAL,
                    )),
                }
            }
            window_sub_tags::REPLACEMENT => {
                let window = self.window(key.as_str());
                let Some(admitted) =
                    self.payload_as_admitted(payload, window.as_ref().map(|window| &window.doc))
                else {
                    return Ok(SealedCheck::Admitted);
                };
                let payload: &[u8] = &admitted;
                let evidence = self.staged_entity_evidence()?;
                check_bounded_replacement(
                    &self.vault,
                    key,
                    payload,
                    &evidence,
                    ReplacementByteBound::NetworkFrame,
                )
                .map(|()| SealedCheck::Admitted)
                .map_err(|error| {
                    if is_window_admission_read_fault(&error) {
                        TransportError::Storage(error.to_string())
                    } else {
                        TransportError::InvalidPayload("window replacement rejected")
                    }
                })
            }
            // A residence update goes up to the home only: one that came
            // down has no door here, and nothing of it installs.
            _ => Ok(SealedCheck::Answered(Vec::new())),
        }
    }

    /// `payload` as its import door reads it, `context` the window it imports
    /// into: its repo copies translated onto the sources this device holds,
    /// with nothing recorded (FIX 7608 slice 4). `None` when it holds on a
    /// ruled cause or its translation fails here: its door judges it once its
    /// pads are in, as it always did (FIX 10474). The recorded translation
    /// runs again after the pads install.
    pub(super) fn payload_as_admitted<'p>(
        &self,
        payload: &'p [u8],
        context: Option<&LoroDoc>,
    ) -> Option<Cow<'p, [u8]>> {
        crate::sync::selector::repo_sync_frame_as_admitted(&self.vault, payload, context)
            .ok()
            .flatten()
    }

    /// Keeps `envelope`, a sealed world update of `key` whose isolated check
    /// waits on an edge endpoint, uninstalled until the check passes (FIX
    /// 10474). It shares the staged updates' memory bound: past it, one
    /// waits alone, as a staged update does.
    pub(super) fn defer_sealed_update(
        &mut self,
        key: &WindowKey,
        envelope: ReceivedWindowPadEnvelope,
    ) -> Result<(), TransportError> {
        // The own-device import's bound on one update (FIX 8247).
        if envelope.payload.len() > MAX_WINDOW_PAD_PAYLOAD_BYTES {
            return Err(TransportError::FrameTooLarge {
                size: envelope.payload.len(),
                max: MAX_WINDOW_PAD_PAYLOAD_BYTES,
            });
        }
        self.deferred_sealed_updates.push(DeferredSealedUpdate {
            key: key.clone(),
            envelope,
            from: self.home_peer,
        });
        if self.staged_world_bytes() > MAX_DECODED_PAYLOAD_BYTES && self.staged_world_count() > 1 {
            self.deferred_sealed_updates.pop();
            return Err(TransportError::InvalidPayload(
                "unresolved world updates past the memory bound",
            ));
        }
        Ok(())
    }

    /// The bytes every world update waiting here holds: staged, or sealed and
    /// deferred.
    pub(in crate::sync::client) fn staged_world_bytes(&self) -> usize {
        let staged: usize = self
            .staged_world_updates
            .iter()
            .map(|(_, bytes, _)| bytes.len())
            .sum();
        let deferred: usize = self
            .deferred_sealed_updates
            .iter()
            .map(|update| update.envelope.payload.len())
            .sum();
        staged + deferred
    }

    /// How many world updates wait here: staged, or sealed and deferred.
    pub(in crate::sync::client) fn staged_world_count(&self) -> usize {
        self.staged_world_updates.len() + self.deferred_sealed_updates.len()
    }

    /// Every world update waiting here, by window: the bytes of each staged
    /// one, then the payload of each deferred sealed one.
    pub(in crate::sync::client) fn waiting_world_updates(
        &self,
    ) -> impl Iterator<Item = (&WindowKey, &[u8])> {
        let staged = self
            .staged_world_updates
            .iter()
            .map(|(key, bytes, _)| (key, bytes.as_slice()));
        let deferred = self
            .deferred_sealed_updates
            .iter()
            .map(|update| (&update.key, update.envelope.payload.as_slice()));
        staged.chain(deferred)
    }

    /// Installs each deferred sealed update whose isolated check now passes
    /// with `evidence` over its live window (FIX 10474): its pads go into
    /// custody and its payload, as the window imports it, joins the staged
    /// updates, to import as they do. One whose pads do not install imports
    /// nothing: under `answers` it goes, its answer added there; with none,
    /// it stays deferred, its pads' repair scheduled. One a demotion closed
    /// is dropped. Returns whether any left the deferred list installed or
    /// answered.
    ///
    /// # Errors
    ///
    /// A refusal other than a waiting edge endpoint; the update is dropped.
    pub(in crate::sync::client) fn install_deferred_sealed_updates(
        &mut self,
        evidence: &HashMap<crate::EntityId, (WindowKey, Vec<u8>)>,
        mut answers: Option<&mut Vec<Vec<u8>>>,
    ) -> Result<bool, TransportError> {
        let mut progressed = false;
        let mut index = 0;
        while index < self.deferred_sealed_updates.len() {
            let key = self.deferred_sealed_updates[index].key.clone();
            let live = self.ensure_window(key.as_str())?;
            // A window demoted since its frame was deferred stays closed.
            if !self.full_window_exchange_allowed(key.as_str())? {
                self.deferred_sealed_updates.remove(index);
                continue;
            }
            let checked = {
                let payload: &[u8] = &self.deferred_sealed_updates[index].envelope.payload;
                match self.payload_as_admitted(payload, Some(&live.doc)) {
                    // Its door judges it once its pads are in.
                    None => Ok(()),
                    Some(admitted) => check_window_update_with_staged_worlds(
                        &self.vault,
                        &live.doc,
                        &admitted,
                        &key,
                        evidence,
                    ),
                }
            };
            match checked {
                Ok(()) => {}
                Err(crate::Error::InvalidConfig(reason)) if reason == EDGE_ENDPOINT_UNRESOLVED => {
                    index += 1;
                    continue;
                }
                Err(error) => {
                    self.deferred_sealed_updates.remove(index);
                    return Err(TransportError::from_window_admission(
                        &error,
                        "staged world residence denied",
                    ));
                }
            }
            let deferred = self.deferred_sealed_updates.remove(index);
            // Read over its window with the updates still waiting for it
            // (FIX 10480), itself no longer among them.
            let receipt = {
                let staged = self.staged_pad_context(&key, &live.doc);
                admit_window_pads(
                    &self.vault,
                    &key,
                    &deferred.envelope,
                    Some(staged.as_ref().unwrap_or(&live.doc)),
                )
            };
            if receipt.readiness == WindowPadReadiness::NotReady {
                let Some(answers) = answers.as_deref_mut() else {
                    match WINDOW_PAD_PART_REPAIR {
                        WindowPadPartRepair::FreshCapsuleRebind => {
                            self.schedule_world_pad_repair(&key);
                        }
                    }
                    self.deferred_sealed_updates.insert(index, deferred);
                    index += 1;
                    continue;
                };
                answers.extend(self.not_ready_answer(&key, window_sub_tags::UPDATE, &receipt)?);
                progressed = true;
                continue;
            }
            progressed = true;
            // FIX 7608 slice 4: a copy edit lands on its source; a held one imports nothing.
            if let Some(payload) = deferred
                .envelope
                .into_payload()
                .try_map_owned(|payload| self.admitted_window_payload(&key, payload))?
            {
                self.staged_world_updates
                    .push((key, payload.to_vec(), deferred.from));
            }
        }
        Ok(progressed)
    }
}
