//! Window blob release and admission: a window blob as a sync peer gets
//! it, and a peer's blob as this window takes it.

use super::*;

impl SyncSecretProjection {
    /// `encoded`, a window blob leaving this device, as a sync peer gets it;
    /// `context` holds an update's dependencies, copied and never changed.
    /// `None` when nothing marked is in it: the caller sends it as it is.
    /// `home` is set for a device's send to its home: an update that goes as
    /// it is then also carries each marked copy re-authored (FIX 10729).
    /// `observe`, when set, sees the post-projection `released` doc in the
    /// Updates Some path just before its final export (FIX2999).
    ///
    /// # Errors
    /// A store failure, or a blob carrying a marked item that cannot be
    /// masked: the caller withholds it and keeps it owed.
    pub(crate) fn release_window_blob(
        &self,
        store: &Store,
        encoded: &[u8],
        context: Option<&LoroDoc>,
        home: bool,
        observe: Option<&mut dyn FnMut(&LoroDoc)>,
    ) -> Result<Option<Vec<u8>>> {
        if self.is_empty() {
            return Ok(None);
        }
        // A blob whose import metadata does not decode has unread contents:
        // while any mark exists it is withheld and stays owed, never sent
        // raw (FIX 10831).
        let Some(input) = meta(encoded) else {
            return Err(Error::InvariantViolation(UNMASKABLE));
        };
        match input.mode {
            EncodedBlobMode::Snapshot | EncodedBlobMode::ShallowSnapshot => {
                let doc =
                    LoroDoc::from_snapshot(encoded).map_err(decode("window copy snapshot"))?;
                let Some(mut parts) = parts_of(&doc) else {
                    return self.unclassified(&doc, &VersionVector::default(), &doc.oplog_vv());
                };
                if !self.release_parts(store, &mut parts)? {
                    return Ok(None);
                }
                let bytes = joined(&parts)?;
                let out = meta(&bytes).ok_or(Error::InvariantViolation(UNMASKABLE))?;
                same_span(&input, &out, &input.mode)
                    .then_some(Some(bytes))
                    .ok_or(Error::InvariantViolation(UNMASKABLE))
            }
            EncodedBlobMode::Updates => {
                // An update is judged by its own operations before anything
                // is rebuilt (FIX 10794): one that carries nothing marked goes
                // as it is. One this device cannot read (it does not hold the
                // update's dependencies) has unknown contents: withheld, owed.
                let Some((scratch, cut)) = with_update(context, encoded) else {
                    return Err(Error::InvariantViolation(UNMASKABLE));
                };
                if !readable_from(&scratch, &input.partial_start_vv) {
                    return Err(Error::InvariantViolation(UNMASKABLE));
                }
                let mut json =
                    scratch.export_json_updates(&input.partial_start_vv, &input.partial_end_vv);
                // A row held as a pad reference is judged by its carrier.
                resolve_carriers(store, &mut json, |_, _| true);
                let carried = self.project_history(&mut json);
                if carried.changed.is_empty() && carried.preserving {
                    // Its registers are not rebuilt, so a re-authored copy
                    // rides along without meeting a rekeyed one (FIX 10729).
                    // The window copy holding the update is the one already
                    // made, never cut again (FIX 10599).
                    return match context.filter(|_| home) {
                        Some(window) => self.reauthored(
                            store,
                            window,
                            window.peer_id(),
                            encoded,
                            spans_of(&input),
                            cut.is_some().then_some(scratch),
                        ),
                        None => Ok(None),
                    };
                }
                let spans = spans_of(&input);
                let Some(mut parts) = parts_of(&scratch).filter(|_| carried.preserving) else {
                    return Err(Error::InvariantViolation(UNMASKABLE));
                };
                if !self.release_parts(store, &mut parts)? {
                    return Err(Error::InvariantViolation(UNMASKABLE));
                }
                let slice = scratch
                    .export(ExportMode::updates_in_range(spans.clone()))
                    .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?;
                let released = LoroDoc::from_snapshot(&joined(&parts)?)
                    .map_err(decode("window copy rebuild"))?;
                if let Some(observe) = observe {
                    observe(&released);
                }
                let bytes = released
                    .export(ExportMode::updates_in_range(spans))
                    .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?;
                let same = match (meta(&bytes), meta(&slice)) {
                    (Some(out), Some(slice)) => {
                        same_span(&input, &out, &EncodedBlobMode::Updates)
                            && out.change_num == slice.change_num
                    }
                    _ => false,
                };
                same.then_some(Some(bytes))
                    .ok_or(Error::InvariantViolation(UNMASKABLE))
            }
            EncodedBlobMode::OutdatedSnapshot | EncodedBlobMode::OutdatedRle => {
                let doc = LoroDoc::new();
                match doc.import(encoded) {
                    Ok(status) if status.pending.is_none() => {
                        self.unclassified(&doc, &VersionVector::default(), &doc.oplog_vv())
                    }
                    _ => Err(Error::InvariantViolation(UNMASKABLE)),
                }
            }
        }
    }

    /// `encoded`, a window blob a peer sent, as this window takes it;
    /// `context` is this window, copied and never changed. A blob that is
    /// not a copy, or one this device cannot read without the ordinary
    /// admission (missing dependencies, an unknown shape), is admitted as it
    /// came and judged there as today.
    ///
    /// # Errors
    /// A store failure, or the visible diff's own failure.
    pub(crate) fn admit_window_blob<'a>(
        &self,
        store: &Store,
        encoded: &'a [u8],
        context: Option<&LoroDoc>,
    ) -> Result<WindowAdmission<'a>> {
        let as_sent = || {
            Ok(WindowAdmission::Admit(
                Cow::Borrowed(encoded),
                Vec::new(),
                Vec::new(),
            ))
        };
        if self.is_empty() {
            return as_sent();
        }
        let Some(input) = meta(encoded) else {
            return as_sent();
        };
        match input.mode {
            EncodedBlobMode::Snapshot | EncodedBlobMode::ShallowSnapshot => {
                let Ok(doc) = LoroDoc::from_snapshot(encoded) else {
                    return as_sent();
                };
                let Some(mut parts) = parts_of(&doc) else {
                    return as_sent();
                };
                let mut held = Vec::new();
                let mut landings = Vec::new();
                if !self.admit_parts(store, context, &mut parts, &mut held, &mut landings)? {
                    return as_sent();
                }
                if !held.is_empty() {
                    if let Some(admitted) = self
                        .admit_held_full_snapshot(store, context, &doc, &input)
                        .or_else(|| self.admit_held_shallow_snapshot(store, context, &doc, &input))
                    {
                        return Ok(admitted);
                    }
                    return Ok(WindowAdmission::Held(held));
                }
                Ok(WindowAdmission::Admit(
                    Cow::Owned(joined(&parts)?),
                    landings,
                    Vec::new(),
                ))
            }
            EncodedBlobMode::Updates => {
                let Some((scratch, cut)) = with_update(context, encoded) else {
                    return as_sent();
                };
                let mut json =
                    scratch.export_json_updates(&input.partial_start_vv, &input.partial_end_vv);
                self.resolve_copy_carriers(store, &mut json);
                let translated = self.translate_history(store, context, &mut json)?;
                // Other carriers or a shell can depend on the held row.
                // Keep their whole-blob hold, not a newly refused update.
                if !translated.held.is_empty() && needs_whole_hold(&json) {
                    return Ok(WindowAdmission::Held(translated.held));
                }
                if let Err(error) = self.unread_rows(store, context, &json) {
                    return if translated.held.is_empty() {
                        Err(error)
                    } else {
                        Ok(WindowAdmission::Held(translated.held))
                    };
                }
                if translated.sources.is_empty() && translated.held.is_empty() {
                    return as_sent();
                }
                // A proven copy edit is never admitted untranslated. The
                // window's cut is read again, never made again (FIX 10599).
                let target = match &cut {
                    Some(cut) => cut.copy(),
                    None => isolated(context),
                };
                let Some(target) = target else {
                    return Err(Error::InvariantViolation(UNMASKABLE));
                };
                let status = target
                    .import_json_updates(json)
                    .map_err(decode("window copy translation"))?;
                if status.pending.is_some() {
                    return if translated.held.is_empty() {
                        as_sent()
                    } else {
                        Ok(WindowAdmission::Held(translated.held))
                    };
                }
                let bytes = target
                    .export(ExportMode::updates_in_range(spans_of(&input)))
                    .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))?;
                Ok(WindowAdmission::Admit(
                    Cow::Owned(bytes),
                    translated.landings,
                    translated.held,
                ))
            }
            EncodedBlobMode::OutdatedSnapshot | EncodedBlobMode::OutdatedRle => as_sent(),
        }
    }

    /// Each marked row value of `parts` as its copy, and each key naming a
    /// marked source as its copy's, in place; whether any changed. A row held
    /// as a pad reference whose pad is here is judged by its carrier, so a
    /// marked row is never shipped as a reference whose pad carries it raw.
    ///
    /// # Errors
    /// A row whose copy is unread this pass: the blob is withheld and owed.
    fn release_parts(&self, store: &Store, parts: &mut Parts) -> Result<bool> {
        let rows = parts.skeleton.roots.iter().position(|root| root == ROWS);
        let sites = sites(&parts.skeleton);
        let mut changed = false;
        for atom in &mut parts.atoms {
            let Some(id) = row_site(&sites, rows, atom.id) else {
                continue;
            };
            let Payload::Value(LoroValue::Binary(raw)) = &atom.payload else {
                continue;
            };
            let raw: &[u8] = raw;
            let carrier = crate::world_keys::image_pad_row(store, raw);
            match self.project_row(&id, carrier.as_deref().unwrap_or(raw)) {
                CopyRow::Keep => {}
                CopyRow::Copy { row, .. } => {
                    atom.payload = Payload::Value(LoroValue::Binary(row.into()));
                    changed = true;
                }
                CopyRow::Sealed { .. } => return Err(Error::InvariantViolation(UNREAD)),
            }
        }
        Ok(rekey_skeleton(&mut parts.skeleton, |key| self.rekey(key)) || changed)
    }

    /// Each copy row value of `parts` as its source row, and each copy key as
    /// its source's, in place; whether any changed. Ruled holds go to `held`,
    /// the new bytes an applied diff lands to `landings` (FIX 10732).
    ///
    /// # Errors
    /// The visible diff's own failure, or a row [`Self::unread_row`] cannot
    /// judge this pass.
    pub(super) fn admit_parts(
        &self,
        store: &Store,
        context: Option<&LoroDoc>,
        parts: &mut Parts,
        held: &mut Vec<HeldEdit>,
        landings: &mut Vec<Landing>,
    ) -> Result<bool> {
        let rows = parts.skeleton.roots.iter().position(|root| root == ROWS);
        let sites = sites(&parts.skeleton);
        let mut changed = false;
        for atom in &mut parts.atoms {
            let Some(id) = row_site(&sites, rows, atom.id) else {
                continue;
            };
            let Payload::Value(LoroValue::Binary(raw)) = &atom.payload else {
                continue;
            };
            let raw: &[u8] = raw;
            let carrier = crate::world_keys::image_pad_row(store, raw);
            match self.source_row(&id, carrier.as_deref().unwrap_or(raw))? {
                InboundRow::Source { id, row, landed } => {
                    if let Some(blob) = landed {
                        landings.push(Landing::of(id, blob, &row));
                    }
                    atom.payload = Payload::Value(LoroValue::Binary(row.into()));
                    changed = true;
                }
                InboundRow::Held(edit) => held.push(edit),
                InboundRow::Ordinary => self.unread_row(store, context, &id)?,
            }
        }
        Ok(rekey_skeleton(&mut parts.skeleton, |key| self.source_key(key)) || changed)
    }

    /// Fails when this window's own row `id` (in `context`, its pad carrier
    /// read) is a marked blob's whole bytes whose copy is unread this pass,
    /// and `id` is no marked source: a peer's write of it may be an edit of
    /// that copy, which this pass cannot judge, so it is not admitted and
    /// stays the peer's pending work (fail closed for unknown markedness,
    /// CALL S4FIX-UNKNOWN-MARK). A marked source's own id is a raw holder's
    /// write, admitted as today.
    pub(super) fn unread_row(
        &self,
        store: &Store,
        context: Option<&LoroDoc>,
        id: &EntityId,
    ) -> Result<()> {
        if self.unread_is_empty() || self.has_source(id) {
            return Ok(());
        }
        let Some(context) = context else {
            return Ok(());
        };
        let Some(loro::ValueOrContainer::Value(LoroValue::Binary(raw))) =
            context.get_map(ROWS).get(&id.to_hex())
        else {
            return Ok(());
        };
        let raw: &[u8] = &raw;
        let carrier = crate::world_keys::image_pad_row(store, raw);
        let unread = carrier
            .as_deref()
            .unwrap_or(raw)
            .get(ENTITY_METADATA_HEADER_LEN..)
            .is_some_and(|body| self.is_unread(ContentHash::of(body).as_bytes()));
        if unread {
            return Err(Error::InvariantViolation(UNREAD_EDIT));
        }
        Ok(())
    }

    /// [`Self::unread_row`] for every row `json` writes.
    pub(super) fn unread_rows(
        &self,
        store: &Store,
        context: Option<&LoroDoc>,
        json: &JsonSchema,
    ) -> Result<()> {
        if self.unread_is_empty() {
            return Ok(());
        }
        for op in json.changes.iter().flat_map(|change| &change.ops) {
            let ContainerID::Root {
                name,
                container_type: ContainerType::Map,
            } = &op.container
            else {
                continue;
            };
            if let (true, JsonOpContent::Map(MapOp::Insert { key, .. })) =
                (name.as_str() == ROWS, &op.content)
                && let Ok(id) = EntityId::from_hex(key)
            {
                self.unread_row(store, context, &id)?;
            }
        }
        Ok(())
    }

    /// A blob the checkpoint does not take: released as it is only when
    /// neither its operations between `from` and `to` nor its state carry
    /// anything marked.
    fn unclassified(
        &self,
        doc: &LoroDoc,
        from: &VersionVector,
        to: &VersionVector,
    ) -> Result<Option<Vec<u8>>> {
        let mut json = doc.export_json_updates(from, to);
        let projected = self.project_history(&mut json);
        if !projected.changed.is_empty() || !projected.preserving || self.state_carries_marked(doc)
        {
            return Err(Error::InvariantViolation(UNMASKABLE));
        }
        Ok(None)
    }

    /// Whether any root map of `doc` holds a marked row or a key naming a
    /// marked source.
    fn state_carries_marked(&self, doc: &LoroDoc) -> bool {
        let LoroValue::Map(roots) = doc.get_deep_value() else {
            return false;
        };
        roots.iter().any(|(root, value)| {
            let LoroValue::Map(entries) = value else {
                return false;
            };
            entries.iter().any(|(key, value)| {
                if self.rekey(key).is_some() {
                    return true;
                }
                let (true, LoroValue::Binary(raw), Ok(id)) =
                    (root == ROWS, value, EntityId::from_hex(key))
                else {
                    return false;
                };
                self.project_row(&id, raw) != CopyRow::Keep
            })
        })
    }
}
