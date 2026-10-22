//! Transaction-bound outline and version inputs shared by the engine and public doors.
use super::*;

impl crate::Vault {
    pub(crate) fn fresh_outline_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        note: EntityId,
    ) -> std::result::Result<KeptOutline, DeckCreateError> {
        match self.deck_outline_freshness_in_txn(txn, note)? {
            OutlineFreshness::Fresh => {}
            OutlineFreshness::NotKept => return Err(invalid("the outline is not kept")),
            OutlineFreshness::Edited => {
                return Err(invalid("the outline changed after its keep; keep it again"));
            }
            OutlineFreshness::EvidenceMoved { .. } => {
                return Err(invalid(
                    "cited evidence moved after the keep; keep it again",
                ));
            }
        }
        OUTLINE_KEEPS
            .get(&self.store, txn, &note)?
            .ok_or_else(|| invalid("the outline is not kept"))
    }

    /// Set each evidence pin's `drift` from its note cursors: a cited
    /// CLAIM's pin always, and with `claimless`, a note document span named
    /// without one (FIX 9814). A pin whose ids and cursors are not this
    /// engine's keeps the caller's flag.
    pub(super) fn map_evidence_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        outline: &mut Value,
        claimless: bool,
    ) -> std::result::Result<(), DeckCreateError> {
        let mut result = Ok(());
        pins_mut(outline, &mut |pin| {
            if result.is_err() {
                return;
            }
            let drifted = if let Some(note_pin) = note_pin(pin) {
                !matches!(
                    crate::note::resolve_deck_pin_in_txn(self, txn, &note_pin),
                    Ok(NoteSpanResolution::Mapped { .. })
                )
            } else if claimless
                && let Some(span) = engine_span(pin).filter(|span| span.claim.is_none())
            {
                !self
                    .observe_span_in_txn(txn, &span)
                    .is_ok_and(|seen| seen.mapped)
            } else {
                return;
            };
            if let Some(object) = pin.as_object_mut() {
                object.insert("drift".to_owned(), Value::Bool(drifted));
            } else {
                result = Err(invalid("evidence pin is not an object"));
            }
        });
        result
    }

    /// What the engine observes of each pin of `outline` it can address, in
    /// document order: the cited document's frontier, the cited CLAIM's
    /// lifecycle and whether the span maps (FIX 9813, 9814). A source that
    /// no longer resolves is observed as such, never an error.
    pub(super) fn observe_evidence_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        outline: &Value,
    ) -> std::result::Result<Vec<EvidenceObservation>, DeckCreateError> {
        let mut spans = Vec::new();
        let mut index = 0;
        pins(outline, &mut |pin| {
            if let Some(span) = engine_span(pin) {
                spans.push((index, span));
            }
            index += 1;
        });
        let mut observed = Vec::with_capacity(spans.len());
        for (pin, span) in spans {
            let seen = self.observe_span_in_txn(txn, &span).ok();
            let lifecycle = match &span.claim {
                Some(claim) => self
                    .get_claim_in_txn(txn, claim)?
                    .map(|body| cited_lifecycle(body.lifecycle)),
                None => None,
            };
            observed.push(EvidenceObservation {
                pin,
                source_frontier: seen.as_ref().map(|seen| seen.frontier.clone()),
                lifecycle,
                mapped: seen.is_some_and(|seen| seen.mapped),
            });
        }
        Ok(observed)
    }

    fn observe_span_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        span: &EngineSpan,
    ) -> Result<crate::note::DeckSpanObservation> {
        crate::note::observe_deck_span_in_txn(
            self,
            txn,
            span.document,
            span.claim,
            &span.start,
            &span.end,
            &span.quote_hash,
        )
    }

    pub(super) fn version_bytes_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        at: &ArtifactVersionRef,
    ) -> Result<Vec<u8>> {
        self.read_blob_artifact_version_in_txn(txn, &at.artifact, at.version)?
            .ok_or(Error::EntityNotFound)
    }

    pub(super) fn font_book_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fonts: &[ArtifactVersionRef],
    ) -> std::result::Result<FontBook, DeckCreateError> {
        let mut book = FontBook::new();
        for font in fonts {
            book.add(self.version_bytes_in_txn(txn, font)?)?;
        }
        Ok(book)
    }

    pub(super) fn asset_bindings_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        assets: &BTreeMap<String, ArtifactVersionRef>,
    ) -> std::result::Result<BTreeMap<String, AssetBinding>, DeckCreateError> {
        assets
            .iter()
            .map(|(asset, at)| {
                Ok((
                    asset.clone(),
                    AssetBinding {
                        handle: at.artifact.to_hex(),
                        media: self.asset_media_in_txn(txn, at)?,
                    },
                ))
            })
            .collect()
    }

    pub(super) fn asset_media_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        at: &ArtifactVersionRef,
    ) -> std::result::Result<MediaType, DeckCreateError> {
        let body = self
            .get_blob_artifact_in_txn(txn, &at.artifact)?
            .ok_or(Error::EntityNotFound)?;
        match body.media_type.as_str() {
            "image/png" => Ok(MediaType::Png),
            "image/jpeg" => Ok(MediaType::Jpeg),
            "image/svg+xml" => Ok(MediaType::Svg),
            _ => Err(invalid("an asset must be PNG, JPEG or SVG")),
        }
    }

    /// Held assets as admitted records with their bytes; the description is
    /// the brief's intended content for the asset.
    pub(super) fn asset_records_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        assets: &BTreeMap<String, ArtifactVersionRef>,
        kept: &KeptOutline,
    ) -> std::result::Result<BTreeMap<String, (AssetRecord, Vec<u8>)>, DeckCreateError> {
        let brief = Brief::parse(&kept.bytes).map_err(CompileError::from)?;
        let mut out = BTreeMap::new();
        for (asset, at) in assets {
            let metadata = self
                .blob_artifact_version_metadata_in_txn(txn, &at.artifact, at.version)?
                .ok_or(Error::EntityNotFound)?;
            let description = brief
                .assets
                .iter()
                .find(|held| held.id == *asset)
                .map(|held| held.content.clone())
                .ok_or_else(|| invalid("a bound asset is not in the outline"))?;
            out.insert(
                asset.clone(),
                (
                    AssetRecord {
                        artifact: at.artifact.to_hex(),
                        version: at.version,
                        content_hash: metadata.content_hash,
                        media: self.asset_media_in_txn(txn, at)?,
                        origin: Origin::Held,
                        provenance: vec![format!(
                            "blob:{}@{}:{}",
                            at.artifact.to_hex(),
                            at.version,
                            metadata.provenance.as_str()
                        )],
                        rights: Vec::new(),
                        description,
                    },
                    self.version_bytes_in_txn(txn, at)?,
                ),
            );
        }
        Ok(out)
    }
}

/// The engine citation pins the closed outline names.
pub(crate) fn outline_pins(bytes: &[u8]) -> std::result::Result<Vec<NotePin>, DeckCreateError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid("outline encoding"))?;
    let mut found = Vec::new();
    let mut bad = false;
    pins(&value, &mut |pin| {
        if pin.get("claim").is_some() {
            match note_pin(pin) {
                Some(pin) => found.push(pin),
                None => bad = true,
            }
        }
    });
    if bad {
        return Err(invalid(
            "outline claim pins require engine ids, frontiers and cursors",
        ));
    }
    Ok(found)
}
