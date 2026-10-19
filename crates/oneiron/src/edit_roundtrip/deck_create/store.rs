//! Transaction-bound outline and version inputs shared by the engine and public doors.
use super::*;

impl crate::Vault {
    pub(crate) fn fresh_outline_in_txn(&self, txn: &heed::RoTxn<'_>, note: EntityId) -> std::result::Result<KeptOutline, DeckCreateError> {
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
        OUTLINE_KEEPS.get(&self.store, txn, &note)?
            .ok_or_else(|| invalid("the outline is not kept"))
    }

    /// Set each evidence pin's `drift` from its note cursors. A pin without
    /// a cited CLAIM, or whose ids and cursors are not this engine's, keeps
    /// the caller's flag.
    pub(super) fn map_evidence_in_txn(&self, txn: &heed::RoTxn<'_>, outline: &mut Value) -> std::result::Result<(), DeckCreateError> {
        let mut result = Ok(());
        pins_mut(outline, &mut |pin| {
            if result.is_err() {
                return;
            }
            let Some(note_pin) = note_pin(pin) else {
                return;
            };
            let drifted = !matches!(
                crate::note::resolve_deck_pin_in_txn(self, txn, &note_pin),
                Ok(NoteSpanResolution::Mapped { .. })
            );
            if let Some(object) = pin.as_object_mut() {
                object.insert("drift".to_owned(), Value::Bool(drifted));
            } else {
                result = Err(invalid("evidence pin is not an object"));
            }
        });
        result
    }

    pub(super) fn version_bytes_in_txn(&self, txn: &heed::RoTxn<'_>, at: &ArtifactVersionRef) -> Result<Vec<u8>> {
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
        return Err(invalid("outline claim pins require engine ids, frontiers and cursors"));
    }
    Ok(found)
}
