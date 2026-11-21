//! Staging one ASSET body streamed from a reader before its put.
//! The body's stream is measured, spilled and published as it passes.

use super::*;

impl crate::Vault {
    /// Streams `reader` into one staged ASSET body, before the transaction
    /// that puts it (FIX 3677): a body past [`ASSET_INLINE_BODY_BYTES`]
    /// spills to a temp file in the body directory as it streams, sealed as
    /// it streams on a sealed vault, and is published under its name (synced,
    /// renamed, the directory synced) when its stream shows it opaque,
    /// interpreted (FIX 22075) or an owning adapter's carrier (FIX 22091),
    /// or, when MessagePack leads it, when the whole-body classification
    /// files it ([`judge_messagepack`]: a record its stored-row readers read
    /// nothing from, or a pack source or shape seed, read whole once, among
    /// them; FIX 12150). Any other body is held whole for its row, as a
    /// slice put holds it. `mime`
    /// is the body's media type, kept in its manifest. Each value of `known`
    /// a published file carries is found as it streams, for its put to mark
    /// (FIX 5395). Nothing is refused for its size (Rule 5).
    ///
    /// A file is one vault instance (KS-2A), minted from `mint` before the
    /// writer that puts it opens: a stager inside a writer passes the
    /// instances reserved before it opened ([`Self::asset_body_mint`]), or
    /// none, and then its long body is read back whole for its row, which a
    /// checkpoint seals under an instance of its own. A spill no instance
    /// backs is a temp under a key held in memory, never published.
    ///
    /// # Errors
    ///
    /// The reader's error, filesystem and storage errors, and
    /// [`Error::InvalidConfig`] for a media type past 65535 bytes.
    pub(crate) fn stage_asset_body(
        &self,
        mut reader: impl Read,
        mime: Option<&str>,
        known: Option<Arc<KnownValues>>,
        mint: Option<&crate::store::BodyMint>,
    ) -> Result<StagedAssetBody> {
        if mime.is_some_and(|mime| mime.len() > usize::from(u16::MAX)) {
            return Err(Error::InvalidConfig(
                "an asset body's media type is past 65535 bytes".to_owned(),
            ));
        }
        let dir = self.store.body_dir()?;
        let mut meter = StageMeter::new(known);
        let mut inline = Vec::new();
        let mut spill = None::<Spill<'_>>;
        let mut frame = vec![0; LINE_INDEX_BLOCK_BYTES as usize];
        loop {
            let read = match reader.read(&mut frame) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            let bytes = &frame[..read];
            meter.feed(bytes);
            if let Some(spill) = &mut spill {
                spill.write(bytes)?;
            } else if (inline.len() + read) as u64 <= ASSET_INLINE_BODY_BYTES {
                inline.extend_from_slice(bytes);
            } else {
                let body = match mint.filter(|_| ASSET_FILE_PLANE) {
                    Some(mint) => BodySpill::create(&dir, Some(mint.mint()?))?,
                    None => BodySpill::ephemeral(&dir)?,
                };
                let mut opened = Spill {
                    dir: &dir,
                    body: Some(body),
                };
                opened.write(&inline)?;
                opened.write(bytes)?;
                inline = Vec::new();
                spill = Some(opened);
            }
        }
        let (facts, shape, text, json, known) = meter.finish();
        let staged = |body| StagedAssetBody {
            facts,
            mime: mime.map(str::to_owned),
            text,
            body,
            key: None,
            known: StreamKnown::default(),
            _pin: None,
        };
        let Some(spill) = spill else {
            return Ok(staged(Staged::Inline(inline)));
        };
        let spilled = spill.finish(&facts)?;
        let held = match spilled.reader() {
            Ok(held) => held,
            Err(error) => {
                dir.discard(spilled.temp());
                return Err(error);
            }
        };
        let whole = |held: &BodyFile| {
            let len = usize::try_from(facts.len)
                .map_err(|_| Error::InvariantViolation("asset body past this machine's memory"))?;
            held.read_range(0, len)
        };
        let kind = match shape {
            StreamShape::Opaque | StreamShape::Interpreted
                if ASSET_FILE_PLANE
                    && mint.is_some()
                    && json
                    && names_birth_source(&held, facts.len) =>
            {
                AssetFileKind::Carrier
            }
            StreamShape::Opaque if ASSET_FILE_PLANE && mint.is_some() => AssetFileKind::Opaque,
            StreamShape::Carrier if ASSET_FILE_PLANE && mint.is_some() => AssetFileKind::Carrier,
            StreamShape::Interpreted if ASSET_FILE_PLANE && mint.is_some() => {
                AssetFileKind::Interpreted
            }
            StreamShape::MessagePack if ASSET_FILE_PLANE && mint.is_some() => {
                match judge_messagepack(&held, facts.len)
                    .inspect_err(|_| dir.discard(spilled.temp()))?
                {
                    Judged::File(kind) => kind,
                    Judged::Row(bytes) => {
                        dir.discard(spilled.temp());
                        return Ok(staged(Staged::Inline(bytes)));
                    }
                }
            }
            _ => {
                // Read whole, as a slice put holds it: the batch door judges it.
                dir.discard(spilled.temp());
                return Ok(staged(Staged::Inline(whole(&held)?)));
            }
        };
        // Pinned before the name exists, so a collector unlinking a released
        // file of the same digest leaves this one alone.
        let pin = self.pin_result_body(facts.blake3);
        let key = spilled.publish(&dir)?;
        Ok(StagedAssetBody {
            key,
            // An interpreted or carrier file's values are placed by the batch
            // door, in its text and in each member, as a body in its row is
            // (FIX 22075, 22091): its stream's root matches mark nothing.
            known: if matches!(kind, AssetFileKind::Interpreted | AssetFileKind::Carrier) {
                StreamKnown::default()
            } else {
                known
            },
            _pin: Some(pin),
            ..staged(Staged::File { file: held, kind })
        })
    }
}
