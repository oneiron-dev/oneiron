//! Real font metrics for fit estimates (ARCH-0077, "Fit estimate"): a
//! bounded sfnt reader for TrueType and CFF OpenType faces, collections
//! included. It maps characters to glyph advances through `cmap` (formats 4
//! and 12) and `hmtx`, and reads the line metrics from `OS/2` or `hhea`.
//!
//! It shapes nothing. Text in a script that needs shaping, or with a
//! character the face does not map, has no measured width: the estimate
//! falls back to the em rule and says so. Estimates choose candidates; they
//! never certify fit.
use std::sync::Arc;

/// Bytes in one font file.
pub const MAX_FONT_BYTES: usize = 64 << 20;
/// Faces read from one collection.
pub const MAX_FACES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FontError {
    #[error("font file over the size limit")]
    TooLarge,
    #[error("not an sfnt font: {0}")]
    Invalid(&'static str),
    #[error("font table missing: {0}")]
    Missing(&'static str),
}

/// The faces a deck's text may be measured with, by family and style.
#[derive(Debug, Clone, Default)]
pub struct FontBook {
    faces: Vec<Arc<Face>>,
}

impl FontBook {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add every face in a font file or collection; returns how many.
    pub fn add(&mut self, bytes: Vec<u8>) -> Result<usize, FontError> {
        if bytes.len() > MAX_FONT_BYTES {
            return Err(FontError::TooLarge);
        }
        let data: Arc<[u8]> = bytes.into();
        let offsets = if data.get(0..4) == Some(&b"ttcf"[..]) {
            let count = u32_at(&data, 8).ok_or(FontError::Invalid("collection header"))?;
            let count = usize::try_from(count)
                .map_err(|_| FontError::Invalid("collection header"))?
                .min(MAX_FACES);
            (0..count)
                .map(|index| {
                    u32_at(&data, 12 + 4 * index)
                        .and_then(|offset| usize::try_from(offset).ok())
                        .ok_or(FontError::Invalid("collection offsets"))
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            vec![0]
        };
        let mut added = 0;
        for offset in offsets {
            self.faces
                .push(Arc::new(Face::parse(data.clone(), offset)?));
            added += 1;
        }
        Ok(added)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.faces.is_empty()
    }

    /// The face for `family` closest to the requested style: the exact
    /// style, then the same weight, then any face of the family.
    #[must_use]
    pub fn face(&self, family: &str, bold: bool, italic: bool) -> Option<Arc<Face>> {
        let family = family.trim();
        let candidates: Vec<&Arc<Face>> = self
            .faces
            .iter()
            .filter(|face| face.family.eq_ignore_ascii_case(family))
            .collect();
        candidates
            .iter()
            .find(|face| face.bold == bold && face.italic == italic)
            .or_else(|| candidates.iter().find(|face| face.bold == bold))
            .or_else(|| candidates.first())
            .map(|face| Arc::clone(face))
    }
}

/// One parsed face. Lookups read the retained file bytes.
#[derive(Debug)]
pub struct Face {
    data: Arc<[u8]>,
    family: String,
    bold: bool,
    italic: bool,
    units_per_em: u16,
    /// Ascent plus descent plus gap, in font units: one single-spaced line.
    line: i64,
    glyphs: u16,
    metrics: u16,
    hmtx: usize,
    cmap: CharMap,
}

#[derive(Debug, Clone, Copy)]
enum CharMap {
    /// Format 4 subtable offset and its segment count.
    Segments { at: usize, count: usize },
    /// Format 12 subtable offset and its group count.
    Groups { at: usize, count: usize },
}

impl Face {
    fn parse(data: Arc<[u8]>, base: usize) -> Result<Self, FontError> {
        let version = u32_at(&data, base).ok_or(FontError::Invalid("offset table"))?;
        if !matches!(version, 0x0001_0000 | 0x4F54_544F | 0x7472_7565) {
            return Err(FontError::Invalid("sfnt version"));
        }
        let tables =
            usize::from(u16_at(&data, base + 4).ok_or(FontError::Invalid("offset table"))?);
        let table = |tag: &[u8; 4]| -> Option<(usize, usize)> {
            (0..tables).find_map(|index| {
                let record = base + 12 + 16 * index;
                (data.get(record..record + 4)? == tag).then_some(())?;
                let offset = usize::try_from(u32_at(&data, record + 8)?).ok()?;
                let length = usize::try_from(u32_at(&data, record + 12)?).ok()?;
                (offset.checked_add(length)? <= data.len()).then_some((offset, length))
            })
        };
        let (head, _) = table(b"head").ok_or(FontError::Missing("head"))?;
        let (hhea, _) = table(b"hhea").ok_or(FontError::Missing("hhea"))?;
        let (maxp, _) = table(b"maxp").ok_or(FontError::Missing("maxp"))?;
        let (hmtx, hmtx_length) = table(b"hmtx").ok_or(FontError::Missing("hmtx"))?;
        let (cmap, _) = table(b"cmap").ok_or(FontError::Missing("cmap"))?;
        let (name, _) = table(b"name").ok_or(FontError::Missing("name"))?;
        let units_per_em = u16_at(&data, head + 18).ok_or(FontError::Invalid("head"))?;
        if !(16..=16_384).contains(&units_per_em) {
            return Err(FontError::Invalid("unitsPerEm"));
        }
        let glyphs = u16_at(&data, maxp + 4).ok_or(FontError::Invalid("maxp"))?;
        let metrics = u16_at(&data, hhea + 34).ok_or(FontError::Invalid("hhea"))?;
        if metrics == 0 || usize::from(metrics) * 4 > hmtx_length {
            return Err(FontError::Invalid("hmtx"));
        }
        let hhea_line = i64::from(i16_at(&data, hhea + 4).ok_or(FontError::Invalid("hhea"))?)
            - i64::from(i16_at(&data, hhea + 6).ok_or(FontError::Invalid("hhea"))?)
            + i64::from(i16_at(&data, hhea + 8).ok_or(FontError::Invalid("hhea"))?);
        let os2 = table(b"OS/2");
        // Office lays lines out on the Windows ascent and descent.
        let line = os2
            .and_then(|(os2, _)| {
                Some(i64::from(u16_at(&data, os2 + 74)?) + i64::from(u16_at(&data, os2 + 76)?))
            })
            .filter(|line| *line > 0)
            .unwrap_or(hhea_line);
        if line <= 0 {
            return Err(FontError::Invalid("line metrics"));
        }
        let selection = os2.and_then(|(os2, _)| u16_at(&data, os2 + 62));
        let weight = os2.and_then(|(os2, _)| u16_at(&data, os2 + 4));
        let mac_style = u16_at(&data, head + 44).unwrap_or(0);
        let bold = selection.map_or(mac_style & 1 != 0, |bits| bits & 0x20 != 0)
            || weight.is_some_and(|weight| weight >= 600);
        let italic = selection.map_or(mac_style & 2 != 0, |bits| bits & 0x01 != 0);
        let family = family(&data, name).ok_or(FontError::Missing("family name"))?;
        let cmap = char_map(&data, cmap).ok_or(FontError::Missing("unicode cmap"))?;
        Ok(Self {
            data,
            family,
            bold,
            italic,
            units_per_em,
            line,
            glyphs,
            metrics,
            hmtx,
            cmap,
        })
    }

    #[must_use]
    pub fn family(&self) -> &str {
        &self.family
    }

    #[must_use]
    pub const fn bold(&self) -> bool {
        self.bold
    }

    #[must_use]
    pub const fn italic(&self) -> bool {
        self.italic
    }

    /// The width of `text` at `size` (both in EMU), or `None` when a
    /// character is unmapped or needs shaping.
    #[must_use]
    pub fn advance(&self, text: &str, size: i64) -> Option<i64> {
        let mut units: i64 = 0;
        for ch in text.chars() {
            if needs_shaping(ch) {
                return None;
            }
            if ch.is_control() {
                continue;
            }
            let glyph = self.glyph(ch)?;
            units += i64::from(self.advance_units(glyph)?);
        }
        Some(units * size / i64::from(self.units_per_em))
    }

    /// One single-spaced line at `size`, in EMU.
    #[must_use]
    pub fn line(&self, size: i64) -> i64 {
        self.line * size / i64::from(self.units_per_em)
    }

    fn advance_units(&self, glyph: u16) -> Option<u16> {
        if glyph >= self.glyphs {
            return None;
        }
        let index = glyph.min(self.metrics - 1);
        u16_at(&self.data, self.hmtx + 4 * usize::from(index))
    }

    fn glyph(&self, ch: char) -> Option<u16> {
        let code = u32::from(ch);
        let data = &self.data;
        let glyph = match self.cmap {
            CharMap::Segments { at, count } => {
                let code = u16::try_from(code).ok()?;
                let ends = at + 14;
                let starts = ends + 2 * count + 2;
                let deltas = starts + 2 * count;
                let ranges = deltas + 2 * count;
                let segment = (0..count)
                    .find(|&i| u16_at(data, ends + 2 * i).is_some_and(|end| end >= code))?;
                let start = u16_at(data, starts + 2 * segment)?;
                if start > code {
                    return None;
                }
                let delta = u16_at(data, deltas + 2 * segment)?;
                let range = u16_at(data, ranges + 2 * segment)?;
                if range == 0 {
                    code.wrapping_add(delta)
                } else {
                    let at =
                        ranges + 2 * segment + usize::from(range) + 2 * usize::from(code - start);
                    match u16_at(data, at)? {
                        0 => 0,
                        glyph => glyph.wrapping_add(delta),
                    }
                }
            }
            CharMap::Groups { at, count } => {
                let groups = at + 16;
                let group = (0..count)
                    .find(|&i| u32_at(data, groups + 12 * i + 4).is_some_and(|end| end >= code))?;
                let start = u32_at(data, groups + 12 * group)?;
                if start > code {
                    return None;
                }
                let first = u32_at(data, groups + 12 * group + 8)?;
                u16::try_from(first.checked_add(code - start)?).ok()?
            }
        };
        (glyph != 0).then_some(glyph)
    }
}

/// Characters of scripts whose widths depend on shaping: joining, reordering
/// or stacking marks, and combining marks anywhere.
#[must_use]
pub fn needs_shaping(ch: char) -> bool {
    matches!(u32::from(ch),
        0x0300..=0x036F
        | 0x0590..=0x08FF
        | 0x0900..=0x0DFF
        | 0x0E00..=0x0EFF
        | 0x0F00..=0x0FFF
        | 0x1000..=0x109F
        | 0x1780..=0x17FF
        | 0x1A00..=0x1AFF
        | 0x1B00..=0x1BFF
        | 0x200C..=0x200F
        | 0xA800..=0xABFF
        | 0xFB1D..=0xFDFF
        | 0xFE20..=0xFE2F
        | 0xFE70..=0xFEFF)
}

/// The typographic family (name id 16), else the family (id 1), preferring
/// Windows English names.
fn family(data: &[u8], name: usize) -> Option<String> {
    let count = usize::from(u16_at(data, name + 2)?);
    let strings = name + usize::from(u16_at(data, name + 4)?);
    let mut best: Option<(u8, String)> = None;
    for index in 0..count {
        let record = name + 6 + 12 * index;
        let platform = u16_at(data, record)?;
        let encoding = u16_at(data, record + 2)?;
        let language = u16_at(data, record + 4)?;
        let id = u16_at(data, record + 6)?;
        let length = usize::from(u16_at(data, record + 8)?);
        let offset = usize::from(u16_at(data, record + 10)?);
        if id != 1 && id != 16 {
            continue;
        }
        let bytes = data.get(strings + offset..strings + offset + length)?;
        let text = match (platform, encoding) {
            (0, _) | (3, 0 | 1 | 10) => {
                let units: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                    .collect();
                String::from_utf16(&units).ok()?
            }
            (1, 0) => bytes.iter().map(|&b| char::from(b)).collect(),
            _ => continue,
        };
        let rank = u8::from(id == 16) * 4
            + u8::from(platform == 3) * 2
            + u8::from(language == 0x0409 || platform == 0);
        if !text.trim().is_empty() && best.as_ref().is_none_or(|(have, _)| rank > *have) {
            best = Some((rank, text.trim().to_owned()));
        }
    }
    best.map(|(_, text)| text)
}

/// The best Unicode subtable: full-repertoire format 12, else BMP format 4.
fn char_map(data: &[u8], cmap: usize) -> Option<CharMap> {
    let count = usize::from(u16_at(data, cmap + 2)?);
    let mut segments = None;
    let mut groups = None;
    for index in 0..count.min(64) {
        let record = cmap + 4 + 8 * index;
        let platform = u16_at(data, record)?;
        let encoding = u16_at(data, record + 2)?;
        let at = cmap + usize::try_from(u32_at(data, record + 4)?).ok()?;
        let unicode = platform == 0 || (platform == 3 && matches!(encoding, 1 | 10));
        if !unicode {
            continue;
        }
        match u16_at(data, at)? {
            4 => {
                let count = usize::from(u16_at(data, at + 6)? / 2);
                // Every array the lookup reads must be inside the file.
                let end = at + 16 + 8 * count;
                if count > 0 && end <= data.len() {
                    segments.get_or_insert(CharMap::Segments { at, count });
                }
            }
            12 => {
                let count = usize::try_from(u32_at(data, at + 12)?).ok()?;
                let end = (at + 16).checked_add(count.checked_mul(12)?)?;
                if count > 0 && end <= data.len() {
                    groups.get_or_insert(CharMap::Groups { at, count });
                }
            }
            _ => {}
        }
    }
    groups.or(segments)
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    let bytes = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn i16_at(data: &[u8], at: usize) -> Option<i16> {
    u16_at(data, at).map(|value| i16::from_be_bytes(value.to_be_bytes()))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
