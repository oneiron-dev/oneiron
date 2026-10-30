//! A PDF's text, for the notes import and the attached folder (OF-554,
//! ARCH-0027: "The first adapter reads a Markdown and PDF folder").
//!
//! The text layer is read first. A PDF whose text layer is blank (a scan)
//! has its page images read by the ingest station's OCR instead
//! (`image_text_recognizer`): a JPEG as it is stored, and 8-bit
//! grey or RGB samples. With no OCR to run it reads as blank. A PDF of any
//! size and any page count is read (rule 5): the only bound is the codec's.
//! Every stream the load or a page decodes is bounded, so a small compressed
//! stream cannot inflate without limit; a page past that bound is left out,
//! and the rest is read.

/// The most one stream, or one page's content, decodes to.
const MAX_DECODED_STREAM: usize = 8 * 1024 * 1024;

/// Why a PDF gives no text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PdfTextError {
    #[error("the file is not a PDF")]
    NotPdf,
    #[error("the PDF is encrypted")]
    Encrypted,
    #[error("the PDF could not be read")]
    Unreadable,
}

/// A PDF's text, and what of it could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfText {
    /// The text of every page, in page order.
    pub text: String,
    /// Pieces left out: a page whose content decodes past the codec's bound,
    /// a font or run of text the reader cannot map, or a scanned page's image
    /// the OCR could not read.
    pub unread: usize,
}

/// The text of every page of `bytes`, in page order.
///
/// # Errors
/// A file that is not a PDF, is encrypted under a password, or does not
/// parse.
pub fn pdf_text(bytes: &[u8]) -> Result<PdfText, PdfTextError> {
    if !bytes.starts_with(b"%PDF-") {
        return Err(PdfTextError::NotPdf);
    }
    let document = lopdf::Document::load_mem_with_options(
        bytes,
        lopdf::LoadOptions::with_max_decompressed_size(MAX_DECODED_STREAM),
    )
    .map_err(|error| match error {
        lopdf::Error::Decryption(_) => PdfTextError::Encrypted,
        _ => PdfTextError::Unreadable,
    })?;
    // A PDF that opened with the empty password is read; one that still
    // holds its encryption needs a password the import does not have.
    if document.is_encrypted() {
        return Err(PdfTextError::Encrypted);
    }
    let pages = document.get_pages().into_keys().collect::<Vec<_>>();
    let mut read = PdfText {
        text: String::new(),
        unread: 0,
    };
    for chunk in document.extract_text_chunks_with_limit(&pages, MAX_DECODED_STREAM) {
        match chunk {
            Ok(chunk) => read.text.push_str(&chunk),
            Err(_) => read.unread += 1,
        }
    }
    if read.text.trim().is_empty()
        && let Ok(recognizer) = super::image::image_text_recognizer()
    {
        read_page_images(&document, recognizer, &mut read);
    }
    Ok(read)
}

/// Reads each page's images with `recognizer`, in page order, onto `read`:
/// a scan's text. An image the OCR cannot take, or cannot read, is counted
/// as unread.
fn read_page_images(
    document: &lopdf::Document,
    recognizer: &dyn super::image::ImageTextRecognizer,
    read: &mut PdfText,
) {
    for page in document.get_pages().into_values() {
        let Ok(pictures) = document.get_page_images(page) else {
            read.unread += 1;
            continue;
        };
        for picture in &pictures {
            let recognized = page_image_bytes(document, picture)
                .and_then(|bytes| recognizer.recognize(&bytes).ok());
            match recognized {
                Some(recognized) if !recognized.text.trim().is_empty() => {
                    read.text.push_str(recognized.text.trim());
                    read.text.push('\n');
                }
                Some(_) => {}
                None => read.unread += 1,
            }
        }
    }
}

/// One page image as bytes an image decoder reads: a JPEG as it is stored,
/// or 8-bit grey or RGB samples as a PNG. `None` for any other encoding (a
/// fax, JBIG2 or JPEG 2000 image, a palette or a mask).
fn page_image_bytes(
    document: &lopdf::Document,
    picture: &lopdf::xobject::PdfImage<'_>,
) -> Option<Vec<u8>> {
    let filters = picture.filters.as_deref().unwrap_or_default();
    if filters.iter().any(|filter| filter == "DCTDecode") {
        return (filters.len() == 1).then(|| picture.content.to_vec());
    }
    if picture.bits_per_component != Some(8) {
        return None;
    }
    let samples = document
        .get_object(picture.id)
        .ok()?
        .as_stream()
        .ok()?
        .get_plain_content_with_limit(MAX_DECODED_STREAM)
        .ok()?;
    let width = u32::try_from(picture.width).ok()?;
    let height = u32::try_from(picture.height).ok()?;
    let decoded = match picture.color_space.as_deref() {
        Some("DeviceRGB") => {
            ::image::DynamicImage::ImageRgb8(::image::RgbImage::from_raw(width, height, samples)?)
        }
        Some("DeviceGray") => {
            ::image::DynamicImage::ImageLuma8(::image::GrayImage::from_raw(width, height, samples)?)
        }
        _ => return None,
    };
    let mut png = Vec::new();
    decoded
        .write_to(std::io::Cursor::new(&mut png), ::image::ImageFormat::Png)
        .ok()?;
    Some(png)
}
