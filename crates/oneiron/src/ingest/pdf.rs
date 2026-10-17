//! A PDF's text, for the notes import and the attached folder (OF-554,
//! ARCH-0027: "The first adapter reads a Markdown and PDF folder").
//!
//! Only the text layer is read. A scanned PDF holds no text to give, and no
//! OCR runs here, so it reads as blank. Every stream the load or a page
//! decodes is bounded, so a small compressed stream cannot inflate without
//! limit.

/// The largest PDF an import reads, as stored.
pub const MAX_PDF_BYTES: u64 = 16 * 1024 * 1024;

/// The most pages read from one PDF.
const MAX_PDF_PAGES: usize = 1_000;

/// The most one stream, or one page's content, decodes to.
const MAX_DECODED_STREAM: usize = 8 * 1024 * 1024;

/// Why a PDF gives no text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PdfTextError {
    #[error("the file is not a PDF")]
    NotPdf,
    #[error("the PDF is larger than an import reads")]
    TooLarge,
    #[error("the PDF is encrypted")]
    Encrypted,
    #[error("the PDF could not be read")]
    Unreadable,
}

/// The text of every page of `bytes`, in page order.
///
/// # Errors
/// A file that is not a PDF, is past [`MAX_PDF_BYTES`] or the page bound,
/// is encrypted under a password, or does not parse.
pub fn pdf_text(bytes: &[u8]) -> Result<String, PdfTextError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PDF_BYTES {
        return Err(PdfTextError::TooLarge);
    }
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
    if pages.len() > MAX_PDF_PAGES {
        return Err(PdfTextError::TooLarge);
    }
    document
        .extract_text_with_limit(&pages, MAX_DECODED_STREAM)
        .map_err(|_| PdfTextError::Unreadable)
}
