//! A PDF's text, for the notes import and the attached folder (OF-554,
//! ARCH-0027: "The first adapter reads a Markdown and PDF folder").
//!
//! Only the text layer is read. A scanned PDF holds no text to give, and no
//! OCR runs here, so it reads as blank. A PDF of any size and any page count
//! is read (rule 5): the only bound is the codec's. Every stream the load or
//! a page decodes is bounded, so a small compressed stream cannot inflate
//! without limit; a page past that bound is left out, and the rest is read.

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
    /// or a font or run of text the reader cannot map.
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
    Ok(read)
}
