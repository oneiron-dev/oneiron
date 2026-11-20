//! The shared drawing program's failures, read by each side as its own.
//!
//! The leaf names every failure its drawing program can report; each side
//! maps each variant to exactly the error it reports today. The admission
//! refusal and the copier failure stay opaque: the leaf never names the
//! ledger's refusal, the engine's codec bound, or the organ's error.

use std::convert::Infallible;

/// The shared drawing program's failures, with the admission refusal `A` and
/// the copier failure `X` left to each side: the engine runs `A = Infallible`
/// and `X = Infallible` except `flatten`, whose copier reports its own
/// preparation error; the organ runs `A` as its ledger refusal and `X` as
/// its own error.
#[derive(Debug)]
pub enum BurnError<A, X = Infallible> {
    /// The admission refused: the organ's ledger refusal. Never constructed
    /// for the engine.
    Admit(A),
    /// The caller-supplied copier failed: each side's own error, passed through.
    External(X),
    /// A lopdf read failed: each side reads it as it does today.
    Lopdf(lopdf::Error),
    /// The display box is past a million points: the engine's limit, the
    /// organ's invalid geometry.
    DisplayTooLarge,
    /// A raster's pixel count does not fit the address space: the organ's
    /// too-large. Unreachable for the engine past its length check.
    TooLarge,
    /// Malformed PDF.
    MalformedPdf,
    /// A PDF construct that cannot be safely flattened.
    UnsupportedPdf,
    /// A page box, rotation, user-unit or field geometry failed its bound.
    InvalidGeometry,
    /// A signature raster failed its shape check.
    InvalidSignatureImage,
    /// Field text needs an unsupported encoding.
    UnsupportedText,
    /// Field text does not fit its box.
    FieldOverflow,
}

impl BurnError<Infallible, Infallible> {
    /// Widen a pure failure into any burn error. Only the logic arms are
    /// reachable: the pure checks admit nothing and read no PDF.
    pub fn into_burn<A, X>(self) -> BurnError<A, X> {
        match self {
            Self::Admit(refusal) => match refusal {},
            Self::External(external) => match external {},
            Self::Lopdf(err) => BurnError::Lopdf(err),
            Self::DisplayTooLarge => BurnError::DisplayTooLarge,
            Self::TooLarge => BurnError::TooLarge,
            Self::MalformedPdf => BurnError::MalformedPdf,
            Self::UnsupportedPdf => BurnError::UnsupportedPdf,
            Self::InvalidGeometry => BurnError::InvalidGeometry,
            Self::InvalidSignatureImage => BurnError::InvalidSignatureImage,
            Self::UnsupportedText => BurnError::UnsupportedText,
            Self::FieldOverflow => BurnError::FieldOverflow,
        }
    }
}

impl<A> BurnError<A, Infallible> {
    /// Widen a copier-free failure past a copier: only `External` changes,
    /// and it is unreachable without one.
    pub fn into_external<X>(self) -> BurnError<A, X> {
        match self {
            Self::Admit(refusal) => BurnError::Admit(refusal),
            Self::External(external) => match external {},
            Self::Lopdf(err) => BurnError::Lopdf(err),
            Self::DisplayTooLarge => BurnError::DisplayTooLarge,
            Self::TooLarge => BurnError::TooLarge,
            Self::MalformedPdf => BurnError::MalformedPdf,
            Self::UnsupportedPdf => BurnError::UnsupportedPdf,
            Self::InvalidGeometry => BurnError::InvalidGeometry,
            Self::InvalidSignatureImage => BurnError::InvalidSignatureImage,
            Self::UnsupportedText => BurnError::UnsupportedText,
            Self::FieldOverflow => BurnError::FieldOverflow,
        }
    }
}
