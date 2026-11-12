pub use crate::office_body::pptx::preview::DeckPreviewRequest;
pub use crate::office_body::pptx::verbs::DeckExportRequest;
pub use crate::office_body::pptx::verbs::DeckForkMergeRequest;
pub use crate::office_body::pptx::verbs::DeckGateRequest;
pub use crate::office_body::pptx::verbs::DeckOracleRequest;
use heed::RoTxn;
use heed::RwTxn;
use loro::LoroDoc;
use serde::Deserialize;
use serde::Serialize;

pub mod preview;
pub mod verbs;
