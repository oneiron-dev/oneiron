//! The seal port's PDF-work adapter: `seal.inspect` + `seal.prepare` over the
//! organ (FIX 7980/8157). `seal.inspect` reads a PDF's page geometry through
//! the organ; `seal.prepare` prepares the PDF the seal later signs,
//! projecting the engine's [`PdfPreparation`] into the lent scalars the
//! organ's ported pipeline takes.
//!
//! Engine sources: `render.rs` (`prepare_esign_pdf_within` orchestration,
//! `inspect_pdf_pages_within` return shape), `render/evidence.rs` (audit
//! projection: the items row, title, recipients, signatures order),
//! `render/presentation.rs` (`present_field` row validation),
//! `render/fields.rs` (burn order: this item's fields against the whole
//! signatures map), `model.rs` (field/value rows), `seal.rs` (the
//! PNG-decoded rasters, lent as one offset-addressed blob).
//!
//! Behavior: the field rows are validated engine-side before the call
//! (`present_field`); the audit-chain replay stays engine-side — its
//! checked output (`chain`/`trail`) is lent in by the caller, which ran
//! `evidence()` (G5; the engine `replay_esign_audit` helper is follow-up,
//! so a second replay here is forbidden). Both verbs ask only `memory.grow`
//! (memory-only handlers, like `verify`); the prepared output is admitted
//! by digest, page count and format bound before it is returned.

mod inspect;

pub use inspect::{PdfInspectionError, inspect_pdf_region_until};

use std::collections::BTreeMap;

use oneiron::blob_artifact::esign::render::{
    PageGeometry, PdfPreparation, PreparedEsignPdf, present_field,
};
use oneiron::blob_artifact::esign::{EsignSealerError, FieldValue};
use oneiron_organ_protocol::{ASK_MEMORY_GROW, ByteBuf};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::observe::{measure_asks, measure_input, measure_output};
use super::{
    FailureReply, HostedSealer, PDF, PDF_FORMAT_BYTES, REVISIONS, SealSettings, VERB_INSPECT,
    VERB_PREPARE, from_value, reply_invalid, to_value,
};
use crate::handlers::AskHandlers;
use crate::host::{CallMeasure, OrganHost};
use crate::resource_memory::MemoryGrow;
use crate::spec::{LentInput, OrganTier};

/// The name of the prepared output (mirror `SEALED_OUTPUT`).
const PREPARED_OUTPUT: &str = "prepared.pdf";

#[derive(Serialize)]
struct InspectArgs {
    stream_decode_bytes: u64,
}

#[derive(Serialize)]
struct PrepareArgs {
    document_ref: String,
    item: u32,
    canonical_url: String,
    artifact_ref: String,
    original_version: u64,
    title: String,
    audit_rows: usize,
    rejection: Option<String>,
    recipients: Vec<WireRecipient>,
    signatures: Vec<WireSignature>,
    fields: Vec<WireField>,
    values: BTreeMap<String, WireValue>,
    raster_index: Vec<RasterEntry>,
    chain: ByteBuf,
    trail: Vec<String>,
}

#[derive(Serialize)]
struct WireRecipient {
    id: String,
    name: String,
    email: String,
    natural_person: Option<String>,
}

#[derive(Serialize)]
struct WireSignature {
    field: String,
    recipient: String,
    at: u64,
}

#[derive(Serialize)]
struct WireField {
    id: String,
    geometry: WireGeometry,
}

#[derive(Serialize)]
struct WireGeometry {
    page: u32,
    x_percent: f64,
    y_percent: f64,
    width_percent: f64,
    height_percent: f64,
}

/// The engine's `FieldValue` row, adjacently tagged exactly like it
/// (`model.rs:140-146`), so the organ reads it by kind.
#[derive(Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum WireValue {
    Text(String),
    Checked(bool),
    Signature { image_ref: String },
}

impl WireValue {
    fn of(value: &FieldValue) -> Self {
        match value {
            FieldValue::Text(text) => Self::Text(text.clone()),
            FieldValue::Checked(checked) => Self::Checked(*checked),
            FieldValue::Signature { image_ref } => Self::Signature {
                image_ref: image_ref.clone(),
            },
        }
    }
}

/// One raster's slice of the lent rasters blob: offsets into it, in the
/// blob's order (mirror the REVISIONS pattern: one offset-addressed
/// `application/octet-stream` input beside the PDF).
#[derive(Serialize)]
struct RasterEntry {
    image_ref: String,
    width: u32,
    height: u32,
    offset: u64,
    len: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum InspectReply {
    Inspected { pages: Vec<WirePage> },
    Failed(FailureReply),
}

#[derive(Deserialize)]
struct WirePage {
    crop: [f64; 4],
    rotation: u16,
    user_unit: f64,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PrepareReply {
    Prepared {
        original_sha256: ByteBuf,
        audit_chain_sha256: ByteBuf,
        original_pages: u32,
        appendix_pages: u32,
    },
    Failed(FailureReply),
}

/// Inspect through the existing isolated seal port without a signing key.
/// Only the memory handler is supplied; trust anchors and fetch settings
/// are unused. This blocks its thread under the supplied call settings.
pub fn inspect_pdf_pages_via_organ(
    host: &OrganHost,
    vault: &oneiron::Vault,
    settings: &SealSettings,
    bytes: &[u8],
) -> Result<Vec<PageGeometry>, EsignSealerError> {
    let args = to_value(&InspectArgs {
        stream_decode_bytes: vault.esign_stream_decode_bytes(),
    })
    .map_err(|_| reply_invalid())?;
    measure_input(vault, bytes);
    let lent = vec![LentInput {
        media_type: PDF.to_owned(),
        bytes: bytes.to_vec(),
    }];
    let memory = MemoryGrow;
    let handlers = AskHandlers::none().with(ASK_MEMORY_GROW, &memory);
    let (reply, _) = super::observe::sized_call(
        host,
        vault,
        settings.call(VERB_INSPECT, 1, args),
        lent,
        &handlers,
        &mut CallMeasure::default(),
    )?;
    inspected_pages(vault, &reply)
}

fn inspected_pages(
    vault: &oneiron::Vault,
    reply: &oneiron_organ_protocol::Value,
) -> Result<Vec<PageGeometry>, EsignSealerError> {
    match from_value(reply)? {
        InspectReply::Inspected { pages } => Ok(pages
            .into_iter()
            .map(|page| PageGeometry {
                crop: page.crop,
                rotation: page.rotation,
                user_unit: page.user_unit,
            })
            .collect()),
        InspectReply::Failed(failure) => Err(failure.into_error(vault)),
    }
}

impl HostedSealer<'_> {
    /// One `seal.inspect` call over `bytes`, in a process of its own: the
    /// PDF's page geometry, in page order. Its one handler reserves its
    /// decodes' memory (`memory.grow`); it is never given signing or fetch.
    /// The return shape matches `inspect_pdf_pages_within`, so the editor
    /// call sites swap with a one-line change.
    pub fn inspect_pdf_pages_via_organ(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<PageGeometry>, EsignSealerError> {
        inspect_pdf_pages_via_organ(self.host, self.vault, &self.settings, bytes)
    }

    /// One `seal.prepare` call over `original` for `request`, in a process
    /// of its own: the prepared PDF the seal later signs. Its one handler
    /// reserves its decodes' memory (`memory.grow`); it is never given
    /// signing or fetch. `chain`/`trail` are the engine audit replay's
    /// checked output, which the caller ran: the organ takes them lent, and
    /// the returned chain must equal them. The return shape matches
    /// `prepare_esign_pdf_within`. A third-party organ cannot choose the
    /// document the engine signs: `None` keeps its existing trusted engine
    /// preparation instead. The actual call's slot tier is checked too,
    /// so a reinstall cannot substitute untrusted prepared bytes.
    pub fn prepare_esign_pdf_via_organ(
        &self,
        original: &[u8],
        request: &PdfPreparation<'_>,
        chain: [u8; 32],
        trail: &[String],
    ) -> Result<Option<PreparedEsignPdf>, EsignSealerError> {
        if self
            .host
            .spec(&self.settings.organ)
            .is_none_or(|spec| spec.tier != OrganTier::FirstParty)
        {
            return Ok(None);
        }
        // Each field row of this item, validated engine-side: the port's
        // burn takes its fields and values as-is.
        for field in request
            .state
            .document
            .fields
            .iter()
            .filter(|field| field.item == request.item)
        {
            let value = request
                .state
                .signatures
                .get(&field.id)
                .map(|signature| &signature.value);
            present_field(field, value).map_err(|_| invalid_field())?;
        }
        let item = request
            .state
            .document
            .items
            .get(request.item as usize)
            .ok_or_else(invalid_field)?;
        // The rasters, each decoded once by the engine seal task already,
        // concatenated into one blob beside the PDF.
        let mut rasters = Vec::new();
        let mut raster_index = Vec::new();
        for (image_ref, image) in request.signature_images.iter() {
            let offset = rasters.len() as u64;
            let len = image.rgba.len() as u64;
            rasters.extend_from_slice(&image.rgba);
            raster_index.push(RasterEntry {
                image_ref: image_ref.clone(),
                width: image.width,
                height: image.height,
                offset,
                len,
            });
        }
        let args = to_value(&PrepareArgs {
            document_ref: request.document_ref.to_owned(),
            item: request.item,
            canonical_url: request.canonical_url.to_owned(),
            artifact_ref: item.artifact_ref.clone(),
            original_version: item.original_version,
            title: request.state.document.title.clone(),
            audit_rows: request.audit.len(),
            rejection: request.state.rejection.clone(),
            recipients: request
                .state
                .document
                .recipients
                .iter()
                .map(|recipient| WireRecipient {
                    id: recipient.id.clone(),
                    name: recipient.name.clone(),
                    email: recipient.email.clone(),
                    natural_person: recipient.natural_person.clone(),
                })
                .collect(),
            // In field-id order: the signatures map's own (BTreeMap) order,
            // as the engine's certificate reads it.
            signatures: request
                .state
                .signatures
                .values()
                .map(|signature| WireSignature {
                    field: signature.field.clone(),
                    recipient: signature.recipient.clone(),
                    at: signature.at,
                })
                .collect(),
            fields: request
                .state
                .document
                .fields
                .iter()
                .filter(|field| field.item == request.item)
                .map(|field| WireField {
                    id: field.id.clone(),
                    geometry: WireGeometry {
                        page: field.geometry.page,
                        x_percent: field.geometry.x_percent,
                        y_percent: field.geometry.y_percent,
                        width_percent: field.geometry.width_percent,
                        height_percent: field.geometry.height_percent,
                    },
                })
                .collect(),
            values: request
                .state
                .signatures
                .iter()
                .map(|(id, signature)| (id.clone(), WireValue::of(&signature.value)))
                .collect(),
            raster_index,
            chain: ByteBuf::from(chain.to_vec()),
            trail: trail.to_vec(),
        })
        .map_err(|_| reply_invalid())?;
        measure_input(self.vault, original);
        let lent = vec![
            LentInput {
                media_type: PDF.to_owned(),
                bytes: original.to_vec(),
            },
            LentInput {
                media_type: REVISIONS.to_owned(),
                bytes: rasters,
            },
        ];
        let memory = MemoryGrow;
        let handlers = AskHandlers::none().with(ASK_MEMORY_GROW, &memory);
        let mut measure = CallMeasure::default();
        let called = self.sized_call_measured(
            self.call(VERB_PREPARE, 1, args),
            lent,
            &handlers,
            &mut measure,
        );
        // Every ask the call made, however it ended.
        measure_asks(self.vault, &handlers.asked());
        let (reply, outcome) = called?;
        if measure.tier != Some(OrganTier::FirstParty) {
            return Ok(None);
        }
        let (original_sha256, audit_chain_sha256, original_pages, appendix_pages) =
            match from_value(&reply)? {
                PrepareReply::Failed(failure) => {
                    return Err(failure.into_error(self.vault));
                }
                PrepareReply::Prepared {
                    original_sha256,
                    audit_chain_sha256,
                    original_pages,
                    appendix_pages,
                } => (
                    original_sha256,
                    audit_chain_sha256,
                    original_pages,
                    appendix_pages,
                ),
            };
        let prepared = outcome
            .outputs
            .iter()
            .find(|output| output.name == PREPARED_OUTPUT && output.media_type == PDF)
            .ok_or_else(reply_invalid)?;
        let original_sha256: [u8; 32] = original_sha256
            .as_slice()
            .try_into()
            .map_err(|_| reply_invalid())?;
        let audit_chain_sha256: [u8; 32] = audit_chain_sha256
            .as_slice()
            .try_into()
            .map_err(|_| reply_invalid())?;
        let digest: [u8; 32] = Sha256::digest(original).into();
        if original_sha256 != digest
            || audit_chain_sha256 != chain
            || original_pages == 0
            || prepared.len() as u64 > PDF_FORMAT_BYTES
        {
            return Err(reply_invalid());
        }
        // The call's outputs give back their budget before the bytes move
        // out.
        let bytes = prepared.to_vec();
        drop(outcome);
        measure_output(self.vault, original, &bytes);
        Ok(Some(PreparedEsignPdf {
            bytes,
            original_sha256,
            audit_chain_sha256,
            original_pages,
            appendix_pages,
        }))
    }
}

/// A field row, or the item it names, the organ must never see.
fn invalid_field() -> EsignSealerError {
    EsignSealerError::InputInvalid {
        code: "invalid_field".to_owned(),
    }
}
