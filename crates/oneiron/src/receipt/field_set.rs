use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::kernel::{
    FIELD_ACTIVATED_MEMORY_IDS, FIELD_BOARD_STATE_REF, FIELD_DISCLOSURE_STAMP,
    FIELD_MANIFEST_ACTOR_CLAIMS, FIELD_MANIFEST_SKILLS, FIELD_MODEL, FIELD_PERSONA_COMPILE_STAMP,
    FIELD_PROMPT_INPUT_REF, FIELD_REASONING_EFFORT, FIELD_SUBSTRATE_REF, ReceiptRecord, hex_lower,
};
// Referenced only by an intra-doc link on the public `ContextReceiptFields`;
// gated so the name is in scope for rustdoc without being an unused import.
#[cfg(doc)]
use super::kernel::ReceiptKind;
use crate::attempt_queue::{ManifestEntry, ManifestKind};
use crate::eiri::EiriMemoryBoard;
use crate::error::{Error, Result};
use crate::prompt::PromptRecompileStamp;

const BOARD_STATE_REF_PREFIX: &str = "board:";
const ACTIVATED_MEMORY_IDS_SEPARATOR: char = ',';

/// OF-369/RS9 context receipt field-set on emit-adjacent receipts.
///
/// Every agent emit is stamped with the exact assembled context that
/// produced it, so "why did she say that" is answered by READING a receipt,
/// never by re-deriving. Record-not-replay law: the LEDGER/bitemporal
/// substrate replays facts-at-T, but derived views (retrieval output, the
/// board as shown) drift with embedder/index/ranker versions, so they are
/// RECORDED here at emit time and never recomputed.
///
/// This is a field-set on the RS1 shared spine, NOT a new receipt kind: it
/// rides the `fields` map of receipts whose kind is
/// [`ReceiptKind::is_emit_adjacent`].
///
/// The provenance joins (`substrate_ref`, `model`, `reasoning_effort`)
/// mirror the ratified provenance ABI, where `substrate_ref` and
/// `reasoning_effort` are themselves optional fields: they are recorded
/// when the emit's provenance carries them, absent otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextReceiptFields {
    /// The OF-217 B9 standing-block compile id in effect for this emit.
    pub persona_compile_stamp: String,
    /// The claim/summary entity ids actually placed in context this emit,
    /// in board row order.
    pub activated_memory_ids: Vec<String>,
    /// Content-hash ref of the Eiri activated-memories board
    /// ([`EiriMemoryBoard`]) at emit — a distinct surface from the
    /// `[CONTEXT_BOARD]` render block, which is never hashed here.
    pub board_state_ref: String,
    /// Provenance join: ref of the MODEL substrate entity in effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub substrate_ref: Option<String>,
    /// Provenance join: model identifier in effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Provenance join: reasoning-effort scalar in effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    /// When OF-236 pre-compression ran, the post-compression input hash
    /// (r-knob auditability).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_input_ref: Option<String>,
    /// OF-365 disclosure stamp for the assembly that produced this emit:
    /// `"mode=<mode>;interlocutors=<class>:<label>[,...]"`. Absent on
    /// receipts stamped before the disclosure clamp existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_stamp: Option<String>,
}

impl ContextReceiptFields {
    /// Captures the field-set at the context-assembly seam — the one hook
    /// where the activation set is finalized (OF-369/RS9 emission point).
    ///
    /// `persona_compile_stamp` records the compile id of the resolved
    /// standing-block prompt in effect; `activated_memory_ids` and
    /// `board_state_ref` record the Eiri activated-memories board
    /// ([`EiriMemoryBoard`]) as shown — not the `[CONTEXT_BOARD]` render
    /// block, which is a distinct surface.
    pub fn from_assembly(persona: &PromptRecompileStamp, board: &EiriMemoryBoard) -> Result<Self> {
        Ok(Self {
            persona_compile_stamp: format!(
                "{}:{}",
                persona.schema_version, persona.resolved_fingerprint
            ),
            activated_memory_ids: board.rows.iter().map(|row| row.id.clone()).collect(),
            board_state_ref: eiri_memory_board_state_ref(board)?,
            substrate_ref: None,
            model: None,
            reasoning_effort: None,
            prompt_input_ref: None,
            disclosure_stamp: None,
        })
    }

    /// Joins the provenance `substrate_ref` (MODEL entity ref) to the stamp.
    #[must_use]
    pub fn substrate_ref(mut self, substrate_ref: impl Into<String>) -> Self {
        self.substrate_ref = Some(substrate_ref.into());
        self
    }

    /// Joins the provenance model identifier to the stamp.
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Joins the provenance reasoning-effort scalar to the stamp.
    #[must_use]
    pub fn reasoning_effort(mut self, reasoning_effort: impl Into<String>) -> Self {
        self.reasoning_effort = Some(reasoning_effort.into());
        self
    }

    /// Records the OF-236 post-compression prompt input hash.
    #[must_use]
    pub fn prompt_input_ref(mut self, prompt_input_ref: impl Into<String>) -> Self {
        self.prompt_input_ref = Some(prompt_input_ref.into());
        self
    }

    /// Records the OF-365 disclosure stamp
    /// (`DisclosureContext::receipt_stamp`) for this emit's assembly.
    #[must_use]
    pub fn disclosure_stamp(mut self, disclosure_stamp: impl Into<String>) -> Self {
        self.disclosure_stamp = Some(disclosure_stamp.into());
        self
    }

    pub(crate) fn append_to_fields(&self, fields: &mut BTreeMap<String, String>) {
        fields.insert(
            FIELD_PERSONA_COMPILE_STAMP.to_owned(),
            self.persona_compile_stamp.clone(),
        );
        fields.insert(
            FIELD_ACTIVATED_MEMORY_IDS.to_owned(),
            self.activated_memory_ids
                .join(&ACTIVATED_MEMORY_IDS_SEPARATOR.to_string()),
        );
        fields.insert(
            FIELD_BOARD_STATE_REF.to_owned(),
            self.board_state_ref.clone(),
        );
        if let Some(substrate_ref) = self.substrate_ref.as_ref() {
            fields.insert(FIELD_SUBSTRATE_REF.to_owned(), substrate_ref.clone());
        }
        if let Some(model) = self.model.as_ref() {
            fields.insert(FIELD_MODEL.to_owned(), model.clone());
        }
        if let Some(reasoning_effort) = self.reasoning_effort.as_ref() {
            fields.insert(FIELD_REASONING_EFFORT.to_owned(), reasoning_effort.clone());
        }
        if let Some(prompt_input_ref) = self.prompt_input_ref.as_ref() {
            fields.insert(FIELD_PROMPT_INPUT_REF.to_owned(), prompt_input_ref.clone());
        }
        if let Some(disclosure_stamp) = self.disclosure_stamp.as_ref() {
            fields.insert(FIELD_DISCLOSURE_STAMP.to_owned(), disclosure_stamp.clone());
        }
    }
}

/// Computes the content-hash ref of the Eiri activated-memories board
/// ([`EiriMemoryBoard`]) — a distinct surface from the `[CONTEXT_BOARD]`
/// render block, which is never hashed here.
///
/// The ref covers the board as shown (rows, scores, budget, companion), so
/// any drift in retrieval output produces a different ref while already
/// recorded receipts keep the ref captured at their emit.
pub fn eiri_memory_board_state_ref(board: &EiriMemoryBoard) -> Result<String> {
    let bytes = rmp_serde::to_vec_named(board)
        .map_err(|_| Error::InvariantViolation("context board state ref encode failed"))?;
    Ok(format!(
        "{BOARD_STATE_REF_PREFIX}{}",
        hex_lower(blake3::hash(&bytes).as_bytes())
    ))
}

/// Projects an attempt's accumulated PACK MANIFEST into receipt fields
/// (ARCH-0053 §2 — the manifest is the attribution hinge).
///
/// This is a field-set on the RS1 shared spine, NOT a new receipt kind and
/// NOT a new store: the terminal receipt of an attempt carries what the pack
/// actually loaded, so an outcome can be attributed to a skill or an actor
/// without re-deriving the pack. Both keys are always stamped, so an absent
/// key means "this receipt predates the manifest" while an empty array means
/// "the pack loaded nothing of that kind".
///
/// Order is the manifest's append order — never sorted, never deduped: the
/// append-only sequence IS the evidence.
pub fn append_pack_manifest_fields(
    receipt: &mut ReceiptRecord,
    manifest: &[ManifestEntry],
) -> Result<()> {
    let skills = manifest_wire_forms(manifest, ManifestKind::Skill);
    let actor_claims = manifest_wire_forms(manifest, ManifestKind::ActorClaim);
    receipt.fields.insert(
        FIELD_MANIFEST_SKILLS.to_owned(),
        encode_wire_forms(&skills)?,
    );
    receipt.fields.insert(
        FIELD_MANIFEST_ACTOR_CLAIMS.to_owned(),
        encode_wire_forms(&actor_claims)?,
    );
    Ok(())
}

fn manifest_wire_forms(manifest: &[ManifestEntry], kind: ManifestKind) -> Vec<String> {
    manifest
        .iter()
        .filter(|entry| entry.kind == kind)
        .map(ManifestEntry::wire_form)
        .collect()
}

fn encode_wire_forms(entries: &[String]) -> Result<String> {
    serde_json::to_string(entries)
        .map_err(|_| Error::InvariantViolation("pack manifest field encode failed"))
}

fn decode_wire_forms(raw: &str) -> Option<Vec<String>> {
    serde_json::from_str(raw).ok()
}

/// Attaches the OF-369 context field-set to an emit-adjacent receipt.
///
/// Non-emit receipts never carry emit context; attaching to one is rejected
/// without modifying the receipt.
pub fn append_context_receipt_fields(
    receipt: &mut ReceiptRecord,
    context: &ContextReceiptFields,
) -> Result<()> {
    if !receipt.receipt_kind.is_emit_adjacent() {
        return Err(Error::EmitAdjacentReceiptRequired {
            surface: "context receipt field-set",
            kind: receipt.receipt_kind.as_str(),
        });
    }
    context.append_to_fields(&mut receipt.fields);
    Ok(())
}

impl ReceiptRecord {
    /// Reads the ARCH-0053 §2 pack manifest recorded on this receipt: the
    /// `skill_id@version` rows the attempt's pack loaded, in append order.
    ///
    /// Returns `None` on receipts stamped before the field-set existed —
    /// distinct from `Some(vec![])`, which records a pack that loaded no
    /// skills. The values are read from the recorded field alone, never
    /// recomputed from the live attempt row (record-not-replay).
    #[must_use]
    pub fn pack_manifest_skills(&self) -> Option<Vec<String>> {
        decode_wire_forms(self.fields.get(FIELD_MANIFEST_SKILLS)?)
    }

    /// Reads the ARCH-0053 §2 pack manifest's `actor.*` claim rows. Same
    /// absent-versus-empty contract as [`Self::pack_manifest_skills`].
    #[must_use]
    pub fn pack_manifest_actor_claims(&self) -> Option<Vec<String>> {
        decode_wire_forms(self.fields.get(FIELD_MANIFEST_ACTOR_CLAIMS)?)
    }

    /// Reads the OF-369 context field-set recorded on this receipt.
    ///
    /// Returns `None` on non-emit receipt kinds and on emit receipts that
    /// were stamped before the field-set existed. The values are read from
    /// the recorded fields alone — never recomputed from live index state.
    #[must_use]
    pub fn context_receipt_fields(&self) -> Option<ContextReceiptFields> {
        if !self.receipt_kind.is_emit_adjacent() {
            return None;
        }
        let persona_compile_stamp = self.fields.get(FIELD_PERSONA_COMPILE_STAMP)?;
        let activated_memory_ids = self.fields.get(FIELD_ACTIVATED_MEMORY_IDS)?;
        let board_state_ref = self.fields.get(FIELD_BOARD_STATE_REF)?;
        Some(ContextReceiptFields {
            persona_compile_stamp: persona_compile_stamp.clone(),
            activated_memory_ids: activated_memory_ids
                .split(ACTIVATED_MEMORY_IDS_SEPARATOR)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .collect(),
            board_state_ref: board_state_ref.clone(),
            substrate_ref: self.fields.get(FIELD_SUBSTRATE_REF).cloned(),
            model: self.fields.get(FIELD_MODEL).cloned(),
            reasoning_effort: self.fields.get(FIELD_REASONING_EFFORT).cloned(),
            prompt_input_ref: self.fields.get(FIELD_PROMPT_INPUT_REF).cloned(),
            disclosure_stamp: self.fields.get(FIELD_DISCLOSURE_STAMP).cloned(),
        })
    }
}
