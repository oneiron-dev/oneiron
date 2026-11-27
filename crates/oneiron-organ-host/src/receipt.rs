//! The engine's receipt for one organ call: facts the host computed, plus
//! the organ's notes, every one of them, whole (Rule 5): how many and how
//! long they run are `[limits]` rows, which ask whether everything is okay.

use oneiron::limit_ask::EngineLimit;
use oneiron::machine_signature::MachineSignatures;
use oneiron::{EntityId, Vault};
use oneiron_organ_protocol::{
    AskCode, Hash32, Locator, Notes, OrganIdentity, ProtocolVersion, Value, to_vec,
};
use serde::{Deserialize, Serialize};

use crate::isolation::OrganIsolation;
use crate::spec::CallClass;

/// What one call read, made and took. Recall and the Dreamer read it as a
/// typed record; a landing writes it into the version's `made_by` envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallReceipt {
    pub organ: OrganIdentity,
    /// The version the session speaks: the lower minor of both sides.
    pub protocol: ProtocolVersion,
    /// What the call's process was isolated with: its namespaces and its
    /// descendant fence, as its start found them (FIX 10582).
    pub isolation: OrganIsolation,
    pub verb: String,
    pub schema: u32,
    /// blake3 of the call's args, as MessagePack.
    pub args_digest: Hash32,
    pub inputs: Vec<ReceiptInput>,
    /// blake3 of the base body, as MessagePack.
    pub base_body: Option<Hash32>,
    pub result_body: Option<Hash32>,
    pub outputs: Vec<ReceiptOutput>,
    /// The organ's word, every entry whole.
    pub notes: Notes,
    pub class: CallClass,
    pub grant: String,
    /// Waiting for the budget and the inputs.
    pub queue_us: u64,
    /// From sending the call to its verified reply.
    pub run_us: u64,
    /// Every ask the organ made, in order (protocol 1.1). A record written
    /// before 1.1 reads as none.
    #[serde(default)]
    pub asks: Vec<AskReceipt>,
    /// Memory the call took past the host's budget when every live call
    /// waited to grow (the soft-target exception, FIX 5284): fully
    /// accounted, and given back as the call's room drains.
    #[serde(default)]
    pub overcommit_bytes: u64,
    /// Time the call waited for budget room to grow, which its deadline
    /// does not count.
    #[serde(default)]
    pub room_wait_us: u64,
    /// The serving machine's signature over this receipt, on a call another
    /// node of the owner's ran (OF-575; Engine ruling
    /// ORGAN-MESH-RECEIPT-SIGNATURE). `None` on a call this machine ran
    /// itself, and on a record written before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<ReceiptSignature>,
}

/// The domain a machine signs a [`CallReceipt`] under, in
/// [`oneiron::machine_signature::machine_signature_transcript`].
pub const CALL_RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"oneiron/organ-call-receipt/v1\0";

/// A machine's signature over a [`CallReceipt`]: its Ed25519 signature
/// under [`CALL_RECEIPT_SIGNATURE_DOMAIN`] over the asking node's call
/// nonce, the call's report digest and the receipt without this field, in
/// the organ codec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptSignature {
    /// The MACHINE that signed, hex.
    pub machine: String,
    /// The 64-byte signature, hex.
    pub signature: String,
    /// The nonce the asking node drew for the call, hex: the signature
    /// answers that one call, so a receipt another call earned never passes
    /// for this one (blind-review P1 on #10409).
    pub call_nonce: String,
    /// blake3 of the call's report, as MessagePack: the report is the
    /// serving machine's word too.
    pub report: Hash32,
}

/// What a machine signs for a receipt: the call it answers, the report it
/// returned beside it, and the receipt with no signature.
#[derive(Serialize)]
struct ReceiptSigningPayload<'a> {
    call_nonce: &'a str,
    report: &'a Hash32,
    receipt: &'a CallReceipt,
}

impl CallReceipt {
    /// The bytes a machine signs for this receipt on the call `call_nonce`
    /// names, whose report digests to `report`.
    fn signed_bytes(&self, call_nonce: &str, report: &Hash32) -> Result<Vec<u8>, String> {
        let unsigned = Self {
            signed_by: None,
            ..self.clone()
        };
        to_vec(&ReceiptSigningPayload {
            call_nonce,
            report,
            receipt: &unsigned,
        })
        .map_err(|err| format!("the receipt did not encode: {err}"))
    }

    /// Signs this receipt as `signer`'s machine, in place of any signature
    /// it held: its answer to the call the asking node drew `call_nonce`
    /// for, which returned `report` beside it.
    ///
    /// # Errors
    /// The receipt did not encode, or `signer` could not sign.
    pub fn sign(
        &mut self,
        signer: &dyn MachineSignatures,
        call_nonce: &str,
        report: &Value,
    ) -> Result<(), String> {
        let report = digest(report);
        let bytes = self.signed_bytes(call_nonce, &report)?;
        let (machine, signature) = signer
            .sign(CALL_RECEIPT_SIGNATURE_DOMAIN, &bytes)
            .map_err(|err| err.to_string())?;
        self.signed_by = Some(ReceiptSignature {
            machine: machine.to_hex(),
            signature: oneiron_hex::encode(&signature),
            call_nonce: call_nonce.to_owned(),
            report,
        });
        Ok(())
    }

    /// The machine whose signature this receipt carries, once `verifier`
    /// finds it that machine's over this receipt, its call nonce and its
    /// report digest, against the key its MACHINE row holds there. Whether
    /// the nonce and the digest are the asking node's call and report is the
    /// asking node's check.
    ///
    /// # Errors
    /// The receipt is unsigned, its signature is malformed, or it is not
    /// the named machine's over this receipt.
    pub fn signer(&self, verifier: &dyn MachineSignatures) -> Result<EntityId, String> {
        let signed = self.signed_by.as_ref().ok_or("the receipt is not signed")?;
        let machine = EntityId::from_hex(&signed.machine)
            .map_err(|_| "the receipt's signer is not a machine id".to_owned())?;
        let signature = oneiron_hex::decode::<64>(&signed.signature)
            .ok_or("the receipt's signature is not 64 bytes of hex")?;
        verifier
            .verify(
                machine,
                CALL_RECEIPT_SIGNATURE_DOMAIN,
                &self.signed_bytes(&signed.call_nonce, &signed.report)?,
                &signature,
            )
            .map_err(|err| err.to_string())?;
        Ok(machine)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptInput {
    /// The artifact id, hex; empty for bytes the caller lent.
    pub artifact: String,
    pub version: u64,
    pub content_hash: Hash32,
    pub len: u64,
    /// Bytes the caller held, not a vault version.
    #[serde(default)]
    pub lent: bool,
}

/// One ask, as the host saw it. Digests are blake3 over MessagePack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskReceipt {
    pub id: u32,
    pub verb: String,
    pub value_digest: Hash32,
    /// The refusal, if the ask got one.
    pub refused: Option<AskCode>,
    /// The answer's bytes the organ was lent, value and data.
    #[serde(default)]
    pub answer_len: u64,
    pub answer_digest: Option<Hash32>,
    /// The answer's bytes, hashed by the host as it sent them.
    pub data_hash: Option<Hash32>,
    pub data_len: u64,
    pub fetch: Option<FetchTarget>,
    pub handler_us: u64,
    /// The serving host's non-delivery reason, or this asking node's
    /// unconfirmed mesh delivery observation.
    #[serde(default)]
    pub unanswered: Option<Unanswered>,
    /// What the handler's key was asked to sign, in the host's own words:
    /// set before the key runs, so it stays when the key failed after
    /// signing or the signature was never delivered.
    #[serde(default)]
    pub signed: Option<SignedReceipt>,
}

/// One signature a handler's key made for an ask. The organ supplied none
/// of these values: the host computed each one before the key signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReceipt {
    pub operation_id: String,
    /// The SHA-256 prehash the key signed.
    pub prehash: [u8; 32],
    /// SHA-256 of the content the prehash commits to: for a seal, the
    /// revision's ByteRange.
    pub content_sha256: [u8; 32],
    /// Which of the call's prepared revisions it signed, if the call has
    /// several.
    pub revision: Option<u32>,
    /// SHA-256 of the signature value; none when the key returned none,
    /// though it may still have signed.
    pub signature_sha256: Option<[u8; 32]>,
}

/// What this host knows of an ask's delivery to its organ. `NotRun` and
/// `NotSent` are the serving host's word for its own call, which ended
/// (cancelled, revoked, replied, past its caps or its organ gone) before
/// the ask was run or sent. `Unknown` is the asking node's word for its own
/// mesh answer, whose send neither succeeded nor failed with an organ
/// receipt: only the serving host's final lines confirm it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unanswered {
    /// Nothing was decided for it: no handler ran, no refusal was made.
    NotRun,
    /// Its answer or refusal was decided but not sent; a handler that
    /// panicked leaves this too.
    NotSent,
    /// Sending its answer or refusal was attempted, but no serving-host
    /// final receipt confirms whether the organ received it. Mesh asking
    /// node only: neither the send's success nor its error says so.
    Unknown,
}

/// Where a `net.fetch` went. The full URL is kept only as a digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchTarget {
    /// `scheme://host:port` of the first hop.
    pub origin: String,
    pub url_digest: Hash32,
    /// The final HTTP status; 0 when nothing was fetched.
    pub status: u16,
    /// The redirects it followed, each hop checked afresh.
    #[serde(default)]
    pub redirects: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptOutput {
    pub name: String,
    pub media_type: String,
    pub content_hash: Hash32,
    pub len: u64,
}

/// Measures an organ's notes against the receipt rows and keeps every one,
/// in order and whole: a touched locator, a warning or a loss is never
/// dropped or cut for its count or its length.
pub(crate) fn measured_notes(vault: &Vault, notes: Notes) -> Notes {
    let items = notes
        .touched
        .len()
        .max(notes.warnings.len())
        .max(notes.losses.len());
    vault.measure_limit(EngineLimit::OrganNoteItems, items as u64);
    let longest = notes
        .touched
        .iter()
        .map(encoded_len)
        .chain(notes.warnings.iter().map(String::len))
        .chain(notes.losses.iter().map(|loss| loss.detail.len()))
        .max()
        .unwrap_or(0);
    vault.measure_limit(EngineLimit::OrganNoteBytes, longest as u64);
    let code = notes.losses.iter().map(|loss| loss.code.len()).max();
    vault.measure_limit(EngineLimit::OrganLossCodeBytes, code.unwrap_or(0) as u64);
    notes
}

fn encoded_len(locator: &Locator) -> usize {
    oneiron_organ_protocol::encoded_len(locator)
        .map_or(usize::MAX, |len| usize::try_from(len).unwrap_or(usize::MAX))
}

/// blake3 of a value's MessagePack encoding, in the protocol's codec.
pub(crate) fn digest<T: Serialize>(value: &T) -> Hash32 {
    to_vec(value).map_or_else(|_| Hash32([0; 32]), |bytes| Hash32::of(&bytes))
}
