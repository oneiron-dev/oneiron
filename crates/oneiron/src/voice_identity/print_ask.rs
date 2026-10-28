//! The owner's typed question about a third party's voice print (FIX 10789). A print whose
//! law evidence marks the owner a question owed ([`VoicePrintLegalEvidence::owner_ask_owed`])
//! raises one "is everything okay" ask to the vault's owners, in the write that keeps the
//! print. It is an ask, never a block: the print is kept and matches as before, and an answer
//! applies nothing. One print is one question: its generation is the question's id and its
//! correlation, so a re-enrolment, which mints a new print, asks again, and the same print
//! never asks twice.

use super::enrollment_law::{VoiceJurisdiction, VoicePrintLegalEvidence};
use super::types::VoicePrintRecordV1;
use crate::llm::decision::{
    AnswerContract, AskTo, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason,
    HumanDecisionRequest, ProviderPin,
};
use crate::{Result, Vault};

/// The host-issued queue identity of a third-party print's owner question.
const PRINT_ASK_QUEUE: &str = "voice.print.third_party";
const PRINT_ASK_QUEUE_VERSION: &str = "v1";

/// The version of the question; bump it with its wording.
const PRINT_ASK_VERSION: u32 = 1;

/// The most characters of a jurisdiction's name the question quotes.
const JURISDICTION_MAX_CHARS: usize = 120;

/// The question's wording: whose print, why it is owed, and that answering changes nothing.
fn print_ask_text(record: &VoicePrintRecordV1) -> String {
    let law = match &record.legal.jurisdiction {
        VoiceJurisdiction::Unresolved => {
            "the law it falls under was not resolved, so it may ask one".to_owned()
        }
        VoiceJurisdiction::Resolved { jurisdiction, .. } => format!(
            "the law of {} asks one before a voiceprint is made",
            jurisdiction
                .chars()
                .take(JURISDICTION_MAX_CHARS)
                .collect::<String>()
        ),
    };
    let contact = record
        .contact_ref
        .map_or_else(String::new, |contact| {
            format!(" as contact {}", contact.to_hex())
        });
    format!(
        "A voice print of someone who is not an owner was made: subject {subject}{contact} \
         (print {print}), with no written release shown, and {law}. The print is kept and \
         recognition goes on; answering here changes nothing. To remove it, withdraw the \
         subject's voice consent. Is everything okay?",
        subject = record.subject_ref.to_hex(),
        print = record.print_generation.to_hex(),
    )
}

/// The owner question `record` owes.
fn print_ask(record: &VoicePrintRecordV1) -> HumanDecisionRequest {
    let evidence = std::iter::once(record.subject_ref)
        .chain(record.contact_ref)
        .collect();
    HumanDecisionRequest {
        question: DecisionQuestion {
            id: record.print_generation,
            version: PRINT_ASK_VERSION,
            text: print_ask_text(record),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        principal: record.subject_ref,
        evidence,
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: PRINT_ASK_QUEUE.to_owned(),
            version: PRINT_ASK_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: Some(record.print_generation),
    }
}

/// Queues the owner question `record` owes, in `txn`, the write that keeps the print; nothing
/// for a print that owes none. Its arrival number, when it queued one.
pub(super) fn queue_print_owner_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &VoicePrintRecordV1,
) -> Result<Option<u64>> {
    if !owes_ask(&record.legal) {
        return Ok(None);
    }
    vault
        .queue_decision_ask_in_txn(txn, &print_ask(record), None)
        .map(Some)
}

/// The flag the law evidence records is the one trigger.
const fn owes_ask(legal: &VoicePrintLegalEvidence) -> bool {
    legal.owner_ask_owed
}
