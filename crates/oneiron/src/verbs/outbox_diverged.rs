//! A vault VM's outbox carrier members as the owner sees them, and his
//! answer to a diverged copy (FIX 11074, FIX 11242): the bodies of `GET` and
//! `POST /v1/owner/outbox/diverged`, which the facade verbs
//! `vault.outbox.diverged.list` and `vault.outbox.diverged.answer` answer as
//! well (FIX 11739). Each copy the carrier keeps of a member it never agreed
//! on carries a card with his two answers, remove or keep; each copy he kept,
//! moved aside under its own name, carries a card with his removal
//! (FIX 11985); each file the guest holds back as damaged at its source is
//! listed beside them. The
//! answer goes to the carrier's companion, which carries it out at its next
//! turn: nothing removes a copy without it.

use oneiron_vault_contract::vm_outbox::{VmOutboxKind, VmOutboxSide};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_records::verbs::outbox_diverged::{
    OutboxCardAction, OutboxCardKind, OutboxDivergedMember, OutboxDivergedPage, OutboxMemberStatus,
    OutboxOwnerCard,
};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::outbox_diverged::{
    OutboxDivergedAnswer, OutboxDivergedAnswerReceipt, OutboxDivergedAnswerRequest,
};
