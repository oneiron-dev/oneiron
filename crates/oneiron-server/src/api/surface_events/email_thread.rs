//! The email thread an inbound mail carries over `/v1/core/surface-events`
//! (FIX 974, OF-414): the CC variant of the submit. An adapter that parsed a
//! mail's RFC 5322 threading headers sends them beside the event, and the
//! engine's scoped named-address door joins the mail to its thread across
//! identities in the one write that queues it
//! (`Vault::enqueue_inbound_email_as`): the passport, the thread membership,
//! then the durable handoff. Headers the passport cannot read take the
//! scoped generic door, as mail with none does, and a submission with no
//! thread takes the generic door as before. Either way the receiving
//! identity resolves under the submitter's own read.

use serde::Deserialize;
use utoipa::ToSchema;

/// The RFC 5322 threading headers of one inbound mail.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(example = json!({
    "message_id": "<CAF2x@mail.example.com>",
    "references": ["<CAF1a@mail.example.com>"],
    "in_reply_to": "<CAF1a@mail.example.com>"
}))]
pub(crate) struct SurfaceEmailThreadPayload {
    /// The `Message-ID` header, with or without its angle brackets.
    #[schema(example = "<CAF2x@mail.example.com>")]
    message_id: String,
    /// The `References` header's message ids, oldest first.
    #[serde(default)]
    references: Vec<String>,
    /// The `In-Reply-To` header's message id.
    #[serde(default)]
    in_reply_to: Option<String>,
}

impl SurfaceEmailThreadPayload {
    fn into_engine(self) -> oneiron::EmailThreadHeaders {
        oneiron::EmailThreadHeaders {
            message_id: self.message_id,
            references: self.references,
            in_reply_to: self.in_reply_to,
        }
    }
}

/// Admits `input` for the submitter reading as `read`: through the scoped
/// email door when it carries a `thread`, else through the scoped generic
/// door, unchanged.
pub(super) fn enqueue_as(
    vault: &oneiron::Vault,
    read: &oneiron::claim::ScopedRead<'_>,
    input: oneiron::InboundSurfaceEventInput,
    thread: Option<SurfaceEmailThreadPayload>,
    now: u64,
) -> oneiron::Result<oneiron::SurfaceEventAdmission> {
    match thread {
        None => vault.enqueue_inbound_surface_event_as(read, input, now),
        Some(thread) => {
            vault.enqueue_inbound_email_as(read, input, Some(&thread.into_engine()), now)
        }
    }
}
