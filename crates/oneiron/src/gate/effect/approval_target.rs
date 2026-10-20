//! FIX 6424 (Engine 10-20 17:4x): an owner's approve-once press approves
//! exactly one send.
//!
//! The generic external-effect composer named a non-mail one-shot digest by
//! its actor, verb class and brief or channel alone, so one press could be
//! spent by another send of the same agent on the same verb. The canonical
//! producer now hands the Gate a typed [`ApprovalTarget`] beside the effect:
//! each family declares exactly the facts that make its send this send, its
//! target and its existing logical send ref (CALLS `FIX 6424 nonce = logical
//! ref`), and the composer appends their pin to the operation kind, as
//! native mail's cold-send digest does (CALLS `FIX 6424 approve-once target
//! pin`).
//!
//! Only the one-shot digest moves. The action requirement every Grant is
//! matched on, the grant echo, budgets, connector settings and the consent
//! precedence never read the target, and an effect that carries none (mail,
//! code waits, artifact publish, brief share, task cancel, and the families
//! FIX 6424's second part pins) composes exactly the digest it composed
//! before. No target names a provider id the send has not been given yet.

use crate::calendar::CalendarInvitePayload;
use crate::entity_id::EntityId;

/// The BLAKE3 domain of the target pin.
const APPROVE_ONCE_TARGET_DOMAIN: &[u8] = b"oneiron.external_effect.approve_once.target.v1";

/// The facts one non-mail send's approve-once press pins, per family. Every
/// `send_ref` is the family's existing logical ref: the dispatch's intent
/// ref, which a retry of the same prepared send carries again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApprovalTarget {
    /// An e-sign send for signature, reminder or void: the document, the
    /// command binding the act was reviewed under (`esign-command:<sha256>`
    /// over the command, the document and the reminder), and its send ref.
    Esign {
        document: String,
        content_ref: Option<String>,
        send_ref: String,
    },
    /// A `calendar.invite`, a booking's confirm and an emergency reschedule
    /// included: the event UID, its SEQUENCE and method, the immutable ICS
    /// version ref, the attendee, the sending identity when one is bound,
    /// and the send ref.
    Calendar {
        uid: String,
        sequence: u32,
        method: String,
        ics_ref: String,
        attendee: String,
        sender: Option<EntityId>,
        send_ref: String,
    },
    /// A message, media, reaction, edit, retraction, push, invite, call or
    /// connect request on a communications connector: the sending identity
    /// when one is bound, the original transport target (never the
    /// counterparty alias the Gate also reads), the thread it replies on,
    /// its content ref, and the send ref.
    Communication {
        sender: Option<EntityId>,
        target: String,
        thread_ref: Option<String>,
        content_ref: Option<String>,
        send_ref: String,
    },
    /// A feedback bundle or a failure-signal batch: the exact endpoint, the
    /// bundle's content ref (its digest), and the send ref.
    HttpBundle {
        endpoint: String,
        content_ref: Option<String>,
        send_ref: String,
    },
}

/// One prepared request on the common outbound adapter, as its canonical
/// producer built it.
pub(crate) struct OutboundSendFacts<'a> {
    /// The connector's normalized registry key.
    pub(crate) connector: &'a str,
    /// The original transport target.
    pub(crate) target: &'a str,
    /// The sending identity the request resolved.
    pub(crate) sender: Option<EntityId>,
    /// The thread the send replies on.
    pub(crate) thread_ref: Option<&'a str>,
    pub(crate) content_ref: Option<&'a str>,
    /// The dispatch's intent ref.
    pub(crate) send_ref: &'a str,
    /// A `calendar.invite`'s frozen five-field body.
    pub(crate) calendar_invite: Option<&'a CalendarInvitePayload>,
}

impl ApprovalTarget {
    /// The target one send on the common outbound adapter pins, by its
    /// connector's family. Mail keeps its own canonical digest (native and
    /// member mail) or stays outside FIX 6424's non-mail census, and Linear
    /// is pinned by its second part: those carry none. A connector the
    /// registry gains later pins as a communication until it is given its
    /// own variant.
    pub(crate) fn for_outbound(facts: &OutboundSendFacts<'_>) -> Option<Self> {
        let send_ref = facts.send_ref.to_owned();
        let content_ref = facts.content_ref.map(str::to_owned);
        let target = match facts.connector {
            "email" | "email_resend" | "email_ses" | "email_postmark" | "linear" => return None,
            "esign" => Self::Esign {
                document: facts.target.to_owned(),
                content_ref,
                send_ref,
            },
            "feedback_cloud" | "feedback_collector" | "feedback_github" | "failure_signals" => {
                Self::HttpBundle {
                    endpoint: facts.target.to_owned(),
                    content_ref,
                    send_ref,
                }
            }
            "calendar" if facts.calendar_invite.is_some() => {
                let invite = facts.calendar_invite?;
                Self::Calendar {
                    uid: invite.uid.clone(),
                    sequence: invite.sequence,
                    method: invite.method.as_str().to_owned(),
                    ics_ref: invite.ics_blob_ref.clone(),
                    attendee: invite.recipient.clone(),
                    sender: facts.sender,
                    send_ref,
                }
            }
            _ => Self::Communication {
                sender: facts.sender,
                target: facts.target.to_owned(),
                thread_ref: facts.thread_ref.map(str::to_owned),
                content_ref,
                send_ref,
            },
        };
        Some(target)
    }

    /// Whether this family's admitted press is recomposed from its frozen
    /// ledger bytes (an e-sign send's or reminder's proof, FIX 6362), so its
    /// frozen payload carries the send ref the press pins.
    pub(crate) const fn freezes_send_ref(&self) -> bool {
        matches!(self, Self::Esign { .. })
    }

    /// `operation_kind` named by this one send, the shape native mail's
    /// cold-send digest takes.
    pub(crate) fn pin(&self, operation_kind: &str) -> String {
        format!("{operation_kind}:once:{}", self.digest().to_hex())
    }

    /// BLAKE3 over the domain, the family tag and the family's fields in
    /// declared order: each length-framed (u64 little-endian), an optional
    /// one tagged present (1) or absent (0), an entity id as lower hex and a
    /// SEQUENCE as decimal.
    fn digest(&self) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(APPROVE_ONCE_TARGET_DOMAIN);
        match self {
            Self::Esign {
                document,
                content_ref,
                send_ref,
            } => {
                field(&mut hasher, "esign");
                field(&mut hasher, document);
                optional(&mut hasher, content_ref.as_deref());
                field(&mut hasher, send_ref);
            }
            Self::Calendar {
                uid,
                sequence,
                method,
                ics_ref,
                attendee,
                sender,
                send_ref,
            } => {
                field(&mut hasher, "calendar");
                field(&mut hasher, uid);
                field(&mut hasher, &sequence.to_string());
                field(&mut hasher, method);
                field(&mut hasher, ics_ref);
                field(&mut hasher, attendee);
                optional(&mut hasher, sender.map(|id| id.to_hex()).as_deref());
                field(&mut hasher, send_ref);
            }
            Self::Communication {
                sender,
                target,
                thread_ref,
                content_ref,
                send_ref,
            } => {
                field(&mut hasher, "communication");
                optional(&mut hasher, sender.map(|id| id.to_hex()).as_deref());
                field(&mut hasher, target);
                optional(&mut hasher, thread_ref.as_deref());
                optional(&mut hasher, content_ref.as_deref());
                field(&mut hasher, send_ref);
            }
            Self::HttpBundle {
                endpoint,
                content_ref,
                send_ref,
            } => {
                field(&mut hasher, "http_bundle");
                field(&mut hasher, endpoint);
                optional(&mut hasher, content_ref.as_deref());
                field(&mut hasher, send_ref);
            }
        }
        hasher.finalize()
    }
}

fn field(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn optional(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update(&[1]);
            field(hasher, value);
        }
        None => {
            hasher.update(&[0]);
        }
    }
}
