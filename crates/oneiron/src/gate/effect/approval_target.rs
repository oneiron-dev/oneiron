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
//! FIX 6424's last part pins) composes exactly the digest it composed
//! before. No target names a provider id the send has not been given yet. A
//! failure-signal batch pins once the next pass carries a held batch's ref
//! and content (FIX 6679).
//!
//! FIX 6424 part 2a (Engine 10-20 21:0x) adds a Linear issue mutation, on
//! the outbound dispatch door and on the mirror's direct admission of both
//! its actors, and a campaign enrollment's outbound leg. A press on either
//! family, once its admission spent it, is kept for that same send's retry
//! ([`ApprovalTarget::keeps_spent_press`]), so the retry reuses it.

use crate::calendar::CalendarInvitePayload;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::gate::ExternalEffectGateInput;
use crate::linear_sync::{LinearEffectRequest, MirroredTaskFields};
use crate::outbound_intent_ledger::PinnedApprovalFamily;

/// The BLAKE3 domain of the target pin.
const APPROVE_ONCE_TARGET_DOMAIN: &[u8] = b"oneiron.external_effect.approve_once.target.v1";
/// A connector whose admitted press is recomposed from its frozen ledger
/// bytes, so its press pins its send's stable logical identity.
const ESIGN_CONNECTOR: &str = "esign";
/// The failure-signal connector: a batch the Gate holds is carried into the
/// next pass under its own send ref and recomposed from its frozen ledger
/// bytes like an e-sign send's (FIX 6679).
const FAILURE_SIGNALS_CONNECTOR: &str = "failure_signals";
/// Whether a failure-signal batch pins its target (CALLS `FIX 6679 held
/// failure-signal batch carries over`, superseding `FIX 6424 failure-signal
/// batches keep the unpinned digest`): the next pass carries a held batch's
/// ref and content, so the owner's press is spent by exactly that batch.
const FAILURE_SIGNAL_BATCHES_PIN: bool = true;

/// The facts one non-mail send's approve-once press pins, per family. Every
/// `send_ref` is the family's existing logical ref: the dispatch's intent
/// ref, or for e-sign its stable ledger identity, which a retry of the same
/// prepared send carries again.
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
    /// A Linear issue create or update through the outbound dispatch door
    /// (CALLS `FIX 6424 ordinary Linear target without mirror facts`): its
    /// canonical verb, its original transport target (the team a create
    /// goes to, the issue an update names), its content ref, the send's
    /// stable logical ref (the logical send a schedule's ask names and its
    /// executor spends, CALLS `FIX 6424 scheduled ask stable identity`), the
    /// digest of the payload the dispatch froze (every frozen field, so a
    /// changed one is another send), and the mirror operation's facts when
    /// the mirror door supplies them. A generic caller supplies none and is
    /// asked for none.
    LinearDispatch {
        verb: String,
        target: String,
        content_ref: Option<String>,
        send_ref: String,
        payload_digest: [u8; 32],
        mirror: Option<LinearMirrorFacts>,
    },
    /// A Linear mirror mutation one of its two actors speaks for (OF-427):
    /// the host scheduler and the TASK revision's writer each press their
    /// own digest over these same facts (CALLS `FIX 6424 Linear dual actor
    /// asks`).
    LinearMirror(LinearMirrorFacts),
    /// A campaign enrollment's outbound leg (CALLS `FIX 6424 campaign event
    /// row versus logical event`).
    Campaign(CampaignLegFacts),
}

/// The facts one Linear mirror operation pins (Engine 10-20 17:4x): its
/// operation id, the nonce, which names the TASK, its revision and the
/// linked issue; the TASK; the issue an update names (a create names none:
/// the bridge picks the team, and the issue does not exist yet); and the
/// exact mirrored fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinearMirrorFacts {
    operation_id: [u8; 32],
    task_ref: EntityId,
    issue: Option<(String, String)>,
    fields: MirroredTaskFields,
}

impl LinearMirrorFacts {
    /// The facts `request`, the exact mutation the host sends, pins.
    pub(crate) fn of(request: &LinearEffectRequest) -> Self {
        Self {
            operation_id: request.operation_id,
            task_ref: request.task_ref,
            issue: request
                .issue
                .as_ref()
                .map(|issue| (issue.issue_id.clone(), issue.team_id.clone())),
            fields: request.fields.clone(),
        }
    }

    fn hash(&self, hasher: &mut blake3::Hasher) {
        field(hasher, &bytes_to_hex_lower(&self.operation_id));
        field(hasher, &self.task_ref.to_hex());
        optional(hasher, self.issue.as_ref().map(|(issue, _)| issue.as_str()));
        optional(hasher, self.issue.as_ref().map(|(_, team)| team.as_str()));
        field(hasher, &self.fields.title);
        optional(hasher, self.fields.description.as_deref());
        optional(
            hasher,
            self.fields
                .priority
                .map(|priority| priority.to_string())
                .as_deref(),
        );
        optional(hasher, self.fields.assignee_ref.as_deref());
        field(hasher, &self.fields.status);
    }
}

/// The facts one campaign enrollment's outbound leg pins (Engine 10-20
/// 21:0x ruling 6): the logical event (query, campaign, recipient entity,
/// epoch), never the event row that carried it; the program step; the
/// consequence id and its durable call sequence, the nonce; and the digest
/// of the frozen outbound body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CampaignLegFacts {
    pub(crate) query_ref: EntityId,
    pub(crate) campaign_ref: EntityId,
    pub(crate) entity_ref: EntityId,
    pub(crate) epoch: u64,
    pub(crate) program_ref: EntityId,
    pub(crate) step_ref: EntityId,
    pub(crate) consequence_id: [u8; 16],
    pub(crate) call_seq: u64,
    pub(crate) payload_digest: [u8; 32],
}

impl CampaignLegFacts {
    fn hash(&self, hasher: &mut blake3::Hasher) {
        field(hasher, &self.query_ref.to_hex());
        field(hasher, &self.campaign_ref.to_hex());
        field(hasher, &self.entity_ref.to_hex());
        field(hasher, &self.epoch.to_string());
        field(hasher, &self.program_ref.to_hex());
        field(hasher, &self.step_ref.to_hex());
        field(hasher, &bytes_to_hex_lower(&self.consequence_id));
        field(hasher, &self.call_seq.to_string());
        field(hasher, &bytes_to_hex_lower(&self.payload_digest));
    }
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
    /// member mail) or stays outside FIX 6424's non-mail census, and a
    /// Linear send's [`Self::LinearDispatch`] is built by its producer from
    /// the request's stable identity: those carry none here. A connector the
    /// registry gains later pins as a communication until it is given its
    /// own variant.
    pub(crate) fn for_outbound(facts: &OutboundSendFacts<'_>) -> Option<Self> {
        let send_ref = facts.send_ref.to_owned();
        let content_ref = facts.content_ref.map(str::to_owned);
        let target = match facts.connector {
            "email" | "email_resend" | "email_ses" | "email_postmark" | "linear" => return None,
            FAILURE_SIGNALS_CONNECTOR if !FAILURE_SIGNAL_BATCHES_PIN => return None,
            ESIGN_CONNECTOR => Self::Esign {
                document: facts.target.to_owned(),
                content_ref,
                send_ref,
            },
            "feedback_cloud"
            | "feedback_collector"
            | "feedback_github"
            | FAILURE_SIGNALS_CONNECTOR => Self::HttpBundle {
                endpoint: facts.target.to_owned(),
                content_ref,
                send_ref,
            },
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

    /// Whether a send on `connector` has its admitted press recomposed from
    /// its frozen ledger bytes (an e-sign send's or reminder's proof, FIX
    /// 6362; a failure-signal batch's, FIX 6679), so its frozen payload
    /// carries the send ref the press pins: the send's stable logical
    /// identity, the one its ledger row and every retry keep (Engine 10-20
    /// 20:4x).
    pub(crate) fn freezes_send_ref_of(connector: &str) -> bool {
        connector == ESIGN_CONNECTOR || connector == FAILURE_SIGNALS_CONNECTOR
    }

    /// Whether a press on this target, once the admission it released spent
    /// it, is kept for that same send's retry (Engine 10-20 21:0x ruling 8,
    /// CALLS `FIX 6424 pinned Pending proof retention`): a Linear mutation,
    /// for each of its actors, and a campaign leg. The retry reuses the kept
    /// press only while its own pinned digest is the kept one.
    pub(crate) fn keeps_spent_press(&self) -> bool {
        matches!(
            self,
            Self::LinearDispatch { .. } | Self::LinearMirror(_) | Self::Campaign(_)
        )
    }

    /// The family a dispatch's kept press is filed under beside its ledger
    /// row, typed by its target, never by its connector: a campaign leg
    /// rides any channel. `None` for every other target.
    pub(crate) fn pinned_family(&self) -> Option<PinnedApprovalFamily> {
        match self {
            Self::LinearDispatch { .. } => Some(PinnedApprovalFamily::LinearDispatch),
            Self::Campaign(_) => Some(PinnedApprovalFamily::CampaignLeg),
            _ => None,
        }
    }

    /// The approve-once digest a held `effect` names, 64 lower-hex: the
    /// Gate's own composer over that very input. `None` for an effect whose
    /// family pins no target.
    pub(crate) fn held_digest(effect: &ExternalEffectGateInput) -> Option<String> {
        effect.provenance.approval_target.as_ref()?;
        super::external_effect_approval_digest(effect).map(|digest| digest.to_hex())
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
            Self::LinearDispatch {
                verb,
                target,
                content_ref,
                send_ref,
                payload_digest,
                mirror,
            } => {
                field(&mut hasher, "linear_dispatch");
                field(&mut hasher, verb);
                field(&mut hasher, target);
                optional(&mut hasher, content_ref.as_deref());
                field(&mut hasher, send_ref);
                field(&mut hasher, &bytes_to_hex_lower(payload_digest));
                match mirror {
                    Some(facts) => {
                        hasher.update(&[1]);
                        facts.hash(&mut hasher);
                    }
                    None => {
                        hasher.update(&[0]);
                    }
                }
            }
            Self::LinearMirror(facts) => {
                field(&mut hasher, "linear_mirror");
                facts.hash(&mut hasher);
            }
            Self::Campaign(facts) => {
                field(&mut hasher, "campaign");
                facts.hash(&mut hasher);
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
