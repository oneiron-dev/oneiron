//! What the engine grants on consent and standing it folds from rows a
//! restore brings back: the ramp offer a sender's reputation earns, a
//! coreference link shared into a pact, the delivery-window restrictions a
//! send meets, a public booking page served, an e-sign principal's autonomy,
//! what a signing ceremony lets its parties do, and whom a calendar
//! invitation may reach.
use super::{Decision, held_by_both};
use crate::blob_artifact::esign::{self, DocumentStatus, EsignState, SigningStatus};
use crate::booking::invite_grant::{booker_identity_in_txn, normalize_identity};
use crate::calendar::invite::CalendarInviteConsentSnapshot;
use crate::channel_identity_provider::native_mail;
use crate::claim::{COREFERENCE_PACT_ID_LEN, ClaimSubject, PREDICATE_COREFERENCE_SHARE_CONSENT};
use crate::delivery_window::{DELIVERY_WINDOW_CLAIM_PREDICATES, DeliveryWindowPolicyClaim};
use crate::edge::EdgeKind;
use crate::outbound_grant::{StandingOutboundGrantScope, standing_outbound_grant_in_txn};
use crate::ports::EntityStoreRead;
use crate::registry::{
    ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_OUTBOUND_GRANT,
    ENTITY_TYPE_PERSON,
};
use crate::{EntityId, Error, Result, Vault};
use std::collections::{BTreeMap, BTreeSet};

/// Whether a native-mail sender's reputation earns it the offer of
/// cold-recipient autonomy: every current observed reputation head its
/// `claim_of` edges reach, under the sender's policy row
/// (`native_mail_reputation_earned`).
pub(super) struct MailReputation;

impl Decision for MailReputation {
    type Subject = EntityId;
    type Answer = bool;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<EntityId>> {
        held_by_both(vaults, ENTITY_TYPE_CHANNEL_IDENTITY)
    }

    fn answers(vault: &Vault, subjects: &BTreeSet<EntityId>) -> Result<Vec<Option<bool>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|identity| native_mail::native_mail_reputation_earned(vault, &txn, *identity).ok())
            .collect())
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}

/// Whether the coreference link between two people may be exported into one
/// pact: the link stored in either direction, and a local approved consent
/// on it naming that pact (`coreference_shared_for_pact_in_txn`).
pub(super) struct SharedCoreference;

impl Decision for SharedCoreference {
    type Subject = (EntityId, EntityId, [u8; COREFERENCE_PACT_ID_LEN]);
    type Answer = bool;

    /// Each pair of people and pact a consent in either vault names, for
    /// people both vaults hold: a link no consent names is never shared, and
    /// one whose person only one vault holds returns or leaves with them.
    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let people = held_by_both(vaults, ENTITY_TYPE_PERSON)?;
        let mut subjects = BTreeSet::new();
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            for (_, consent) in
                vault.claims_with_predicate_in_txn(&txn, PREDICATE_COREFERENCE_SHARE_CONSENT)?
            {
                if let ClaimSubject::Edge {
                    source,
                    kind: EdgeKind::SameAs,
                    target,
                } = &consent.subject
                    && people.contains(source)
                    && people.contains(target)
                    && let Ok(pact) = crate::claim::coreference_share_consent_pact_id(&consent)
                {
                    subjects.insert((*source.min(target), *source.max(target), pact));
                }
            }
        }
        Ok(subjects)
    }

    fn answers(vault: &Vault, subjects: &BTreeSet<Self::Subject>) -> Result<Vec<Option<bool>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|(a, b, pact)| {
                crate::federation::coreference_shared_for_pact_in_txn(vault, &txn, *a, *b, pact)
                    .ok()
            })
            .collect())
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}

/// The delivery-window restrictions the outbound door reads for a send that
/// names one subject: each `delivery_window.*` claim on the subject that its
/// `claim_of` edge reaches (`stored_delivery_window_policy_claims`) and that
/// restricts any send (`DeliveryWindowPolicyClaim::restricts`). One only
/// ever holds or degrades a send, so a restriction the live door reads is
/// lifted when the restored door reads none with its reach: a duplicate
/// that differs only in source or reason holds the same sends to the same
/// retry.
pub(super) struct DeliveryWindows;

impl Decision for DeliveryWindows {
    type Subject = EntityId;
    type Answer = Vec<DeliveryWindowPolicyClaim>;

    /// Every subject a delivery-window claim names in either vault.
    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<EntityId>> {
        let mut subjects = BTreeSet::new();
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            for predicate in DELIVERY_WINDOW_CLAIM_PREDICATES {
                for (_, claim) in vault.claims_with_predicate_in_txn(&txn, predicate)? {
                    if let ClaimSubject::Entity(subject) = claim.subject {
                        subjects.insert(subject);
                    }
                }
            }
        }
        Ok(subjects)
    }

    fn answers(vault: &Vault, subjects: &BTreeSet<EntityId>) -> Result<Vec<Option<Self::Answer>>> {
        Ok(subjects
            .iter()
            .map(|subject| {
                crate::outbound::stored_delivery_window_policy_claims(
                    vault,
                    std::slice::from_ref(subject),
                )
                .ok()
                .map(|claims| {
                    claims
                        .into_iter()
                        .filter(DeliveryWindowPolicyClaim::restricts)
                        .collect()
                })
            })
            .collect())
    }

    fn loosens(live: &Self::Answer, restored: &Self::Answer) -> bool {
        live.iter()
            .any(|restriction| !restored.iter().any(|kept| kept.same_reach(restriction)))
    }
}

/// Whether a public booking page is served at an instant: its indexed
/// publication, live, owned and published, with every event configuration
/// still the one the owner pinned (`load_public_booking_page`).
pub(super) struct BookingPublications;

impl Decision for BookingPublications {
    /// A page, and the first instant from now that a publication of it is
    /// valid.
    type Subject = (EntityId, u64);
    type Answer = bool;

    /// Every page a publication in either vault names, at the first instant
    /// from now inside that publication's lifetime, for pages both vaults
    /// hold live: one only one vault holds returns or leaves with the
    /// restore. A publication already over serves nothing again.
    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        // The live vault's clock: both vaults are asked at the same instant.
        let now = vaults[0].now_recorded_at();
        let mut subjects = BTreeSet::new();
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            for (_, publication) in vault
                .claims_with_predicate_in_txn(&txn, crate::booking::BOOKING_PUBLIC_PAGE_PREDICATE)?
            {
                if let (ClaimSubject::Entity(page), Some(from), Some(to)) = (
                    &publication.subject,
                    publication.valid_from,
                    publication.valid_to,
                ) && from.max(now) < to
                {
                    subjects.insert((*page, from.max(now)));
                }
            }
        }
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            let mut live = BTreeSet::new();
            for (page, _) in &subjects {
                if crate::vault::live_entity_row_in_txn(&vault.store, &txn, page)?.is_live() {
                    live.insert(*page);
                }
            }
            subjects.retain(|(page, _)| live.contains(page));
        }
        Ok(subjects)
    }

    fn answers(vault: &Vault, subjects: &BTreeSet<Self::Subject>) -> Result<Vec<Option<bool>>> {
        Ok(subjects
            .iter()
            .map(|(page, at)| {
                crate::booking::load_public_booking_page(vault, *page, *at)
                    .ok()
                    .map(|served| served.is_some())
            })
            .collect())
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}

/// Whether an automated e-sign principal may sign, or send, on its own: the
/// one identity it resolves to, and every principal policy that resolves to
/// the same one, all of which must grant it (`automated_signing_allowed`,
/// `automated_outbound_allowed`).
pub(super) struct PrincipalAutonomy;

/// What a principal's automation may do without a human.
pub(super) struct Autonomy {
    sign: bool,
    send: bool,
}

impl Decision for PrincipalAutonomy {
    type Subject = EntityId;
    type Answer = Autonomy;

    /// Every principal a policy in either vault names, the identity each
    /// resolves to, and every merged or split identity that resolves to one
    /// of those: any other principal resolves to an identity no policy does.
    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<EntityId>> {
        let mut subjects = BTreeSet::new();
        for vault in vaults {
            let principals: Vec<EntityId> = vault
                .signing_principals()?
                .iter()
                .filter_map(|policy| EntityId::from_hex(&policy.principal_ref).ok())
                .collect();
            let txn = vault.store.env.read_txn()?;
            let mut heads = BTreeSet::new();
            for principal in &principals {
                // One that does not resolve fails every answer closed.
                heads.extend(
                    vault
                        .resolve_entity_in_txn(&txn, principal)
                        .unwrap_or_default(),
                );
            }
            subjects.extend(crate::identity_redirect::inbound_redirect_shells_in_txn(
                &vault.store,
                &txn,
                &heads,
            )?);
            subjects.extend(heads);
            subjects.extend(principals);
        }
        Ok(subjects)
    }

    fn answers(vault: &Vault, subjects: &BTreeSet<EntityId>) -> Result<Vec<Option<Autonomy>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|principal| {
                let principal = principal.to_hex();
                let principal = Some(principal.as_str());
                Some(Autonomy {
                    sign: esign::automated_signing_allowed(vault, &txn, principal).ok()?,
                    send: esign::automated_outbound_allowed(vault, &txn, principal).ok()?,
                })
            })
            .collect())
    }

    fn loosens(live: &Autonomy, restored: &Autonomy) -> bool {
        (!live.sign && restored.sign) || (!live.send && restored.send)
    }
}

/// What a signing ceremony lets its parties do, as it folds from the event
/// claims its document's `claim_of` edges reach (`esign_document`): its owner
/// sends it only as a draft; a recipient reads its PDF once the ceremony is
/// under way and the recipient's turn has come, and signs or declines only
/// on its turn of an open ceremony, each until its deadline
/// (`execute_signing_action`, `esign_pdf_for_capability`), and only while it
/// holds a capability no one revoked.
pub(super) struct EsignCeremonies;

/// What the ceremony gates decide on, by recipient.
pub(super) struct CeremonyPosture {
    draft: bool,
    readers: BTreeSet<String>,
    actors: BTreeSet<String>,
    deadlines: BTreeMap<String, u64>,
}

impl CeremonyPosture {
    /// The posture `state` folds to for the recipients `holds` a capability
    /// for; the rest read and do nothing.
    fn of(state: &EsignState, holds: impl Fn(&str) -> bool) -> Self {
        let open = state.status == DocumentStatus::Pending;
        let under_way = !matches!(
            state.status,
            DocumentStatus::Draft | DocumentStatus::Voided | DocumentStatus::Expired
        );
        let mut posture = Self {
            draft: state.status == DocumentStatus::Draft,
            readers: BTreeSet::new(),
            actors: BTreeSet::new(),
            deadlines: BTreeMap::new(),
        };
        for (recipient, progress) in &state.recipients {
            if !holds(recipient) {
                continue;
            }
            if under_way && !(open && progress.signing == SigningStatus::Waiting) {
                posture.readers.insert(recipient.clone());
            }
            if open && state.rejection.is_none() && progress.signing == SigningStatus::Ready {
                posture.actors.insert(recipient.clone());
            }
            posture
                .deadlines
                .insert(recipient.clone(), progress.expires_at);
        }
        posture
    }
}

impl Decision for EsignCeremonies {
    type Subject = EntityId;
    type Answer = CeremonyPosture;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<EntityId>> {
        held_by_both(vaults, ENTITY_TYPE_BLOB_ARTIFACT)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<EntityId>,
    ) -> Result<Vec<Option<CeremonyPosture>>> {
        // Each fold reads in its own transaction, so the capabilities are
        // read after.
        let states: Vec<Option<EsignState>> = subjects
            .iter()
            .map(|document| vault.esign_document(*document).ok())
            .collect();
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .zip(states)
            .map(|(document, state)| {
                Some(CeremonyPosture::of(&state?, |recipient| {
                    esign::recipient_capability_unrevoked_in(vault, &txn, *document, recipient)
                        .unwrap_or(false)
                }))
            })
            .collect())
    }

    fn loosens(live: &CeremonyPosture, restored: &CeremonyPosture) -> bool {
        (!live.draft && restored.draft)
            || !restored.readers.is_subset(&live.readers)
            || !restored.actors.is_subset(&live.actors)
            || restored.deadlines.iter().any(|(recipient, deadline)| {
                live.deadlines
                    .get(recipient)
                    .is_none_or(|current| deadline > current)
            })
    }
}

/// Whether a calendar invitation REQUEST may reach a recipient at all: a
/// standing `comm.last_touch` with them on email or the calendar that their
/// party's `claim_of` edges reach, or an active standing grant that covers
/// them, a booking page's through a confirmed booking on that page that they
/// booked (`resolve_consent_basis`). Which of these carries the invitation,
/// and which grant, changes nothing it may do.
pub(super) struct CalendarInviteConsent;

impl Decision for CalendarInviteConsent {
    /// A recipient, spelled as a send names one.
    type Subject = String;
    type Answer = bool;

    /// Every recipient spelling either vault can answer apart from the rest:
    /// each comm party's key, each contact a grant names and, where a booking
    /// page grant can cover a booker, each booker identity a person row of
    /// either vault carries, with the spellings that fold onto it
    /// (`booker_spellings`). A channel grant covers every recipient alike.
    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<String>> {
        let mut parties = BTreeSet::new();
        let mut subjects = BTreeSet::new();
        let mut pages = false;
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            parties.extend(crate::comm::comm_party_keys_in_txn(&vault.store, &txn)?);
            for id in vault
                .store
                .port_entity_ids_by_type(&txn, ENTITY_TYPE_OUTBOUND_GRANT, None)?
            {
                match standing_outbound_grant_in_txn(&vault.store, &txn, &id?)?
                    .map(|grant| grant.scope)
                {
                    Some(StandingOutboundGrantScope::Contact { contact_ref }) => {
                        subjects.extend(spelling(&contact_ref));
                    }
                    Some(StandingOutboundGrantScope::BookingPageInvites { .. }) => pages = true,
                    _ => {}
                }
            }
        }
        subjects.extend(parties.iter().map(String::as_str).filter_map(spelling));
        if pages {
            let mut identities = BTreeSet::new();
            for vault in vaults {
                let txn = vault.store.env.read_txn()?;
                for person in vault
                    .store
                    .port_entity_ids_by_type(&txn, ENTITY_TYPE_PERSON, None)?
                {
                    identities.extend(
                        booker_identity_in_txn(vault, &txn, &person?)
                            .map_err(|error| Error::InvalidConfig(error.to_string()))?,
                    );
                }
            }
            for identity in &identities {
                subjects.extend(booker_spellings(identity, &parties));
            }
        }
        Ok(subjects)
    }

    /// Each subject's answer from one read of the vault's consent evidence,
    /// which folds it as the invitation door does
    /// (`CalendarInviteConsentSnapshot`).
    fn answers(vault: &Vault, subjects: &BTreeSet<String>) -> Result<Vec<Option<bool>>> {
        let consent = CalendarInviteConsentSnapshot::read(vault);
        Ok(subjects
            .iter()
            .map(|recipient| consent.basis(recipient).ok().map(|basis| basis.is_some()))
            .collect())
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}

/// `value` as a send names a recipient: trimmed, and not empty.
fn spelling(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// The spellings of a booker identity that a booking page grant covers
/// alike, as they fold onto one address (`normalize_identity`): the identity
/// as stored and as it folds, and, of the bare spellings and of those behind
/// a `mailto:`, which a contact grant tells apart, the first that is no comm
/// party's key. A prior thread reads only a party's exact key, so that one
/// answers for every other of its kind that is none.
fn booker_spellings(identity: &str, parties: &BTreeSet<String>) -> impl Iterator<Item = String> {
    let address = normalize_identity(identity);
    let bare = first_unkeyed(casings(&address), &address, parties);
    let prefixed = first_unkeyed(
        ["mailto:", "MAILTO:"]
            .into_iter()
            .flat_map(|prefix| casings(&address).map(move |casing| format!("{prefix}{casing}"))),
        &address,
        parties,
    );
    [spelling(identity), spelling(&address), bare, prefixed]
        .into_iter()
        .flatten()
}

/// Every casing of the ASCII letters of `address`, lower case first: bit `n`
/// of a casing's number raises the `n`th letter.
fn casings(address: &str) -> impl Iterator<Item = String> {
    let letters = address
        .bytes()
        .filter(u8::is_ascii_alphabetic)
        .count()
        .min(63);
    (0..1_u64 << letters).map(move |mask| {
        let mut letter = 0_u32;
        address
            .chars()
            .map(|character| {
                if !character.is_ascii_alphabetic() {
                    return character;
                }
                let raised = mask.checked_shr(letter).is_some_and(|bits| (bits & 1) == 1);
                letter += 1;
                if raised {
                    character.to_ascii_uppercase()
                } else {
                    character
                }
            })
            .collect::<String>()
    })
}

/// The first of `spellings` that a send can name, that folds onto `address`
/// and that is no comm party's key. Only a casing that spells out the prefix
/// the fold strips fails to fold, two in 64 at most, so twice as many
/// spellings as there are keys, and two, hold one.
fn first_unkeyed(
    spellings: impl Iterator<Item = String>,
    address: &str,
    parties: &BTreeSet<String>,
) -> Option<String> {
    spellings.take(2 * (parties.len() + 1)).find(|spelling| {
        !spelling.is_empty()
            && spelling.trim() == spelling.as_str()
            && normalize_identity(spelling) == address
            && !parties.contains(spelling)
    })
}
