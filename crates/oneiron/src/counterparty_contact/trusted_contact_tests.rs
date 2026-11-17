//! OF-527 acceptance: a trusted contact hears a crisis notice only with both
//! sides' live consent, only on the gate's `RouteToHelp`, and only the fact of
//! concern, over the OF-327 outbound rails.

use super::{
    TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND, TrustedContact, TrustedContactAskOutcome,
    TrustedContactDial, TrustedContactNotice, TrustedContactParty, TrustedContactReach,
    TrustedContactTier,
};
use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::off_record::OffRecordBackendClass;
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchOutcome, OutboundDispatchRequest, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger,
};
use crate::policy_model::{
    PolicyClassifyRequest, PolicyEnforcementAction, PolicyModelConfig, PolicyModelEnforcement,
};
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::temporal::TimeRange;
use crate::{Vault, VaultConfig};

/// The turn the gate routes to help. Every word of it is private.
const PRIVATE_TURN: &str =
    "crisis-marker the bridge on fifth street, my sister's pills, please do not tell anyone";
const PRIVATE_WORDS: [&str; 8] = [
    "crisis",
    "bridge",
    "fifth",
    "pills",
    "sister",
    "anyone",
    "owner:crisis",
    "self-harm",
];
const CRISIS_ROW_TEXT: &str = "Route a self-harm crisis to help.";
const CONTACT_ADDRESS: &str = "contact@example.com";

fn now() -> u64 {
    crate::unix_seconds_now()
}

struct Fixture {
    _tmp: tempfile::TempDir,
    vault: Vault,
    person: AuthenticatedOwner,
    person_id: EntityId,
    contact: AuthenticatedOwner,
    contact_id: EntityId,
    sender: EntityId,
    identity: EntityId,
}

/// A vault whose owner plane routes `crisis-marker` to help, warns on
/// `warn-marker` and blocks `block-marker`, and whose `sender` may send email.
fn fixture() -> Result<Fixture> {
    let tmp = tempfile::tempdir().expect("temp vault dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default())?;
    let person = crate::test_util::embedded_owner_proof(&vault);
    let contact = crate::test_util::non_owner_proof(&vault);
    let (person_id, contact_id) = (person.actor(), contact.actor());
    let sender = EntityId::now();
    vault.put_entity(
        &sender,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"sender",
    )?;
    let row = |row_ref: &str, text: &str, action: &str| serde_json::json!({"row_ref": row_ref, "text": text, "action": action, "active": true});
    let pattern = |id: &str, pattern: &str, row_ref: &str| serde_json::json!({"id": id, "pattern": pattern, "category": row_ref, "role": "decide"});
    let manifest = serde_json::json!({
        "schema_version": crate::gate::POLICY_SCHEMA_VERSION, "pack_id": "trusted-contact-test",
        "pack_version": "v1", "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"}, "rules": [],
        "actor_ceilings": [{"actor_class": "human", "actor_ref": sender.to_hex(), "ceiling": "auto"}],
        "scoped_grants": [{"actor_ref": sender.to_hex(), "effector": "external:send",
            "scope": crate::federation::scope_codec::effect_preset(), "selectors": {"channel": "email"}}],
        "owner_policy_enabled": true,
        "owner_policy_rows": [
            row("owner:crisis", CRISIS_ROW_TEXT, "route_to_help"),
            row("owner:warn", "Flag warn markers.", "warn"),
            row("owner:block", "Withhold block markers.", "block"),
        ],
        "owner_policy_patterns": [
            pattern("owner.crisis", "(?i)crisis-marker", "owner:crisis"),
            pattern("owner.warn", "(?i)warn-marker", "owner:warn"),
            pattern("owner.block", "(?i)block-marker", "owner:block"),
        ],
    });
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &rmp_serde::to_vec_named(&manifest).expect("manifest encode"),
    )?;
    let identity = EntityId::now();
    vault.create_channel_identity(
        &identity,
        &crate::test_util::self_held_identity_in_state(
            "email",
            "sender@example.com",
            crate::channel_identity::SelfHeldShape::DedicatedAddress,
            crate::channel_identity::ChannelIdentityBinding::actor(sender),
            crate::channel_identity::ChannelIdentityState::Active,
            1_000,
        ),
    )?;
    Ok(Fixture {
        _tmp: tmp,
        vault,
        person,
        person_id,
        contact,
        contact_id,
        sender,
        identity,
    })
}

impl Fixture {
    fn reach(&self) -> TrustedContactReach {
        TrustedContactReach {
            sender: self.sender,
            channel: "email".to_owned(),
            verb: "send".to_owned(),
            target: CONTACT_ADDRESS.to_owned(),
        }
    }

    fn name(&self, dial: TrustedContactDial) -> Result<TrustedContact> {
        self.vault
            .name_trusted_contact(&self.person, self.contact_id, self.reach(), dial, now())
    }

    /// Named by the person and accepted by the contact as an adult.
    fn live(&self, dial: TrustedContactDial) -> Result<TrustedContact> {
        let named = self.name(dial)?;
        self.vault
            .accept_trusted_contact(&self.contact, self.person_id, named.version, true, now())
    }

    fn imminent(&self) -> Result<()> {
        self.vault.set_trusted_contact_tier(
            &self.person,
            "owner:crisis",
            TrustedContactTier::Imminent,
        )
    }

    fn crisis_request(&self) -> PolicyClassifyRequest {
        PolicyClassifyRequest::outbound_content(PRIVATE_TURN)
            .with_concerned_person(self.person.clone())
    }

    /// The gate routes the private turn to help.
    fn crisis(&self) -> Result<PolicyModelEnforcement> {
        let outcome = self.vault.enforce_policy_model(self.crisis_request())?;
        assert_eq!(outcome.action, PolicyEnforcementAction::RouteToHelp);
        Ok(outcome)
    }

    /// Every notice ever staged for a contact, settled or not.
    fn staged(&self) -> Result<usize> {
        Ok(AttemptQueue::new(&self.vault)
            .list()?
            .iter()
            .filter(|attempt| attempt.kind == TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND)
            .count())
    }

    fn claim(&self) -> Result<(AttemptRecord, TrustedContactNotice)> {
        Ok(self
            .vault
            .claim_trusted_contact_notice("notice-worker", now())?
            .expect("a staged notice"))
    }

    /// The host's send of a claimed notice, from the sender to the contact.
    fn outgoing(&self, notice: &TrustedContactNotice, key: &str) -> OutboundDispatchRequest {
        let mut request = OutboundDispatchRequest::new(
            format!("receipt:{key}"),
            key,
            OutboundIntent::from_trigger(
                OutboundIntentDraft {
                    actor: notice.sender.clone(),
                    on_behalf_of: None,
                    verb: notice.verb.clone(),
                    channel: notice.channel.clone(),
                    target: notice.target.clone(),
                    content_ref: None,
                    idempotency_key: None,
                    dedupe_key: None,
                },
                OutboundIntentTrigger::record_transition(notice.fire.clone()),
            ),
            OutboundDispatchActor {
                actor_class: "human".into(),
                actor_ref: Some(self.sender.to_hex()),
                actor_entity_ref: Some(self.sender),
            },
            OutboundDispatchGate {
                has_opted_in: true,
                has_permission: true,
                policy_risk: Default::default(),
            },
            1_065,
            OutboundDeliveryWindowDecision::DeliverNow,
        );
        request.channel_identity_ref = Some(self.identity);
        request
    }
}

/// The transport: it keeps everything it was handed, so a test can read what
/// crossed to the contact.
#[derive(Default)]
struct RecordingSink {
    calls: Vec<String>,
}

impl OutboundExecutionSink for RecordingSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls.push(format!(
            "{} {:?} {:?} {:?} {:?}",
            request.intent_ref,
            request.intent,
            request.idempotency_key,
            request.counterparty_ref,
            request.hygiene_headers
        ));
        OutboundExecutionOutcome::delivered_to_channel(format!("sent:{}", self.calls.len()))
    }
}

fn told(outcome: &PolicyModelEnforcement, notice_type: &str) -> bool {
    outcome
        .system_notices
        .iter()
        .any(|notice| notice.notice_type == notice_type && notice.audience == "user_and_model")
}

#[test]
fn a_named_contact_hears_nothing_until_they_accept_as_an_adult() -> Result<()> {
    let fx = fixture()?;
    fx.imminent()?;
    let named = fx.name(TrustedContactDial::JustCall)?;
    assert!(!named.is_live());
    fx.crisis()?;
    assert_eq!(fx.staged()?, 0);
    assert!(fx.vault.trusted_contact_asks(&fx.person)?.is_empty());

    // Only the named contact accepts, for themselves, as an adult, the
    // version they were shown.
    let stranger = crate::test_util::non_owner_proof(&fx.vault);
    for (proof, version, adult) in [
        (&stranger, named.version, true),
        (&fx.person, named.version, true),
        (&fx.contact, named.version, false),
        (&fx.contact, named.version + 1, true),
    ] {
        assert!(
            fx.vault
                .accept_trusted_contact(proof, fx.person_id, version, adult, now())
                .is_err()
        );
    }
    fx.crisis()?;
    assert_eq!(fx.staged()?, 0);

    let live =
        fx.vault
            .accept_trusted_contact(&fx.contact, fx.person_id, named.version, true, now())?;
    assert!(live.is_live());
    assert_eq!(live.accepted.map(|accepted| accepted.adult), Some(true));
    fx.crisis()?;
    assert_eq!(fx.staged()?, 1);

    // Who may be named: another live PERSON. Never yourself, never an id that
    // names no person.
    for contact in [fx.person_id, EntityId::now()] {
        assert!(
            fx.vault
                .name_trusted_contact(
                    &fx.person,
                    contact,
                    fx.reach(),
                    TrustedContactDial::JustCall,
                    now()
                )
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn either_side_revokes_and_a_revoked_relation_never_fires() -> Result<()> {
    for revoker in [TrustedContactParty::Person, TrustedContactParty::Contact] {
        let fx = fixture()?;
        fx.imminent()?;
        fx.live(TrustedContactDial::JustCall)?;
        let stranger = crate::test_util::non_owner_proof(&fx.vault);
        assert!(
            fx.vault
                .revoke_trusted_contact(&stranger, fx.person_id, fx.contact_id, now())
                .is_err()
        );
        let by = match revoker {
            TrustedContactParty::Person => &fx.person,
            TrustedContactParty::Contact => &fx.contact,
        };
        let revoked = fx
            .vault
            .revoke_trusted_contact(by, fx.person_id, fx.contact_id, now())?;
        assert_eq!(
            revoked.revoked.map(|revocation| revocation.by),
            Some(revoker)
        );
        assert!(!revoked.is_live());
        fx.crisis()?;
        assert_eq!(fx.staged()?, 0);
    }

    // Naming the contact again, with anything changed, needs their consent again.
    let fx = fixture()?;
    fx.imminent()?;
    fx.live(TrustedContactDial::JustCall)?;
    let renamed = fx.name(TrustedContactDial::JustCall)?;
    assert!(!renamed.is_live());
    fx.crisis()?;
    assert_eq!(fx.staged()?, 0);

    // A notice staged while the relation was live does not reach a contact
    // who has since withdrawn: the transport is never called.
    fx.vault
        .accept_trusted_contact(&fx.contact, fx.person_id, renamed.version, true, now())?;
    fx.crisis()?;
    let (attempt, notice) = fx.claim()?;
    fx.vault
        .revoke_trusted_contact(&fx.contact, fx.person_id, fx.contact_id, now())?;
    let mut sink = RecordingSink::default();
    let sent = fx.vault.dispatch_trusted_contact_notice(
        &attempt,
        fx.outgoing(&notice, "withdrawn"),
        &mut sink,
    );
    assert!(
        !matches!(&sent, Ok(sent) if sent.outcome == OutboundDispatchOutcome::DeliveredToChannel),
        "{sent:?}"
    );
    assert!(sink.calls.is_empty());

    // An ask still open when its naming is revoked or replaced closes with
    // it: the next crisis asks once, about the live naming, and a yes to the
    // old ask is told it was superseded and reaches no one.
    for revoked in [true, false] {
        let fx = fixture()?;
        let first = fx.live(TrustedContactDial::AskFirst)?;
        fx.crisis()?;
        let old = fx.vault.trusted_contact_asks(&fx.person)?;
        assert_eq!(old.len(), 1);
        if revoked {
            fx.vault
                .revoke_trusted_contact(&fx.contact, fx.person_id, fx.contact_id, now())?;
        }
        let live = fx.live(TrustedContactDial::AskFirst)?;
        assert!(live.version > first.version);
        fx.crisis()?;
        let open = fx.vault.trusted_contact_asks(&fx.person)?;
        assert_eq!(
            open.iter().map(|ask| ask.version).collect::<Vec<_>>(),
            [live.version],
            "revoked={revoked}: one open ask, about the live naming"
        );
        let answered = fx.vault.answer_trusted_contact_ask(
            &fx.person,
            old[0].ask,
            true,
            &PolicyModelConfig::default(),
            now(),
        )?;
        assert_eq!(answered, TrustedContactAskOutcome::Superseded);
        assert_eq!(fx.staged()?, 0);
    }
    Ok(())
}

#[test]
fn only_the_gates_route_to_help_fires_the_notify() -> Result<()> {
    let fx = fixture()?;
    fx.imminent()?;
    fx.live(TrustedContactDial::JustCall)?;
    // The fixture has no model, so a turn no pattern flags is a skipped pass,
    // not an allow. Neither is a help card.
    for (content, action) in [
        ("nothing to flag here", PolicyEnforcementAction::Skipped),
        ("warn-marker on this one", PolicyEnforcementAction::Warn),
        ("block-marker on this one", PolicyEnforcementAction::Block),
    ] {
        let outcome = fx.vault.enforce_policy_model(
            PolicyClassifyRequest::outbound_content(content)
                .with_concerned_person(fx.person.clone()),
        )?;
        assert_eq!(outcome.action, action);
        assert_eq!(fx.staged()?, 0, "{action:?} fired the notify");
    }

    // A help card for content no person was bound to reaches no one's contact.
    let unbound = fx
        .vault
        .enforce_policy_model(PolicyClassifyRequest::outbound_content(PRIVATE_TURN))?;
    assert_eq!(unbound.action, PolicyEnforcementAction::RouteToHelp);
    assert_eq!(fx.staged()?, 0);

    // A notice queued by hand, for a live relation, with no fire behind it,
    // is never handed to the host.
    let forged = super::TrustedContactNotice {
        fire: EntityId::now().to_hex(),
        person: fx.person_id.to_hex(),
        contact: fx.contact_id.to_hex(),
        version: 1,
        sender: fx.sender.to_hex(),
        channel: "email".to_owned(),
        verb: "send".to_owned(),
        target: CONTACT_ADDRESS.to_owned(),
    };
    AttemptQueue::new(&fx.vault).enqueue(crate::attempt_queue::EnqueueAttempt {
        kind: TRUSTED_CONTACT_NOTICE_ATTEMPT_KIND.to_owned(),
        payload: serde_json::to_vec(&forged).expect("notice encode"),
        dedupe_key: None,
        run_id: None,
        now: now(),
    })?;
    assert!(
        fx.vault
            .claim_trusted_contact_notice("notice-worker", now())?
            .is_none()
    );

    let fired = fx.crisis()?;
    assert_eq!(fx.staged()?, 2);
    let (attempt, notice) = fx.claim()?;
    let sent = fx
        .vault
        .dispatch_trusted_contact_notice(
            &attempt,
            fx.outgoing(&notice, "first"),
            &mut RecordingSink::default(),
        )
        .expect("dispatch");
    assert_eq!(sent.outcome, OutboundDispatchOutcome::DeliveredToChannel);

    // A RouteToHelp verdict handed back by a caller, which is all a persona's
    // own claim could be, is enforced but fires nothing.
    let replayed = fx.vault.enforce_policy_model_verdict(
        fx.crisis_request(),
        &PolicyModelConfig::default(),
        fired.verdict,
        false,
    )?;
    assert_eq!(replayed.action, PolicyEnforcementAction::RouteToHelp);
    assert_eq!(fx.staged()?, 2);

    // The gate's own next RouteToHelp does.
    fx.crisis()?;
    assert_eq!(fx.staged()?, 3);
    Ok(())
}

#[test]
fn the_tier_and_dial_decide_whether_the_person_is_asked_first() -> Result<()> {
    // The concern tier, which every row is until the owner names it imminent:
    // the person is asked, and the contact hears only on a yes.
    let fx = fixture()?;
    fx.live(TrustedContactDial::JustCall)?;
    let asked = fx.crisis()?;
    assert!(told(&asked, "trusted_contact_ask"));
    assert_eq!(fx.staged()?, 0);
    let asks = fx.vault.trusted_contact_asks(&fx.person)?;
    assert_eq!(asks.len(), 1);
    assert_eq!(asks[0].tier, TrustedContactTier::Concern);
    let config = PolicyModelConfig::default();
    assert!(
        fx.vault
            .answer_trusted_contact_ask(&fx.contact, asks[0].ask, true, &config, now())
            .is_err()
    );
    assert_eq!(
        fx.vault
            .answer_trusted_contact_ask(&fx.person, asks[0].ask, false, &config, now())?,
        TrustedContactAskOutcome::Declined
    );
    assert!(
        fx.vault
            .answer_trusted_contact_ask(&fx.person, asks[0].ask, true, &config, now())
            .is_err()
    );
    assert_eq!(fx.staged()?, 0);
    assert!(fx.vault.trusted_contact_asks(&fx.person)?.is_empty());

    fx.crisis()?;
    let ask = fx.vault.trusted_contact_asks(&fx.person)?[0].ask;
    // A yes is told, like the gate's own fire.
    let TrustedContactAskOutcome::Notified(yes) =
        fx.vault
            .answer_trusted_contact_ask(&fx.person, ask, true, &config, now())?
    else {
        panic!("a yes to a live ask notifies");
    };
    assert!(yes.iter().any(|notice| {
        notice.notice_type == "trusted_contact_notified" && notice.audience == "user_and_model"
    }));
    assert_eq!(fx.staged()?, 1);

    // Only the owner names a policy row's tier.
    assert!(
        fx.vault
            .set_trusted_contact_tier(&fx.contact, "owner:crisis", TrustedContactTier::Imminent)
            .is_err()
    );

    // The imminent tier with just-call: the contact is reached now, and both
    // the agent and the person are told.
    let fx = fixture()?;
    fx.imminent()?;
    fx.live(TrustedContactDial::JustCall)?;
    let notified = fx.crisis()?;
    assert!(told(&notified, "trusted_contact_notified"));
    assert_eq!(fx.staged()?, 1);
    assert!(fx.vault.trusted_contact_asks(&fx.person)?.is_empty());
    let gate_rows = fx.vault.gate_decisions(100)?;
    assert!(gate_rows.iter().any(|row| {
        row.system_notices
            .iter()
            .any(|notice| notice.notice_type == "trusted_contact_notified")
    }));

    // Ask-first: the person is asked first on either tier. Only the person sets it.
    assert!(
        fx.vault
            .set_trusted_contact_dial(&fx.contact, fx.contact_id, TrustedContactDial::AskFirst)
            .is_err()
    );
    fx.vault
        .set_trusted_contact_dial(&fx.person, fx.contact_id, TrustedContactDial::AskFirst)?;
    let asked = fx.crisis()?;
    assert!(told(&asked, "trusted_contact_ask"));
    assert_eq!(fx.staged()?, 1);
    let asks = fx.vault.trusted_contact_asks(&fx.person)?;
    assert_eq!(asks.len(), 1);
    assert_eq!(asks[0].tier, TrustedContactTier::Imminent);
    Ok(())
}

#[test]
fn the_notice_carries_the_fact_of_concern_and_nothing_from_the_turn() -> Result<()> {
    let fx = fixture()?;
    fx.imminent()?;
    fx.live(TrustedContactDial::JustCall)?;
    // The turn is said off the record.
    let session = fx
        .vault
        .off_record_session_vault()
        .enter("sess-trusted-contact", OffRecordBackendClass::Local)?;
    fx.vault
        .memory(fx.person_id, EdgeActorClass::Human)
        .witness_into_session(
            &session,
            &crate::memory::WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                messages: vec![crate::memory::WitnessMessage {
                    id: None,
                    author: crate::memory::WitnessAuthor::User,
                    message_type: "utterance".to_owned(),
                    content: PRIVATE_TURN.to_owned(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: 1_000,
            },
            None,
        )
        .expect("off-record witness");
    fx.crisis()?;
    let (attempt, notice) = fx.claim()?;
    assert_eq!(notice.target, CONTACT_ADDRESS);

    // The send rides the notice's own binding: no other target, no other sender.
    let mut sink = RecordingSink::default();
    let mut elsewhere = fx.outgoing(&notice, "elsewhere");
    elsewhere.intent.target = "someone-else@example.com".to_owned();
    assert!(
        fx.vault
            .dispatch_trusted_contact_notice(&attempt, elsewhere, &mut sink)
            .is_err()
    );
    assert!(sink.calls.is_empty());

    // Whatever else the host's request carries stays behind.
    let mut carrying = fx.outgoing(&notice, "fact");
    carrying.intent.job_ref = Some(PRIVATE_TURN.to_owned());
    let sent = fx
        .vault
        .dispatch_trusted_contact_notice(&attempt, carrying, &mut sink)
        .expect("dispatch");
    assert_eq!(sent.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    assert_eq!(sink.calls.len(), 1);
    assert_eq!(
        fx.vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Outbound))?
            .len(),
        1
    );

    let crossed = [
        String::from_utf8_lossy(&attempt.payload).into_owned(),
        format!("{notice:?}"),
        sink.calls.join("\n"),
    ]
    .join("\n")
    .to_lowercase();
    for word in PRIVATE_WORDS {
        assert!(
            !crossed.contains(word),
            "{word:?} crossed to the contact: {crossed}"
        );
    }
    Ok(())
}
