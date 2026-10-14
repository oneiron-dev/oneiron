//! Owner-authored writes carry their own confirmation (security pack 2, F14
//! R6). A critical claim the vault's owner writes on the owner's own full
//! credential lands with nothing to confirm and consolidates at once. The same
//! write on any other credential that names the owner's PERSON keeps its
//! critical confirm, and nothing consolidates it before the owner clears it.
use super::*;

const FACADE_CLAIM_UPSERT: &str = "/v1/core/facade/claim_upsert";

/// One critical claim about the owner. Each leg names its own predicate: an
/// upsert on a subject and predicate that already hold a head is a
/// replacement, which waits for review whoever writes it.
fn health_claim(id: oneiron::EntityId, owner: oneiron::EntityId, value: &str) -> Value {
    serde_json::json!({
        "id": id.to_hex(),
        "predicate": format!("health.allergy_{value}"),
        "subject_ref": owner.to_hex(),
        "value": value,
        "confidence": 1.0,
        "source": "user_stated",
    })
}

/// What a write left behind: the claim's stored approval, whether a critical
/// confirm waits on it, and whether it consolidates.
fn outcome(
    server: &SyncServer,
    claim: oneiron::EntityId,
) -> (Option<oneiron::ClaimApprovalStatus>, bool, bool) {
    let approval = server
        .vault
        .get_claim(&claim)
        .unwrap()
        .map(|body| body.approval);
    let confirm_waits = server
        .vault
        .pending_gate_consents(64)
        .unwrap()
        .iter()
        .any(|row| {
            row.claim_id == *claim.as_bytes()
                && row
                    .reason_codes
                    .iter()
                    .any(|reason| reason.contains("critical_confirm"))
        });
    let consolidates = server
        .vault
        .consolidate_claim_vad_now(&claim, server.vault.now_recorded_at())
        .is_ok();
    (approval, confirm_waits, consolidates)
}

/// Lets an agent-class credential on the owner's PERSON land Auto, so the
/// critical floor is the only thing its write waits on.
fn agent_on_owner_lands_auto(server: &SyncServer, owner: oneiron::EntityId) {
    use rmpv::Value as Mp;
    super::context_board_history::edit_vault_policy(server, 200, |entries| {
        let (_, Mp::Array(ceilings)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("actor_ceilings"))
            .expect("the vault policy names actor ceilings")
        else {
            panic!("actor ceilings are an array");
        };
        ceilings.push(Mp::Map(vec![
            (Mp::from("actor_class"), Mp::from("agent")),
            (Mp::from("actor_ref"), Mp::from(owner.to_hex())),
            (Mp::from("ceiling"), Mp::from("auto")),
        ]));
    });
}

/// Ruling R6's check: the owner's own write attaches no confirm and
/// consolidates; an agent-class credential on the owner's PERSON, the owner's
/// credential narrowed to read and write, and the owner's credential handed to
/// another key each land Auto with the confirm attached and stay
/// unconsolidated. On main every leg's confirm attaches and nothing holds
/// consolidation back, so the owner leg fails on the confirm and the three
/// others on consolidation.
#[tokio::test]
async fn an_owners_own_critical_claim_carries_its_own_confirmation() {
    let (_dir, server) = auth_test_server();
    let owner = server.vault().ensure_embedded_owner_actor().unwrap();
    agent_on_owner_lands_auto(&server, owner);
    let full = format!("principal_ref={};actor_class=human", owner.to_hex());
    let legs = [
        ("the owner's own full credential", test_bearer(&full), false),
        (
            "an agent-class credential on the owner's PERSON",
            test_bearer(&format!(
                "jti=owner-as-agent;principal_ref={};actor_class=agent",
                owner.to_hex()
            )),
            true,
        ),
        (
            "the owner's credential narrowed to read and write",
            test_bearer(&format!(
                "jti=owner-narrow;principal_ref={};actor_class=human;scope=core:read,core:write",
                owner.to_hex()
            )),
            true,
        ),
    ];
    let mut wrong = Vec::new();
    for (index, (leg, authorization, held)) in legs.into_iter().enumerate() {
        let claim = seeded_test_entity_id(0x2440_0010 + index as u128);
        let body = health_claim(claim, owner, &format!("leg{index}"));
        let (status, reply) = route_json(
            server.clone(),
            core_request_with_authz("POST", FACADE_CLAIM_UPSERT, authorization, Some(&body)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{leg}: {reply}");
        let expected = (Some(oneiron::ClaimApprovalStatus::Auto), held, !held);
        let found = outcome(&server, claim);
        if found != expected {
            wrong.push(format!(
                "{leg}: (approval, confirm, consolidates) = {found:?}"
            ));
        }
    }

    // The owner's own slip, handed to another key under a caveat that
    // narrows nothing: the mint still names the owner, but the holder is not.
    let (mut handed, owner_key) = slip_credentials::credential(&server, &full);
    let next = ed25519_dalek::SigningKey::from_bytes(blake3::hash(b"r6 handed holder").as_bytes());
    handed
        .attenuate_to(
            oneiron::authority::SlipCaveat::default(),
            &owner_key,
            next.verifying_key().to_bytes(),
        )
        .unwrap();
    let claim = seeded_test_entity_id(0x2440_0020);
    let request = slip_credentials::bind_slip_request(
        &server,
        &handed,
        &next,
        core_request_with_authz(
            "POST",
            FACADE_CLAIM_UPSERT,
            String::new(),
            Some(&health_claim(claim, owner, "handed")),
        ),
    );
    let response = api_routes(server.clone()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "the handed slip writes");
    let found = outcome(&server, claim);
    if found != (Some(oneiron::ClaimApprovalStatus::Auto), true, false) {
        wrong.push(format!(
            "the owner's credential handed to another key: (approval, confirm, consolidates) = {found:?}"
        ));
    }
    assert!(wrong.is_empty(), "FAILBEFORE R6: {wrong:#?}");
}

/// The owner proof is revalidated in the write's own transaction: once the
/// owner's credential is revoked, a write bound to the proof it built is
/// refused and leaves no claim, rather than landing with a confirm attached.
#[tokio::test]
async fn a_revoked_owner_proof_refuses_the_write_it_was_bound_to() {
    let (_dir, server) = auth_test_server();
    let owner = server.vault().ensure_embedded_owner_actor().unwrap();
    let full = format!(
        "jti=owner-revoked;principal_ref={};actor_class=human",
        owner.to_hex()
    );
    let auth = slip_credentials::authenticate(&server, &full);
    let proof = crate::api::owner_routes::owner(&auth, &server).expect("the owner is admitted");
    let memory = server
        .vault
        .memory(owner, oneiron::EdgeActorClass::Human)
        .with_owner_authorship(&proof);
    let upsert = |claim: oneiron::EntityId, value: &str| {
        let input: oneiron::memory::ClaimInput =
            serde_json::from_value(health_claim(claim, owner, value)).unwrap();
        memory.claim_upsert(&input)
    };

    let live = seeded_test_entity_id(0x2440_0030);
    upsert(live, "dust").expect("a live proof writes");
    assert_eq!(
        outcome(&server, live),
        (Some(oneiron::ClaimApprovalStatus::Auto), false, true)
    );

    slip_credentials::revoke(&server, &full);
    let stale = seeded_test_entity_id(0x2440_0031);
    assert!(upsert(stale, "mould").is_err(), "a revoked proof wrote");
    assert_eq!(server.vault.get_claim(&stale).unwrap(), None);
}
