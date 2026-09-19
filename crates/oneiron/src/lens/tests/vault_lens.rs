use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::{EdgeActorClass, EntityId, Result, TimeRange};
use chrono::DateTime;
fn unix(date: &str) -> u64 {
    DateTime::parse_from_rfc3339(date)
        .expect("date")
        .timestamp() as u64
}

#[test]
fn vault_lens_composes_sections_and_on_this_day_requeries_valid_time() -> Result<()> {
    let (_dir, vault) = test_vault();
    let owner = EntityId::now();
    put_person(&vault, &owner)?;
    let now = unix("2026-09-19T00:00:00Z");
    let past = unix("2025-09-19T00:00:00Z");
    let old_claim = EntityId::now();
    let current_claim = EntityId::now();
    for (id, at, value) in [(old_claim, past, "tea"), (current_claim, now, "coffee")] {
        let mut body = ClaimBody::new(
            "profile.likes",
            ClaimSubject::Entity(owner),
            rmpv::Value::from(value),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        body.valid_from = Some(at);
        body.valid_to = Some(at + 86400);
        vault.put_claim(
            &id,
            &body,
            TimeRange {
                start: at,
                end: at + 86399,
            },
            at,
        )?;
    }
    let conversation = EntityId::now();
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "Visible thread entry".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: now,
        })
        .expect("witness");
    let read = vault.scoped_read(actor_key("viewer"));
    let mut request = VaultLensRequest {
        card_id: render_id("vault-card"),
        anchor: owner,
        thread: Some(conversation),
        valid_at: now,
        learned_at: now,
        limit: 32,
    };
    let projection = read.project_vault_lens(&request)?;
    assert_eq!(projection.claim_refs, vec![current_claim]);
    let rendered = projection.card.render()?;
    let atoms: Vec<_> = rendered.nodes.iter().map(|node| &node.atom).collect();
    assert!(atoms.iter().any(|a| matches!(a, LensAtom::LedgerRow(_))));
    assert!(
        atoms
            .iter()
            .any(|a| matches!(a, LensAtom::DossierSection(_)))
    );
    assert!(atoms.iter().any(|a| matches!(a, LensAtom::AsofScrubber(_))));
    assert!(
        atoms
            .iter()
            .any(|a| matches!(a, LensAtom::NeighborhoodGraph(_)))
    );
    assert!(atoms.iter().any(|a| matches!(a, LensAtom::ThreadEntry(_))));
    let prior =
        read.apply_vault_lens_action(&mut request, VaultLensAction::OnThisDay { today: now })?;
    assert_eq!(request.valid_at, past);
    assert_eq!(prior.valid_at, past);
    assert_eq!(prior.claim_refs, vec![old_claim]);
    assert!(
        prior
            .card
            .actions
            .iter()
            .any(|a| a.action.command.as_str() == VAULT_ON_THIS_DAY_ACTION)
    );
    Ok(())
}

#[test]
fn vault_lens_rejects_over_bounds_and_does_not_move_scrubber_on_failure() -> Result<()> {
    let (_dir, vault) = test_vault();
    let anchor = EntityId::now();
    put_person(&vault, &anchor)?;
    let read = vault.scoped_read(actor_key("viewer"));
    let mut request = VaultLensRequest {
        card_id: render_id("bounded"),
        anchor,
        thread: None,
        valid_at: 1,
        learned_at: 1,
        limit: VAULT_LENS_MAX_ROWS + 1,
    };
    assert!(read.project_vault_lens(&request).is_err());
    assert!(
        read.apply_vault_lens_action(&mut request, VaultLensAction::AsOf(2))
            .is_err()
    );
    assert_eq!(request.valid_at, 1);
    assert_eq!(
        today_last_year(unix("2024-02-29T12:34:56Z"))?,
        unix("2023-02-28T12:34:56Z")
    );
    assert!(today_last_year(0).is_err());
    Ok(())
}

#[test]
fn vault_graph_atoms_reject_duplicate_nodes_and_dangling_edges() {
    let node = serde_json::json!({"id":"one","label":"one"});
    assert!(
        serde_json::from_value::<NeighborhoodGraphAtom>(serde_json::json!({
            "nodes":[node,node],"edges":[]
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<NeighborhoodGraphAtom>(serde_json::json!({
            "nodes":[node],"edges":[{"from":"one","to":"missing","label":"edge"}]
        }))
        .is_err()
    );
}
