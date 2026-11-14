//! A hosted relay's own decision names the self-host route: the decision's
//! `works_self_hosted` and `self_hosted_note`, and the engine-written Block
//! body's last sentence; the outage halt keeps the host's own text (census
//! L9-61; DEC-0005 #will-sweep; RULING L9-61-POLICY-SELFHOST = A).

use super::*;

const UNAVAILABLE_NOTICE: &str = "The hosted relay cannot check this message right now.";
const SELF_HOSTED_NOTE: &str =
    "A self-hosted vault that sends through its own connector relays through no hosted policy.";

/// A hosted door's config: the local-model offer every kept halt names.
fn door_config() -> PolicyModelConfig {
    PolicyModelConfig {
        hosted_local_model_offer: Some(crate::store::GateSystemNoticeAction {
            label: "Use a local model".to_owned(),
            target: "oneiron://settings/models/local".to_owned(),
        }),
        ..PolicyModelConfig::default()
    }
}

fn decide(
    vault: &Vault,
    content: &str,
    backend: &dyn LlmBackend,
    budget: &BudgetLease,
) -> Result<doors::HostedRelayDecision> {
    let registry = hosted_edge_registry(hosted_serious_crime_block());
    block_on(doors::enforce_hosted_relay(
        vault,
        PolicyClassifyRequest::outbound_content(content),
        &hosted_witness(),
        &registry,
        &door_config(),
        Some(tier(backend, budget)),
        &EMPTY_VAULT_SIDE_VERDICTS,
        UNAVAILABLE_NOTICE,
    ))
}

#[test]
fn a_hosted_block_names_the_self_host_route() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let budget = lease("self-host-block");
    let decision = decide(&vault, BOMB_CONTENT, &blocking_backend(), &budget)?;
    assert!(decision.outbound_halted, "{decision:?}");
    assert!(decision.works_self_hosted, "{decision:?}");
    assert_eq!(decision.self_hosted_note, SELF_HOSTED_NOTE);
    let block = decision
        .system_notices
        .iter()
        .find(|notice| notice.notice_type == SYSTEM_NOTICE_TYPE_BLOCK)
        .unwrap_or_else(|| panic!("a hosted Block notice: {decision:?}"));
    assert!(
        block
            .body
            .starts_with("The hosted relay service withheld this content under its "),
        "{}",
        block.body
    );
    assert!(
        block
            .body
            .ends_with(" legal policy. A self-hosted vault that sends through its own connector relays through no hosted policy."),
        "{}",
        block.body
    );
    let wire = serde_json::to_value(&decision).expect("the decision serializes");
    assert_eq!(wire["works_self_hosted"], JsonValue::Bool(true), "{wire}");
    assert_eq!(wire["self_hosted_note"], SELF_HOSTED_NOTE, "{wire}");
    Ok(())
}

#[test]
fn a_hosted_outage_halt_names_the_self_host_route_and_keeps_the_hosts_text() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let budget = lease("self-host-halt");
    let decision = decide(&vault, CLEAN_CONTENT, &FailingPolicyBackend, &budget)?;
    assert!(decision.outbound_halted, "{decision:?}");
    let degrade = decision.degraded.as_ref().expect("an availability degrade");
    assert!(decision.works_self_hosted, "{decision:?}");
    assert_eq!(decision.self_hosted_note, SELF_HOSTED_NOTE);
    let halt = decision
        .system_notices
        .iter()
        .find(|notice| notice.notice_type == "policy_relay_unavailable")
        .unwrap_or_else(|| panic!("a halt notice: {decision:?}"));
    assert_eq!(
        halt.body,
        format!("{}\n{UNAVAILABLE_NOTICE}", degrade.as_str()),
        "the halt body stays the host's text"
    );
    Ok(())
}
