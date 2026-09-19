//! Terminal-pact emission goes through the live stored authority fold.
use super::support::*;
use super::*;
use crate::deletion::*;

#[test]
fn cooperative_deletion_terminal_pact_gate_and_cutoff() -> crate::error::Result<()> {
    for kind in [
        FederationLifecycleKind::Disconnect,
        FederationLifecycleKind::Dissolve,
    ] {
        let (_temp, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
        let fixture = pact_fixture(55);
        crate::federation::admit_peer_authority_log_entry(
            &vault,
            &fixture.peer_vault_id,
            &encode_authority_log_entry_body(&fixture.peer_genesis)?,
        )?;
        let time = TimeRange { start: 1, end: 1 };
        vault.put_authority_log_entry(&fixture.genesis, time, 1)?;
        let connect = lifecycle_entry(
            &fixture,
            vec![authority_entry_hash(&fixture.genesis)?],
            1,
            connect_action(&fixture),
        );
        vault.put_authority_log_entry(&connect, time, 1)?;
        let sign = |cutoff| {
            vault.sign_cooperative_deletion_request(
                &fixture.pact_id,
                vec![],
                cutoff,
                [9; 16],
                authority_key_from_ed(&fixture.owner),
                |bytes| Ok(fixture.owner.sign(bytes).to_bytes().to_vec()),
            )
        };
        assert_eq!(
            sign(1).unwrap_err().kind(),
            crate::ErrorKind::CooperativeDeletionRequiresTerminalPact
        );
        let terminal = lifecycle_entry(
            &fixture,
            vec![authority_entry_hash(&connect)?],
            2,
            unilateral_action_with(&fixture, fixture.pact_id, fixture.grant_ref, kind, 1),
        );
        vault.put_authority_log_entry(&terminal, time, 1)?;
        let signed = sign(1)?;
        let bytes = encode_signed_cooperative_deletion_request(&signed)?;
        assert_eq!(
            decode_and_verify_cooperative_deletion_request(
                &bytes,
                &authority_key_from_ed(&fixture.owner)
            )?,
            signed.body
        );
        assert_eq!(signed.body.requester_vault_id, fixture.vault_id);
        assert_eq!(signed.body.peer_vault_id, fixture.peer_vault_id);
        assert!(sign(2).is_err());
    }
    Ok(())
}
