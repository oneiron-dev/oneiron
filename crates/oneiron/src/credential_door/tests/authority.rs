use super::*;

#[test]
fn every_preset_meet_narrows_and_cannot_restore_verbs() {
    let names = ["door.push", "door.inject", "door.lease", "door.redeem"];
    let (_tmp, vault, _door) = door_fixture();
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"door-test-root").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    for name in names {
        let preset = super::super::verb_class::preset(name).unwrap();
        assert!(preset.is_narrowing_of(&crate::federation::Scope::top()));
        for other in names {
            let other = super::super::verb_class::preset(other).unwrap();
            let mut slip = root.clone();
            slip.attenuate(crate::authority::SlipCaveat {
                scope: Some(preset.clone()),
                ..Default::default()
            })
            .unwrap();
            slip.attenuate(crate::authority::SlipCaveat {
                scope: Some(other.clone()),
                ..Default::default()
            })
            .unwrap();
            slip.attenuate(crate::authority::SlipCaveat {
                scope: Some(crate::federation::Scope::top()),
                ..Default::default()
            })
            .unwrap();
            let proof = issuer.binding_proof(&slip, b"presets").unwrap();
            let verified = vault
                .verify_capability_slip(&issuer, &slip, b"presets", &proof)
                .unwrap();
            assert_eq!(verified.scope(), &preset.meet(&other));
            assert!(verified.scope().is_narrowing_of(&preset));
            assert!(verified.scope().is_narrowing_of(&other));
        }
    }
    assert!(super::super::verb_class::preset("unregistered-class").is_none());
}
