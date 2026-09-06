use super::*;

#[test]
fn ppr_vad_defaults_and_sweep_are_pinned() {
    assert_eq!(PPR_VAD_ALPHA_DEFAULT.to_bits(), 0.0_f32.to_bits());
    assert_eq!(PPR_VAD_ALPHA_MAX, 0.4);
    assert_eq!(PPR_VAD_ALPHA_SWEEP, &[0.0, 0.1, 0.2, 0.3, 0.4]);
    for config in [
        VaultConfig::default(),
        VaultConfig::device(),
        VaultConfig::server(),
    ] {
        assert_eq!(config.ppr_vad_alpha.to_bits(), 0.0_f32.to_bits());
    }
    let mut changed = VaultConfig::device();
    changed.ppr_vad_alpha = 0.1;
    assert_ne!(changed, VaultConfig::device());
}

#[test]
fn ppr_vad_alpha_accepts_closed_range() {
    for alpha in PPR_VAD_ALPHA_SWEEP
        .iter()
        .copied()
        .chain([-0.0, f32::MIN_POSITIVE, 0.25])
    {
        validate_ppr_vad_alpha(alpha).expect("valid alpha");
    }
}

#[test]
fn ppr_vad_alpha_rejects_every_invalid_class() {
    for alpha in [
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        -0.1,
        -f32::MIN_POSITIVE,
        f32::from_bits(PPR_VAD_ALPHA_MAX.to_bits() + 1),
        f32::MAX,
    ] {
        assert!(matches!(
            validate_ppr_vad_alpha(alpha),
            Err(crate::Error::InvalidConfig(_))
        ));
    }
}

#[test]
fn ppr_community_presets_are_default_off_and_participate_in_equality() {
    for config in [
        VaultConfig::default(),
        VaultConfig::device(),
        VaultConfig::server(),
    ] {
        assert_eq!(config.ppr_community, PprCommunityConfig::default());
        assert_eq!(config.ppr_community.beta.to_bits(), 0.0_f32.to_bits());
        assert_eq!(config.ppr_vad_alpha.to_bits(), 0.0_f32.to_bits());
        validate_ppr_community(&config.ppr_community).expect("valid preset");
    }
    let mut changed = VaultConfig::device();
    changed.ppr_community.beta = 0.2;
    assert_ne!(changed, VaultConfig::device());
    validate_ppr_community(&changed.ppr_community).expect("valid experiment");
}

#[test]
fn ppr_community_validation_rejects_nonfinite_and_relaxed_safety_bounds() {
    for field in 0..5 {
        for invalid in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.1] {
            let mut config = PprCommunityConfig::default();
            match field {
                0 => config.beta = invalid,
                1 => config.gamma = invalid,
                2 => config.multiplier_cap = invalid,
                3 => config.max_graph_fraction = invalid,
                _ => config.max_top_k_fraction = invalid,
            }
            assert!(matches!(
                validate_ppr_community(&config),
                Err(crate::Error::InvalidConfig(_))
            ));
        }
    }
    for config in [
        PprCommunityConfig {
            gamma: 0.9,
            ..Default::default()
        },
        PprCommunityConfig {
            multiplier_cap: 1.51,
            ..Default::default()
        },
        PprCommunityConfig {
            max_graph_fraction: 0.101,
            ..Default::default()
        },
        PprCommunityConfig {
            max_top_k_fraction: 0.701,
            ..Default::default()
        },
    ] {
        assert!(validate_ppr_community(&config).is_err());
    }
}
