//! Pinned-model tests.

#[cfg(test)]
mod tests {
    use super::super::tests_a::tests::pinned_settings;
    use super::super::*;

    use std::fs;

    /// A transmit the pin file does not cover refuses at the transmit
    /// chokepoint — a pinned run never falls back to running unpinned.
    #[test]
    fn uncovered_transmit_refuses_instead_of_running_unpinned() {
        let mut settings =
            pinned_settings(r#"{"allowed":["z-ai/glm-5.2@r1"],"background_tier_enabled":true}"#);
        settings.model = "z-ai/glm-5.3".to_owned();
        let body = openrouter_request_body(&[], 900, "nonce", &settings);

        let error = pinned_transmit_attestation(&settings, &body)
            .expect_err("an uncovered transmitted model must refuse");
        assert!(error.contains("does not cover transmitted model `z-ai/glm-5.3`"));

        // The same refusal guards the single provider-call chokepoint, before
        // any request is spawned.
        let error = call_openrouter("test-key", &[], 900, "nonce", &settings)
            .expect_err("call_openrouter must refuse an uncovered transmit");
        assert!(error.contains("refusing to transmit unpinned"));

        // Flag parsing refuses the same way, before the run starts.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pinned.json");
        fs::write(
            &path,
            r#"{"allowed":["z-ai/glm-5.2@r1"],"background_tier_enabled":true}"#,
        )
        .expect("write pinned config");
        let args = [
            "--model".to_owned(),
            "z-ai/glm-5.3".to_owned(),
            "--pinned-config".to_owned(),
            path.display().to_string(),
        ];
        let error = parse_run_flags(&args).expect_err("uncovered model must refuse the run");
        assert!(error.contains("does not cover transmitted model `z-ai/glm-5.3`"));
    }
}
