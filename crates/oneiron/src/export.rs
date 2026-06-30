#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ExportManifest {
    version: u8,
    secret_redaction: SecretRedactionManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct SecretRedactionManifest {
    redacted: bool,
    structurally_secret_nulled: bool,
}

impl ExportManifest {
    const VERSION: u8 = 1;

    #[must_use]
    pub fn clear() -> Self {
        Self::from_redacted(false)
    }

    #[must_use]
    pub fn from_redacted(redacted: bool) -> Self {
        Self {
            version: Self::VERSION,
            secret_redaction: SecretRedactionManifest {
                redacted,
                structurally_secret_nulled: redacted,
            },
        }
    }

    #[must_use]
    pub const fn redacted(&self) -> bool {
        self.secret_redaction.redacted
    }

    #[must_use]
    pub const fn structurally_secret_nulled(&self) -> bool {
        self.secret_redaction.structurally_secret_nulled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_manifest_redaction_snapshot_records_secret_nulled_state() {
        let manifest = ExportManifest::from_redacted(true);

        let snapshot = serde_json::to_string_pretty(&manifest).expect("manifest serializes");

        assert_eq!(
            snapshot,
            "{\n  \"version\": 1,\n  \"secret_redaction\": {\n    \"redacted\": true,\n    \"structurally_secret_nulled\": true\n  }\n}"
        );
        assert!(manifest.redacted());
        assert!(manifest.structurally_secret_nulled());
    }
}
