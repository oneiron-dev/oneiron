//! What a managed vault's settings file (`--settings-file`) may not set, as
//! dotted fields of the server's config schema: the leaves the supervisor
//! owns and the leaves that name a key by an environment variable.
//!
//! The vault refuses a settings file that sets any of them, by presence
//! alone, before it reads anything the file names; an array's items count
//! as the array's own field. A supervisor reads the same tables and
//! [`matches_any`] to keep them out of the file it writes, and passes its
//! own bindings on argv instead.

/// The leaves the supervisor owns, as dotted fields (`*` is any one key): the
/// listener, ingress and auth, the tenant's identity, posture and custody,
/// the machine's declared class, the credential broker's process and roots,
/// the voice loop's socket, the key directory and the publisher training
/// outbox.
pub const SUPERVISOR_OWNED: &[&str] = &[
    "vault_path",
    "host",
    "port",
    "artifact_port",
    "auth_secret",
    "oauth_issuer",
    "oauth_jwks_uri",
    "oauth_resource_indicator",
    "kit_bundle_public_urls",
    "allow_unauthenticated",
    "allowed_origins",
    "artifact_domains",
    "artifact_vault_name",
    "trusted_proxies",
    "lease_vault_id",
    "privacy_posture",
    "hosted_kms_key_ref",
    "device_class",
    "models.broker.socket",
    "models.broker.uid",
    "models.broker.program",
    "models.broker.extra_roots",
    "models.voice.socket",
    "keystore.dir",
    crate::conversation_training::OUTBOX_DIR_SETTING,
];

/// The leaves that name a key by the environment variable holding it.
pub const ENVIRONMENT_KEYS: &[&str] = &[
    "runtime.byo_key_env",
    "embedder.api_key_env",
    "embedder.remote.api_key_env",
    "gpu.api_key_env",
    "models.providers.*.key_env",
    "models.decisions.system_one.key_env",
];

/// Whether `field`, a dotted field given one key per part, is one of
/// `patterns`, dotted fields where `*` is any one key.
#[must_use]
pub fn matches_any<S: AsRef<str>>(field: &[S], patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| {
        pattern.split('.').count() == field.len()
            && pattern
                .split('.')
                .zip(field)
                .all(|(segment, key)| segment == "*" || segment == key.as_ref())
    })
}
