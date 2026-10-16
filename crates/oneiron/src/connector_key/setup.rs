//! Guided pack setup's grants and connection checks (OF-378).
//!
//! An owner allows a connection's permissions one by one; each allowed
//! permission is one standing consent grant whose Gate receipt the consent
//! door writes, and one withdrawn is revoked through the same door, with its
//! receipt. There is no second grant or receipt store: the setup session
//! keeps the grant refs and decision ids only.
//!
//! A connection is checked before use. The check is the host's: either a
//! [`PackConnectionVerifier`] runs one read-only provider call through the
//! credential door, or a bound connector key clears its real qualification
//! suite. A pack names a check; it never names a URL. A check passes against
//! exactly the grants, custody records and key it ran with; when any of them
//! moves, the result goes stale and the connection is not ready.

use std::collections::BTreeSet;
use std::io::Read;
use std::time::Duration;

use super::normalize_connector_key;
use super::qualification::{GroundingOracle, QualificationConnector, QualificationPlan};
use super::record::ConnectorKeyStatus;
use super::txn::read_connector_key_in_txn;
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use crate::error::{Error, Result};
use crate::skill_hub::pack_catalog::{
    MAX_SETUP_PERMISSIONS, PackSetupAuth, PackSetupCheckRecord, PackSetupConnection,
    PackSetupGrantRef, PackSetupKeyRef, PackSetupPermission, PackSetupSecret, PackSetupSession,
    PackSetupView, live_custody_in_txn, pin_connection_custody_in_txn,
};
use crate::{EntityId, Vault};

/// The actor class every pack-connection grant is narrowed to.
pub const PACK_CONNECTION_ACTOR_CLASS: &str = "pack-connection";
/// The connection checks [`ProviderConnectionChecks`] runs, by name.
pub const SLACK_AUTH_TEST_CHECK: &str = "slack.auth_test";
pub const LINE_BOT_INFO_CHECK: &str = "line.bot_info";
pub const GMAIL_PROFILE_CHECK: &str = "gmail.profile";
const MAX_CHECK_REPLY_BYTES: u64 = 64 * 1024;
const MAX_CHECK_TEXT_BYTES: usize = 512;

/// What a host is asked to prove about one connection. Names only: the host
/// reads the credential through the credential door itself.
#[derive(Debug, Clone, Copy)]
pub struct PackConnectionCheck<'a> {
    pub pack: &'a str,
    pub connection: &'a str,
    /// The declared check name the host maps to its own provider call.
    pub check: &'a str,
    pub auth: PackSetupAuth,
    /// The connection's credential names; the first is the one to present.
    pub secrets: &'a [PackSetupSecret],
    /// The provider scopes of the permissions the owner allowed.
    pub allowed_scopes: &'a [String],
}

/// What the provider said about the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackConnectionEvidence {
    /// The provider account the credential belongs to: a workspace, an
    /// Official Account, a mailbox.
    pub account: String,
    /// What the provider reports the credential holds. Empty when the
    /// provider reports nothing; then only the account is compared.
    pub scopes: Vec<String>,
    /// A digest of the provider's reply, never the reply.
    pub evidence: String,
}

/// The host's connection check. One read-only provider call: never a send,
/// a post or a connection request, and never a URL the pack chose.
pub trait PackConnectionVerifier {
    /// A refusal is the reason in plain words.
    fn verify(
        &self,
        vault: &Vault,
        check: &PackConnectionCheck<'_>,
    ) -> std::result::Result<PackConnectionEvidence, String>;
}

impl Vault {
    /// The owner allowed exactly `allowed` of one connection's permissions.
    /// Each newly allowed permission mints a standing consent grant with its
    /// Gate receipt; one withdrawn since the last answer is revoked through
    /// the owner's consent door, with its receipt.
    pub(crate) fn allow_pack_connection(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        content_hash: Option<&str>,
        connection: &str,
        allowed: &[String],
    ) -> Result<PackSetupView> {
        let withdrawn = {
            let principal = owner.principal_ref_for_read(self)?.to_owned();
            let txn = self.store.env.read_txn()?;
            let binding = self.bind_pack_setup_in_txn(&txn, &principal, pack, content_hash)?;
            let session = self.require_pack_setup_in_txn(&txn, &binding)?;
            check_allowed(
                declared_connection(&binding.setup.connections, connection)?,
                allowed,
            )?;
            let mut withdrawn = Vec::new();
            for grant in &session.grants {
                if grant.connection == connection
                    && !allowed.contains(&grant.permission)
                    && crate::consent::standing_grant_is_active_in_txn(
                        &self.store,
                        &txn,
                        &grant.grant_ref,
                    )?
                {
                    withdrawn.push(grant.grant_ref.clone());
                }
            }
            withdrawn
        };
        for grant_ref in &withdrawn {
            self.revoke_consent_grant(owner, grant_ref)?;
        }
        self.with_write_txn_grouped(|txn| {
            let principal = owner.principal_ref_in_txn(self, txn)?.to_owned();
            let binding = self.bind_pack_setup_in_txn(txn, &principal, pack, content_hash)?;
            let mut session = self.require_pack_setup_in_txn(txn, &binding)?;
            let declared = declared_connection(&binding.setup.connections, connection)?;
            check_allowed(declared, allowed)?;
            session.grants.retain(|grant| {
                grant.connection != declared.id || allowed.contains(&grant.permission)
            });
            let at = crate::unix_seconds_now();
            for permission in &declared.permissions {
                if !allowed.contains(&permission.id) {
                    continue;
                }
                let bound = connection_bound(
                    &binding.receipt.pack_name,
                    &binding.receipt.content_hash,
                    &declared.id,
                    permission,
                )?;
                let grant_ref = bound.digest().to_hex();
                let held = session.grants.iter().any(|grant| {
                    grant.connection == declared.id
                        && grant.permission == permission.id
                        && grant.grant_ref == grant_ref
                });
                if held
                    && crate::consent::standing_grant_is_active_in_txn(
                        &self.store,
                        txn,
                        &grant_ref,
                    )?
                {
                    continue;
                }
                let receipt = self.create_standing_grant_in_txn(txn, owner, bound)?;
                session.grants.retain(|grant| {
                    grant.connection != declared.id || grant.permission != permission.id
                });
                session.grants.push(PackSetupGrantRef {
                    connection: declared.id.clone(),
                    permission: permission.id.clone(),
                    grant_ref: receipt.grant_ref().unwrap_or(grant_ref),
                    decision_id: receipt.decision_id().to_hex(),
                    granted_at: at,
                });
            }
            self.put_pack_setup_in_txn(txn, &binding, &mut session)?;
            self.pack_setup_view_in_txn(txn, &binding, &session)
        })
    }

    /// Binds a registered connector key to a connection. The key must govern
    /// the connection's declared connector, be usable, and hold custody the
    /// connection names. Binding activates nothing: a Pending key still
    /// needs its real qualification.
    pub(crate) fn bind_pack_connection_key(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        content_hash: Option<&str>,
        connection: &str,
        key: &str,
    ) -> Result<PackSetupView> {
        let key_id = EntityId::from_hex(key)?;
        self.with_write_txn_grouped(|txn| {
            let principal = owner.principal_ref_in_txn(self, txn)?.to_owned();
            let binding = self.bind_pack_setup_in_txn(txn, &principal, pack, content_hash)?;
            let mut session = self.require_pack_setup_in_txn(txn, &binding)?;
            let declared = declared_connection(&binding.setup.connections, connection)?;
            let connector = declared
                .connector
                .as_deref()
                .ok_or_else(|| invalid("the connection governs no connector key"))?;
            let record = read_connector_key_in_txn(&self.store, txn, &key_id)?
                .ok_or(Error::EntityNotFound)?;
            if record.connector != normalize_connector_key(connector) {
                return Err(invalid("the key governs another connector"));
            }
            if matches!(
                record.status,
                ConnectorKeyStatus::Suspended | ConnectorKeyStatus::Revoked
            ) {
                return Err(invalid("the key is suspended or revoked"));
            }
            if let Some(secret_ref) = record.secret_ref.as_deref()
                && !declared
                    .secrets
                    .iter()
                    .any(|secret| secret.name == secret_ref)
            {
                return Err(invalid(
                    "the key's custody is not a credential this connection names",
                ));
            }
            session.keys.retain(|bound| bound.connection != declared.id);
            session.keys.push(PackSetupKeyRef {
                connection: declared.id.clone(),
                key_id: key_id.to_hex(),
            });
            self.put_pack_setup_in_txn(txn, &binding, &mut session)?;
            self.pack_setup_view_in_txn(txn, &binding, &session)
        })
    }

    /// Checks one connection through the host's verifier and records the
    /// result. The connection's credentials must be stored and its required
    /// permissions allowed first; the provider's reported scopes must match
    /// what the owner allowed, no more and no less.
    pub fn verify_pack_connection(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        content_hash: Option<&str>,
        connection: &str,
        verifier: &dyn PackConnectionVerifier,
    ) -> Result<PackSetupView> {
        let (declared, basis, allowed_scopes) =
            self.pack_connection_before_check(owner, pack, content_hash, connection)?;
        let at = crate::unix_seconds_now();
        let check = PackConnectionCheck {
            pack,
            connection: &declared.id,
            check: &declared.verify,
            auth: declared.auth,
            secrets: &declared.secrets,
            allowed_scopes: &allowed_scopes,
        };
        let record = match verifier.verify(self, &check) {
            Ok(evidence) => judge_evidence(&declared, &allowed_scopes, evidence, basis, at),
            Err(reason) => PackSetupCheckRecord {
                connection: declared.id.clone(),
                verified: false,
                account: None,
                evidence: None,
                reason: Some(bounded(&reason)),
                basis,
                checked_at: at,
            },
        };
        self.record_pack_connection_check(owner, pack, content_hash, &declared, record)
    }

    /// Checks a connection whose bound connector key is Pending through the
    /// key's own qualification door: the real probe suite over the owner's
    /// freshly stamped slate, which flips the key Active and appends
    /// `gate.connector_key.qualify`. The setup records its report digest.
    #[expect(
        clippy::too_many_arguments,
        reason = "the setup frame plus the qualification door's own inputs"
    )]
    pub fn qualify_pack_connection(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        content_hash: Option<&str>,
        connection: &str,
        expected_revision: &str,
        connector: &dyn QualificationConnector,
        plan: &QualificationPlan,
        oracle: &dyn GroundingOracle,
    ) -> Result<PackSetupView> {
        let (declared, basis, _) =
            self.pack_connection_before_check(owner, pack, content_hash, connection)?;
        let key = {
            let principal = owner.principal_ref_for_read(self)?.to_owned();
            let txn = self.store.env.read_txn()?;
            let binding = self.bind_pack_setup_in_txn(&txn, &principal, pack, content_hash)?;
            let session = self.require_pack_setup_in_txn(&txn, &binding)?;
            let bound = session
                .keys
                .iter()
                .find(|key| key.connection == declared.id)
                .ok_or_else(|| invalid("bind a connector key to the connection first"))?;
            EntityId::from_hex(&bound.key_id)?
        };
        let at = crate::unix_seconds_now();
        let record = match self.qualify_connector_key(
            &key,
            expected_revision,
            connector,
            plan,
            oracle,
            at,
        ) {
            Ok((record, report)) => PackSetupCheckRecord {
                connection: declared.id.clone(),
                verified: true,
                account: Some(bounded(&record.connector)),
                evidence: Some(report.report_hash),
                reason: None,
                basis,
                checked_at: at,
            },
            Err(error) => PackSetupCheckRecord {
                connection: declared.id.clone(),
                verified: false,
                account: None,
                evidence: None,
                reason: Some(bounded(&error.to_string())),
                basis,
                checked_at: at,
            },
        };
        self.record_pack_connection_check(owner, pack, content_hash, &declared, record)
    }

    /// A connection of an Active pack runs only once checked: some owner's
    /// session over the installed source holds a check that still matches
    /// its grants, custody and key.
    pub fn require_pack_connection_verified(&self, pack: &str, connection: &str) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        let (declared, sessions) = {
            let (setup, sessions) = self.installed_pack_setup_in_txn(&txn, pack)?;
            let declared = declared_connection(&setup.connections, connection)?.clone();
            (declared, sessions)
        };
        for session in &sessions {
            if self
                .connection_state_in_txn(&txn, &declared, session)?
                .ready
            {
                return Ok(());
            }
        }
        Err(invalid(
            "the connection is not checked; run the pack's setup before using it",
        ))
    }

    /// Every grant a run asks for that a setup connection serves needs one
    /// such connection checked. A pack without setup, and a grant no
    /// connection serves, ask nothing more.
    pub(crate) fn require_pack_grants_verified(&self, pack: &str, grants: &[&str]) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        let Some(receipt) = self.installed_pack_in_txn(&txn, pack)? else {
            return Ok(());
        };
        let source = self
            .pack_source_in_txn(&txn, &EntityId::from_hex(&receipt.source_id)?)?
            .ok_or_else(|| invalid("installed source unavailable"))?;
        let Some(setup) = source.manifest().setup.as_ref() else {
            return Ok(());
        };
        let sessions = self.pack_setup_sessions_in_txn(&txn, pack, &receipt.content_hash)?;
        for grant in grants {
            let mut serving = setup.connections_for_grant(grant).peekable();
            if serving.peek().is_none() {
                continue;
            }
            let mut ready = false;
            'serving: for connection in serving {
                for session in &sessions {
                    if self
                        .connection_state_in_txn(&txn, connection, session)?
                        .ready
                    {
                        ready = true;
                        break 'serving;
                    }
                }
            }
            if !ready {
                return Err(invalid(
                    "a connection this run needs is not checked; run the pack's setup",
                ));
            }
        }
        Ok(())
    }

    /// What a check runs against: the allowed permissions' grant refs, each
    /// credential's custody record and rotation generation, and the bound
    /// key while it is usable.
    pub(crate) fn pack_connection_basis_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        connection: &PackSetupConnection,
        session: &PackSetupSession,
    ) -> Result<String> {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron.pack-setup.check-basis.v1");
        for permission in &connection.permissions {
            if let Some(grant) = session.grants.iter().find(|grant| {
                grant.connection == connection.id && grant.permission == permission.id
            }) && crate::consent::standing_grant_is_active_in_txn(
                &self.store,
                txn,
                &grant.grant_ref,
            )? {
                frame(&mut hasher, permission.id.as_bytes());
                frame(&mut hasher, grant.grant_ref.as_bytes());
            }
        }
        for secret in &connection.secrets {
            frame(&mut hasher, secret.name.as_bytes());
            match live_custody_in_txn(&self.store, txn, &secret.name)? {
                Some((id, generation)) => {
                    frame(&mut hasher, id.as_bytes());
                    frame(&mut hasher, &generation.to_be_bytes());
                }
                None => frame(&mut hasher, b"absent"),
            }
        }
        if let Some(bound) = session
            .keys
            .iter()
            .find(|key| key.connection == connection.id)
        {
            let usable =
                read_connector_key_in_txn(&self.store, txn, &EntityId::from_hex(&bound.key_id)?)?
                    .is_some_and(|record| {
                        matches!(
                            record.status,
                            ConnectorKeyStatus::Pending | ConnectorKeyStatus::Active
                        )
                    });
            frame(&mut hasher, bound.key_id.as_bytes());
            let state: &[u8] = if usable { b"usable" } else { b"unusable" };
            frame(&mut hasher, state);
        }
        Ok(hasher.finalize().to_hex().to_string())
    }

    fn installed_pack_setup_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        pack: &str,
    ) -> Result<(
        crate::skill_hub::pack_catalog::PackSetup,
        Vec<PackSetupSession>,
    )> {
        let receipt = self
            .installed_pack_in_txn(txn, pack)?
            .ok_or_else(|| invalid("the pack is not installed"))?;
        let source = self
            .pack_source_in_txn(txn, &EntityId::from_hex(&receipt.source_id)?)?
            .ok_or_else(|| invalid("installed source unavailable"))?;
        let setup = source
            .manifest()
            .setup
            .clone()
            .ok_or_else(|| invalid("the pack declares no setup"))?;
        let sessions = self.pack_setup_sessions_in_txn(txn, pack, &receipt.content_hash)?;
        Ok((setup, sessions))
    }

    /// The connection, its basis and its allowed scopes, refusing a check
    /// before its credentials are stored and its required permissions
    /// allowed.
    fn pack_connection_before_check(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        content_hash: Option<&str>,
        connection: &str,
    ) -> Result<(PackSetupConnection, String, Vec<String>)> {
        let principal = owner.principal_ref_for_read(self)?.to_owned();
        let txn = self.store.env.read_txn()?;
        let binding = self.bind_pack_setup_in_txn(&txn, &principal, pack, content_hash)?;
        let session = self.require_pack_setup_in_txn(&txn, &binding)?;
        let declared = declared_connection(&binding.setup.connections, connection)?.clone();
        let state = self.connection_state_in_txn(&txn, &declared, &session)?;
        if !state.secrets.iter().all(|secret| secret.stored) {
            return Err(invalid(
                "store the connection's credentials through the owner secrets door first",
            ));
        }
        let granted = |id: &str| {
            state
                .permissions
                .iter()
                .any(|permission| permission.id == id && permission.granted)
        };
        if declared
            .required()
            .any(|permission| !granted(&permission.id))
        {
            return Err(invalid(
                "allow the connection's required permissions before checking it",
            ));
        }
        let allowed_scopes = declared
            .permissions
            .iter()
            .filter(|permission| granted(&permission.id))
            .filter_map(|permission| permission.scope.clone())
            .collect();
        let basis = self.pack_connection_basis_in_txn(&txn, &declared, &session)?;
        Ok((declared, basis, allowed_scopes))
    }

    fn record_pack_connection_check(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        content_hash: Option<&str>,
        declared: &PackSetupConnection,
        record: PackSetupCheckRecord,
    ) -> Result<PackSetupView> {
        self.with_write_txn_grouped(|txn| {
            let principal = owner.principal_ref_in_txn(self, txn)?.to_owned();
            let binding = self.bind_pack_setup_in_txn(txn, &principal, pack, content_hash)?;
            let mut session = self.require_pack_setup_in_txn(txn, &binding)?;
            // A grant, credential or key that moved while the check ran makes
            // its answer about something else.
            if self.pack_connection_basis_in_txn(txn, declared, &session)? != record.basis {
                return Err(invalid(
                    "the connection changed while it was checked; check it again",
                ));
            }
            pin_connection_custody_in_txn(&self.store, txn, declared, &mut session)?;
            session
                .checks
                .retain(|check| check.connection != declared.id);
            session.checks.push(record);
            self.put_pack_setup_in_txn(txn, &binding, &mut session)?;
            self.pack_setup_view_in_txn(txn, &binding, &session)
        })
    }
}

/// The read-only provider checks the engine ships for its built-in packs.
/// Each check name maps to one fixed provider endpoint; the credential is
/// read through the credential door for the declared effector and goes
/// only to that endpoint.
pub struct ProviderConnectionChecks {
    client: reqwest::blocking::Client,
}

impl ProviderConnectionChecks {
    /// Every check name this verifier answers.
    pub const CHECKS: [&'static str; 3] = [
        SLACK_AUTH_TEST_CHECK,
        LINE_BOT_INFO_CHECK,
        GMAIL_PROFILE_CHECK,
    ];

    /// A bounded HTTPS client: no proxy, no redirects, short timeouts.
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| invalid("connection check client unavailable"))?;
        Ok(Self { client })
    }
}

impl PackConnectionVerifier for ProviderConnectionChecks {
    fn verify(
        &self,
        vault: &Vault,
        check: &PackConnectionCheck<'_>,
    ) -> std::result::Result<PackConnectionEvidence, String> {
        let (method, url) = match check.check {
            SLACK_AUTH_TEST_CHECK => (reqwest::Method::POST, "https://slack.com/api/auth.test"),
            LINE_BOT_INFO_CHECK => (reqwest::Method::GET, "https://api.line.me/v2/bot/info"),
            GMAIL_PROFILE_CHECK => (
                reqwest::Method::GET,
                "https://gmail.googleapis.com/gmail/v1/users/me/profile",
            ),
            other => return Err(format!("this host has no connection check named {other}")),
        };
        let secret = check
            .secrets
            .first()
            .ok_or_else(|| "the connection names no credential to check".to_owned())?;
        let mut reply = None;
        vault
            .inject_secret_at_door(&secret.name, &secret.effector, &mut |value: &[u8]| {
                let credential = std::str::from_utf8(value)
                    .map_err(|_| invalid("the stored credential is not text"))?;
                let response = self
                    .client
                    .request(method.clone(), url)
                    .bearer_auth(credential.trim())
                    .send()
                    .map_err(|error| {
                        Error::InvalidConfig(format!(
                            "connection check could not reach the provider: {}",
                            error.without_url()
                        ))
                    })?;
                let status = response.status().as_u16();
                let scopes = response
                    .headers()
                    .get("x-oauth-scopes")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let mut body = Vec::new();
                response
                    .take(MAX_CHECK_REPLY_BYTES + 1)
                    .read_to_end(&mut body)
                    .map_err(|_| invalid("connection check reply unreadable"))?;
                if body.len() as u64 > MAX_CHECK_REPLY_BYTES {
                    return Err(invalid("connection check reply exceeds bound"));
                }
                reply = Some((status, scopes, body));
                Ok(())
            })
            .map_err(|error| error.to_string())?;
        let (status, scopes, body) = reply.ok_or_else(|| "the check did not run".to_owned())?;
        let evidence = blake3::hash(&body).to_hex().to_string();
        if !(200..300).contains(&status) {
            return Err(format!(
                "the provider refused the credential (HTTP {status})"
            ));
        }
        let reply: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| "the provider's reply is not JSON".to_owned())?;
        let field = |name| reply_field(&reply, name);
        let account = match check.check {
            SLACK_AUTH_TEST_CHECK => {
                if reply.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                    return Err(format!(
                        "Slack refused the credential: {}",
                        field("error").unwrap_or("no reason given")
                    ));
                }
                format!(
                    "{} ({}) as {}",
                    field("team").unwrap_or("workspace"),
                    field("team_id").unwrap_or("unknown"),
                    field("user").unwrap_or("the app")
                )
            }
            LINE_BOT_INFO_CHECK => format!(
                "{} ({})",
                field("displayName").unwrap_or("Official Account"),
                field("basicId").unwrap_or("unknown")
            ),
            _ => field("emailAddress").unwrap_or_default().to_owned(),
        };
        Ok(PackConnectionEvidence {
            account,
            scopes: scopes
                .map(|header| {
                    header
                        .split(',')
                        .map(str::trim)
                        .filter(|scope| !scope.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            evidence,
        })
    }
}

/// One allowed permission's standing bound: the pack, as a pack-connection
/// actor, may do the permission's grant class, on this connection of this
/// exact source, with a receipt on every use.
fn connection_bound(
    pack: &str,
    content_hash: &str,
    connection: &str,
    permission: &PackSetupPermission,
) -> Result<GrantBound> {
    let actor =
        ActorBound::new(format!("pack:{pack}"))?.with_actor_class(PACK_CONNECTION_ACTOR_CLASS)?;
    let class = ActionClass::new(
        permission
            .grant
            .clone()
            .unwrap_or_else(|| format!("pack.{connection}.{}", permission.id)),
    )?;
    let envelope = ActionEnvelope::new([
        format!("connection:{connection}"),
        format!("permission:{}", permission.id),
        format!("source:{content_hash}"),
    ])?
    .with_receipt_required(true);
    GrantBound::action(actor, class, envelope)
}

/// The provider's word against the owner's: an account must be named, and
/// reported scopes must be exactly the allowed ones.
fn judge_evidence(
    declared: &PackSetupConnection,
    allowed: &[String],
    evidence: PackConnectionEvidence,
    basis: String,
    at: u64,
) -> PackSetupCheckRecord {
    let held: BTreeSet<&str> = evidence.scopes.iter().map(String::as_str).collect();
    let explained: BTreeSet<&str> = declared
        .permissions
        .iter()
        .filter_map(|permission| permission.scope.as_deref())
        .collect();
    let reason = if evidence.account.trim().is_empty() {
        Some("the provider named no account for this credential".to_owned())
    } else if held.is_empty() {
        None
    } else {
        let missing: Vec<&str> = allowed
            .iter()
            .map(String::as_str)
            .filter(|scope| !held.contains(scope))
            .collect();
        let unexplained: Vec<&str> = held
            .iter()
            .copied()
            .filter(|scope| !explained.contains(scope))
            .collect();
        let declined: Vec<&str> = held
            .iter()
            .copied()
            .filter(|scope| explained.contains(scope) && !allowed.iter().any(|a| a == scope))
            .collect();
        if !missing.is_empty() {
            Some(format!("the provider did not grant {}", missing.join(", ")))
        } else if !unexplained.is_empty() {
            Some(format!(
                "the credential holds permissions this pack never explained: {}",
                unexplained.join(", ")
            ))
        } else if !declined.is_empty() {
            Some(format!(
                "the credential holds permissions you declined: {}",
                declined.join(", ")
            ))
        } else {
            None
        }
    };
    PackSetupCheckRecord {
        connection: declared.id.clone(),
        verified: reason.is_none(),
        account: Some(bounded(&evidence.account)),
        evidence: Some(evidence.evidence),
        reason: reason.map(|reason| bounded(&reason)),
        basis,
        checked_at: at,
    }
}

fn reply_field<'a>(reply: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    reply.get(name).and_then(serde_json::Value::as_str)
}

fn declared_connection<'a>(
    connections: &'a [PackSetupConnection],
    id: &str,
) -> Result<&'a PackSetupConnection> {
    connections
        .iter()
        .find(|connection| connection.id == id)
        .ok_or_else(|| invalid("the pack declares no such connection"))
}

fn check_allowed(connection: &PackSetupConnection, allowed: &[String]) -> Result<()> {
    if allowed.len() > MAX_SETUP_PERMISSIONS
        || allowed.iter().any(|id| connection.permission(id).is_none())
    {
        return Err(invalid("the connection asks for no such permission"));
    }
    if connection
        .required()
        .any(|permission| !allowed.contains(&permission.id))
    {
        return Err(invalid(
            "the connection cannot work without a permission it requires; allow it or leave the connection unset",
        ));
    }
    Ok(())
}

fn frame(hasher: &mut blake3::Hasher, part: &[u8]) {
    hasher.update(&(part.len() as u64).to_be_bytes());
    hasher.update(part);
}

fn bounded(text: &str) -> String {
    let mut cut = text.len().min(MAX_CHECK_TEXT_BYTES);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text[..cut].to_owned()
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("pack setup: {reason}"))
}
