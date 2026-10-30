//! Pack connection grant and verification doors: allow, bind, verify and the
//! checked-connection reads a pack install relies on.
//! Entry: `Vault::verify_pack_connection`. The provider checks they run stay in `setup`.

use super::*;

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
    /// what the owner allowed, no more and no less. A built-in pack whose
    /// every connection is then ready qualifies Active in the same flow.
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
                provider_account: None,
                evidence: None,
                reason: Some(bounded(&reason)),
                basis,
                checked_at: at,
            },
        };
        let view =
            self.record_pack_connection_check(owner, pack, content_hash, &declared, record)?;
        self.qualify_checked_builtin(owner, pack, view)
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
                provider_account: None,
                evidence: Some(report.report_hash),
                reason: None,
                basis,
                checked_at: at,
            },
            Err(error) => PackSetupCheckRecord {
                connection: declared.id.clone(),
                verified: false,
                account: None,
                provider_account: None,
                evidence: None,
                reason: Some(bounded(&error.to_string())),
                basis,
                checked_at: at,
            },
        };
        let view =
            self.record_pack_connection_check(owner, pack, content_hash, &declared, record)?;
        self.qualify_checked_builtin(owner, pack, view)
    }

    /// A built-in pack qualifies on its checked setup (Engine ruling 10-17):
    /// once every connection is ready, its Candidate turns Active in the same
    /// flow and the view shows it. Any other pack's view returns unchanged.
    fn qualify_checked_builtin(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
        view: PackSetupView,
    ) -> Result<PackSetupView> {
        if !view.ready || !self.qualify_builtin_on_checked_setup(pack, &view.content_hash)? {
            return Ok(view);
        }
        self.pack_setup(owner, pack, Some(&view.content_hash))
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

    /// Whether every connection the installed `pack` declares is checked,
    /// read as [`Self::require_pack_connection_verified`] reads one, in the
    /// caller's snapshot: the built-in channel gate's test (OF-378). A pack
    /// without setup has nothing to check.
    pub(crate) fn pack_connections_checked_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        pack: &str,
    ) -> Result<bool> {
        let Some(receipt) = self.installed_pack_in_txn(txn, pack)? else {
            return Ok(false);
        };
        let source = self
            .pack_source_in_txn(txn, &EntityId::from_hex(&receipt.source_id)?)?
            .ok_or_else(|| invalid("installed source unavailable"))?;
        let Some(setup) = source.manifest().setup.as_ref() else {
            return Ok(true);
        };
        let sessions = self.pack_setup_sessions_in_txn(txn, pack, &receipt.content_hash)?;
        for connection in &setup.connections {
            let mut ready = false;
            for session in &sessions {
                if self
                    .connection_state_in_txn(txn, connection, session)?
                    .ready
                {
                    ready = true;
                    break;
                }
            }
            if !ready {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The same check over one exact source, Candidate or installed: a
    /// built-in qualifies on it before it is Active. Some owner's session
    /// over that source holds a check that still matches its live grants,
    /// stored credentials and key; that check is returned.
    pub fn require_candidate_pack_connection_verified(
        &self,
        pack: &str,
        content_hash: &str,
        connection: &str,
    ) -> Result<PackSetupCheckRecord> {
        let txn = self.store.env.read_txn()?;
        let receipt = self.pack_setup_receipt_in_txn(&txn, pack, Some(content_hash))?;
        let source = self
            .pack_source_in_txn(&txn, &EntityId::from_hex(&receipt.source_id)?)?
            .ok_or_else(|| invalid("the pack source is no longer live"))?;
        if source.content_hash().to_hex() != receipt.content_hash {
            return Err(invalid("the pack source is no longer live"));
        }
        let setup = source
            .manifest()
            .setup
            .as_ref()
            .ok_or_else(|| invalid("the pack declares no setup"))?;
        let declared = declared_connection(&setup.connections, connection)?;
        for session in self.pack_setup_sessions_in_txn(&txn, pack, &receipt.content_hash)? {
            if self
                .connection_state_in_txn(&txn, declared, &session)?
                .ready
                && let Some(check) = session
                    .checks
                    .into_iter()
                    .find(|check| check.connection == declared.id)
            {
                return Ok(check);
            }
        }
        Err(invalid(
            "the connection is not checked; run the pack's setup before using it",
        ))
    }

    /// The credential a checked connection presents to its provider: the
    /// first one it declares. A served send reads its value only through the
    /// credential door for the declared effector (OF-187).
    pub fn verified_pack_connection_secret(
        &self,
        pack: &str,
        connection: &str,
    ) -> Result<PackSetupSecret> {
        self.require_pack_connection_verified(pack, connection)?;
        let txn = self.store.env.read_txn()?;
        let (setup, _) = self.installed_pack_setup_in_txn(&txn, pack)?;
        declared_connection(&setup.connections, connection)?
            .secrets
            .first()
            .cloned()
            .ok_or_else(|| invalid("the connection names no credential"))
    }

    /// One named credential of a checked connection: the one `name` names
    /// among those it declares, which a served send reads only through the
    /// credential door for the declared effector, as it reads the first.
    pub fn verified_pack_connection_named_secret(
        &self,
        pack: &str,
        connection: &str,
        name: &str,
    ) -> Result<PackSetupSecret> {
        self.require_pack_connection_verified(pack, connection)?;
        let txn = self.store.env.read_txn()?;
        let (setup, _) = self.installed_pack_setup_in_txn(&txn, pack)?;
        declared_connection(&setup.connections, connection)?
            .secrets
            .iter()
            .find(|secret| secret.name == name)
            .cloned()
            .ok_or_else(|| invalid("the connection declares no such credential"))
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
        if !declared.required_secrets_stored(&state.secrets) {
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
