//! The isolated qualification probes of the built-in channels this host
//! serves (FIX 710): Slack's `auth.test`, LINE's bot info, Telegram's
//! `getMe`, and the native mail server's JMAP domain read. Each is the
//! channel's own read-only check call, with the credential the owner's setup
//! checked, through the credential door. Every read runs on a transport of
//! its own: a fresh provider client or a fresh mail server session. A probe
//! never sends and writes nothing to the vault; the engine's built-in
//! qualifier reads its answers.

use oneiron::Vault;
use oneiron::connector_key::qualification::{
    ProbeReply, ProbeRequest, ProbeTool, QualificationConnection, QualificationConnector,
    QualificationFailure,
};
use oneiron::connector_key::{
    LINE_BOT_INFO_CHECK, NATIVE_MAIL_JMAP_CHECK, PackConnectionCheck, PackConnectionEvidence,
    PackConnectionVerifier, ProviderConnectionChecks, SLACK_AUTH_TEST_CHECK, TELEGRAM_GET_ME_CHECK,
};

use crate::config::NativeMailConfig;

/// One built-in channel connection's probe.
pub(super) struct BuiltinChannelProbe<'a> {
    vault: &'a Vault,
    check: PackConnectionCheck<'a>,
    /// The host's `[native_mail]` server, for the native mail check.
    native_mail: Option<&'a NativeMailConfig>,
}

impl<'a> BuiltinChannelProbe<'a> {
    /// The probe of `check` when this host has its channel's client: `None`
    /// for any other check, and for the native mail check on a host that
    /// names no `[native_mail]` server.
    pub(super) fn for_check(
        vault: &'a Vault,
        check: PackConnectionCheck<'a>,
        native_mail: Option<&'a NativeMailConfig>,
    ) -> Option<Self> {
        let served = match check.check {
            SLACK_AUTH_TEST_CHECK | LINE_BOT_INFO_CHECK | TELEGRAM_GET_ME_CHECK => true,
            NATIVE_MAIL_JMAP_CHECK => native_mail.is_some(),
            _ => false,
        };
        served.then_some(Self {
            vault,
            check,
            native_mail,
        })
    }

    /// One identity read on a transport of its own.
    fn read(&self) -> Result<PackConnectionEvidence, String> {
        match (self.check.check, self.native_mail) {
            (NATIVE_MAIL_JMAP_CHECK, Some(server)) => {
                super::checks::native_mail_ready(self.vault, &self.check, server)
            }
            (NATIVE_MAIL_JMAP_CHECK, None) => {
                Err("this host has no [native_mail] server configured".to_owned())
            }
            _ => ProviderConnectionChecks::new()
                .map_err(|error| error.to_string())?
                .verify(self.vault, &self.check),
        }
    }
}

impl QualificationConnector for BuiltinChannelProbe<'_> {
    fn connect(&self) -> Result<Box<dyn QualificationConnection + '_>, QualificationFailure> {
        Ok(Box::new(ProbeConnection { probe: self }))
    }

    /// The channel's account as the provider names it now, read apart from
    /// any call reply.
    fn effect_state(&self) -> Result<Vec<u8>, QualificationFailure> {
        self.read()
            .map(|evidence| evidence.probe_state())
            .map_err(|_| QualificationFailure::Transport)
    }
}

/// A connection lists the check's one identity tool; each call reads anew.
struct ProbeConnection<'p, 'a> {
    probe: &'p BuiltinChannelProbe<'a>,
}

impl QualificationConnection for ProbeConnection<'_, '_> {
    fn tools_list(&mut self) -> Result<Vec<ProbeTool>, QualificationFailure> {
        Ok(vec![PackConnectionEvidence::probe_tool(
            self.probe.check.check,
        )])
    }

    fn call(&mut self, request: &ProbeRequest) -> Result<ProbeReply, QualificationFailure> {
        if request.name != self.probe.check.check {
            return Err(QualificationFailure::IncompletePlan);
        }
        Ok(match self.probe.read() {
            Ok(evidence) => evidence.probe_reply(request),
            Err(reason) => PackConnectionEvidence::probe_refusal(request, &reason),
        })
    }
}
