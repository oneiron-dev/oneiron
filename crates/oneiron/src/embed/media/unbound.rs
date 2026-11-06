use super::{
    BTreeSet, EgressDecision, EgressPredicate, EmbedderLocality, Error, InputKind, MediaEgressGate,
    MediaEmbedReport, MediaEmbeddingInput, PendingMedia, Result, Vault,
};
use crate::settings::ReadDestination;

/// An owned, admitted stored input for observing an undeclared model's native width.
/// Its bytes and source rows outlive the read transaction that selected them.
pub struct UnboundMediaSample(PendingMedia);

impl UnboundMediaSample {
    #[must_use]
    pub fn input(&self) -> MediaEmbeddingInput<'_> {
        self.0.input()
    }
}

impl Vault {
    /// The first stored input of `kinds` admitted toward `destination`, without a space lookup.
    /// No transaction remains open when this returns.
    ///
    /// # Errors
    ///
    /// Storage errors, or a third-party model without an egress grant.
    pub fn first_unbound_media_input(
        &self,
        kinds: &BTreeSet<InputKind>,
        locality: EmbedderLocality,
        egress: Option<&dyn EgressPredicate>,
        destination: &ReadDestination,
    ) -> Result<Option<UnboundMediaSample>> {
        let egress = match locality {
            EmbedderLocality::OnDevice => None,
            EmbedderLocality::OwnerServer => egress,
            EmbedderLocality::ThirdParty => Some(egress.ok_or_else(|| {
                Error::InvalidConfig(
                    "a third-party media embedder has no egress grant for stored media".into(),
                )
            })?),
        };
        let rtxn = self.store.env.read_txn()?;
        let gate = egress
            .map(|egress| MediaEgressGate::read(self, &rtxn, egress, destination))
            .transpose()?;
        let mut report = MediaEmbedReport::default();
        let mut sample = None;
        self.scan_documents_in_txn(&rtxn, kinds, &mut report, |document| {
            if let Some(gate) = &gate
                && !gate.admits(&self.store, &rtxn, &document)?
            {
                return Ok(true);
            }
            sample = Some(UnboundMediaSample(document));
            Ok(false)
        })?;
        Ok(sample)
    }

    /// Re-asks the ordinary media egress and device-local rules immediately before dispatch,
    /// without manufacturing a declared space or an expected vector width.
    ///
    /// # Errors
    ///
    /// Storage errors reading the source worlds.
    pub fn unbound_media_may_leave(
        &self,
        locality: EmbedderLocality,
        egress: Option<&dyn EgressPredicate>,
        destination: &ReadDestination,
        input: &MediaEmbeddingInput<'_>,
    ) -> Result<bool> {
        let gate = match (locality, egress) {
            (EmbedderLocality::OnDevice, _) | (EmbedderLocality::OwnerServer, None) => {
                return Ok(true);
            }
            (EmbedderLocality::ThirdParty, None) => return Ok(false),
            (EmbedderLocality::OwnerServer | EmbedderLocality::ThirdParty, Some(gate)) => gate,
        };
        if gate.decide_media(input) != EgressDecision::Allow {
            return Ok(false);
        }
        self.media_rows_may_leave(None, input.source_rows(), destination)
    }
}
