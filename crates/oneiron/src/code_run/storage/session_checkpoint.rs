//! Native session BODY publication inside a workflow's queue writer.

use super::records::{
    FinishedOutput, RAW_OUTPUT_SECRETS, RAW_OUTPUT_TAINTS, RAW_OUTPUTS, finish_output_sourced,
    load_whole_body,
};
use crate::code_run::{CodeRunRawOutput, ResultOccurrence};
use crate::off_record::{OffRecordSession, SessionWriteRoute};
use crate::session_overlay::RouteTarget;
use crate::store::{BODY_KEYS, BodySink, SessionStoreView, body_key_row_in_txn};
use crate::{EntityId, Result};

pub(crate) struct SessionCheckpointBody(FinishedOutput);

impl SessionCheckpointBody {
    pub(crate) fn output(&self) -> &CodeRunRawOutput {
        &self.0.output
    }

    pub(crate) fn admitted_bytes(&self, session: &OffRecordSession<'_>) -> Result<Vec<u8>> {
        load_whole_body(
            &self.0.output,
            self.0.body.clone(),
            self.0.key.as_ref().map(|key| key.row()),
            || session.body_dirs(),
        )
    }
}

impl OffRecordSession<'_> {
    /// The session's actual directory is selected before a byte enters a
    /// sink. An overlay body never mints a canonical custody instance.
    pub(crate) fn stage_checkpoint_body(
        &self,
        route: &SessionWriteRoute,
        path: String,
        bytes: &[u8],
    ) -> Result<SessionCheckpointBody> {
        route.require_recording(self.session_ref())?;
        if route.target() != RouteTarget::Overlay {
            return Err(crate::Error::InvalidConfig(
                "workflow session checkpoint route changed".to_owned(),
            ));
        }
        self.admit_participant()?;
        let mut sink = BodySink::new(
            self.body_dir(route.target())?,
            self.limit_watch()
                .bound(crate::limit_ask::EngineLimit::CodeResultInlineBytes),
            None,
        )
        .sweeping(self.known_source()?);
        sink.write(bytes)?;
        let finished =
            finish_output_sourced(path, sink, true, None, self.limit_watch(), |digest| {
                self.pin_result_body(digest)
            })?;
        self.admit_participant()?;
        Ok(SessionCheckpointBody(finished))
    }

    /// Called only inside this session's native routed transaction. Its
    /// RAW_OUTPUT row holds the body itself; no canonical owned descriptor
    /// or body history is fabricated for session bytes.
    pub(crate) fn put_checkpoint_body_in_txn(
        &self,
        route: &SessionWriteRoute,
        view: &SessionStoreView<'_>,
        txn: &mut heed::RwTxn<'_>,
        body: &SessionCheckpointBody,
        owner: EntityId,
    ) -> Result<()> {
        route.require_recording(self.session_ref())?;
        if route.target() != RouteTarget::Overlay {
            return Err(crate::Error::InvalidConfig(
                "workflow session checkpoint route changed".to_owned(),
            ));
        }
        let finished = &body.0;
        if let Some(key) = &finished.key {
            let dir = self.body_dir(route.target())?;
            let held = BODY_KEYS.get(view, txn, key.digest())?;
            let kept = match held.as_ref() {
                Some(held) => key.keeps(held, &dir)?,
                None => false,
            };
            if !kept {
                BODY_KEYS.put(view, txn, key.digest(), key.row())?;
            }
        }
        if let Some(reason) = finished.secret {
            let key = ResultOccurrence::of(Some(owner), &finished.output)?
                .mark_key(&finished.output.handle);
            RAW_OUTPUT_SECRETS.put(view, txn, &key, &reason.to_owned())?;
        }
        RAW_OUTPUTS.put(
            view,
            txn,
            &finished.output.handle,
            &finished.body.holding(true),
        )
    }

    /// The caller has already checked the current queue lease, participant,
    /// source readers and exact checkpoint row, and holds its custody guard
    /// and digest pin. Open body+key in that same composed snapshot.
    pub(crate) fn checkpoint_body_in_txn(
        &self,
        view: &SessionStoreView<'_>,
        txn: &heed::RoTxn<'_>,
        owner: EntityId,
        output: &CodeRunRawOutput,
    ) -> Result<Option<Vec<u8>>> {
        crate::code_run::codec::validate_raw_output(output)?;
        let occurrence = ResultOccurrence::of(Some(owner), output)?.mark_key(&output.handle);
        if RAW_OUTPUT_SECRETS.get(view, txn, &occurrence)?.is_some()
            || RAW_OUTPUT_TAINTS
                .get(view, txn, &occurrence)?
                .is_some_and(|taints| !taints.is_empty())
        {
            return Ok(None);
        }
        let Some(body) = RAW_OUTPUTS.get(view, txn, &output.handle)? else {
            return Ok(None);
        };
        let key = body_key_row_in_txn(view, txn, &output.raw_blake3)?;
        load_whole_body(output, body, key.as_ref(), || self.body_dirs()).map(Some)
    }
}
