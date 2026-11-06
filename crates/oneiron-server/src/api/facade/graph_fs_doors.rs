//! Cooperative file reads with the facade's original invocation setup.
use super::*;

pub(super) async fn graph_fs_bytes<I: serde::de::DeserializeOwned, O: serde::Serialize>(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    input: Result<serde_json::Value, FacadeApiError>,
    verb: &'static str,
    read: impl FnOnce(
        &oneiron::Memory<'_>,
        I,
        &oneiron::batch::ReadPacing,
    ) -> oneiron::memory::MemoryResult<O>
    + Send
    + 'static,
) -> Result<FacadeCallOutput, FacadeApiError> {
    let auth = call.auth();
    auth.require(CoreScope::Read)?;
    auth.require_lane_record_scope()?;
    let value = input?;
    let (actor, class) = facade_actor(server, auth)?;
    let server = Arc::clone(server);
    let owned = call.owned();
    let run_writes = super::host_doors::support::calling_run_writes();
    oneiron::batch::read_cooperatively(move |pacing| {
        oneiron::skill_attribution::with_run_write_token(run_writes.as_ref(), || {
            let producers = oneiron::memory::ProducerRows::default();
            let output = super::invoke::facade_invoke_on_thread(
                &server,
                &owned.call(),
                actor,
                class,
                verb,
                value,
                &producers,
                None,
                |memory, value| {
                    oneiron::task_verb::verb_hook_boundary::row(memory, verb, value, |value| {
                        let input = serde_json::from_value(value).map_err(|error| {
                            oneiron::memory::MemoryError::bad_request(format!(
                                "invalid SDK request: {error}"
                            ))
                        })?;
                        let outcome = read(memory, input, &pacing)?;
                        serde_json::to_value(outcome).map_err(|_| {
                            oneiron::memory::MemoryError::bad_request("SDK result encoding failed")
                        })
                    })
                },
            )?;
            Ok(FacadeCallOutput::listed(output, &producers))
        })
    })
    .await
    .map_err(MemoryError::from)?
}
