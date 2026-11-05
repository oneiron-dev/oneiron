//! Cooperative snapshot-file reads with the facade's original invocation setup.
use super::*;

pub(super) async fn graph_fs_read_file(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    input: Result<serde_json::Value, FacadeApiError>,
) -> Result<FacadeCallOutput, FacadeApiError> {
    const VERB: &str = "graph_fs.read_file";
    let auth = call.auth();
    auth.require(CoreScope::Read)?;
    auth.require_lane_record_scope()?;
    let value = input?;
    let (actor, class) = facade_actor(server, auth)?;
    let server = Arc::clone(server);
    let owned = call.owned();
    oneiron::batch::read_cooperatively(move |pacing| {
        let producers = oneiron::memory::ProducerRows::default();
        let output = super::invoke::facade_invoke_on_thread(
            &server,
            &owned.call(),
            actor,
            class,
            VERB,
            value,
            &producers,
            None,
            |memory, value| {
                oneiron::task_verb::verb_hook_boundary::row(memory, VERB, value, |value| {
                    let input = serde_json::from_value(value).map_err(|error| {
                        oneiron::memory::MemoryError::bad_request(format!(
                            "invalid SDK request: {error}"
                        ))
                    })?;
                    let outcome = memory.graph_fs_read_file_with_pacing(input, &pacing)?;
                    serde_json::to_value(outcome).map_err(|_| {
                        oneiron::memory::MemoryError::bad_request("SDK result encoding failed")
                    })
                })
            },
        )?;
        Ok(FacadeCallOutput::listed(output, &producers))
    })
    .await
    .map_err(MemoryError::from)?
}
