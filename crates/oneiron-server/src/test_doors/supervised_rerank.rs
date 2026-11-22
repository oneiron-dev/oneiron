//! Doors for `tests/supervised_rerank_socket.rs` (L9-15): the reranker on a
//! managed llama.cpp worker's own Unix socket, its peer checked against the
//! supervised child.

pub use crate::models::socket_launch_door::{
    SocketStub, record_socket_launch, reranker_on_device_view,
};

/// Marks this process as the one that launches managed workers, as plain
/// and embedded serve do before they build their models.
pub fn permit_worker_launch() {
    crate::models::permit_worker_launch();
}
