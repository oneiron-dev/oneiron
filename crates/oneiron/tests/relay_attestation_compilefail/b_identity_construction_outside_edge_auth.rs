//! (b) `AuthenticatedConnectionIdentity` must not be constructible outside
//! the edge-auth path: both fields are private and the only constructor is
//! `AuthenticatedConnectionIdentity::from_edge_auth`, owned by the
//! connector-edge auth layer.

fn main() {
    let _ = oneiron::AuthenticatedConnectionIdentity {
        service_identity: "connector-edge:cloud-vault".to_owned(),
        connection_class: oneiron::ConnectionClass::CloudVaultPeer,
    };
}
