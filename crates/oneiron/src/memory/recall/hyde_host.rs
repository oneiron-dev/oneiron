//! Stable authority key for a host expansion's pending work, without storing credentials.
impl super::Memory<'_> {
    /// Binds pending host work to the same actor, slip, binding key, scope and locality.
    /// Verification-time remaining TTL is not an identity. This key grants no read authority.
    pub fn hyde_host_credential_key(&self) -> super::MemoryResult<[u8; 32]> {
        let proof = self.read_proof.as_ref().ok_or_else(|| {
            super::MemoryError::bad_request("HyDE host work requires the caller's verified credential")
        })?;
        let claims = proof.claims();
        let bytes = serde_json::to_vec(&(
            self.actor.to_hex(), self.actor_class as u8, self.locality == crate::claim::CallerLocality::OnDevice,
            claims.slip_id, claims.binding_key, &claims.holder_ref, proof.scope(),
            &claims.records, &claims.channels, &claims.org_ref,
        )).map_err(|_| super::MemoryError::bad_request("HyDE credential scope cannot be encoded"))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
}
