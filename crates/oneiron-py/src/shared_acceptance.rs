//! Original-value shared invitation acceptance for the Python binding.
//!
//! The successful HTTPS acceptance as its native value, never a decoded
//! receipt: the exact request, recipient key and returned credential stay
//! with the verified call that produced them. A receipt record cannot
//! construct this object or supply its provenance.

use std::sync::Arc;

use pyo3::prelude::*;

use crate::{encode, raise};

/// A successful acceptance on the connected HTTPS home, kept as the native
/// value. Receipt records cannot construct this object or supply its provenance.
#[pyclass(frozen)]
pub(crate) struct NativeSharedAcceptance {
    pub(crate) inner: Arc<oneiron_remote::HttpsSharedInvitationAcceptance>,
}

impl NativeSharedAcceptance {
    /// The native acceptance, retained as its original value.
    pub(crate) fn from_accepted(accepted: oneiron_remote::HttpsSharedInvitationAcceptance) -> Self {
        Self {
            inner: Arc::new(accepted),
        }
    }
}

#[pymethods]
impl NativeSharedAcceptance {
    /// The normalized HTTPS home the acceptance selected.
    fn home_url(&self) -> String {
        self.inner.home_url().to_owned()
    }

    /// The exact facade URL the original acceptance used.
    fn acceptance_url(&self) -> String {
        self.inner.acceptance_url().to_owned()
    }

    /// The original request; reading it does not create another acceptance.
    fn request(&self) -> PyResult<String> {
        encode(self.inner.request())
    }

    /// The complete original receipt and member credential, available even
    /// after member-client creation or native bootstrap fails.
    fn reply(&self) -> PyResult<String> {
        encode(self.inner.reply())
    }

    /// A remote member handle on the same HTTPS home and original HTTP wire.
    /// Each request still passes the home's ordinary admission checks.
    fn member_client(&self, py: Python<'_>) -> PyResult<crate::NativeClient> {
        let inner = py.detach(|| self.inner.member_client()).map_err(raise)?;
        Ok(crate::NativeClient { inner, keep: None })
    }
}
