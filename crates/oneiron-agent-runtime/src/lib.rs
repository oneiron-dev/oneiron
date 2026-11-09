//! `oneiron-agent-runtime`: the lifted half of `oneiron::code_sandbox` (core split; plan
//! lanes/kimi/OPUS-STORE/CORE-SPLIT-PLAN-20261107.md). It sits above `oneiron`: every `crate::x` path in
//! the moved code resolves through the glob below to `oneiron::x`, unless this crate defines `x`.
//! lift_mover.py checks that no local item shadows a core one; the lints catch a second glob re-export
//! of the same name and a private item hiding a public glob re-export.
#![deny(ambiguous_glob_reexports, hidden_glob_reexports)]

#[allow(unused_imports)]
pub(crate) use oneiron::*;

pub mod code_sandbox;

/// The extension traits that carry methods of core types which moved here.
pub mod ext {
    pub use crate::code_sandbox::egress::CodeSandboxEgressFixtureFixtureForwardExt;
    pub use crate::code_sandbox::egress::CodeSandboxEgressFloorGuestPermitsExt;
    pub use crate::code_sandbox::egress::CodeSandboxEgressFloorVaultExt;
    pub use crate::code_sandbox::egress::CodeSandboxEgressNameGateEgressNameRefusalExt;
    pub use crate::code_sandbox::egress::CodeSandboxEgressNameGateFieldsExt;
    pub use crate::code_sandbox::egress::quic::CodeSandboxEgressQuicCryptoClientKeysExt;
    pub use crate::code_sandbox::egress::quic::CodeSandboxEgressQuicFlowsFlowTableExt;
    pub use crate::code_sandbox::egress::quic::CodeSandboxEgressQuicFlowsReleaseExt;
    pub use crate::code_sandbox::egress::quic::CodeSandboxEgressQuicInitialVersionExt;
    pub use crate::code_sandbox::egress::quic::CodeSandboxEgressQuicInitialReaderExt;
    pub use crate::code_sandbox::egress::quic::CodeSandboxEgressQuicReassemblyCryptoStreamExt;
    pub use crate::code_sandbox::egress::CodeSandboxEgressReceiptVaultExt;
    pub use crate::code_sandbox::CodeSandboxGuestErrorGuestProgramErrorExt;
    pub use crate::code_sandbox::microvm::CodeSandboxMicrovmAdapterMicroVmSandboxAdapterExt;
    pub use crate::code_sandbox::microvm::CodeSandboxMicrovmCredentialCredentialDestinationExt;
    pub use crate::code_sandbox::microvm::CodeSandboxMicrovmCredentialCredentialAllowlistExt;
    pub use crate::code_sandbox::microvm::CodeSandboxMicrovmCredentialCredentialInjectionExt;
    pub use crate::code_sandbox::microvm::CodeSandboxMicrovmCredentialCredentialEgressProxyExt;
    pub use crate::code_sandbox::microvm::CodeSandboxMicrovmHandleGuestImageExt;
    pub use crate::code_sandbox::microvm::CodeSandboxMicrovmHandleMicroVmHandleExt;
    pub use crate::code_sandbox::microvm::CodeSandboxMicrovmHandleExecutionBudgetExt;
    pub use crate::code_sandbox::microvm::CodeSandboxMicrovmOutputMicroVmOutputSpoolExt;
    pub use crate::code_sandbox::proposal::body::CodeSandboxProposalBodyTextSandboxProposalTextExt;
}
