//! Browser wire shapes, shared by code mode and the credential-bound host doors.
pub use oneiron_browser::{
    BatchInput as BrowserBatchInput, ClickInput as BrowserClickInput,
    CropInput as BrowserCropInput, ExpectInput as BrowserExpectInput,
    FindInput as BrowserFindInput, HandoverInput as BrowserHandoverInput,
    LibraryFindInput as BrowserLibraryFindInput, LibraryRetireInput as BrowserLibraryRetireInput,
    LibraryRetiredInput as BrowserLibraryRetiredInput, LibraryRunInput as BrowserLibraryRunInput,
    ObservationBase as BrowserObservationBase, ObserveInput as BrowserObserveInput,
    OpenInput as BrowserOpenInput, PointInput as BrowserPointInput,
    ProposeInput as BrowserLibraryProposeInput, Rebound as BrowserRebound,
    RowSplice as BrowserRowSplice, ScreenshotInput as BrowserScreenshotInput,
    SelectInput as BrowserSelectInput, StepRebound as BrowserStepRebound,
    TypeInput as BrowserTypeInput, ViewInput as BrowserViewInput,
    WaitForInput as BrowserWaitForInput, ZoomInput as BrowserZoomInput,
};

// Each browser answer as the run's door gives it (CUA-001): the verb's own,
// with the takeover a person ended and the agent's move to another tab since
// its last answer, once each.
pub type BrowserBatchOutput = oneiron_browser::BrowserAnswer<oneiron_browser::BatchOutput>;
pub type BrowserExpectOutput = oneiron_browser::BrowserAnswer<oneiron_browser::ExpectOutput>;
pub type BrowserFindOutput = oneiron_browser::BrowserAnswer<oneiron_browser::FindOutput>;
pub type BrowserHandoverOutput = oneiron_browser::BrowserAnswer<oneiron_browser::HandoverOutput>;
pub type BrowserImageOutput = oneiron_browser::BrowserAnswer<oneiron_browser::ImageOutput>;
pub type BrowserLibraryFindOutput =
    oneiron_browser::BrowserAnswer<oneiron_browser::LibraryFindOutput>;
pub type BrowserLibraryProposeOutput =
    oneiron_browser::BrowserAnswer<oneiron_browser::ProposeOutput>;
pub type BrowserLibraryRetireOutput =
    oneiron_browser::BrowserAnswer<oneiron_browser::LibraryRetireOutput>;
pub type BrowserLibraryRetiredOutput =
    oneiron_browser::BrowserAnswer<oneiron_browser::LibraryRetiredOutput>;
pub type BrowserLibraryRunOutput =
    oneiron_browser::BrowserAnswer<oneiron_browser::LibraryRunOutput>;
pub type BrowserObservationPage = oneiron_browser::BrowserAnswer<oneiron_browser::ObservationPage>;
pub type BrowserScreenshotOutput =
    oneiron_browser::BrowserAnswer<oneiron_browser::ScreenshotOutput>;
pub type BrowserWaitForOutput = oneiron_browser::BrowserAnswer<oneiron_browser::WaitForOutput>;
