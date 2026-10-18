//! Browser wire shapes, shared by code mode and the credential-bound host doors.
pub use oneiron_browser::{
    BatchInput as BrowserBatchInput, BatchOutput as BrowserBatchOutput,
    ClickInput as BrowserClickInput, CropInput as BrowserCropInput,
    ExpectInput as BrowserExpectInput, ExpectOutput as BrowserExpectOutput,
    FindInput as BrowserFindInput, FindOutput as BrowserFindOutput,
    HandoverInput as BrowserHandoverInput, HandoverOutput as BrowserHandoverOutput,
    ImageOutput as BrowserImageOutput, ObservationPage as BrowserObservationPage,
    ObserveInput as BrowserObserveInput, OpenInput as BrowserOpenInput,
    PointInput as BrowserPointInput, ScreenshotInput as BrowserScreenshotInput,
    ScreenshotOutput as BrowserScreenshotOutput, SelectInput as BrowserSelectInput,
    TypeInput as BrowserTypeInput, ViewInput as BrowserViewInput,
    WaitForInput as BrowserWaitForInput, WaitForOutput as BrowserWaitForOutput,
    ZoomInput as BrowserZoomInput,
};
