/**
 * @oneiron/xlsx-viewer — OF-336 xlsx viewer instrument.
 *
 * A view-only spreadsheet lens: SheetJS CE parses the blob (in a worker, lazily
 * per sheet) into Univer `IWorkbookData`; a pinned community Univer plugin set
 * renders it. Comments are ARTL-2 `anchored_annotation` claims (engine-side,
 * never viewer-local); the version scrubber and diff view read ARTL-3 manifest
 * ops only. No client recalculation, no export path, no Univer-Pro imports.
 */

// Coordinates
export * from "./a1";

// Import bridge (SheetJS CE -> Univer IWorkbookData)
export {
  readWorkbook,
  readWorkbookOutline,
  readSheet,
  readSheetMetas,
  sheetId,
  type ParseOptions,
  type SheetMeta,
} from "./bridge/parse";
export {
  createLocalWorkbookSource,
  createWorkerWorkbookSource,
  createInlineParseWorker,
  type WorkbookSource,
  type ParseWorkerLike,
} from "./bridge/source";
export { assembleWorkbook, loadedSheetCount } from "./bridge/assemble";
export { handleParseRequest } from "./bridge/handler";
export type {
  ParseRequest,
  ParseResponse,
  OutlineRequest,
  SheetRequest,
  OutlineResponse,
  SheetResponse,
  ErrorResponse,
} from "./bridge/protocol";

// Comments (ARTL-2 seam)
export * from "./annotations/types";
export {
  InMemoryAnnotationClient,
  threadsAtVersion,
  type AnnotationClient,
} from "./annotations/client";
export { CommentOverlayController, type CommentAnchorPin } from "./annotations/overlay";

// Manifest diff (ARTL-3 seam, D7)
export * from "./manifest/types";
export {
  diffManifest,
  formatCellValue,
  highlightCell,
  type ManifestDiff,
  type CellHighlight,
  type BandHighlight,
  type SheetChange,
} from "./manifest/diff";

// Version scrubber (D1 + D7)
export {
  VersionScrubber,
  InMemoryVersionChainClient,
  type VersionChainClient,
  type ArtifactVersion,
  type VersionProvenance,
} from "./versions/scrubber";

// Univer mount (heavyweight instrument glue)
export {
  createXlsxViewer,
  type XlsxViewerOptions,
  type XlsxViewerInstance,
} from "./univer/mount";
