/**
 * Message protocol between the main thread and the parse worker.
 *
 * Bytes cross the wire EXACTLY ONCE: an `init` seeds a session with the
 * workbook bytes (transferred, not cloned) and returns the cheap outline;
 * subsequent `sheet` requests carry only the session id, so visiting a tab
 * never re-clones a 30MB workbook. The worker owns the bytes for the session's
 * lifetime and frees them on `dispose`.
 */
import type { IWorkbookData, IWorksheetData } from "@univerjs/core";
import type { ParseOptions } from "./parse";

/** Seed a session with the workbook bytes; response is the outline. */
export interface InitRequest {
  readonly kind: "init";
  readonly id: number;
  readonly session: string;
  readonly bytes: Uint8Array;
  readonly name?: string;
}

/** Parse one sheet in an already-initialised session (bytes NOT re-sent). */
export interface SheetRequest {
  readonly kind: "sheet";
  readonly id: number;
  readonly session: string;
  readonly sheetName: string;
  readonly options?: ParseOptions;
}

/** Release a session's bytes and caches. Fire-and-forget (no response). */
export interface DisposeRequest {
  readonly kind: "dispose";
  readonly session: string;
}

export type ParseRequest = InitRequest | SheetRequest | DisposeRequest;

export interface InitResponse {
  readonly kind: "init";
  readonly id: number;
  readonly workbook: IWorkbookData;
}

export interface SheetResponse {
  readonly kind: "sheet";
  readonly id: number;
  readonly sheet: Partial<IWorksheetData>;
}

export interface ErrorResponse {
  readonly kind: "error";
  readonly id: number;
  readonly message: string;
}

export type ParseResponse = InitResponse | SheetResponse | ErrorResponse;
