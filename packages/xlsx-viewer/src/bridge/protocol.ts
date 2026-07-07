/**
 * Message protocol between the main thread and the parse worker.
 * The worker only ever moves plain data (bytes in, `IWorkbookData` fragments
 * out), so it carries no Univer runtime and no viewer state.
 */
import type { IWorkbookData, IWorksheetData } from "@univerjs/core";
import type { ParseOptions } from "./parse";

export interface OutlineRequest {
  readonly kind: "outline";
  readonly id: number;
  readonly bytes: Uint8Array;
  readonly name?: string;
}

export interface SheetRequest {
  readonly kind: "sheet";
  readonly id: number;
  readonly bytes: Uint8Array;
  readonly sheetName: string;
  readonly options?: ParseOptions;
}

export type ParseRequest = OutlineRequest | SheetRequest;

export interface OutlineResponse {
  readonly kind: "outline";
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

export type ParseResponse = OutlineResponse | SheetResponse | ErrorResponse;
