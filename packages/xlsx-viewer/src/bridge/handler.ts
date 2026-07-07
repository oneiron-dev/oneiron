/**
 * Pure request->response handler shared by the worker and by tests. Keeping it
 * separate from `worker.ts` lets the same parse logic be exercised without
 * spinning up a Worker.
 */
import { readSheet, readWorkbookOutline } from "./parse";
import type { ParseRequest, ParseResponse } from "./protocol";

export function handleParseRequest(request: ParseRequest): ParseResponse {
  try {
    if (request.kind === "outline") {
      return {
        kind: "outline",
        id: request.id,
        workbook: readWorkbookOutline(request.bytes, request.name),
      };
    }
    return {
      kind: "sheet",
      id: request.id,
      sheet: readSheet(request.bytes, request.sheetName, request.options),
    };
  } catch (err) {
    return {
      kind: "error",
      id: request.id,
      message: err instanceof Error ? err.message : String(err),
    };
  }
}
