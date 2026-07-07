/**
 * Session-aware request handler shared by the worker and by tests. It owns the
 * per-session workbook bytes (seeded once by `init`) and a per-session parsed-
 * sheet cache, so a `sheet` request re-parses nothing it has already produced
 * and never needs the bytes re-sent. Keeping it separate from `worker.ts` lets
 * the same logic run without spinning up a Worker.
 */
import { readSheet, readWorkbookOutline } from "./parse";
import type { ParseRequest, ParseResponse } from "./protocol";
import type { IWorksheetData } from "@univerjs/core";

interface Session {
  bytes: Uint8Array;
  name: string;
  sheets: Map<string, Partial<IWorksheetData>>;
}

export class ParseSessionStore {
  private readonly sessions = new Map<string, Session>();

  /** Returns a response for init/sheet, or null for dispose (no reply). */
  handle(request: ParseRequest): ParseResponse | null {
    try {
      switch (request.kind) {
        case "init": {
          this.sessions.set(request.session, {
            bytes: request.bytes,
            name: request.name ?? "workbook",
            sheets: new Map(),
          });
          return {
            kind: "init",
            id: request.id,
            workbook: readWorkbookOutline(request.bytes, request.name),
          };
        }
        case "sheet": {
          const session = this.sessions.get(request.session);
          if (!session) {
            throw new Error(`unknown parse session: ${request.session}`);
          }
          let sheet = session.sheets.get(request.sheetName);
          if (!sheet) {
            sheet = readSheet(session.bytes, request.sheetName, request.options);
            session.sheets.set(request.sheetName, sheet);
          }
          return { kind: "sheet", id: request.id, sheet };
        }
        case "dispose": {
          this.sessions.delete(request.session);
          return null;
        }
      }
    } catch (err) {
      return {
        kind: "error",
        id: request.kind === "dispose" ? -1 : request.id,
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
