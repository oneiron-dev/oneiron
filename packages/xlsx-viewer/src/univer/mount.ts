/**
 * Univer mount adapter — the heavyweight instrument glue (OF-368 D8).
 *
 * This is the only module that touches Univer at runtime. It pins the
 * community (Apache-2.0) `@univerjs/*` plugin set — grid, styles, formula,
 * thread-comments — and renders VIEW-ONLY:
 *
 *  - No export path. There is no import of `@univerjs-pro/*`; the xlsx export
 *    tax is avoided because round-tripping happens agent-side on the original
 *    blob (OF-368 D5). The automated `tests/no-pro-imports.test.ts` guards this.
 *  - No client-side recalculation. The bridge emits cells carrying cached
 *    values only (never a live `f`), so the formula engine — present for the
 *    formula bar per D8 — has nothing to recompute.
 *  - Comments are NOT stored in Univer. The store of record is ARTL-2
 *    `anchored_annotation` claims via {@link CommentOverlayController}; the
 *    Univer thread-comment plugin supplies the on-grid affordance only. Wiring
 *    Univer's comment model to ARTL-2 is a reconciliation seam (post-ONE-1552).
 *
 * The mount is not unit-tested (a canvas render is not meaningfully assertable
 * headless); its gate is `tsc`. The lazy-mount composition it relies on
 * (`assembleWorkbook`) and everything else is covered by the suite.
 */
import {
  ICommandService,
  IUniverInstanceService,
  LocaleType,
  LogLevel,
  Univer,
  UniverInstanceType,
} from "@univerjs/core";
import { UniverFormulaEnginePlugin } from "@univerjs/engine-formula";
import { UniverRenderEnginePlugin } from "@univerjs/engine-render";
import { UniverSheetsPlugin } from "@univerjs/sheets";
import { UniverSheetsFormulaPlugin } from "@univerjs/sheets-formula";
import { UniverSheetsNumfmtPlugin } from "@univerjs/sheets-numfmt";
import { UniverSheetsThreadCommentPlugin } from "@univerjs/sheets-thread-comment";
import { UniverSheetsUIPlugin } from "@univerjs/sheets-ui";
import { UniverThreadCommentPlugin } from "@univerjs/thread-comment";
import { UniverUIPlugin } from "@univerjs/ui";
import type { IWorkbookData, IWorksheetData, Workbook } from "@univerjs/core";
import type { WorkbookSource } from "../bridge/source";
import type { CommentOverlayController } from "../annotations/overlay";
import type { VersionScrubber } from "../versions/scrubber";
import { computeMountPlan } from "./plan";
import { isEditCommandId } from "./readonly";

export interface XlsxViewerOptions {
  readonly container: HTMLElement;
  readonly source: WorkbookSource;
  readonly overlay?: CommentOverlayController;
  readonly scrubber?: VersionScrubber;
  readonly darkMode?: boolean;
}

export interface XlsxViewerInstance {
  readonly univer: Univer;
  /** Load a sheet's cells (if not already) and remount the workbook with it. */
  showSheet(sheetName: string): Promise<void>;
  /** Sheet names, workbook order. */
  sheetNames(): string[];
  /** The sheet currently mounted with cell data. */
  activeSheet(): string | undefined;
  dispose(): void;
}

/**
 * Register the pinned, view-only community plugin set. Isolated so the no-Pro
 * audit and the plugin list have a single source of truth.
 */
function registerViewOnlyPlugins(univer: Univer, container: HTMLElement): void {
  univer.registerPlugin(UniverRenderEnginePlugin);
  univer.registerPlugin(UniverFormulaEnginePlugin);
  univer.registerPlugin(UniverUIPlugin, { container });
  univer.registerPlugin(UniverSheetsPlugin);
  univer.registerPlugin(UniverSheetsUIPlugin);
  univer.registerPlugin(UniverSheetsFormulaPlugin);
  univer.registerPlugin(UniverSheetsNumfmtPlugin);
  // Comment affordance only; store of record is ARTL-2 (reconciliation seam).
  univer.registerPlugin(UniverThreadCommentPlugin);
  univer.registerPlugin(UniverSheetsThreadCommentPlugin);
}

/**
 * Enforce view-only by rejecting any edit command before it executes. Blocks
 * only mutating commands ({@link isEditCommandId}); navigation, selection, and
 * active-sheet switching pass through untouched.
 */
function registerReadOnlyGuard(univer: Univer): void {
  const commandService = univer.__getInjector().get(ICommandService);
  commandService.beforeCommandExecuted((info) => {
    if (isEditCommandId(info.id)) {
      throw new Error(`xlsx viewer is read-only: blocked command ${info.id}`);
    }
  });
}

/**
 * Mount the xlsx viewer instrument into `container`. Only the active sheet's
 * cells are parsed up front; other sheets load on {@link XlsxViewerInstance.showSheet}.
 */
export async function createXlsxViewer(options: XlsxViewerOptions): Promise<XlsxViewerInstance> {
  const { container, source, darkMode } = options;

  const univer = new Univer({
    locale: LocaleType.EN_US,
    logLevel: LogLevel.SILENT,
    darkMode: darkMode ?? false,
  });
  registerViewOnlyPlugins(univer, container);
  registerReadOnlyGuard(univer);

  const instanceService = univer.__getInjector().get(IUniverInstanceService);

  const outline = await source.outline();
  const loaded = new Map<string, Partial<IWorksheetData>>();

  const orderedNames: string[] = [];
  for (const sid of outline.sheetOrder) {
    const name = outline.sheets[sid]?.name;
    if (name !== undefined) {
      orderedNames.push(name);
    }
  }

  /** (Re)create the workbook unit and activate the requested sheet. */
  function mountActive(activeName: string): string {
    const plan = computeMountPlan(outline, loaded, activeName);
    const unit: Workbook = univer.createUnit<IWorkbookData, Workbook>(
      UniverInstanceType.UNIVER_SHEET,
      plan.workbook,
    );
    // Univer opens sheetOrder[0] by default; re-activate the requested sheet so
    // the grid does not silently reopen on the first tab after a remount.
    const worksheet = unit.getSheetBySheetId(plan.activeSheetId);
    if (worksheet) {
      unit.setActiveSheet(worksheet);
    }
    return plan.workbook.id;
  }

  let active: string | undefined = orderedNames[0];
  let mountedId: string | undefined;
  if (active !== undefined) {
    loaded.set(active, await source.sheet(active));
    mountedId = mountActive(active);
  }

  return {
    univer,
    sheetNames() {
      return [...orderedNames];
    },
    activeSheet() {
      return active;
    },
    async showSheet(sheetName: string) {
      if (!orderedNames.includes(sheetName)) {
        throw new Error(`no such sheet: ${sheetName}`);
      }
      if (!loaded.has(sheetName)) {
        loaded.set(sheetName, await source.sheet(sheetName));
      }
      active = sheetName;
      // Remount with the newly loaded sheet. Incremental in-place injection is a
      // follow-up optimisation; correctness-first for the MVP.
      if (mountedId !== undefined) {
        instanceService.disposeUnit(mountedId);
      }
      mountedId = mountActive(sheetName);
    },
    dispose() {
      source.dispose();
      univer.dispose();
    },
  };
}
