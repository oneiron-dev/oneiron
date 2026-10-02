#!/usr/bin/env python3
"""Windows Excel recorder for the pinned spreadsheet-compat cases (COM through pywin32).

Mirrors harness/scripts/office/excel_cases.js + run_excel_oracle.py on the Mac: one new workbook per case,
setup cells typed as the corpus says (strings kept as text), the Z1 canary =1111+2222, the case formula at the
check anchor, Calculate, SaveAs xlsx, Close. The receipt is then built from the saved files with the harness's own
readers (cached_cells / validate_setup / result_value copied verbatim), so collect_excel_goldens.py can pin it.
Usage: python win_excel_cases.py --cases cases.json --output OUTDIR [--limit N]
"""
import argparse, hashlib, json, os, re, sys, time, zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

NS = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --- copied verbatim from harness/scripts/office/run_excel_oracle.py (the readers the goldens are proven with)
def cached_cells(path):
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise ValueError("invalid output ZIP")
        strings = []
        if "xl/sharedStrings.xml" in archive.namelist():
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            strings = ["".join(item.itertext()) for item in root.findall("s:si", NS)]
        root = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
        cells = {}
        for cell in root.findall(".//s:sheetData/s:row/s:c", NS):
            kind = cell.get("t", "n")
            value = cell.find("s:v", NS)
            if kind == "inlineStr":
                value = cell.find("s:is", NS)
                decoded = "".join(value.itertext()) if value is not None else ""
            elif value is None:
                decoded = None
            elif kind == "s":
                decoded = strings[int(value.text)]
            elif kind == "b":
                decoded = value.text == "1"
            elif kind in ("e", "str"):
                decoded = value.text or ""
            else:
                decoded = float(value.text) if value.text else None
            cells[cell.attrib["r"]] = decoded
        return cells


def validate_setup(case, cells):
    for address, expected in case.get("setup_cells", {}).items():
        if isinstance(expected, str) and expected.startswith("="):
            continue
        actual = cells.get(address)
        if expected is None:
            if actual not in (None, ""):
                raise ValueError(f"setup blank changed at {address}")
        elif isinstance(expected, bool):
            if type(actual) is not bool or actual != expected:
                raise ValueError(f"setup boolean changed at {address}")
        elif isinstance(expected, str):
            if type(actual) is not str or actual != expected:
                raise ValueError(f"setup string changed at {address}")
        elif isinstance(actual, bool) or not isinstance(actual, (float, int)) or actual != expected:
            raise ValueError(f"setup number changed at {address}")


def coordinate(address):
    match = re.fullmatch(r"([A-Z]+)([1-9][0-9]*)", address)
    if not match:
        raise ValueError("bad cell address")
    col = 0
    for ch in match[1]:
        col = col * 26 + ord(ch) - ord("A") + 1
    return int(match[2]), col


def address(row, col):
    letters = ""
    while col:
        col, rem = divmod(col - 1, 26)
        letters = chr(65 + rem) + letters
    return f"{letters}{row}"


def result_value(case, cells):
    check = case.get("check_range", "F1")
    first, _, last = check.partition(":")
    if not last:
        return cells.get(first)
    sr, sc = coordinate(first)
    er, ec = coordinate(last)
    grid = [[cells.get(address(r, c)) for c in range(sc, ec + 1)] for r in range(sr, er + 1)]
    expected = case.get("expected")
    if isinstance(expected, list) and expected and not isinstance(expected[0], list):
        return [v for row in grid for v in row]
    return grid
# --- end of the copied readers


def excel_file_version(app):
    try:
        import win32api
        exe = os.path.join(app.Path, 'EXCEL.EXE')
        info = win32api.GetFileVersionInfo(exe, '\\')
        ms, ls = info['FileVersionMS'], info['FileVersionLS']
        return f'{ms >> 16}.{ms & 0xffff}.{ls >> 16}.{ls & 0xffff}'
    except Exception:
        return None


def record(cases, out):
    """One Excel instance, one new workbook per case (the Mac JXA steps in the same order)."""
    import pythoncom, win32com.client
    pythoncom.CoInitialize()
    app = win32com.client.DispatchEx('Excel.Application')
    report = dict(cases=[])
    try:
        app.Visible = False
        app.DisplayAlerts = False
        app.AskToUpdateLinks = False
        app.EnableEvents = False
        app.ScreenUpdating = False
        app.AutomationSecurity = 3
        report.update(version=f'{app.Version}.{app.Build}', excel_build=excel_file_version(app),
                      initialWorkbooks=app.Workbooks.Count, region=None)
        try:
            import locale
            report['region'] = locale.getlocale()
        except Exception:
            pass
        for index, c in enumerate(cases):
            row = dict(id=c['id'], status='error', stage='new', file=f'case-{index:04}.xlsx')
            wb = None
            try:
                wb = app.Workbooks.Add()
                row['workbookName'] = wb.Name
                wb.Date1904 = False
                sheet = wb.Worksheets(1)
                sheet.Name = 'Sheet1'
                row['stage'] = 'setup'
                for addr, value in (c.get('setup_cells') or {}).items():
                    if value is None:
                        continue
                    rng = sheet.Range(addr)
                    if isinstance(value, str) and value.startswith('='):
                        rng.Formula2 = value
                    else:
                        # Preserve the corpus's typed string: Excel otherwise converts "2" and "TRUE" into numeric/boolean cells.
                        if isinstance(value, str):
                            rng.NumberFormat = '@'
                        rng.Value = value
                sheet.Range('Z1').Formula2 = '=1111+2222'
                anchor = (c.get('check_range') or 'F1').split(':')[0]
                row['stage'] = 'formula'
                try:
                    sheet.Range(anchor).Formula2 = c['formula']
                except Exception as error:
                    row['formulaError'] = str(error)[:400]
                row['formulaRetained'] = bool(sheet.Range(anchor).HasFormula)
                if not row['formulaRetained'] and not row.get('formulaError'):
                    row['formulaError'] = 'Excel did not retain the requested formula'
                row['stage'] = 'recalc'
                sheet.Calculate()
                row['canary'] = sheet.Range('Z1').Value2
                row['date1904'] = bool(wb.Date1904)
                row['stage'] = 'calculated'
                row['status'] = 'formula-rejected' if row.get('formulaError') else 'ok'
                row['stage'] = 'save'
                wb.SaveAs(Filename=str(out / row['file']), FileFormat=51, ConflictResolution=2, CreateBackup=False)
                if wb.Name != row['file']:
                    raise RuntimeError('Excel did not save the owned workbook')
                wb.Close(SaveChanges=False)
                wb = None
                row['stage'] = 'saved'
            except Exception as error:
                row['error'] = str(error)[:400]
                row['status'] = 'error'
                try:
                    if wb is not None:
                        wb.Close(SaveChanges=False)
                except Exception:
                    pass
            row['remainingWorkbooks'] = app.Workbooks.Count
            report['cases'].append(row)
            print(index + 1, len(cases), row['status'], c['id'], flush=True)
            if row['status'] == 'error' or row['remainingWorkbooks'] != 0:
                report['error'] = json.dumps(row)
                break
    finally:
        try:
            report['finalWorkbooks'] = app.Workbooks.Count
            app.Quit()
        except Exception:
            pass
        pythoncom.CoUninitialize()
    return report


def build_receipt(cases, cases_path, out, report, started):
    me = digest(Path(__file__).resolve())
    receipt = {"status": "running", "input_sha256": digest(cases_path), "script_sha256": me, "cleanup_sha256": me,
               "save_sha256": me, "runner_sha256": me, "platform": "windows", "excel_build": report.get('excel_build'),
               "region": report.get('region'), "app_version": report.get('excel_build') or report.get('version'),
               "cases": {}, "batches": [dict(report=report)], "started_at": started,
               "sources": [dict(platform="windows", excel_build=report.get('excel_build'), region="en-US", driver_sha256=me)]}
    try:
        for case, result in zip(cases[:len(report['cases'])], report['cases']):
            if result['status'] not in ('ok', 'formula-rejected'):
                raise RuntimeError(f"case {case['id']} ended {result['status']}: {result.get('error')}")
            path = out / result['file']
            values = cached_cells(path)
            if result['canary'] != 3333 or values.get('Z1') != 3333 or result['date1904']:
                raise RuntimeError(f"untrusted recalc or unexpected calendar mode in {case['id']}")
            validate_setup(case, values)
            value = result_value(case, values)
            status = result['status']
            if status == 'ok' and value is None:
                status = 'missing-cache'
            receipt['cases'][case['id']] = {"status": status, "value": value, "output_sha256": digest(path), "file": path.name,
                                            "formula_rejection": result.get('formulaError'), "canary": 3333}
        if len(receipt['cases']) != len(cases) or report.get('error'):
            raise RuntimeError(f"recorded {len(receipt['cases'])} of {len(cases)}; {report.get('error')}")
        receipt['status'] = 'completed'
    except Exception as error:
        receipt['status'] = 'failed'
        receipt['error'] = str(error)
    receipt['finished_at'] = time.time()
    receipt['lock_retained'] = False
    return receipt


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--cases', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--limit', type=int)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    cases = json.loads(a.cases.read_text(encoding='utf-8'))
    if a.limit is not None:
        cases = cases[:a.limit]
    started = time.time()
    report = record(cases, a.output.resolve())
    receipt = build_receipt(cases, a.cases, a.output, report, started)
    (a.output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    counts = {}
    for row in receipt['cases'].values():
        counts[row['status']] = counts.get(row['status'], 0) + 1
    (a.output / 'done.txt').write_text(json.dumps(dict(status=receipt['status'], cases=len(receipt['cases']), counts=counts, error=receipt.get('error'))) + '\n')
    print('DONE', receipt['status'], json.dumps(counts), receipt.get('error', ''), flush=True)


if __name__ == '__main__':
    main()
